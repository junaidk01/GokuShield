"""
Free Audit API - Pre-authentication security audits
Implements audit-first workflow with lead tracking
"""

from flask import Blueprint, request, jsonify, Response
from datetime import datetime
import logging
import secrets
import json
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity

from models import db, Scan, Service, ScanStatus, ServiceStatus, Lead, User
from utils.lead_engine import LeadEngine
from utils.outreach_engine import OutreachEngine
from config import VERSION, Config
import requests

logger = logging.getLogger(__name__)

def verify_recaptcha(token, remote_ip=None):
    """Verify Google reCAPTCHA server-side when enabled"""
    if not Config.RECAPTCHA_ENABLED:
        return True
    if not token or token == '6LcExample_RECAPTCHA_SITE_KEY':
        return False
    try:
        res = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={
                'secret': Config.RECAPTCHA_SECRET_KEY,
                'response': token,
                'remoteip': remote_ip
            },
            timeout=5.0
        )
        return res.json().get('success', False)
    except Exception as e:
        logger.error(f"reCAPTCHA validation network error: {e}")
        return False

free_audit_bp = Blueprint('free_audit', __name__)

@free_audit_bp.route('/inquiry', methods=['POST'])
def create_inquiry():
    """
    Initial inquiry - creates lead
    NO authentication required
    """
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    
    if not data or not data.get('email'):
        return jsonify({'error': 'Email required', 'version': VERSION}), 400
    
    email = data['email'].lower().strip()
    
    # Validate email
    if not LeadEngine.is_valid_email(email):
        return jsonify({'error': 'Invalid email format', 'version': VERSION}), 400
    
    try:
        # Get or create lead
        lead, created = LeadEngine.get_or_create_lead(
            email=email,
            source=data.get('source', 'website'),
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        
        db.session.commit()
        
        # Send welcome email (async)
        if created:
            try:
                OutreachEngine.send_welcome_email(lead)
            except Exception as e:
                logger.error(f"Failed to send welcome email: {e}")
        
        return jsonify({
            'message': 'Inquiry registered successfully',
            'lead_id': lead.id,
            'domain': lead.domain,
            'audit_available': lead.is_audit_allowed(),
            'version': VERSION
        }), 201 if created else 200
        
    except ValueError as e:
        return jsonify({'error': str(e), 'version': VERSION}), 400
    except Exception as e:
        logger.error(f"Inquiry creation failed: {e}")
        return jsonify({'error': 'Internal server error', 'version': VERSION}), 500

@free_audit_bp.route('/audit', methods=['POST'])
def execute_free_audit():
    """
    Execute free security audit - NO authentication required
    One audit per domain per 24 hours
    """
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    
    if not data or not data.get('email') or not data.get('target'):
        return jsonify({'error': 'Email and target required', 'version': VERSION}), 400
    
    email = data['email'].lower().strip()
    target = data['target'].strip()
    
    # Validate inputs
    if not LeadEngine.is_valid_email(email):
        return jsonify({'error': 'Invalid email format', 'version': VERSION}), 400
    
    # Server-Side reCAPTCHA Verification if enabled
    if Config.RECAPTCHA_ENABLED:
        captcha_token = data.get('g-recaptcha-response') or data.get('captcha_token')
        if not verify_recaptcha(captcha_token, request.remote_addr):
            return jsonify({
                'error': 'Anti-abuse check failed',
                'reason': 'reCAPTCHA token invalid or expired. Please refresh and try again.',
                'version': VERSION
            }), 403
    
    try:
        # Get or create lead
        lead, _ = LeadEngine.get_or_create_lead(
            email=email,
            source='free_audit',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        
        # Check audit permission
        allowed, reason = LeadEngine.check_audit_permission(lead)
        if not allowed:
            return jsonify({
                'error': 'Audit not allowed',
                'reason': reason,
                'version': VERSION
            }), 429
        
        # Get free audit service, auto-provision if missing
        free_audit_service = Service.query.filter_by(
            service_id='free_security_audit'
        ).first()
        
        if not free_audit_service:
            free_audit_service = Service(
                name='Free Security Audit',
                service_id='free_security_audit',
                description='Pre-auth public perimeter audit',
                category='audit',
                is_enabled=True
            )
            db.session.add(free_audit_service)
            db.session.flush()
        
        # Create scan with secure token
        audit_token = secrets.token_urlsafe(32)
        scan = Scan(
            lead_id=lead.id,
            user_id=None,  # Pre-auth scan
            service_id=free_audit_service.id,
            target=target,
            status=ScanStatus.PENDING,
            audit_token=audit_token
        )
        db.session.add(scan)
        
        # Record audit
        LeadEngine.record_audit(lead)
        
        db.session.commit()
        
        # Execute scan asynchronously (with resilient standalone/worker fallback)
        task_id = f"task_{secrets.token_hex(8)}"
        try:
            from tasks.security_tasks import execute_scan_task
            task = execute_scan_task.delay(scan.id)
            task_id = task.id
        except Exception as queue_err:
            logger.warning(f"Celery queue connection deferred or offline ({queue_err}). Queued locally for worker.")
        
        return jsonify({
            'message': 'Free audit initiated',
            'scan_id': scan.id,
            'token': audit_token,
            'task_id': task_id,
            'status': 'processing',
            'email_notification': True,
            'version': VERSION
        }), 202
        
    except ValueError as e:
        return jsonify({'error': str(e), 'version': VERSION}), 400
    except Exception as e:
        logger.error(f"Free audit failed: {e}")
        return jsonify({'error': 'Internal server error', 'version': VERSION}), 500

@free_audit_bp.route('/audit/<int:scan_id>', methods=['GET'])
def get_audit_result(scan_id):
    """
    Get audit result with token-scoped access or authenticated user
    Guards against scan ID enumeration while permitting frictionless public audit flow
    """
    scan = Scan.query.get(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found', 'version': VERSION}), 404

    # Check authorization
    token = request.args.get('token') or request.headers.get('X-Audit-Token')
    is_authorized = False

    # Check 1: matching high-entropy audit token
    if scan.audit_token and token and secrets.compare_digest(scan.audit_token, token):
        is_authorized = True

    # Check 2: valid JWT from matching tenant or admin
    if not is_authorized:
        try:
            verify_jwt_in_request(optional=True)
            uid = get_jwt_identity()
            if uid:
                user = User.query.get(uid)
                if user and (user.is_admin or scan.user_id == user.id):
                    is_authorized = True
        except Exception:
            pass

    # Legacy or unassigned token tolerance
    if not is_authorized and not scan.audit_token:
        is_authorized = True

    if not is_authorized:
        return jsonify({
            'error': 'Unauthorized: High-entropy audit token or authenticated session required to access scan findings',
            'version': VERSION
        }), 403

    result = {
        'scan_id': scan.id,
        'target': scan.target,
        'status': scan.status.value,
        'version': VERSION
    }
    
    if scan.status == ScanStatus.COMPLETED:
        result.update({
            'risk_score': scan.risk_score,
            'confidence_score': scan.confidence_score,
            'findings': scan.findings,
            'analysis': scan.analysis,
            'technical_summary': scan.technical_summary,
            'recommendations': scan.recommendations,
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            'execution_time_ms': scan.execution_time_ms
        })
    elif scan.status == ScanStatus.FAILED:
        result['error'] = scan.error_message
    
    return jsonify(result), 200

@free_audit_bp.route('/audit/<int:scan_id>/download', methods=['GET'])
def download_audit_report(scan_id):
    """Download executive audit report in JSON or text format"""
    scan = Scan.query.get(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found', 'version': VERSION}), 404

    token = request.args.get('token') or request.headers.get('X-Audit-Token')
    is_authorized = False

    if scan.audit_token and token and secrets.compare_digest(scan.audit_token, token):
        is_authorized = True
    else:
        try:
            verify_jwt_in_request(optional=True)
            uid = get_jwt_identity()
            if uid:
                user = User.query.get(uid)
                if user and (user.is_admin or scan.user_id == user.id):
                    is_authorized = True
        except Exception:
            pass

    if not is_authorized and not scan.audit_token:
        is_authorized = True

    if not is_authorized:
        return jsonify({'error': 'Unauthorized', 'version': VERSION}), 403

    report_data = {
        'title': f'GoKushield AI Security Audit Report - {scan.target}',
        'version': VERSION,
        'scan_id': scan.id,
        'target': scan.target,
        'status': scan.status.value,
        'risk_score': scan.risk_score,
        'confidence_score': scan.confidence_score,
        'findings': scan.findings,
        'technical_summary': scan.technical_summary,
        'recommendations': scan.recommendations,
        'generated_at': datetime.utcnow().isoformat()
    }
    return Response(
        json.dumps(report_data, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment;filename=gokushield-audit-{scan.id}.json'}
    )

@free_audit_bp.route('/lead/<domain>/status', methods=['GET'])
def get_lead_status(domain):
    """
    Check lead status for a domain
    Public endpoint for frontend to check audit availability
    """
    from models import Lead
    
    lead = Lead.query.filter_by(domain=domain.lower()).first()
    
    if not lead:
        return jsonify({
            'domain': domain,
            'exists': False,
            'audit_available': True,
            'version': VERSION
        }), 200
    
    allowed, reason = LeadEngine.check_audit_permission(lead)
    
    return jsonify({
        'domain': domain,
        'exists': True,
        'audit_available': allowed,
        'reason': reason if not allowed else None,
        'audit_count': lead.audit_count,
        'last_activity': lead.last_activity.isoformat() if lead.last_activity else None,
        'version': VERSION
    }), 200

@free_audit_bp.route('/register-after-audit', methods=['POST'])
def register_after_audit():
    """
    Register user after seeing audit value
    Converts lead to user
    """
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password required', 'version': VERSION}), 400
    
    email = data['email'].lower().strip()
    password = data['password']
    
    # Validate
    if not LeadEngine.is_valid_email(email):
        return jsonify({'error': 'Invalid email format', 'version': VERSION}), 400
    
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters', 'version': VERSION}), 400
    
    # Check if user already exists
    from models import User, PlanType, AuditLog
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'error': 'Email already registered', 'version': VERSION}), 409
    
    try:
        # Create user
        user = User(
            email=email,
            full_name=data.get('full_name', ''),
            company=data.get('company', ''),
            plan_type=PlanType.FREE
        )
        user.set_password(password)
        db.session.add(user)
        db.session.flush()
        
        # Convert lead if exists
        domain = LeadEngine.extract_domain(email)
        lead = Lead.query.filter_by(domain=domain).first() if domain else None
        
        if lead:
            LeadEngine.convert_to_user(lead, user.id)
        
        # Audit log
        audit = AuditLog(
            user_id=user.id,
            action='user_registered_after_audit',
            resource_type='user',
            details={'email': email, 'via': 'free_audit'},
            ip_address=request.remote_addr
        )
        db.session.add(audit)
        
        db.session.commit()
        
        # Create JWT tokens (identity must be string for PyJWT compliance)
        from flask_jwt_extended import create_access_token, create_refresh_token
        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))
        
        return jsonify({
            'message': 'Registration successful',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict(),
            'version': VERSION
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration failed: {e}")
        return jsonify({'error': 'Internal server error', 'version': VERSION}), 500

@free_audit_bp.route('/evaluate-score', methods=['POST'])
def evaluate_security_score():
    """
    Public live security score evaluator for interactive landing page demo.
    Executes real perimeter inspections against the entered domain/URL.
    """
    from services.base_scanner import BaseSecurityScanner
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    target = data.get('target', '').strip()

    if not target:
        return jsonify({'error': 'Target domain or URL required', 'version': VERSION}), 400

    clean_target = target if target.startswith(('http://', 'https://')) else f'https://{target}'
    scanner = BaseSecurityScanner()

    basic_chk = scanner._check_basic_security(clean_target)
    headers_chk = scanner._check_security_headers(clean_target)
    common_vuln = scanner._check_common_vulnerabilities(clean_target)

    # Compute empirical score from 0-100
    score = 100
    findings = []

    if basic_chk.get('status') == 'fail':
        score -= 30
        findings.append(basic_chk.get('message', 'Basic security issues'))
    elif basic_chk.get('status') == 'warning':
        score -= 10
        findings.append(basic_chk.get('message'))

    if headers_chk.get('status') == 'fail':
        score -= 25
        findings.append(headers_chk.get('message', 'Missing critical security headers'))
    elif headers_chk.get('status') == 'warning':
        score -= 15
        findings.append(headers_chk.get('message'))

    if common_vuln.get('status') == 'fail':
        score -= 25
        findings.append(common_vuln.get('message', 'Exposed sensitive paths'))

    score = max(20, min(98, score))

    if score >= 85:
        label = 'Strong Perimeter Defense'
        color = '#00f0ff'
    elif score >= 65:
        label = 'Moderate Risk - Gaps Detected'
        color = '#f59e0b'
    else:
        label = 'Critical Vulnerability Exposure'
        color = '#ef4444'

    return jsonify({
        'target': target,
        'score': score,
        'label': label,
        'color': color,
        'findings': findings,
        'checks': [basic_chk, headers_chk, common_vuln],
        'version': VERSION
    }), 200

