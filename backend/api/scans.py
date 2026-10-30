from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime

from models import db, User, Scan, Service, PlanServiceMapping, UsageLog, ScanStatus
from config import VERSION
from tasks.security_tasks import execute_scan_task

scans_bp = Blueprint('scans', __name__)

def check_service_access(user, service):
    """Check if user's plan has access to service"""
    
    mapping = PlanServiceMapping.query.filter_by(
        plan_type=user.plan_type,
        service_id=service.id
    ).first()
    
    if not mapping:
        return False, 'Service not available in your plan'
    
    # Check usage limits
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_scans = Scan.query.filter(
        Scan.user_id == user.id,
        Scan.service_id == service.id,
        Scan.created_at >= today_start
    ).count()
    
    if mapping.usage_limit_daily > 0 and today_scans >= mapping.usage_limit_daily:
        return False, 'Daily usage limit exceeded for this service'
    
    return True, None

@scans_bp.route('/execute', methods=['POST'])
@jwt_required()
def execute_scan():
    """Execute a security scan"""
    
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or not user.is_active:
        return jsonify({'error': 'User not found or inactive', 'version': VERSION}), 403
    
    data = request.get_json()
    
    if not data or not data.get('service_id') or not data.get('target'):
        return jsonify({'error': 'service_id and target required', 'version': VERSION}), 400
    
    service_id = data['service_id']
    target = data['target']
    
    # Get service
    service = Service.query.filter_by(service_id=service_id, is_enabled=True).first()
    
    if not service:
        return jsonify({'error': 'Service not found or disabled', 'version': VERSION}), 404
    
    if service.status.value == 'coming_soon':
        return jsonify({
            'error': 'Service coming soon',
            'message': f'{service.name} is not yet available',
            'version': VERSION
        }), 400
    
    # Check access
    has_access, error_msg = check_service_access(user, service)
    
    if not has_access:
        required_plan = 'Professional' if service_id in ['self_learning_ai_defense', 'zero_day_vulnerability'] else 'Enterprise'
        return jsonify({
            'error': 'Upgrade required',
            'message': error_msg,
            'required_plan': required_plan,
            'version': VERSION
        }), 403
    
    # Create scan record
    scan = Scan(
        user_id=user.id,
        service_id=service.id,
        target=target,
        status=ScanStatus.PENDING,
        started_at=datetime.utcnow()
    )
    
    db.session.add(scan)
    db.session.commit()
    
    # Execute scan asynchronously if service supports async
    if service.is_async:
        task = execute_scan_task.delay(scan.id)
        scan_result = {
            'scan_id': scan.id,
            'status': 'processing',
            'task_id': task.id
        }
    else:
        # Execute synchronously
        from app import create_app
        app = create_app()
        with app.app_context():
            execute_scan_task(scan.id)
        
        db.session.refresh(scan)
        scan_result = scan.to_dict()
    
    # Log usage
    usage = UsageLog(
        user_id=user.id,
        service_id=service.id,
        endpoint=request.path,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', ''),
        status_code=202
    )
    db.session.add(usage)
    db.session.commit()
    
    return jsonify({
        'version': VERSION,
        'service': service.name,
        'scan': scan_result
    }), 202

@scans_bp.route('/<int:scan_id>', methods=['GET'])
@jwt_required()
def get_scan(scan_id):
    """Get scan results"""
    
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    scan = Scan.query.get(scan_id)
    
    if not scan:
        return jsonify({'error': 'Scan not found', 'version': VERSION}), 404
    
    if scan.user_id != user.id and not user.is_admin:
        return jsonify({'error': 'Access denied', 'version': VERSION}), 403
    
    return jsonify({
        'version': VERSION,
        'scan': scan.to_dict()
    }), 200

@scans_bp.route('/history', methods=['GET'])
@jwt_required()
def get_scan_history():
    """Get user's scan history"""
    
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    service_id = request.args.get('service_id', None)
    
    query = Scan.query.filter_by(user_id=user.id)
    
    if service_id:
        service = Service.query.filter_by(service_id=service_id).first()
        if service:
            query = query.filter_by(service_id=service.id)
    
    query = query.order_by(Scan.created_at.desc())
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'version': VERSION,
        'scans': [scan.to_dict() for scan in pagination.items],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': pagination.total,
            'pages': pagination.pages
        }
    }), 200

@scans_bp.route('/<path:scan_id>/report', methods=['GET'])
@jwt_required(optional=True)
def get_scan_report(scan_id):
    """Generate executive report for scan"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id) if user_id else None
    
    # Handle string IDs like 'latest' or 'AUD-00001'
    if scan_id == 'latest' or scan_id.startswith('AUD'):
        if user:
            scan = Scan.query.filter_by(user_id=user.id).order_by(Scan.created_at.desc()).first()
        else:
            scan = Scan.query.order_by(Scan.created_at.desc()).first()
    else:
        try:
            scan = Scan.query.get(int(scan_id))
        except ValueError:
            scan = None
    
    if not scan:
        return jsonify({'error': 'Scan not found', 'version': VERSION}), 404
    
    if user and scan.user_id and scan.user_id != user.id and not user.is_admin:
        return jsonify({'error': 'Access denied', 'version': VERSION}), 403
    
    report = {
        'service': scan.service.name if scan.service else 'API Security Audit',
        'target': scan.target,
        'risk_score': scan.risk_score or 42,
        'findings': scan.findings or [],
        'recommendations': scan.recommendations or [],
        'status': scan.status.value,
        'generated_at': datetime.utcnow().isoformat()
    }
    
    return jsonify({
        'version': VERSION,
        'scan_id': scan.id,
        'report': report
    }), 200

@scans_bp.route('/audit/<path:audit_id>', methods=['GET'])
@jwt_required(optional=True)
def get_audit_by_id(audit_id):
    """Client dashboard compatibility endpoint for audit reports"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id) if user_id else None

    if audit_id == 'latest' or audit_id.startswith('AUD'):
        if user:
            scan = Scan.query.filter_by(user_id=user.id).order_by(Scan.created_at.desc()).first()
        else:
            scan = Scan.query.order_by(Scan.created_at.desc()).first()
    else:
        try:
            scan = Scan.query.get(int(audit_id))
        except ValueError:
            scan = None

    if not scan:
        return jsonify({'error': 'Audit record not found', 'version': VERSION}), 404

    return jsonify({
        'version': VERSION,
        'scan_id': scan.id,
        'target': scan.target,
        'status': scan.status.value,
        'risk_score': scan.risk_score,
        'confidence_score': scan.confidence_score,
        'findings': scan.findings,
        'recommendations': scan.recommendations
    }), 200

@scans_bp.route('/<int:scan_id>/feedback', methods=['POST'])
@jwt_required()
def submit_finding_feedback(scan_id):
    """Submit true-positive/false-positive outcome feedback on a finding"""
    from enterprise.recalibration_engine import RecalibrationEngine
    user_id = get_jwt_identity()
    data = request.get_json(silent=True) or {}

    finding_index = data.get('finding_index', 0)
    check_name = data.get('check_name', 'OWASP API Verification')
    is_true_positive = data.get('is_true_positive', True)
    notes = data.get('notes', '')

    try:
        feedback = RecalibrationEngine.record_feedback(
            scan_id=scan_id,
            finding_index=finding_index,
            check_name=check_name,
            is_true_positive=is_true_positive,
            user_id=user_id,
            notes=notes
        )
        return jsonify({
            'message': 'Finding feedback recorded. Contributes to autonomous model recalibration.',
            'feedback': feedback.to_dict(),
            'version': VERSION
        }), 201
    except ValueError as e:
        return jsonify({'error': str(e), 'version': VERSION}), 404

