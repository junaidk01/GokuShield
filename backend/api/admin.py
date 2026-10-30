from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
import pyotp

from models import db, User, Service, PlanServiceMapping, UsageLog, AuditLog, IPBlacklist, Scan, ServiceStatus, PlanType, RemediationAction, Lead, Outreach, OutreachStatus
from config import VERSION
from utils.decorators import admin_required

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/users', methods=['GET'])
@jwt_required()
@admin_required
def list_users():
    """List all users"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    users = User.query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'version': VERSION,
        'users': [u.to_dict() for u in users.items],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': users.total,
            'pages': users.pages
        }
    }), 200

@admin_bp.route('/users/<int:user_id>/plan', methods=['PUT'])
@jwt_required()
@admin_required
def update_user_plan(user_id):
    """Update user's plan"""
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found', 'version': VERSION}), 404
    
    data = request.get_json()
    
    if not data or not data.get('plan_type'):
        return jsonify({'error': 'plan_type required', 'version': VERSION}), 400
    
    try:
        new_plan = PlanType(data['plan_type'])
        old_plan = user.plan_type
        user.plan_type = new_plan
        user.plan_started_at = datetime.utcnow()
        
        admin_id = get_jwt_identity()
        audit = AuditLog(
            user_id=admin_id,
            action='update_user_plan',
            resource_type='user',
            resource_id=user_id,
            details={'from': old_plan.value, 'to': new_plan.value},
            ip_address=request.remote_addr
        )
        db.session.add(audit)
        db.session.commit()
        
        return jsonify({
            'version': VERSION,
            'message': 'Plan updated successfully',
            'user': user.to_dict()
        }), 200
    except ValueError:
        return jsonify({'error': 'Invalid plan type', 'version': VERSION}), 400

@admin_bp.route('/services/<int:service_id>/toggle', methods=['PUT'])
@jwt_required()
@admin_required
def toggle_service(service_id):
    """Enable/disable service"""
    service = Service.query.get(service_id)
    
    if not service:
        return jsonify({'error': 'Service not found', 'version': VERSION}), 404
    
    service.is_enabled = not service.is_enabled
    
    admin_id = get_jwt_identity()
    audit = AuditLog(
        user_id=admin_id,
        action='toggle_service',
        resource_type='service',
        resource_id=service_id,
        details={'is_enabled': service.is_enabled},
        ip_address=request.remote_addr
    )
    db.session.add(audit)
    db.session.commit()
    
    return jsonify({
        'version': VERSION,
        'message': f"Service {'enabled' if service.is_enabled else 'disabled'}",
        'service': service.to_dict()
    }), 200

@admin_bp.route('/usage', methods=['GET'])
@jwt_required()
@admin_required
def get_usage_stats():
    """Get platform usage statistics"""
    from sqlalchemy import func
    
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    total_scans = Scan.query.count()
    
    # Usage by plan
    usage_by_plan = db.session.query(
        User.plan_type,
        func.count(User.id)
    ).group_by(User.plan_type).all()
    
    return jsonify({
        'version': VERSION,
        'stats': {
            'total_users': total_users,
            'active_users': active_users,
            'total_scans': total_scans,
            'users_by_plan': {plan.value: count for plan, count in usage_by_plan}
        }
    }), 200

@admin_bp.route('/blacklist', methods=['POST'])
@jwt_required()
@admin_required
def add_to_blacklist():
    """Add IP to blacklist"""
    data = request.get_json()
    
    if not data or not data.get('ip_address'):
        return jsonify({'error': 'ip_address required', 'version': VERSION}), 400
    
    blacklist = IPBlacklist(
        ip_address=data['ip_address'],
        reason=data.get('reason', 'Manually blacklisted'),
        expires_at=data.get('expires_at')
    )
    
    db.session.add(blacklist)
    
    admin_id = get_jwt_identity()
    audit = AuditLog(
        user_id=admin_id,
        action='add_ip_blacklist',
        resource_type='ip_blacklist',
        details={'ip_address': data['ip_address']},
        ip_address=request.remote_addr
    )
    db.session.add(audit)
    db.session.commit()
    
    return jsonify({
        'version': VERSION,
        'message': 'IP blacklisted successfully'
    }), 201


@admin_bp.route('/remediations', methods=['GET'])
@jwt_required()
@admin_required
def list_remediation_actions():
    """
    List remediation actions awaiting approval. This is the queue for
    'self-dependent, but with approval': findings are suggested here,
    nothing is applied to any system until an admin approves it, and even
    approval only marks status — actually making the change is still a
    manual step (see review_notes / status='applied' as a record of that).
    """
    status = request.args.get('status', 'pending')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    query = RemediationAction.query
    if status != 'all':
        query = query.filter_by(status=status)

    actions = query.order_by(RemediationAction.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        'version': VERSION,
        'actions': [a.to_dict() for a in actions.items],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': actions.total,
            'pages': actions.pages
        }
    }), 200


@admin_bp.route('/remediations/<int:action_id>', methods=['PUT'])
@jwt_required()
@admin_required
def review_remediation_action(action_id):
    """
    Approve, reject, or mark a remediation action as applied.
    Body: { "status": "approved" | "rejected" | "applied", "notes": "..." }
    This endpoint only records a decision — it does not execute anything
    against live infrastructure. Applying the actual fix remains a manual
    step; 'applied' is you confirming you did it.
    """
    data = request.get_json() or {}
    new_status = data.get('status')

    if new_status not in ('approved', 'rejected', 'applied'):
        return jsonify({
            'error': "status must be one of: approved, rejected, applied",
            'version': VERSION
        }), 400

    action = RemediationAction.query.get(action_id)
    if not action:
        return jsonify({'error': 'Remediation action not found', 'version': VERSION}), 404

    admin_id = get_jwt_identity()
    action.status = new_status
    action.reviewed_by_user_id = admin_id
    action.reviewed_at = datetime.utcnow()
    if data.get('notes'):
        action.review_notes = data['notes']

    audit = AuditLog(
        user_id=admin_id,
        action=f'remediation_{new_status}',
        resource_type='remediation_action',
        resource_id=action.id,
        details={'check_name': action.check_name, 'scan_id': action.scan_id},
        ip_address=request.remote_addr
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({
        'version': VERSION,
        'action': action.to_dict()
    }), 200

@admin_bp.route('/stats', methods=['GET'])
@jwt_required()
@admin_required
def get_admin_dashboard_stats():
    """Get high-level dashboard metrics for admin panel"""
    total_audits = Scan.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    paid_clients = User.query.filter(User.plan_type != PlanType.FREE).count()
    total_leads = Lead.query.count()
    
    return jsonify({
        'version': VERSION,
        'total_audits': total_audits,
        'active_users': active_users,
        'paid_clients': paid_clients,
        'total_leads': total_leads,
        'system_status': 'online'
    }), 200

@admin_bp.route('/audits', methods=['GET'])
@jwt_required()
@admin_required
def list_admin_audits():
    """List all audits for admin overview"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    scans = Scan.query.order_by(Scan.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    results = []
    
    for s in scans.items:
        domain = ''
        email = ''
        if s.lead:
            domain = s.lead.domain
            email = s.lead.email
        elif s.user:
            domain = s.user.company or (s.user.email.split('@')[1] if '@' in s.user.email else '')
            email = s.user.email
            
        results.append({
            'audit_id': f"AUD-{s.id:05d}",
            'scan_id': s.id,
            'company_domain': domain or s.target,
            'email': email or 'anonymous',
            'created_at': s.created_at.isoformat(),
            'status': s.status.value,
            'risk_score': s.risk_score,
            'target': s.target
        })
        
    return jsonify(results), 200

@admin_bp.route('/audit-logs', methods=['GET'])
@jwt_required()
@admin_required
def list_admin_audit_logs():
    """
    Read-only Admin Activity Audit Log UI data source.
    Strictly read-only; no edit or delete endpoints exist.
    """
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'version': VERSION,
        'logs': [l.to_dict() for l in logs.items],
        'total': logs.total,
        'pages': logs.pages,
        'page': page
    }), 200

@admin_bp.route('/system/health', methods=['GET'])
@jwt_required()
@admin_required
def get_system_health():
    """System and Ollama health verification endpoint"""
    from flask import current_app
    from sqlalchemy import text
    
    db_ok = True
    try:
        db.session.execute(text('SELECT 1'))
    except Exception:
        db_ok = False
        
    redis_ok = False
    if hasattr(current_app, 'redis_client') and current_app.redis_client:
        try:
            current_app.redis_client.ping()
            redis_ok = True
        except Exception:
            redis_ok = False
            
    ollama_ok = False
    if hasattr(current_app, 'ollama_client') and current_app.ollama_client:
        try:
            ollama_ok = current_app.ollama_client.check_health()
        except Exception:
            ollama_ok = False
            
    return jsonify({
        'version': VERSION,
        'status': 'healthy' if (db_ok and ollama_ok) else 'degraded',
        'database': 'connected' if db_ok else 'disconnected',
        'redis': 'connected' if redis_ok else 'unavailable',
        'ollama': 'running' if ollama_ok else 'offline',
        'api': 'healthy',
        'timestamp': datetime.utcnow().isoformat()
    }), 200

@admin_bp.route('/plans', methods=['GET'])
@jwt_required()
@admin_required
def list_plans():
    """List plans and service allocations for admin management"""
    plans = [
        {
            'name': 'Starter',
            'plan_type': 'starter',
            'price': 19,
            'api_limit': 10,
            'monthly_requests': 50000,
            'features': ['10 APIs', '50K requests/mo', 'Basic Threat Detection', 'Email Support']
        },
        {
            'name': 'Professional',
            'plan_type': 'professional',
            'price': 59,
            'api_limit': 50,
            'monthly_requests': 500000,
            'features': ['50 APIs', '500K requests/mo', 'AI Threat Detection', 'Custom Rules', 'Priority Support']
        },
        {
            'name': 'Enterprise',
            'plan_type': 'enterprise',
            'price': 179,
            'api_limit': -1,
            'monthly_requests': 2000000,
            'features': ['Unlimited APIs', '2M+ requests/mo', 'Dedicated Account Manager', '24/7 Phone Support', 'Enterprise SLA']
        }
    ]
    return jsonify({'version': VERSION, 'plans': plans}), 200

@admin_bp.route('/outreach', methods=['GET'])
@jwt_required()
@admin_required
def list_outreach_campaigns():
    """List outreach message history and statistics"""
    from utils.outreach_engine import OutreachEngine
    stats = OutreachEngine.get_outreach_stats()
    recent = Outreach.query.order_by(Outreach.created_at.desc()).limit(50).all()
    
    return jsonify({
        'version': VERSION,
        'stats': stats,
        'recent_outreach': [o.to_dict() for o in recent]
    }), 200

@admin_bp.route('/outreach/trigger', methods=['POST'])
@jwt_required()
@admin_required
def trigger_outreach_campaign():
    """Trigger outreach email (welcome, audit_report, follow_up, cold_outreach, upgrade_prompt)"""
    from utils.outreach_engine import OutreachEngine
    data = request.get_json() or {}
    
    template = data.get('template', 'follow_up')
    email = data.get('email')
    domain = data.get('domain', '')
    
    if not email:
        return jsonify({'error': 'Recipient email required', 'version': VERSION}), 400
        
    admin_id = get_jwt_identity()
    
    try:
        if template == 'cold_outreach':
            outreach = OutreachEngine.send_cold_outreach(email=email, domain=domain or email.split('@')[1], company_name=data.get('company', ''))
        elif template == 'welcome':
            lead = Lead.query.filter_by(email=email).first()
            if not lead:
                lead = Lead(email=email, domain=domain or email.split('@')[1], source='admin_trigger')
                db.session.add(lead)
                db.session.commit()
            outreach = OutreachEngine.send_welcome_email(lead)
        else:
            lead = Lead.query.filter_by(email=email).first()
            scan_dummy = {'risk_score': 65, 'confidence_score': 90, 'findings': [{'title': 'Exposed Security Headers'}], 'analysis': 'Recommended upgrade to Pro.'}
            outreach = OutreachEngine.send_follow_up(lead or Lead(email=email, domain=domain or email.split('@')[1]), scan_dummy)
            
        audit = AuditLog(
            user_id=admin_id,
            action=f'trigger_outreach_{template}',
            resource_type='outreach',
            resource_id=outreach.id if outreach else None,
            details={'email': email, 'template': template},
            ip_address=request.remote_addr
        )
        db.session.add(audit)
        db.session.commit()
        
        return jsonify({
            'version': VERSION,
            'message': f'Outreach {template} queued successfully for {email}',
            'outreach_id': outreach.id if outreach else None
        }), 200
    except Exception as e:
        return jsonify({'error': str(e), 'version': VERSION}), 500

@admin_bp.route('/recalibrate', methods=['POST'])
@jwt_required()
@admin_required
def trigger_recalibration():
    """Trigger scoring weight recalibration using recorded scan feedback"""
    from enterprise.recalibration_engine import RecalibrationEngine
    admin_id = get_jwt_identity()
    result = RecalibrationEngine.run_recalibration_job(admin_user_id=admin_id)
    return jsonify({
        'version': VERSION,
        'message': 'Autonomous scoring weight recalibration executed',
        'result': result
    }), 200

@admin_bp.route('/recalibration-stats', methods=['GET'])
@jwt_required()
@admin_required
def get_recalibration_stats():
    """Retrieve check precision metrics and weight modifiers"""
    from enterprise.recalibration_engine import RecalibrationEngine
    metrics = RecalibrationEngine.get_feedback_metrics()
    return jsonify({
        'version': VERSION,
        'metrics': metrics
    }), 200


