from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from models import db, User, Service, Scan, ScanStatus
from config import VERSION
from utils.usage_enforcement import enforce_usage_limits
from tasks.security_tasks import execute_scan_task

services_bp = Blueprint('services', __name__)

# Service-specific routes: /api/<service_name>
# Each service gets its own endpoint with MANDATORY enforcement

@services_bp.route('/<service_id>/scan', methods=['POST'])
@jwt_required()
@enforce_usage_limits(service_id_param='service_id')
def scan_service(service_id, _service=None, _user=None, _usage=None):
    """
    Execute scan for specific service
    PROTECTED: Usage limits and plan access enforced
    """
    user = _user  # Injected by enforce_usage_limits decorator
    service = _service  # Injected by enforce_usage_limits decorator
    
    data = request.get_json()
    
    if not data or not data.get('target'):
        return jsonify({'error': 'target required', 'version': VERSION}), 400
    
    # Create scan
    scan = Scan(
        user_id=user.id,
        service_id=service.id,
        target=data['target'],
        status=ScanStatus.PENDING
    )
    
    db.session.add(scan)
    db.session.commit()
    
    # Execute async
    if service.is_async:
        task = execute_scan_task.delay(scan.id)
        return jsonify({
            'version': VERSION,
            'scan_id': scan.id,
            'status': 'processing',
            'task_id': task.id
        }), 202
    else:
        execute_scan_task(scan.id)
        db.session.refresh(scan)
        return jsonify({
            'version': VERSION,
            'scan': scan.to_dict()
        }), 200

@services_bp.route('/<service_id>/info', methods=['GET'])
def get_service_info(service_id):
    """Get service information - Public endpoint"""
    service = Service.query.filter_by(service_id=service_id).first()
    
    if not service:
        return jsonify({'error': 'Service not found', 'version': VERSION}), 404
    
    return jsonify({
        'version': VERSION,
        'service': service.to_dict()
    }), 200
