"""
Usage enforcement decorators and utilities
Ensures all service execution respects plan limits
"""

from functools import wraps
from flask import request, jsonify, current_app
from flask_jwt_extended import get_jwt_identity
from datetime import datetime
import logging

from models import db, User, Service, PlanServiceMapping, ServiceUsage, UsageLog, AuditLog
from config import VERSION

logger = logging.getLogger(__name__)

def enforce_usage_limits(service_id_param='service_id'):
    """
    Decorator to enforce usage limits before service execution
    Checks:
    - Plan has access to service
    - User hasn't exceeded daily/monthly limits
    - Service is enabled
    
    Usage:
        @enforce_usage_limits()
        def my_scan_endpoint():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get current user
            try:
                user_id = get_jwt_identity()
            except:
                return jsonify({
                    'error': 'Authentication required',
                    'version': VERSION
                }), 401
            
            user = User.query.get(user_id)
            if not user or not user.is_active:
                return jsonify({
                    'error': 'User not found or inactive',
                    'version': VERSION
                }), 403
            
            # Get service_id from kwargs or request data
            service_id_value = kwargs.get(service_id_param)
            if not service_id_value:
                data = request.get_json() or {}
                service_id_value = data.get(service_id_param)
            
            if not service_id_value:
                return jsonify({
                    'error': 'Service ID required',
                    'version': VERSION
                }), 400
            
            # Get service
            service = Service.query.filter_by(service_id=service_id_value).first()
            if not service:
                return jsonify({
                    'error': 'Service not found',
                    'version': VERSION
                }), 404
            
            # Check if service is enabled
            if not service.is_enabled:
                return jsonify({
                    'error': 'Service temporarily unavailable',
                    'version': VERSION
                }), 503
            
            # Check plan access
            plan_mapping = PlanServiceMapping.query.filter_by(
                plan_type=user.plan_type,
                service_id=service.id
            ).first()
            
            if not plan_mapping or not plan_mapping.is_enabled:
                return jsonify({
                    'error': 'Service not available in your plan',
                    'message': f'Upgrade to access {service.name}',
                    'service_name': service.name,
                    'current_plan': user.plan_type.value,
                    'upgrade_required': True,
                    'version': VERSION
                }), 403
            
            # Get or create usage tracking
            usage = ServiceUsage.query.filter_by(
                user_id=user.id,
                service_id=service.id
            ).first()
            
            if not usage:
                usage = ServiceUsage(
                    user_id=user.id,
                    service_id=service.id
                )
                db.session.add(usage)
                db.session.flush()
            
            # Check limits
            allowed, limit_type = usage.check_limit(
                plan_mapping.usage_limit_daily,
                plan_mapping.usage_limit_monthly
            )
            
            if not allowed:
                return jsonify({
                    'error': f'{limit_type.capitalize()} limit exceeded',
                    'message': f'You have reached your {limit_type} usage limit for {service.name}',
                    'service_name': service.name,
                    'daily_count': usage.daily_count,
                    'monthly_count': usage.monthly_count,
                    'daily_limit': plan_mapping.usage_limit_daily,
                    'monthly_limit': plan_mapping.usage_limit_monthly,
                    'upgrade_required': True,
                    'version': VERSION
                }), 429
            
            # Increment usage
            usage.increment()
            
            # Log usage
            usage_log = UsageLog(
                user_id=user.id,
                service_id=service.id,
                endpoint=request.endpoint,
                method=request.method,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', '')
            )
            db.session.add(usage_log)
            
            db.session.commit()
            
            # Add service to kwargs for handler
            kwargs['_service'] = service
            kwargs['_user'] = user
            kwargs['_usage'] = usage
            
            # Execute original function
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

def check_service_access(user, service_id):
    """
    Utility function to check if user has access to a service
    Returns: (has_access, error_message)
    """
    service = Service.query.filter_by(service_id=service_id).first()
    if not service:
        return False, 'Service not found'
    
    if not service.is_enabled:
        return False, 'Service temporarily unavailable'
    
    plan_mapping = PlanServiceMapping.query.filter_by(
        plan_type=user.plan_type,
        service_id=service.id
    ).first()
    
    if not plan_mapping or not plan_mapping.is_enabled:
        return False, f'Service not available in {user.plan_type.value} plan'
    
    return True, None

def get_usage_stats(user_id, service_id=None):
    """
    Get usage statistics for a user
    If service_id provided, returns stats for that service
    Otherwise returns all services
    """
    query = ServiceUsage.query.filter_by(user_id=user_id)
    
    if service_id:
        service = Service.query.filter_by(service_id=service_id).first()
        if service:
            query = query.filter_by(service_id=service.id)
    
    usages = query.all()
    
    stats = []
    for usage in usages:
        service = Service.query.get(usage.service_id)
        if not service:
            continue
        
        user = User.query.get(user_id)
        plan_mapping = PlanServiceMapping.query.filter_by(
            plan_type=user.plan_type,
            service_id=service.id
        ).first()
        
        stats.append({
            'service_id': service.service_id,
            'service_name': service.name,
            'daily_count': usage.daily_count,
            'monthly_count': usage.monthly_count,
            'total_count': usage.total_count,
            'daily_limit': plan_mapping.usage_limit_daily if plan_mapping else -1,
            'monthly_limit': plan_mapping.usage_limit_monthly if plan_mapping else -1,
            'last_used_at': usage.last_used_at.isoformat() if usage.last_used_at else None
        })
    
    return stats

def reset_daily_usage():
    """
    Reset daily usage counters for all users
    Called by Celery Beat scheduler
    """
    try:
        usages = ServiceUsage.query.all()
        count = 0
        
        for usage in usages:
            usage.daily_count = 0
            usage.daily_reset_at = datetime.utcnow()
            count += 1
        
        db.session.commit()
        
        logger.info(f"Reset daily usage for {count} service usages")
        return {'reset': count}
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to reset daily usage: {e}")
        raise

def reset_monthly_usage():
    """
    Reset monthly usage counters for all users
    Called by Celery Beat scheduler
    """
    try:
        usages = ServiceUsage.query.all()
        count = 0
        
        for usage in usages:
            usage.monthly_count = 0
            usage.monthly_reset_at = datetime.utcnow()
            count += 1
        
        db.session.commit()
        
        logger.info(f"Reset monthly usage for {count} service usages")
        return {'reset': count}
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to reset monthly usage: {e}")
        raise

def log_audit_action(user_id, action, resource_type, resource_id=None, details=None):
    """
    Log admin action to audit trail
    """
    try:
        audit = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            ip_address=request.remote_addr if request else None,
            user_agent=request.headers.get('User-Agent', '') if request else None
        )
        db.session.add(audit)
        db.session.commit()
        
        logger.info(f"Audit log: {action} on {resource_type} by user {user_id}")
        
    except Exception as e:
        logger.error(f"Failed to log audit action: {e}")

def require_admin(f):
    """
    Decorator to require admin privileges
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            user_id = get_jwt_identity()
        except:
            return jsonify({
                'error': 'Authentication required',
                'version': VERSION
            }), 401
        
        user = User.query.get(user_id)
        if not user or not user.is_admin:
            return jsonify({
                'error': 'Admin privileges required',
                'version': VERSION
            }), 403
        
        kwargs['_admin_user'] = user
        return f(*args, **kwargs)
    
    return decorated_function
