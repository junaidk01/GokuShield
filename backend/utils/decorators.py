from flask import jsonify
from flask_jwt_extended import get_jwt_identity
from functools import wraps
import pyotp

from models import User
from config import VERSION

def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.is_admin:
            return jsonify({
                'error': 'Admin privileges required',
                'version': VERSION
            }), 403
        
        return f(*args, **kwargs)
    
    return decorated_function

def mfa_required(f):
    """Decorator to require MFA verification"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'error': 'User not found',
                'version': VERSION
            }), 404
        
        if user.mfa_enabled:
            from flask import request
            data = request.get_json() or {}
            mfa_code = data.get('mfa_code')
            
            if not mfa_code:
                return jsonify({
                    'error': 'MFA code required',
                    'requires_mfa': True,
                    'version': VERSION
                }), 403
            
            # Verify MFA code
            totp = pyotp.TOTP(user.mfa_secret)
            if not totp.verify(mfa_code, valid_window=1):
                return jsonify({
                    'error': 'Invalid MFA code',
                    'version': VERSION
                }), 403
        
        return f(*args, **kwargs)
    
    return decorated_function

def rate_limit(max_requests=100, window=3600):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import request, current_app
            import redis
            from datetime import datetime
            
            try:
                redis_client = redis.from_url(current_app.config['REDIS_URL'])
                
                # Create rate limit key
                user_id = get_jwt_identity() if hasattr(get_jwt_identity, '__call__') else 'anonymous'
                ip = request.remote_addr
                key = f"ratelimit:{f.__name__}:{user_id}:{ip}"
                
                # Check current count
                current = redis_client.get(key)
                
                if current and int(current) >= max_requests:
                    return jsonify({
                        'error': 'Rate limit exceeded',
                        'message': f'Maximum {max_requests} requests per {window} seconds',
                        'version': VERSION
                    }), 429
                
                # Increment counter
                pipe = redis_client.pipeline()
                pipe.incr(key)
                pipe.expire(key, window)
                pipe.execute()
                
            except Exception as e:
                # If Redis fails, allow request
                print(f"Rate limit check failed: {e}")
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator
