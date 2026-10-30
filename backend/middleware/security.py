from flask import request, jsonify
from functools import wraps
import requests

from config import VERSION

def add_security_headers(response):
    """Add security headers to all responses"""
    from flask import current_app
    
    for header, value in current_app.config.get('SECURITY_HEADERS', {}).items():
        response.headers[header] = value
    
    response.headers['X-Version'] = VERSION
    
    return response

def verify_captcha(captcha_token: str) -> bool:
    """Verify reCAPTCHA token"""
    from flask import current_app
    
    if not current_app.config.get('RECAPTCHA_ENABLED'):
        return True  # Skip if not enabled
    
    secret = current_app.config.get('RECAPTCHA_SECRET_KEY')
    
    if not secret:
        return True
    
    try:
        response = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={
                'secret': secret,
                'response': captcha_token
            },
            timeout=5
        )
        
        result = response.json()
        return result.get('success', False)
    except:
        return False  # Fail closed

def captcha_required(f):
    """Decorator to require CAPTCHA verification"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import current_app
        
        if not current_app.config.get('RECAPTCHA_ENABLED'):
            return f(*args, **kwargs)
        
        data = request.get_json() or {}
        captcha_token = data.get('captcha_token') or request.form.get('captcha_token')
        
        if not captcha_token:
            return jsonify({
                'error': 'CAPTCHA verification required',
                'version': VERSION
            }), 400
        
        if not verify_captcha(captcha_token):
            return jsonify({
                'error': 'CAPTCHA verification failed',
                'version': VERSION
            }), 400
        
        return f(*args, **kwargs)
    
    return decorated_function

def check_ssrf(url: str) -> bool:
    """Check if URL might be SSRF attack"""
    from urllib.parse import urlparse
    
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        if not hostname:
            return False
        
        # Block localhost and internal IPs
        blocked = [
            'localhost',
            '127.0.0.1',
            '0.0.0.0',
            '169.254',  # AWS metadata
            '10.',      # Private Class A
            '172.16',   # Private Class B
            '192.168'   # Private Class C
        ]
        
        for blocked_host in blocked:
            if blocked_host in hostname.lower():
                return True
        
        return False
    except:
        return True  # Fail closed

def ssrf_protection(f):
    """Decorator to protect against SSRF"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        data = request.get_json() or {}
        
        # Check common URL fields
        url_fields = ['url', 'target', 'base_url', 'endpoint']
        
        for field in url_fields:
            if field in data and check_ssrf(data[field]):
                return jsonify({
                    'error': 'Invalid URL: Internal/private URLs not allowed',
                    'version': VERSION
                }), 400
        
        return f(*args, **kwargs)
    
    return decorated_function
