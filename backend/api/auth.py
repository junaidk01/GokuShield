from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import re
import secrets

from models import db, User, LoginAttempt, IPBlacklist, AuditLog, PlanType
from config import VERSION
from utils.suspicious_login_protection import SuspiciousLoginProtection
from utils.outreach_engine import OutreachEngine

auth_bp = Blueprint('auth', __name__)

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def check_ip_blacklisted(ip_address):
    blacklist_entry = IPBlacklist.query.filter_by(ip_address=ip_address).first()
    if blacklist_entry:
        if blacklist_entry.expires_at and blacklist_entry.expires_at < datetime.utcnow():
            db.session.delete(blacklist_entry)
            db.session.commit()
            return False
        return True
    return False

def check_brute_force(email, ip_address):
    """Check for brute force attempts"""
    window_start = datetime.utcnow() - timedelta(minutes=15)
    
    failed_attempts = LoginAttempt.query.filter(
        LoginAttempt.email == email,
        LoginAttempt.ip_address == ip_address,
        LoginAttempt.successful == False,
        LoginAttempt.created_at >= window_start
    ).count()
    
    if failed_attempts >= 5:
        # Blacklist IP for 1 hour
        blacklist = IPBlacklist(
            ip_address=ip_address,
            reason=f'Brute force attempt on {email}',
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )
        db.session.add(blacklist)
        db.session.commit()
        return True
    
    return False

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Validation
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password required', 'version': VERSION}), 400
    
    email = data['email'].lower().strip()
    password = data['password']
    
    if not is_valid_email(email):
        return jsonify({'error': 'Invalid email format', 'version': VERSION}), 400
    
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters', 'version': VERSION}), 400
    
    # Check if user exists
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered', 'version': VERSION}), 409
    
    # Create user
    user = User(
        email=email,
        full_name=data.get('full_name', ''),
        company=data.get('company', ''),
        plan_type=PlanType.FREE
    )
    user.set_password(password)
    
    db.session.add(user)
    
    # Audit log
    audit = AuditLog(
        user_id=None,
        action='user_registered',
        resource_type='user',
        details={'email': email},
        ip_address=request.remote_addr
    )
    db.session.add(audit)
    
    db.session.commit()
    
    return jsonify({
        'message': 'Registration successful',
        'user': user.to_dict(),
        'version': VERSION
    }), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password required', 'version': VERSION}), 400
    
    email = data['email'].lower().strip()
    password = data['password']
    
    # Find user first
    user = User.query.filter_by(email=email).first()
    
    # COMPREHENSIVE SECURITY CHECK
    allowed, reason = SuspiciousLoginProtection.comprehensive_check(
        email=email,
        ip_address=ip_address,
        user_agent=user_agent,
        user=user
    )
    
    if not allowed:
        # Log failed attempt
        attempt = LoginAttempt(
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            successful=False
        )
        db.session.add(attempt)
        db.session.commit()
        
        return jsonify({
            'error': 'Access denied',
            'reason': reason,
            'version': VERSION
        }), 403
    
    # Verify credentials
    if not user or not user.check_password(password):
        # Log failed attempt
        attempt = LoginAttempt(
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            successful=False
        )
        db.session.add(attempt)
        db.session.commit()
        
        return jsonify({'error': 'Invalid credentials', 'version': VERSION}), 401
    
    # Successful login
    attempt = LoginAttempt(
        email=email,
        ip_address=ip_address,
        user_agent=user_agent,
        successful=True
    )
    db.session.add(attempt)
    
    user.last_login = datetime.utcnow()
    
    audit = AuditLog(
        user_id=user.id,
        action='user_login',
        resource_type='user',
        ip_address=ip_address,
        details={'user_agent': user_agent}
    )
    db.session.add(audit)
    
    db.session.commit()
    
    # Create tokens (identity must be string for PyJWT / RFC 7519 compliance)
    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))
    
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': user.to_dict(),
        'version': VERSION
    }), 200

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    user_id = get_jwt_identity()
    access_token = create_access_token(identity=str(user_id))
    
    return jsonify({
        'access_token': access_token,
        'version': VERSION
    }), 200

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found', 'version': VERSION}), 404
    
    return jsonify({
        'user': user.to_dict(),
        'version': VERSION
    }), 200

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    user_id = get_jwt_identity()
    
    audit = AuditLog(
        user_id=user_id,
        action='user_logout',
        resource_type='user',
        ip_address=request.remote_addr
    )
    db.session.add(audit)
    db.session.commit()
    
    return jsonify({
        'message': 'Logged out successfully',
        'version': VERSION
    }), 200

@auth_bp.route('/mfa/enable', methods=['POST'])
@jwt_required()
def enable_mfa():
    """Enable MFA for user"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found', 'version': VERSION}), 404
    
    if user.mfa_enabled:
        return jsonify({'error': 'MFA already enabled', 'version': VERSION}), 400
    
    # Generate new MFA secret
    import pyotp
    import qrcode
    import io
    import base64
    
    secret = pyotp.random_base32()
    user.mfa_secret = secret
    
    # Generate QR code
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name='GoKushield AI'
    )
    
    # Create QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    db.session.commit()
    
    return jsonify({
        'version': VERSION,
        'secret': secret,
        'qr_code': f"data:image/png;base64,{qr_code_base64}",
        'message': 'Scan QR code with authenticator app and verify with code'
    }), 200

@auth_bp.route('/mfa/verify', methods=['POST'])
@jwt_required()
def verify_mfa():
    """Verify and activate MFA"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found', 'version': VERSION}), 404
    
    data = request.get_json()
    
    if not data or not data.get('code'):
        return jsonify({'error': 'MFA code required', 'version': VERSION}), 400
    
    import pyotp
    totp = pyotp.TOTP(user.mfa_secret)
    
    if totp.verify(data['code'], valid_window=1):
        user.mfa_enabled = True
        db.session.commit()
        
        return jsonify({
            'version': VERSION,
            'message': 'MFA enabled successfully'
        }), 200
    else:
        return jsonify({
            'error': 'Invalid MFA code',
            'version': VERSION
        }), 400

@auth_bp.route('/mfa/disable', methods=['POST'])
@jwt_required()
def disable_mfa():
    """Disable MFA"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found', 'version': VERSION}), 404
    
    data = request.get_json()
    
    if not data or not data.get('password'):
        return jsonify({'error': 'Password required to disable MFA', 'version': VERSION}), 400
    
    if not user.check_password(data['password']):
        return jsonify({'error': 'Invalid password', 'version': VERSION}), 401
    
    user.mfa_enabled = False
    user.mfa_secret = None
    db.session.commit()
    
    return jsonify({
        'version': VERSION,
        'message': 'MFA disabled successfully'
    }), 200

@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    """
    Request password reset email with secure one-time token.
    Fails silently on unknown email to prevent account enumeration.
    """
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    email = data.get('email', '').lower().strip()
    
    if not email or not is_valid_email(email):
        return jsonify({'error': 'Valid email address required', 'version': VERSION}), 400
        
    user = User.query.filter_by(email=email).first()
    if user and user.is_active:
        token = secrets.token_urlsafe(32)
        user.reset_password_token = token
        user.reset_password_expires_at = datetime.utcnow() + timedelta(hours=1)
        db.session.commit()
        
        reset_link = f"https://www.gokushield.com/reset-password?token={token}&email={user.email}"
        OutreachEngine.send_password_reset_email(user.email, reset_link)
        
    return jsonify({
        'message': 'If an account exists with this email, password reset instructions have been dispatched.',
        'version': VERSION
    }), 200

@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """
    Reset password using validated one-time token.
    """
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    token = data.get('token', '').strip()
    new_password = data.get('password', '').strip()
    
    if not token or not new_password:
        return jsonify({'error': 'Token and new password required', 'version': VERSION}), 400
        
    if len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters', 'version': VERSION}), 400
        
    user = User.query.filter_by(reset_password_token=token).first()
    if not user:
        return jsonify({'error': 'Invalid or expired reset token', 'version': VERSION}), 400
        
    if user.reset_password_expires_at and user.reset_password_expires_at < datetime.utcnow():
        user.reset_password_token = None
        user.reset_password_expires_at = None
        db.session.commit()
        return jsonify({'error': 'Reset token has expired. Please request a new one.', 'version': VERSION}), 400
        
    user.set_password(new_password)
    user.reset_password_token = None
    user.reset_password_expires_at = None
    user.unlock_account()
    
    audit = AuditLog(
        user_id=user.id,
        action='password_reset_completed',
        resource_type='user',
        details={'email': user.email},
        ip_address=request.remote_addr
    )
    db.session.add(audit)
    db.session.commit()
    
    return jsonify({
        'message': 'Password has been successfully updated. You may now log in.',
        'version': VERSION
    }), 200

