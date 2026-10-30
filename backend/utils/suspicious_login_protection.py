"""
Suspicious Login Protection Module
IP reputation, geo-velocity detection, account lockout
"""

from datetime import datetime, timedelta
from models import db, LoginAttempt, IPBlacklist, User
import logging
import hashlib

logger = logging.getLogger(__name__)

class SuspiciousLoginProtection:
    """Advanced login protection system"""
    
    # Known malicious IP ranges (simplified - in production use threat intelligence feeds)
    SUSPICIOUS_IP_RANGES = [
        '10.0.0.',  # Private networks (shouldn't be used for public auth)
        '192.168.',  # Private networks
        '172.16.',   # Private networks
    ]
    
    @staticmethod
    def check_ip_reputation(ip_address):
        """
        Check IP reputation
        Returns: (is_suspicious, reason)
        """
        # Check private IP ranges
        for suspicious_range in SuspiciousLoginProtection.SUSPICIOUS_IP_RANGES:
            if ip_address.startswith(suspicious_range):
                return True, f'Suspicious IP range: {ip_address}'
        
        # Check blacklist
        blacklist = IPBlacklist.query.filter_by(ip_address=ip_address).first()
        if blacklist:
            if blacklist.expires_at and blacklist.expires_at < datetime.utcnow():
                # Expired, remove
                db.session.delete(blacklist)
                db.session.commit()
                return False, None
            return True, blacklist.reason
        
        return False, None
    
    @staticmethod
    def check_geo_velocity(email, ip_address, user_agent):
        """
        Check for impossible travel (geo-velocity)
        If user logs in from drastically different locations in short time
        Returns: (is_suspicious, reason)
        """
        # Get recent successful logins (last 6 hours)
        window_start = datetime.utcnow() - timedelta(hours=6)
        
        recent_logins = LoginAttempt.query.filter(
            LoginAttempt.email == email,
            LoginAttempt.successful == True,
            LoginAttempt.created_at >= window_start
        ).order_by(LoginAttempt.created_at.desc()).limit(5).all()
        
        if not recent_logins:
            return False, None
        
        # Check IP change frequency
        recent_ips = [attempt.ip_address for attempt in recent_logins]
        unique_ips = set(recent_ips)
        
        # If more than 3 different IPs in 6 hours, flag as suspicious
        if len(unique_ips) > 3:
            return True, f'Multiple IPs detected: {len(unique_ips)} locations in 6 hours'
        
        # Check user agent changes
        recent_agents = [attempt.user_agent for attempt in recent_logins if attempt.user_agent]
        
        if recent_agents and user_agent:
            # Simplified: check if user agent drastically different
            if len(set(recent_agents)) > 2 and user_agent not in recent_agents:
                return True, 'User agent mismatch - possible account takeover'
        
        return False, None
    
    @staticmethod
    def check_brute_force(email, ip_address):
        """
        Check for brute force attempts
        Returns: (is_blocked, reason)
        """
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
            
            logger.warning(f'Brute force detected: {ip_address} on {email}')
            return True, 'Too many failed login attempts'
        
        return False, None
    
    @staticmethod
    def lock_account_temporarily(user_id, hours=2):
        """Temporarily lock user account"""
        user = User.query.get(user_id)
        if user:
            user.is_active = False
            user.locked_until = datetime.utcnow() + timedelta(hours=hours)
            db.session.commit()
            logger.warning(f'Account locked: user_id={user_id} for {hours} hours')
    
    @staticmethod
    def check_account_lockout(user):
        """
        Check if account is locked
        Returns: (is_locked, reason)
        """
        if not user.is_active:
            # Check if temporary lock expired
            if hasattr(user, 'locked_until') and user.locked_until:
                if user.locked_until < datetime.utcnow():
                    # Unlock
                    user.is_active = True
                    user.locked_until = None
                    db.session.commit()
                    return False, None
                else:
                    remaining = int((user.locked_until - datetime.utcnow()).total_seconds() / 60)
                    return True, f'Account temporarily locked ({remaining} minutes remaining)'
            return True, 'Account disabled'
        
        return False, None
    
    @staticmethod
    def detect_credential_stuffing(email, ip_address):
        """
        Detect credential stuffing attacks
        Multiple different emails from same IP
        Returns: (is_suspicious, reason)
        """
        window_start = datetime.utcnow() - timedelta(minutes=30)
        
        # Count unique emails attempted from this IP
        unique_emails = db.session.query(LoginAttempt.email).filter(
            LoginAttempt.ip_address == ip_address,
            LoginAttempt.created_at >= window_start,
            LoginAttempt.successful == False
        ).distinct().count()
        
        if unique_emails >= 10:
            # Likely credential stuffing
            return True, f'Credential stuffing detected: {unique_emails} accounts targeted from {ip_address}'
        
        return False, None
    
    @staticmethod
    def comprehensive_check(email, ip_address, user_agent, user=None):
        """
        Run all security checks
        Returns: (is_allowed, reason)
        """
        # 1. IP reputation
        suspicious, reason = SuspiciousLoginProtection.check_ip_reputation(ip_address)
        if suspicious:
            return False, reason
        
        # 2. Brute force
        blocked, reason = SuspiciousLoginProtection.check_brute_force(email, ip_address)
        if blocked:
            return False, reason
        
        # 3. Credential stuffing
        suspicious, reason = SuspiciousLoginProtection.detect_credential_stuffing(email, ip_address)
        if suspicious:
            # Blacklist IP
            blacklist = IPBlacklist(
                ip_address=ip_address,
                reason=reason,
                expires_at=datetime.utcnow() + timedelta(hours=24)
            )
            db.session.add(blacklist)
            db.session.commit()
            return False, 'Suspicious activity detected'
        
        # 4. Geo-velocity (if user exists)
        if user:
            suspicious, reason = SuspiciousLoginProtection.check_geo_velocity(email, ip_address, user_agent)
            if suspicious:
                # Don't block but flag for review
                logger.warning(f'Geo-velocity alert: {email} - {reason}')
                # In production, might send email verification or MFA challenge
        
        # 5. Account lockout (if user exists)
        if user:
            locked, reason = SuspiciousLoginProtection.check_account_lockout(user)
            if locked:
                return False, reason
        
        return True, None
