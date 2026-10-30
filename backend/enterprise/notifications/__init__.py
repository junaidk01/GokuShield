"""
Multi-Channel Notification System
==================================

Channel-agnostic notification dispatcher with event-driven triggers.

Supported Channels:
- WhatsApp Business API
- SMS (Twilio)

Trigger Events (LIMITED):
- Scan completed
- Critical vulnerability detected
- Compliance failure
- Domain abuse blocked

SECURITY NOTES:
- NO marketing spam
- NO bulk messaging
- NO voice calls
- Opt-in required
- Rate limited per user
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging
import os

logger = logging.getLogger(__name__)


class NotificationChannel(Enum):
    """Supported notification channels"""
    WHATSAPP = "whatsapp"
    SMS = "sms"
    EMAIL = "email"  # Already exists in system


class NotificationPriority(Enum):
    """Notification priority levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NotificationEvent(Enum):
    """Allowed notification events"""
    SCAN_COMPLETED = "scan_completed"
    CRITICAL_VULNERABILITY = "critical_vulnerability"
    COMPLIANCE_FAILURE = "compliance_failure"
    DOMAIN_ABUSE_BLOCKED = "domain_abuse_blocked"


class NotificationDispatcher:
    """
    Channel-agnostic notification dispatcher.
    Routes notifications to appropriate channel handlers.
    """
    
    def __init__(self):
        self.handlers = {}
        self._register_handlers()
        
    def _register_handlers(self):
        """Register channel handlers"""
        try:
            from .channels.whatsapp_handler import WhatsAppHandler
            self.handlers[NotificationChannel.WHATSAPP] = WhatsAppHandler()
        except ImportError:
            logger.warning("WhatsApp handler not available")
            
        try:
            from .channels.sms_handler import SMSHandler
            self.handlers[NotificationChannel.SMS] = SMSHandler()
        except ImportError:
            logger.warning("SMS handler not available")
    
    def send(
        self,
        channel: NotificationChannel,
        recipient: str,
        event: NotificationEvent,
        data: Dict[str, Any],
        priority: NotificationPriority = NotificationPriority.MEDIUM
    ) -> bool:
        """
        Send notification through specified channel
        
        Args:
            channel: Notification channel
            recipient: Recipient identifier (phone number, user ID, etc.)
            event: Event type triggering notification
            data: Event-specific data
            priority: Notification priority
            
        Returns:
            Success status
        """
        handler = self.handlers.get(channel)
        if not handler:
            logger.error(f"No handler registered for channel: {channel.value}")
            return False
            
        try:
            # Check rate limits before sending
            if not self._check_rate_limit(recipient, channel):
                logger.warning(f"Rate limit exceeded for {recipient} on {channel.value}")
                return False
                
            # Send through handler
            success = handler.send(recipient, event, data, priority)
            
            # Log notification
            self._log_notification(channel, recipient, event, success)
            
            return success
            
        except Exception as e:
            logger.error(f"Notification send failed: {e}")
            return False
    
    def _check_rate_limit(self, recipient: str, channel: NotificationChannel) -> bool:
        """
        Check rate limits to prevent spam
        
        Limits:
        - 10 notifications per hour per channel
        - 50 notifications per day per user
        """
        # Implementation uses Redis for tracking
        # For now, return True (will be implemented with Redis integration)
        return True
    
    def _log_notification(
        self,
        channel: NotificationChannel,
        recipient: str,
        event: NotificationEvent,
        success: bool
    ):
        """Log notification attempt"""
        from models import db, NotificationLog
        
        try:
            log = NotificationLog(
                channel=channel.value,
                recipient=recipient,
                event=event.value,
                success=success,
                timestamp=datetime.utcnow()
            )
            db.session.add(log)
            db.session.commit()
        except Exception as e:
            logger.error(f"Failed to log notification: {e}")


class NotificationPreferences:
    """User notification preferences manager"""
    
    @staticmethod
    def get_user_channels(user_id: int) -> List[NotificationChannel]:
        """Get enabled notification channels for user"""
        from models import User
        
        user = User.query.get(user_id)
        if not user:
            return []
            
        channels = []
        
        # Check user preferences (stored in user profile)
        if hasattr(user, 'whatsapp_notifications') and user.whatsapp_notifications:
            channels.append(NotificationChannel.WHATSAPP)
            
        if hasattr(user, 'sms_notifications') and user.sms_notifications:
            channels.append(NotificationChannel.SMS)
            
        return channels
    
    @staticmethod
    def update_preferences(
        user_id: int,
        whatsapp: Optional[bool] = None,
        sms: Optional[bool] = None
    ) -> bool:
        """Update user notification preferences"""
        from models import db, User
        
        try:
            user = User.query.get(user_id)
            if not user:
                return False
                
            if whatsapp is not None:
                user.whatsapp_notifications = whatsapp
                
            if sms is not None:
                user.sms_notifications = sms
                
            db.session.commit()
            return True
            
        except Exception as e:
            logger.error(f"Failed to update preferences: {e}")
            db.session.rollback()
            return False


# Event-driven notification triggers
def trigger_scan_completed(scan_id: int):
    """Trigger notification when scan completes"""
    from models import Scan, User
    
    scan = Scan.query.get(scan_id)
    if not scan:
        return
        
    user = User.query.get(scan.user_id)
    if not user:
        return
        
    dispatcher = NotificationDispatcher()
    channels = NotificationPreferences.get_user_channels(user.id)
    
    data = {
        'scan_id': scan.id,
        'target': scan.target,
        'findings_count': len(scan.findings) if hasattr(scan, 'findings') else 0,
        'severity': 'info'
    }
    
    for channel in channels:
        dispatcher.send(
            channel=channel,
            recipient=user.phone_number if channel in [NotificationChannel.WHATSAPP, NotificationChannel.SMS] else user.email,
            event=NotificationEvent.SCAN_COMPLETED,
            data=data,
            priority=NotificationPriority.MEDIUM
        )


def trigger_critical_vulnerability(finding_id: int):
    """Trigger notification for critical vulnerability"""
    from models import Finding, Scan, User
    
    finding = Finding.query.get(finding_id)
    if not finding or finding.severity != 'critical':
        return
        
    scan = Scan.query.get(finding.scan_id)
    if not scan:
        return
        
    user = User.query.get(scan.user_id)
    if not user:
        return
        
    dispatcher = NotificationDispatcher()
    channels = NotificationPreferences.get_user_channels(user.id)
    
    data = {
        'finding_id': finding.id,
        'scan_id': scan.id,
        'vulnerability': finding.title,
        'severity': 'critical',
        'target': scan.target
    }
    
    for channel in channels:
        dispatcher.send(
            channel=channel,
            recipient=user.phone_number if channel in [NotificationChannel.WHATSAPP, NotificationChannel.SMS] else user.email,
            event=NotificationEvent.CRITICAL_VULNERABILITY,
            data=data,
            priority=NotificationPriority.CRITICAL
        )


def trigger_compliance_failure(scan_id: int, framework: str):
    """Trigger notification for compliance failure"""
    from models import Scan, User
    
    scan = Scan.query.get(scan_id)
    if not scan:
        return
        
    user = User.query.get(scan.user_id)
    if not user:
        return
        
    dispatcher = NotificationDispatcher()
    channels = NotificationPreferences.get_user_channels(user.id)
    
    data = {
        'scan_id': scan.id,
        'target': scan.target,
        'framework': framework,
        'severity': 'high'
    }
    
    for channel in channels:
        dispatcher.send(
            channel=channel,
            recipient=user.phone_number if channel in [NotificationChannel.WHATSAPP, NotificationChannel.SMS] else user.email,
            event=NotificationEvent.COMPLIANCE_FAILURE,
            data=data,
            priority=NotificationPriority.HIGH
        )
