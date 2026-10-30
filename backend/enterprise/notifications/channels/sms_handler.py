"""
SMS Notification Handler (Twilio)
==================================

Handles SMS notifications via Twilio API.

Configuration via environment variables:
- TWILIO_ACCOUNT_SID
- TWILIO_AUTH_TOKEN
- TWILIO_PHONE_NUMBER
"""

import logging
import os
from typing import Dict, Any
from ..import NotificationEvent, NotificationPriority

logger = logging.getLogger(__name__)


class SMSHandler:
    """Twilio SMS notification handler"""
    
    def __init__(self):
        self.account_sid = os.environ.get('TWILIO_ACCOUNT_SID', '')
        self.auth_token = os.environ.get('TWILIO_AUTH_TOKEN', '')
        self.from_number = os.environ.get('TWILIO_PHONE_NUMBER', '')
        self.enabled = bool(self.account_sid and self.auth_token and self.from_number)
        
        if self.enabled:
            try:
                from twilio.rest import Client
                self.client = Client(self.account_sid, self.auth_token)
            except ImportError:
                logger.error("Twilio SDK not installed (pip install twilio)")
                self.enabled = False
        else:
            logger.warning("SMS handler not configured")
    
    def send(
        self,
        recipient: str,
        event: NotificationEvent,
        data: Dict[str, Any],
        priority: NotificationPriority
    ) -> bool:
        """
        Send SMS message
        
        Args:
            recipient: Phone number in E.164 format
            event: Notification event type
            data: Event data
            priority: Message priority
            
        Returns:
            Success status
        """
        if not self.enabled:
            logger.warning("SMS handler not configured, skipping")
            return False
            
        try:
            message_body = self._format_message(event, data)
            
            message = self.client.messages.create(
                body=message_body,
                from_=self.from_number,
                to=recipient
            )
            
            logger.info(f"SMS sent to {recipient}, SID: {message.sid}")
            return True
            
        except Exception as e:
            logger.error(f"SMS send failed: {e}")
            return False
    
    def _format_message(self, event: NotificationEvent, data: Dict[str, Any]) -> str:
        """Format notification message for SMS (160 char limit)"""
        
        if event == NotificationEvent.SCAN_COMPLETED:
            return (
                f"GoKushield: Scan completed for {data.get('target', 'N/A')}. "
                f"{data.get('findings_count', 0)} findings. Check dashboard."
            )
            
        elif event == NotificationEvent.CRITICAL_VULNERABILITY:
            return (
                f"CRITICAL: {data.get('vulnerability', 'Vulnerability')} detected "
                f"on {data.get('target', 'N/A')}. Immediate action required!"
            )
            
        elif event == NotificationEvent.COMPLIANCE_FAILURE:
            return (
                f"Compliance Alert: {data.get('framework', 'Unknown')} "
                f"failure on {data.get('target', 'N/A')}. Review needed."
            )
            
        elif event == NotificationEvent.DOMAIN_ABUSE_BLOCKED:
            return "GoKushield: Suspicious activity blocked. Check security dashboard."
            
        else:
            return f"GoKushield Security Alert: {event.value}"
