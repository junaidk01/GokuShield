"""
WhatsApp Business API Handler
==============================

Handles WhatsApp notifications via WhatsApp Business API.

Requirements:
- WhatsApp Business API access
- Valid business phone number
- User opt-in required

Configuration via environment variables:
- WHATSAPP_API_URL
- WHATSAPP_API_TOKEN
- WHATSAPP_BUSINESS_PHONE
"""

import requests
import logging
import os
from typing import Dict, Any
from ..import NotificationEvent, NotificationPriority

logger = logging.getLogger(__name__)


class WhatsAppHandler:
    """WhatsApp Business API notification handler"""
    
    def __init__(self):
        self.api_url = os.environ.get('WHATSAPP_API_URL', '')
        self.api_token = os.environ.get('WHATSAPP_API_TOKEN', '')
        self.business_phone = os.environ.get('WHATSAPP_BUSINESS_PHONE', '')
        self.enabled = bool(self.api_url and self.api_token and self.business_phone)
        
        if not self.enabled:
            logger.warning("WhatsApp handler not configured")
    
    def send(
        self,
        recipient: str,
        event: NotificationEvent,
        data: Dict[str, Any],
        priority: NotificationPriority
    ) -> bool:
        """
        Send WhatsApp message
        
        Args:
            recipient: Phone number in E.164 format (e.g., +1234567890)
            event: Notification event type
            data: Event data
            priority: Message priority
            
        Returns:
            Success status
        """
        if not self.enabled:
            logger.warning("WhatsApp handler not configured, skipping")
            return False
            
        try:
            message = self._format_message(event, data)
            
            payload = {
                'messaging_product': 'whatsapp',
                'to': recipient,
                'type': 'text',
                'text': {
                    'body': message
                }
            }
            
            headers = {
                'Authorization': f'Bearer {self.api_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{self.api_url}/messages",
                json=payload,
                headers=headers,
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                logger.info(f"WhatsApp sent to {recipient}")
                return True
            else:
                logger.error(f"WhatsApp API error: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"WhatsApp send failed: {e}")
            return False
    
    def _format_message(self, event: NotificationEvent, data: Dict[str, Any]) -> str:
        """Format notification message for WhatsApp"""
        
        if event == NotificationEvent.SCAN_COMPLETED:
            return (
                f"🔐 *GoKushield Security Scan Completed*\n\n"
                f"Target: {data.get('target', 'N/A')}\n"
                f"Findings: {data.get('findings_count', 0)}\n\n"
                f"View detailed report in your dashboard."
            )
            
        elif event == NotificationEvent.CRITICAL_VULNERABILITY:
            return (
                f"🚨 *CRITICAL: Security Vulnerability Detected*\n\n"
                f"Target: {data.get('target', 'N/A')}\n"
                f"Issue: {data.get('vulnerability', 'Unknown')}\n\n"
                f"⚠️ *Immediate action required*\n"
                f"Review details in your dashboard."
            )
            
        elif event == NotificationEvent.COMPLIANCE_FAILURE:
            return (
                f"⚠️ *Compliance Alert*\n\n"
                f"Target: {data.get('target', 'N/A')}\n"
                f"Framework: {data.get('framework', 'Unknown')}\n\n"
                f"Your system has compliance issues that need attention."
            )
            
        elif event == NotificationEvent.DOMAIN_ABUSE_BLOCKED:
            return (
                f"🛡️ *Domain Abuse Blocked*\n\n"
                f"A suspicious activity was detected and blocked.\n\n"
                f"Check your security dashboard for details."
            )
            
        else:
            return f"GoKushield Security Alert: {event.value}"
