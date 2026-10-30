"""
Outreach Module - Automated email campaigns
Trigger-based, logged, auditable outreach system
"""

from models import db, Outreach, Lead, User, OutreachStatus, AuditLog
from datetime import datetime
from typing import Dict, Optional
import logging

logger = logging.getLogger(__name__)

class OutreachEngine:
    """
    Manages automated outreach campaigns
    All messages are trigger-based and logged
    """
    
    # Email templates
    TEMPLATES = {
        'welcome': {
            'subject': 'Welcome to GoKushield AI - Your Free Security Audit',
            'html': '''
                <html>
                <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background: #dc2626; padding: 20px; text-align: center;">
                        <h1 style="color: white; margin: 0;">GoKushield AI</h1>
                    </div>
                    <div style="padding: 30px;">
                        <h2>Welcome!</h2>
                        <p>Thank you for your interest in GoKushield AI.</p>
                        <p>We're processing your free security audit for <strong>{{domain}}</strong>.</p>
                        <p>You'll receive your comprehensive security report shortly.</p>
                        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
                        <p><strong>What's Next?</strong></p>
                        <ul>
                            <li>Review your audit results</li>
                            <li>Understand your security posture</li>
                            <li>Explore our protection plans</li>
                        </ul>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="https://www.gokushield.com/?ref=welcome" style="background: #dc2626; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Visit Dashboard</a>
                        </div>
                    </div>
                    <div style="background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666;">
                        <p>GoKushield AI - AI-Powered API Security Protection</p>
                        <p>&copy; 2026 JK TECH. All rights reserved.</p>
                    </div>
                </body>
                </html>
            ''',
            'text': '''
                Welcome to GoKushield AI!
                
                Thank you for your interest in GoKushield AI.
                
                We're processing your free security audit for {{domain}}.
                You'll receive your comprehensive security report shortly.
                
                What's Next?
                - Review your audit results
                - Understand your security posture
                - Explore our protection plans
                
                Visit: https://www.gokushield.com/?ref=welcome
                
                GoKushield AI - AI-Powered API Security Protection
                © 2026 JK TECH. All rights reserved.
            '''
        },
        
        'audit_report': {
            'subject': 'Your Security Audit Results - {{domain}}',
            'html': '''
                <html>
                <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background: #dc2626; padding: 20px; text-align: center;">
                        <h1 style="color: white; margin: 0;">Security Audit Complete</h1>
                    </div>
                    <div style="padding: 30px;">
                        <h2>Audit Results for {{domain}}</h2>
                        <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
                            <p><strong>Risk Score:</strong> <span style="font-size: 24px; color: {{risk_color}};">{{risk_score}}/100</span></p>
                            <p><strong>Confidence:</strong> {{confidence_score}}%</p>
                        </div>
                        <h3>Key Findings:</h3>
                        {{findings_html}}
                        <h3>Our Recommendation:</h3>
                        <p>{{recommendation}}</p>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="https://www.gokushield.com/pricing?ref=audit" style="background: #dc2626; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Protect Your API Now</a>
                        </div>
                    </div>
                    <div style="background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666;">
                        <p>GoKushield AI - AI-Powered API Security Protection</p>
                        <p>&copy; 2026 JK TECH. All rights reserved.</p>
                    </div>
                </body>
                </html>
            ''',
            'text': '''
                Security Audit Complete
                
                Audit Results for {{domain}}
                
                Risk Score: {{risk_score}}/100
                Confidence: {{confidence_score}}%
                
                Key Findings:
                {{findings_text}}
                
                Our Recommendation:
                {{recommendation}}
                
                Protect Your API: https://www.gokushield.com/pricing?ref=audit
                
                GoKushield AI - AI-Powered API Security Protection
                © 2026 JK TECH. All rights reserved.
            '''
        },
        
        'follow_up': {
            'subject': 'Have you reviewed your security audit? - {{domain}}',
            'html': '''
                <html>
                <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background: #dc2626; padding: 20px; text-align: center;">
                        <h1 style="color: white; margin: 0;">Follow-up: Your Security Audit</h1>
                    </div>
                    <div style="padding: 30px;">
                        <p>Hi there,</p>
                        <p>We noticed you recently ran a free security audit for <strong>{{domain}}</strong>.</p>
                        <p>Have you had a chance to review the results?</p>
                        <p><strong>Quick Recap:</strong></p>
                        <ul>
                            <li>Risk Score: {{risk_score}}/100</li>
                            <li>Issues Found: {{issues_count}}</li>
                            <li>Recommendations: {{recommendations_count}}</li>
                        </ul>
                        <p>Ready to protect your API? Our AI-powered security platform can help.</p>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="https://www.gokushield.com/signup?ref=followup&email={{email}}" style="background: #dc2626; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Get Started Free</a>
                        </div>
                        <p style="font-size: 12px; color: #666;">Don't want these emails? <a href="https://www.gokushield.com/unsubscribe?email={{email}}">Unsubscribe</a></p>
                    </div>
                    <div style="background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666;">
                        <p>GoKushield AI - AI-Powered API Security Protection</p>
                        <p>&copy; 2026 JK TECH. All rights reserved.</p>
                    </div>
                </body>
                </html>
            ''',
            'text': '''
                Follow-up: Your Security Audit
                
                Hi there,
                
                We noticed you recently ran a free security audit for {{domain}}.
                Have you had a chance to review the results?
                
                Quick Recap:
                - Risk Score: {{risk_score}}/100
                - Issues Found: {{issues_count}}
                - Recommendations: {{recommendations_count}}
                
                Ready to protect your API? Our AI-powered security platform can help.
                
                Get Started: https://www.gokushield.com/signup?ref=followup&email={{email}}
                
                Don't want these emails? Unsubscribe: https://www.gokushield.com/unsubscribe?email={{email}}
                
                GoKushield AI - AI-Powered API Security Protection
                © 2026 JK TECH. All rights reserved.
            '''
        },
        
        'upgrade_prompt': {
            'subject': 'Upgrade to Professional Protection - {{domain}}',
            'html': '''
                <html>
                <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background: #dc2626; padding: 20px; text-align: center;">
                        <h1 style="color: white; margin: 0;">Upgrade Your Protection</h1>
                    </div>
                    <div style="padding: 30px;">
                        <p>Your API deserves professional-grade security.</p>
                        <p>Based on your audit results, we recommend upgrading to:</p>
                        <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
                            <h3 style="margin-top: 0;">{{recommended_plan}} Plan</h3>
                            <p style="font-size: 32px; font-weight: bold; color: #dc2626; margin: 10px 0;">${{price}}/month</p>
                            <ul style="list-style: none; padding: 0;">
                                {{features_html}}
                            </ul>
                        </div>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="https://www.gokushield.com/upgrade?plan={{plan_id}}&ref=email" style="background: #dc2626; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Upgrade Now</a>
                        </div>
                    </div>
                    <div style="background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666;">
                        <p>GoKushield AI - AI-Powered API Security Protection</p>
                        <p>&copy; 2026 JK TECH. All rights reserved.</p>
                    </div>
                </body>
                </html>
            ''',
            'text': '''
                Upgrade Your Protection
                
                Your API deserves professional-grade security.
                
                Based on your audit results, we recommend:
                
                {{recommended_plan}} Plan - ${{price}}/month
                {{features_text}}
                
                Upgrade Now: https://www.gokushield.com/upgrade?plan={{plan_id}}&ref=email
                
                GoKushield AI - AI-Powered API Security Protection
                © 2026 JK TECH. All rights reserved.
            '''
        },
        
        'cold_outreach': {
            'subject': 'Automated API Security Assessment for {{domain}}',
            'html': '''
                <html>
                <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background: #dc2626; padding: 20px; text-align: center;">
                        <h1 style="color: white; margin: 0;">GoKushield Cyber Intelligence</h1>
                    </div>
                    <div style="padding: 30px;">
                        <h2>Hi {{company_name}},</h2>
                        <p>We recently analyzed public perimeter security postures across high-growth domains, including <strong>{{domain}}</strong>.</p>
                        <p>With API attacks increasing over 300% year-over-year, having an immutable, deterministic security baseline is vital before facing board audits, investor due diligence, or compliance reviews.</p>
                        <div style="background: #111; color: #fff; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #dc2626;">
                            <h3 style="color: #ef4444; margin-top: 0;">Get Your Free Security Audit</h3>
                            <p>We provide a 100% free, full-surface scan for <strong>{{domain}}</strong> without requiring passwords or credit cards:</p>
                            <ul>
                                <li>OWASP API Top 10 vulnerabilities & broken authentication detection</li>
                                <li>Exposed endpoints, outdated headers, and SSL/TLS configuration checks</li>
                                <li>Deterministic 0-100 risk score with human-readable remediation hints</li>
                            </ul>
                        </div>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="https://www.gokushield.com?ref=cold_outreach&target={{domain}}" style="background: #dc2626; color: white; padding: 14px 32px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold;">Launch Free Audit for {{domain}}</a>
                        </div>
                        <p style="font-size: 13px; color: #888;">One free audit per company domain. Results are sealed and cryptographically verifiable.</p>
                    </div>
                    <div style="background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666;">
                        <p>GoKushield AI - Audit-First Cyber Intelligence</p>
                        <p>&copy; 2026 JK TECH. All rights reserved.</p>
                    </div>
                </body>
                </html>
            ''',
            'text': '''
                Automated API Security Assessment for {{domain}}
                
                Hi {{company_name}},
                
                We recently analyzed public perimeter security postures across high-growth domains, including {{domain}}.
                
                With API attacks surging over 300% YoY, having an immutable, deterministic security baseline is vital for your engineering posture.
                
                GoKushield provides a 100% free security audit for {{domain}}:
                - OWASP API Top 10 vulnerability identification
                - SSL/TLS and security headers assessment
                - Deterministic 0-100 risk score and remediation guidance
                
                Launch your free audit: https://www.gokushield.com?ref=cold_outreach&target={{domain}}
                
                GoKushield AI - Audit-First Cyber Intelligence
                © 2026 JK TECH. All rights reserved.
            '''
        },
        'password_reset': {
            'subject': 'GoKushield AI - Reset Your Security Dashboard Password',
            'html': '''
                <html>
                <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #000; color: #fff;">
                    <div style="background: #000; border-bottom: 2px solid #00f0ff; padding: 20px; text-align: center;">
                        <h1 style="color: #ff3333; margin: 0;">GOKUSHIELD <span style="color: #00f0ff;">AI</span></h1>
                    </div>
                    <div style="padding: 30px; background: #111;">
                        <h2 style="color: #fff;">Password Reset Request</h2>
                        <p style="color: #ccc;">We received a request to reset your GoKushield AI client dashboard password.</p>
                        <p style="color: #ccc;">Click the secure link below to set a new password. This link is valid for 60 minutes:</p>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="{{reset_url}}" style="background: #00f0ff; color: #000; font-weight: bold; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
                        </div>
                        <p style="color: #888; font-size: 12px;">If you did not request this, please disregard this email. Your account remains secure.</p>
                    </div>
                </body>
                </html>
            ''',
            'text': '''
                GoKushield AI - Password Reset Request
                
                Click the link below to set a new password (valid for 60 minutes):
                {{reset_url}}
                
                If you did not request this, please disregard this email.
            '''
        }
    }
    
    @staticmethod
    def _render_template(template: str, data: Dict) -> str:
        """Simple template variable replacement"""
        for key, value in data.items():
            template = template.replace(f'{{{{{key}}}}}', str(value))
        return template
    
    @staticmethod
    def create_outreach(template_name: str, recipient_email: str, 
                       data: Dict, lead_id: Optional[int] = None,
                       user_id: Optional[int] = None) -> Outreach:
        """
        Create an outreach message
        Does not send - messages are processed by background worker
        """
        if template_name not in OutreachEngine.TEMPLATES:
            raise ValueError(f"Unknown template: {template_name}")
        
        template = OutreachEngine.TEMPLATES[template_name]
        
        # Render templates
        subject = OutreachEngine._render_template(template['subject'], data)
        content_html = OutreachEngine._render_template(template['html'], data)
        content_text = OutreachEngine._render_template(template['text'], data)
        
        outreach = Outreach(
            lead_id=lead_id,
            user_id=user_id,
            template_name=template_name,
            subject=subject,
            recipient_email=recipient_email,
            content_html=content_html,
            content_text=content_text,
            data=data,
            status=OutreachStatus.PENDING
        )
        
        db.session.add(outreach)
        db.session.commit()
        
        logger.info(f"Created outreach {template_name} for {recipient_email}")
        
        return outreach
    
    @staticmethod
    def send_welcome_email(lead: Lead):
        """Send welcome email to new lead"""
        data = {
            'email': lead.email,
            'domain': lead.domain
        }
        return OutreachEngine.create_outreach('welcome', lead.email, data, lead_id=lead.id)
    
    @staticmethod
    def send_audit_report(lead: Lead, scan_result: Dict):
        """Send audit report email"""
        risk_score = scan_result.get('risk_score', 0)
        
        # Determine risk color
        if risk_score < 30:
            risk_color = '#16a34a'  # green
        elif risk_score < 70:
            risk_color = '#d97706'  # orange
        else:
            risk_color = '#dc2626'  # red
        
        # Format findings
        findings = scan_result.get('findings', [])
        findings_html = '<ul>'
        findings_text = ''
        for finding in findings[:5]:  # Top 5
            findings_html += f'<li>{finding.get("title", "Issue found")}</li>'
            findings_text += f'- {finding.get("title", "Issue found")}\n'
        findings_html += '</ul>'
        
        data = {
            'email': lead.email,
            'domain': lead.domain,
            'risk_score': risk_score,
            'risk_color': risk_color,
            'confidence_score': scan_result.get('confidence_score', 0),
            'findings_html': findings_html,
            'findings_text': findings_text,
            'recommendation': scan_result.get('analysis', 'Review your security posture and consider upgrading.')
        }
        
        return OutreachEngine.create_outreach('audit_report', lead.email, data, lead_id=lead.id)
    
    @staticmethod
    def send_follow_up(lead: Lead, scan_result: Dict):
        """Send follow-up email to unconverted leads"""
        data = {
            'email': lead.email,
            'domain': lead.domain,
            'risk_score': scan_result.get('risk_score', 0),
            'issues_count': len(scan_result.get('findings', [])),
            'recommendations_count': len(scan_result.get('recommendations', []))
        }
        return OutreachEngine.create_outreach('follow_up', lead.email, data, lead_id=lead.id)
    
    @staticmethod
    def send_upgrade_prompt(user: User, recommended_plan: str = 'Professional', price: int = 49):
        """Send upgrade prompt to existing users"""
        features_map = {
            'Starter': ['10 scans/day', 'Basic AI analysis', 'Email support'],
            'Professional': ['100 scans/day', 'Advanced AI analysis', 'Priority support', 'Custom reports'],
            'Enterprise': ['Unlimited scans', 'Enterprise AI', '24/7 support', 'Custom integrations']
        }
        
        features = features_map.get(recommended_plan, [])
        features_html = ''.join([f'<li style="margin: 5px 0;">✓ {f}</li>' for f in features])
        features_text = '\n'.join([f'✓ {f}' for f in features])
        
        data = {
            'email': user.email,
            'domain': user.email.split('@')[1] if '@' in user.email else '',
            'recommended_plan': recommended_plan,
            'price': price,
            'features_html': features_html,
            'features_text': features_text,
            'plan_id': recommended_plan.lower()
        }
        
        return OutreachEngine.create_outreach('upgrade_prompt', user.email, data, user_id=user.id)
    
    @staticmethod
    def send_cold_outreach(email: str, domain: str, company_name: str = ''):
        """Send automated cold outreach email to prospective target"""
        if not company_name:
            company_name = domain.split('.')[0].capitalize() if domain else 'there'
            
        data = {
            'email': email,
            'domain': domain,
            'company_name': company_name
        }
        
        # Check if lead exists, create if not
        from models import Lead, LeadStatus
        lead = Lead.query.filter_by(domain=domain).first()
        if not lead:
            lead = Lead(email=email, domain=domain, source='cold_outreach', status=LeadStatus.NEW)
            db.session.add(lead)
            db.session.commit()
            
        return OutreachEngine.create_outreach('cold_outreach', email, data, lead_id=lead.id)
    
    @staticmethod
    def process_pending_outreach(limit: int = 100):
        """
        Process pending outreach messages
        This should be called by a Celery task
        """
        pending = Outreach.query.filter_by(status=OutreachStatus.PENDING).limit(limit).all()
        
        sent_count = 0
        failed_count = 0
        
        for outreach in pending:
            try:
                # Here you would integrate with actual email service (SMTP, SendGrid, etc.)
                # For now, we mark as sent
                outreach.status = OutreachStatus.SENT
                outreach.sent_at = datetime.utcnow()
                sent_count += 1
                
                logger.info(f"Sent {outreach.template_name} to {outreach.recipient_email}")
                
            except Exception as e:
                outreach.status = OutreachStatus.FAILED
                outreach.error_message = str(e)
                failed_count += 1
                
                logger.error(f"Failed to send {outreach.template_name} to {outreach.recipient_email}: {e}")
        
        db.session.commit()
        
        return {'sent': sent_count, 'failed': failed_count}
    
    @staticmethod
    def get_outreach_stats():
        """Get outreach statistics"""
        stats = {
            'total': Outreach.query.count(),
            'pending': Outreach.query.filter_by(status=OutreachStatus.PENDING).count(),
            'sent': Outreach.query.filter_by(status=OutreachStatus.SENT).count(),
            'failed': Outreach.query.filter_by(status=OutreachStatus.FAILED).count(),
            'delivered': Outreach.query.filter_by(status=OutreachStatus.DELIVERED).count()
        }
        return stats

    @staticmethod
    def send_password_reset_email(email: str, reset_url: str):
        """Send password reset instructions with secure one-time token"""
        return OutreachEngine.create_outreach(
            template_name='password_reset',
            recipient_email=email,
            data={'reset_url': reset_url}
        )
