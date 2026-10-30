"""
Lead Engine - Pre-authentication lead management
Enforces one free audit per domain with abuse prevention
"""

from models import db, Lead, LeadStatus, AuditLog
from datetime import datetime, timedelta
import re
from typing import Optional, Tuple

class LeadEngine:
    """
    Manages pre-authentication leads
    Enforces domain-based free audit policy
    """
    
    @staticmethod
    def extract_domain(email: str) -> str:
        """Extract domain from email"""
        return email.split('@')[1].lower() if '@' in email else ''
    
    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def get_or_create_lead(email: str, source: str = 'website', 
                          ip_address: str = None, user_agent: str = None) -> Tuple[Lead, bool]:
        """
        Get existing lead or create new one
        Returns: (lead, created)
        """
        email = email.lower().strip()
        domain = LeadEngine.extract_domain(email)
        
        if not domain:
            raise ValueError("Invalid email address")
        
        # Check if lead exists by domain (email-independent)
        lead = Lead.query.filter_by(domain=domain).first()
        
        if lead:
            # Update last activity
            lead.last_activity = datetime.utcnow()
            # Update email if changed (same domain)
            if lead.email != email:
                lead.email = email
            return lead, False
        
        # Create new lead
        lead = Lead(
            email=email,
            domain=domain,
            source=source,
            ip_address=ip_address,
            user_agent=user_agent,
            status=LeadStatus.NEW
        )
        db.session.add(lead)
        
        return lead, True
    
    @staticmethod
    def check_audit_permission(lead: Lead) -> Tuple[bool, Optional[str]]:
        """
        Check if lead can perform free audit
        Returns: (allowed, reason_if_not)
        """
        # Check if blocked
        if lead.is_blocked:
            if lead.blocked_until and lead.blocked_until < datetime.utcnow():
                # Unblock if expired
                lead.is_blocked = False
                lead.blocked_until = None
                lead.status = LeadStatus.AUDITED
            else:
                return False, f"Domain blocked: {lead.blocked_reason}"
        
        # Enforce Policy: Strictly 1 free audit per company domain (Immutable, no free rescan)
        if (lead.audit_count or 0) >= 1:
            return False, "This domain has already received its one free audit. Your audit report is sealed and permanently accessible. Upgrade to a paid plan to unlock continuous rescans."
        
        return True, None
    
    @staticmethod
    def record_audit(lead: Lead):
        """Record that lead performed an audit"""
        lead.increment_audit()
        db.session.commit()
    
    @staticmethod
    def convert_to_user(lead: Lead, user_id: int):
        """Mark lead as converted to registered user"""
        lead.status = LeadStatus.CONVERTED
        lead.converted_user_id = user_id
        lead.converted_at = datetime.utcnow()
        db.session.commit()
    
    @staticmethod
    def block_domain(domain: str, reason: str, hours: int = 24):
        """Manually block a domain"""
        lead = Lead.query.filter_by(domain=domain).first()
        if lead:
            lead.block(reason, hours)
            db.session.commit()
            
            # Audit log
            audit = AuditLog(
                action='domain_blocked',
                resource_type='lead',
                resource_id=lead.id,
                details={'domain': domain, 'reason': reason, 'hours': hours}
            )
            db.session.add(audit)
            db.session.commit()
    
    @staticmethod
    def unblock_domain(domain: str):
        """Manually unblock a domain"""
        lead = Lead.query.filter_by(domain=domain).first()
        if lead and lead.is_blocked:
            lead.is_blocked = False
            lead.blocked_until = None
            lead.blocked_reason = None
            if lead.status == LeadStatus.BLOCKED:
                lead.status = LeadStatus.AUDITED
            db.session.commit()
            
            # Audit log
            audit = AuditLog(
                action='domain_unblocked',
                resource_type='lead',
                resource_id=lead.id,
                details={'domain': domain}
            )
            db.session.add(audit)
            db.session.commit()
    
    @staticmethod
    def get_lead_stats():
        """Get lead statistics"""
        from sqlalchemy import func
        
        stats = {
            'total_leads': Lead.query.count(),
            'new_leads': Lead.query.filter_by(status=LeadStatus.NEW).count(),
            'audited_leads': Lead.query.filter_by(status=LeadStatus.AUDITED).count(),
            'converted_leads': Lead.query.filter_by(status=LeadStatus.CONVERTED).count(),
            'blocked_leads': Lead.query.filter_by(status=LeadStatus.BLOCKED).count(),
            'total_audits': db.session.query(func.sum(Lead.audit_count)).scalar() or 0,
            'conversion_rate': 0.0
        }
        
        if stats['audited_leads'] > 0:
            stats['conversion_rate'] = round(
                (stats['converted_leads'] / stats['audited_leads']) * 100, 2
            )
        
        return stats
    
    @staticmethod
    def get_recent_leads(limit: int = 50):
        """Get recent leads"""
        return Lead.query.order_by(Lead.created_at.desc()).limit(limit).all()
    
    @staticmethod
    def get_unconverted_leads(days: int = 7):
        """
        Get leads that performed audits but didn't convert
        Useful for follow-up campaigns
        """
        cutoff = datetime.utcnow() - timedelta(days=days)
        return Lead.query.filter(
            Lead.status == LeadStatus.AUDITED,
            Lead.last_activity >= cutoff,
            Lead.converted_user_id.is_(None)
        ).order_by(Lead.last_activity.desc()).all()

    @staticmethod
    def score_lead(lead: Lead) -> int:
        """
        Lead Intelligence Engine: score lead from 1 to 100 based on
        domain tier, audit activity, source, and corporate indicators.
        """
        score = 50  # Baseline
        domain = lead.domain.lower() if lead.domain else ''
        
        # High value TLD / domain indicators
        if any(domain.endswith(tld) for tld in ['.io', '.ai', '.tech', '.co', '.org', '.com']):
            score += 15
        if any(term in domain for term in ['api', 'cloud', 'pay', 'fin', 'sec', 'data', 'health']):
            score += 15
            
        # Activity engagement
        if lead.audit_count > 0:
            score += 10
        if lead.status == LeadStatus.AUDITED:
            score += 10
            
        return min(max(score, 1), 100)

    @staticmethod
    def ingest_scraped_lead(domain: str, email: str, source: str = 'lead_scraper', metadata: dict = None) -> Tuple[Lead, bool]:
        """
        Automated Lead Scraping ingestion:
        Accepts verified prospective company leads from scraper agents.
        """
        email = email.lower().strip()
        domain = domain.lower().strip() or LeadEngine.extract_domain(email)
        
        lead = Lead.query.filter_by(domain=domain).first()
        if lead:
            lead.last_activity = datetime.utcnow()
            return lead, False
            
        lead = Lead(
            email=email,
            domain=domain,
            source=source,
            status=LeadStatus.NEW
        )
        db.session.add(lead)
        db.session.commit()
        return lead, True

    @staticmethod
    def log_calling_agent(lead_id: int, agent_name: str, outcome: str, notes: str = ''):
        """
        Voice / Calling Agent activity logging
        """
        audit = AuditLog(
            action='calling_agent_outreach',
            resource_type='lead',
            resource_id=lead_id,
            details={
                'agent_name': agent_name,
                'outcome': outcome,
                'notes': notes,
                'timestamp': datetime.utcnow().isoformat()
            }
        )
        db.session.add(audit)
        db.session.commit()
        return audit

    @staticmethod
    def log_mail_agent(lead_id: int, campaign_name: str, status: str = 'dispatched'):
        """
        Mail Agent automated dispatch logging
        """
        audit = AuditLog(
            action='mail_agent_dispatch',
            resource_type='lead',
            resource_id=lead_id,
            details={
                'campaign': campaign_name,
                'status': status,
                'timestamp': datetime.utcnow().isoformat()
            }
        )
        db.session.add(audit)
        db.session.commit()
        return audit
