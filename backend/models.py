"""
Complete models with Lead, ServiceUsage, and Outreach systems
This replaces the original models.py with full production-ready models
"""

from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import enum

db = SQLAlchemy()
bcrypt = Bcrypt()

class PlanType(enum.Enum):
    FREE = 'free'
    STARTER = 'starter'
    PROFESSIONAL = 'professional'
    ENTERPRISE = 'enterprise'

class ServiceStatus(enum.Enum):
    ACTIVE = 'active'
    IN_PROCESS = 'in_process'
    COMING_SOON = 'coming_soon'
    DISABLED = 'disabled'

class ScanStatus(enum.Enum):
    PENDING = 'pending'
    PROCESSING = 'processing'
    COMPLETED = 'completed'
    FAILED = 'failed'

class LeadStatus(enum.Enum):
    NEW = 'new'
    AUDITED = 'audited'
    CONVERTED = 'converted'
    BLOCKED = 'blocked'

class OutreachStatus(enum.Enum):
    PENDING = 'pending'
    SENT = 'sent'
    FAILED = 'failed'
    DELIVERED = 'delivered'

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255))
    company = db.Column(db.String(255))
    
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    
    plan_type = db.Column(db.Enum(PlanType), default=PlanType.FREE, nullable=False)
    plan_started_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # MFA
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(32))
    
    # Security tracking
    failed_login_count = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime)
    last_ip = db.Column(db.String(45))
    last_geo_location = db.Column(db.String(100))
    
    # Password Reset
    reset_password_token = db.Column(db.String(128), index=True, nullable=True)
    reset_password_expires_at = db.Column(db.DateTime, nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    locked_until = db.Column(db.DateTime, nullable=True)  # Temporary account lock
    
    # Relationships
    apis = db.relationship('API', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    scans = db.relationship('Scan', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    usage_logs = db.relationship('UsageLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    service_usage = db.relationship('ServiceUsage', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def is_account_locked(self):
        """Check if account is temporarily locked"""
        if self.account_locked_until and self.account_locked_until > datetime.utcnow():
            return True
        return False
    
    def lock_account(self, duration_minutes=30):
        """Temporarily lock account"""
        self.account_locked_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
        self.failed_login_count += 1
    
    def unlock_account(self):
        """Unlock account and reset failed login count"""
        self.account_locked_until = None
        self.failed_login_count = 0
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'full_name': self.full_name,
            'company': self.company,
            'is_active': self.is_active,
            'is_admin': self.is_admin,
            'is_verified': self.is_verified,
            'plan_type': self.plan_type.value,
            'mfa_enabled': self.mfa_enabled,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

class Lead(db.Model):
    """
    Pre-authentication lead tracking
    Enforces one free audit per domain (email-independent)
    """
    __tablename__ = 'leads'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    domain = db.Column(db.String(255), nullable=False, index=True)  # Extracted from email
    
    # Source tracking
    source = db.Column(db.String(100))  # 'website', 'api', 'referral'
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(512))
    
    # Activity tracking
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    audit_count = db.Column(db.Integer, default=0)
    
    # Status
    status = db.Column(db.Enum(LeadStatus), default=LeadStatus.NEW, nullable=False)
    
    # Abuse prevention
    is_blocked = db.Column(db.Boolean, default=False)
    blocked_reason = db.Column(db.String(255))
    blocked_until = db.Column(db.DateTime)
    
    # Conversion tracking
    converted_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    converted_at = db.Column(db.DateTime)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    def is_audit_allowed(self):
        """Check if lead can perform free audit"""
        # Check if blocked
        if self.is_blocked:
            if self.blocked_until and self.blocked_until < datetime.utcnow():
                self.is_blocked = False
                self.blocked_until = None
                return True
            return False
        
        # Check domain cooldown (24 hours between audits)
        if self.last_activity:
            cooldown_end = self.last_activity + timedelta(hours=24)
            if datetime.utcnow() < cooldown_end:
                return False
        
        return True
    
    def increment_audit(self):
        """Increment audit count"""
        self.audit_count += 1
        self.last_activity = datetime.utcnow()
        if self.status == LeadStatus.NEW:
            self.status = LeadStatus.AUDITED
    
    def block(self, reason, hours=24):
        """Block lead for abuse"""
        self.is_blocked = True
        self.blocked_reason = reason
        self.blocked_until = datetime.utcnow() + timedelta(hours=hours)
        self.status = LeadStatus.BLOCKED
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'domain': self.domain,
            'audit_count': self.audit_count,
            'status': self.status.value,
            'first_seen': self.first_seen.isoformat(),
            'last_activity': self.last_activity.isoformat() if self.last_activity else None
        }

class Outreach(db.Model):
    """
    Automated outreach system
    Trigger-based email campaigns
    """
    __tablename__ = 'outreach'
    
    id = db.Column(db.Integer, primary_key=True)
    lead_id = db.Column(db.Integer, db.ForeignKey('leads.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Message details
    template_name = db.Column(db.String(100), nullable=False)  # 'welcome', 'audit_report', 'follow_up'
    subject = db.Column(db.String(255), nullable=False)
    recipient_email = db.Column(db.String(255), nullable=False)
    
    # Content
    content_html = db.Column(db.Text)
    content_text = db.Column(db.Text)
    
    # Personalization data
    data = db.Column(db.JSON)  # Template variables
    
    # Status
    status = db.Column(db.Enum(OutreachStatus), default=OutreachStatus.PENDING, nullable=False)
    error_message = db.Column(db.Text)
    
    # Tracking
    sent_at = db.Column(db.DateTime)
    delivered_at = db.Column(db.DateTime)
    opened_at = db.Column(db.DateTime)
    clicked_at = db.Column(db.DateTime)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'template_name': self.template_name,
            'recipient_email': self.recipient_email,
            'status': self.status.value,
            'sent_at': self.sent_at.isoformat() if self.sent_at else None,
            'created_at': self.created_at.isoformat()
        }

class API(db.Model):
    __tablename__ = 'apis'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    name = db.Column(db.String(255), nullable=False)
    base_url = db.Column(db.String(512), nullable=False)
    description = db.Column(db.Text)
    
    is_active = db.Column(db.Boolean, default=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scans = db.relationship('Scan', backref='api', lazy='dynamic', cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'base_url': self.base_url,
            'description': self.description,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

class Service(db.Model):
    __tablename__ = 'services'
    
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100))
    description = db.Column(db.Text)
    
    status = db.Column(db.Enum(ServiceStatus), default=ServiceStatus.ACTIVE, nullable=False)
    is_enabled = db.Column(db.Boolean, default=True)
    
    requires_ai = db.Column(db.Boolean, default=True)
    is_async = db.Column(db.Boolean, default=True)
    
    # Pricing (future use)
    base_cost = db.Column(db.Integer, default=1)  # Credit cost
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    plan_mappings = db.relationship('PlanServiceMapping', backref='service', lazy='dynamic')
    
    def to_dict(self):
        return {
            'id': self.id,
            'service_id': self.service_id,
            'name': self.name,
            'category': self.category,
            'description': self.description,
            'status': self.status.value,
            'is_enabled': self.is_enabled,
            'requires_ai': self.requires_ai
        }

class PlanServiceMapping(db.Model):
    """
    Defines which services are available per plan
    and their usage limits
    """
    __tablename__ = 'plan_service_mappings'
    
    id = db.Column(db.Integer, primary_key=True)
    plan_type = db.Column(db.Enum(PlanType), nullable=False, index=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=False, index=True)
    
    # Usage limits
    usage_limit_daily = db.Column(db.Integer, default=-1)  # -1 = unlimited
    usage_limit_monthly = db.Column(db.Integer, default=-1)
    
    # Access control
    is_enabled = db.Column(db.Boolean, default=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        db.UniqueConstraint('plan_type', 'service_id', name='unique_plan_service'),
    )
    
    def to_dict(self):
        return {
            'id': self.id,
            'plan_type': self.plan_type.value,
            'service_id': self.service_id,
            'usage_limit_daily': self.usage_limit_daily,
            'usage_limit_monthly': self.usage_limit_monthly,
            'is_enabled': self.is_enabled
        }

class ServiceUsage(db.Model):
    """
    Tracks service usage per user for quota enforcement
    Reset daily/monthly via Celery Beat
    """
    __tablename__ = 'service_usage'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=False, index=True)
    
    # Counters
    daily_count = db.Column(db.Integer, default=0)
    monthly_count = db.Column(db.Integer, default=0)
    total_count = db.Column(db.Integer, default=0)
    
    # Reset tracking
    daily_reset_at = db.Column(db.DateTime, default=datetime.utcnow)
    monthly_reset_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # First and last usage
    first_used_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'service_id', name='unique_user_service'),
    )
    
    def increment(self):
        """Increment usage counters"""
        now = datetime.utcnow()
        
        # Check if daily reset needed
        if self.daily_reset_at.date() < now.date():
            self.daily_count = 0
            self.daily_reset_at = now
        
        # Check if monthly reset needed
        if self.monthly_reset_at.month != now.month or self.monthly_reset_at.year != now.year:
            self.monthly_count = 0
            self.monthly_reset_at = now
        
        self.daily_count += 1
        self.monthly_count += 1
        self.total_count += 1
        self.last_used_at = now
    
    def check_limit(self, daily_limit, monthly_limit):
        """Check if usage is within limits"""
        if daily_limit > 0 and self.daily_count >= daily_limit:
            return False, 'daily'
        if monthly_limit > 0 and self.monthly_count >= monthly_limit:
            return False, 'monthly'
        return True, None
    
    def to_dict(self):
        return {
            'user_id': self.user_id,
            'service_id': self.service_id,
            'daily_count': self.daily_count,
            'monthly_count': self.monthly_count,
            'total_count': self.total_count,
            'last_used_at': self.last_used_at.isoformat() if self.last_used_at else None
        }

class Scan(db.Model):
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Nullable for free audits
    lead_id = db.Column(db.Integer, db.ForeignKey('leads.id'), nullable=True)  # For pre-auth audits
    api_id = db.Column(db.Integer, db.ForeignKey('apis.id'), nullable=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=False)
    
    target = db.Column(db.String(512), nullable=False)
    status = db.Column(db.Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    audit_token = db.Column(db.String(128), unique=True, index=True, nullable=True)
    
    # Results
    risk_score = db.Column(db.Integer)  # 0-100
    confidence_score = db.Column(db.Integer)  # 0-100
    
    findings = db.Column(db.JSON)
    analysis = db.Column(db.Text)
    technical_summary = db.Column(db.Text)
    recommendations = db.Column(db.JSON)
    
    raw_data = db.Column(db.JSON)
    error_message = db.Column(db.Text)
    
    # Execution tracking
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    execution_time_ms = db.Column(db.Integer)
    
    # AI tracking
    ai_model_used = db.Column(db.String(100))
    ai_tokens_used = db.Column(db.Integer)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'service_id': self.service_id,
            'target': self.target,
            'status': self.status.value,
            'risk_score': self.risk_score,
            'confidence_score': self.confidence_score,
            'findings': self.findings,
            'analysis': self.analysis,
            'technical_summary': self.technical_summary,
            'recommendations': self.recommendations,
            'audit_token': self.audit_token,
            'error_message': self.error_message,
            'created_at': self.created_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'execution_time_ms': self.execution_time_ms
        }

class UsageLog(db.Model):
    """
    General API usage logging (all requests)
    """
    __tablename__ = 'usage_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=True)
    
    endpoint = db.Column(db.String(255))
    method = db.Column(db.String(10))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(512))
    
    response_time_ms = db.Column(db.Integer)
    status_code = db.Column(db.Integer)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    successful = db.Column(db.Boolean, default=False)
    
    # Geo tracking
    country = db.Column(db.String(100))
    city = db.Column(db.String(100))
    
    # Device tracking
    user_agent = db.Column(db.String(512))
    device_fingerprint = db.Column(db.String(64))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

class IPBlacklist(db.Model):
    __tablename__ = 'ip_blacklist'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    reason = db.Column(db.String(255))
    expires_at = db.Column(db.DateTime)
    
    # Auto-added or manual
    is_auto = db.Column(db.Boolean, default=True)
    added_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class AuditLog(db.Model):
    """
    Immutable audit trail for all admin actions
    """
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    action = db.Column(db.String(100), nullable=False, index=True)
    resource_type = db.Column(db.String(100))
    resource_id = db.Column(db.Integer)
    
    details = db.Column(db.JSON)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(512))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'details': self.details,
            'created_at': self.created_at.isoformat()
        }

class ScanFeedback(db.Model):
    """
    Outcome feedback on a scan's findings (true positive / false positive),
    recorded by an admin or client reviewing the result. This is the raw
    material a future recalibration job reads to adjust risk-scoring
    weights per check type — the real, honest version of "self-learning":
    the system improves from recorded outcomes, not from an unexplained
    black box.
    """
    __tablename__ = 'scan_feedback'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False, index=True)
    finding_index = db.Column(db.Integer, nullable=False)  # position within Scan.findings
    check_name = db.Column(db.String(255), nullable=False, index=True)

    is_true_positive = db.Column(db.Boolean, nullable=False)
    notes = db.Column(db.Text)

    submitted_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'finding_index': self.finding_index,
            'check_name': self.check_name,
            'is_true_positive': self.is_true_positive,
            'notes': self.notes,
            'created_at': self.created_at.isoformat()
        }


class RemediationAction(db.Model):
    """
    One remediation suggestion tied to a specific scan finding, tracked
    through an approval workflow: pending -> approved/rejected -> applied.
    This is intentionally guidance-and-approval only. Nothing in this
    codebase applies these actions to live infrastructure automatically —
    "applied" is a status you set after you've made the change yourself.
    Automating actual infrastructure changes is a distinct, higher-risk
    project that needs its own careful scoping before being built.
    """
    __tablename__ = 'remediation_actions'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False, index=True)
    finding_index = db.Column(db.Integer, nullable=False)
    check_name = db.Column(db.String(255), nullable=False, index=True)
    severity = db.Column(db.String(20))

    suggested_action = db.Column(db.Text, nullable=False)
    owasp_category = db.Column(db.String(100))

    status = db.Column(db.String(20), nullable=False, default='pending', index=True)
    # pending | approved | rejected | applied

    reviewed_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    reviewed_at = db.Column(db.DateTime)
    review_notes = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'finding_index': self.finding_index,
            'check_name': self.check_name,
            'severity': self.severity,
            'suggested_action': self.suggested_action,
            'owasp_category': self.owasp_category,
            'status': self.status,
            'reviewed_by_user_id': self.reviewed_by_user_id,
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None,
            'review_notes': self.review_notes,
            'created_at': self.created_at.isoformat()
        }


class SystemHealth(db.Model):
    """
    System health snapshots for monitoring
    """
    __tablename__ = 'system_health'
    
    id = db.Column(db.Integer, primary_key=True)
    
    component = db.Column(db.String(50), nullable=False)  # 'api', 'db', 'redis', 'ollama', 'celery'
    status = db.Column(db.String(20), nullable=False)  # 'up', 'down', 'degraded'
    
    details = db.Column(db.JSON)
    response_time_ms = db.Column(db.Integer)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

class TransactionStatus(enum.Enum):
    PENDING = 'pending'
    COMPLETED = 'completed'
    FAILED = 'failed'
    REFUNDED = 'refunded'

class Transaction(db.Model):
    __tablename__ = 'transactions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    invoice_number = db.Column(db.String(64), unique=True, nullable=False, index=True)
    plan_type = db.Column(db.Enum(PlanType), nullable=False)
    amount_cents = db.Column(db.Integer, nullable=False)
    currency = db.Column(db.String(3), default='USD')
    payment_method = db.Column(db.String(50), default='card')
    status = db.Column(db.Enum(TransactionStatus), default=TransactionStatus.PENDING, nullable=False)
    gateway_reference = db.Column(db.String(255))
    discount_applied = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship('User', backref=db.backref('transactions', lazy='dynamic'))

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'invoice_number': self.invoice_number,
            'plan_type': self.plan_type.value,
            'amount_usd': self.amount_cents / 100.0,
            'currency': self.currency,
            'payment_method': self.payment_method,
            'status': self.status.value,
            'gateway_reference': self.gateway_reference,
            'discount_applied': self.discount_applied,
            'created_at': self.created_at.isoformat()
        }

