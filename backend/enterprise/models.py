"""
Enterprise Model Extensions
===========================

Additional models to support enterprise features:
- Notification preferences
- Notification logs
- SIEM event logs
- Compliance tracking
"""

from models import db
from datetime import datetime


class NotificationPreference(db.Model):
    """User notification preferences"""
    __tablename__ = 'notification_preferences'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Channel preferences
    whatsapp_enabled = db.Column(db.Boolean, default=False)
    whatsapp_number = db.Column(db.String(20))
    sms_enabled = db.Column(db.Boolean, default=False)
    sms_number = db.Column(db.String(20))
    email_enabled = db.Column(db.Boolean, default=True)
    
    # Event preferences
    notify_scan_completed = db.Column(db.Boolean, default=True)
    notify_critical_vulnerability = db.Column(db.Boolean, default=True)
    notify_compliance_failure = db.Column(db.Boolean, default=True)
    notify_domain_abuse = db.Column(db.Boolean, default=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'channels': {
                'whatsapp': {
                    'enabled': self.whatsapp_enabled,
                    'number': self.whatsapp_number
                },
                'sms': {
                    'enabled': self.sms_enabled,
                    'number': self.sms_number
                },
                'email': {
                    'enabled': self.email_enabled
                }
            },
            'events': {
                'scan_completed': self.notify_scan_completed,
                'critical_vulnerability': self.notify_critical_vulnerability,
                'compliance_failure': self.notify_compliance_failure,
                'domain_abuse': self.notify_domain_abuse
            }
        }


class NotificationLog(db.Model):
    """Notification delivery logs"""
    __tablename__ = 'notification_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    channel = db.Column(db.String(20), nullable=False)  # whatsapp, sms, email
    recipient = db.Column(db.String(255), nullable=False)
    event = db.Column(db.String(50), nullable=False)
    
    success = db.Column(db.Boolean, default=False)
    error_message = db.Column(db.Text)
    
    metadata = db.Column(db.JSON)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'channel': self.channel,
            'recipient': self.recipient,
            'event': self.event,
            'success': self.success,
            'error_message': self.error_message,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class SIEMEvent(db.Model):
    """SIEM event logs for federation"""
    __tablename__ = 'siem_events'
    
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    source = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)  # authentication, vulnerability, etc.
    severity = db.Column(db.String(20), nullable=False)  # info, low, medium, high, critical
    
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    
    metadata = db.Column(db.JSON)
    
    # CEF and LEEF formats for SIEM export
    cef_format = db.Column(db.Text)
    leef_format = db.Column(db.Text)
    
    # Forwarding status
    forwarded = db.Column(db.Boolean, default=False)
    forwarded_at = db.Column(db.DateTime)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source': self.source,
            'category': self.category,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'metadata': self.metadata
        }


class ComplianceSnapshot(db.Model):
    """Compliance status snapshots"""
    __tablename__ = 'compliance_snapshots'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    
    framework = db.Column(db.String(50), nullable=False)  # soc2, iso27001, pci_dss
    overall_status = db.Column(db.String(20), nullable=False)  # pass, attention, risk
    
    total_findings = db.Column(db.Integer, default=0)
    controls_affected = db.Column(db.Integer, default=0)
    critical_findings = db.Column(db.Integer, default=0)
    high_findings = db.Column(db.Integer, default=0)
    
    compliance_percentage = db.Column(db.Float)
    
    control_violations = db.Column(db.JSON)
    evidence_checklist = db.Column(db.JSON)
    recommendations = db.Column(db.JSON)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'framework': self.framework,
            'overall_status': self.overall_status,
            'summary': {
                'total_findings': self.total_findings,
                'controls_affected': self.controls_affected,
                'critical_findings': self.critical_findings,
                'high_findings': self.high_findings,
                'compliance_percentage': self.compliance_percentage
            },
            'control_violations': self.control_violations,
            'evidence_checklist': self.evidence_checklist,
            'recommendations': self.recommendations,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class SecurityPostureHistory(db.Model):
    """Security posture score history"""
    __tablename__ = 'security_posture_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'))
    
    score = db.Column(db.Integer, nullable=False)  # 0-100
    grade = db.Column(db.String(2), nullable=False)  # A-F
    status = db.Column(db.String(20), nullable=False)  # excellent, good, fair, poor, critical
    
    total_findings = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'scan_id': self.scan_id,
            'score': self.score,
            'grade': self.grade,
            'status': self.status,
            'findings': {
                'total': self.total_findings,
                'critical': self.critical_count,
                'high': self.high_count,
                'medium': self.medium_count,
                'low': self.low_count
            },
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class RemediationTracking(db.Model):
    """Track remediation progress for findings"""
    __tablename__ = 'remediation_tracking'
    
    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.Integer, nullable=False)  # Reference to finding
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    status = db.Column(db.String(20), default='open')  # open, in_progress, resolved, wont_fix
    priority = db.Column(db.String(20))  # critical, high, medium, low
    
    assigned_to = db.Column(db.String(255))
    due_date = db.Column(db.DateTime)
    
    remediation_steps = db.Column(db.JSON)  # AI-suggested steps
    actual_fix = db.Column(db.Text)  # What was actually done
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    
    def to_dict(self):
        return {
            'id': self.id,
            'finding_id': self.finding_id,
            'user_id': self.user_id,
            'status': self.status,
            'priority': self.priority,
            'assigned_to': self.assigned_to,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'remediation_steps': self.remediation_steps,
            'actual_fix': self.actual_fix,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None
        }


# Migration helper function
def create_enterprise_tables():
    """Create enterprise tables if they don't exist"""
    try:
        db.create_all()
        print("Enterprise tables created successfully")
        return True
    except Exception as e:
        print(f"Error creating enterprise tables: {e}")
        return False
