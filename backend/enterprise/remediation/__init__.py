"""
AI-Suggested Fixes Module
==========================

AI-powered remediation guidance WITHOUT automated enforcement.

Provides:
- Suggested fixes per finding
- Copy-ready remediation steps
- Code examples and configuration samples
- "Recommended Action" section for reports

CRITICAL:
- NO auto-apply fixes
- NO changes to customer infrastructure
- Suggestions ONLY

Trust > automation.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class RemediationGuide:
    """
    Remediation guidance database with code examples.
    """
    
    # Remediation templates by vulnerability type
    REMEDIATION_TEMPLATES = {
        'sql_injection': {
            'title': 'SQL Injection Remediation',
            'priority': 'critical',
            'steps': [
                'Use parameterized queries or prepared statements',
                'Implement input validation and sanitization',
                'Apply principle of least privilege to database accounts',
                'Enable query logging and monitoring'
            ],
            'code_examples': {
                'python': '''# Before (Vulnerable)
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# After (Secure)
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))''',
                'node': '''// Before (Vulnerable)
const query = `SELECT * FROM users WHERE id = ${userId}`;
connection.query(query);

// After (Secure)
const query = 'SELECT * FROM users WHERE id = ?';
connection.query(query, [userId]);''',
                'php': '''// Before (Vulnerable)
$query = "SELECT * FROM users WHERE id = $user_id";
mysqli_query($conn, $query);

// After (Secure)
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();'''
            },
            'verification': [
                'Test with common SQL injection payloads',
                'Review database query logs',
                'Run automated security scanner',
                'Verify parameterized queries are used consistently'
            ]
        },
        
        'xss': {
            'title': 'Cross-Site Scripting (XSS) Remediation',
            'priority': 'high',
            'steps': [
                'Encode all user-generated content before output',
                'Implement Content Security Policy (CSP) headers',
                'Use modern frameworks with built-in XSS protection',
                'Validate and sanitize input on both client and server'
            ],
            'code_examples': {
                'python': '''# Using Flask/Jinja2 (automatic escaping)
from markupsafe import escape

# Before (Vulnerable)
return f"<div>{user_input}</div>"

# After (Secure)
return f"<div>{escape(user_input)}</div>"

# Or use Jinja2 templates (auto-escaping enabled by default)
return render_template('page.html', content=user_input)''',
                'node': '''// Using Express + EJS/Pug
const DOMPurify = require('isomorphic-dompurify');

// Before (Vulnerable)
res.send(`<div>${userInput}</div>`);

// After (Secure)
const clean = DOMPurify.sanitize(userInput);
res.send(`<div>${clean}</div>`);''',
                'headers': '''# Content Security Policy Header
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:'''
            },
            'verification': [
                'Test with XSS payloads (e.g., <script>alert(1)</script>)',
                'Verify CSP headers are set',
                'Check that user input is properly escaped',
                'Review JavaScript event handlers'
            ]
        },
        
        'authentication_bypass': {
            'title': 'Authentication Bypass Remediation',
            'priority': 'critical',
            'steps': [
                'Implement multi-factor authentication (MFA)',
                'Use strong password policies',
                'Implement account lockout after failed attempts',
                'Use secure session management',
                'Never trust client-side authentication checks'
            ],
            'code_examples': {
                'python': '''# Flask example with secure authentication
from flask_login import login_required, current_user
from werkzeug.security import check_password_hash

@app.route('/protected')
@login_required  # Server-side auth check
def protected_route():
    if not current_user.is_authenticated:
        return abort(401)
    return render_template('protected.html')

# Password verification
def verify_password(stored_hash, password):
    return check_password_hash(stored_hash, password)''',
                'node': '''// Express example with JWT
const jwt = require('jsonwebtoken');

// Middleware for authentication
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) return res.sendStatus(401);
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Protected route
app.get('/protected', authenticateToken, (req, res) => {
    res.json({ data: 'Protected data' });
});'''
            },
            'verification': [
                'Test authentication bypass techniques',
                'Verify MFA is enforced for sensitive operations',
                'Check session timeout configurations',
                'Review authentication logs'
            ]
        },
        
        'weak_crypto': {
            'title': 'Weak Cryptography Remediation',
            'priority': 'high',
            'steps': [
                'Use TLS 1.2 or higher for all communications',
                'Implement strong cipher suites',
                'Use bcrypt/Argon2 for password hashing',
                'Rotate encryption keys regularly'
            ],
            'code_examples': {
                'python': '''# Secure password hashing with bcrypt
import bcrypt

# Hash password
password = b"user_password"
salt = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(password, salt)

# Verify password
if bcrypt.checkpw(password, hashed):
    print("Password matches")

# Secure data encryption (AES)
from cryptography.fernet import Fernet

key = Fernet.generate_key()
f = Fernet(key)
encrypted = f.encrypt(b"sensitive data")
decrypted = f.decrypt(encrypted)''',
                'nginx': '''# Nginx TLS configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256';
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;'''
            },
            'verification': [
                'Run SSL/TLS scanner (e.g., testssl.sh)',
                'Verify cipher suite configurations',
                'Check password hashing algorithms',
                'Review key management practices'
            ]
        },
        
        'broken_access_control': {
            'title': 'Broken Access Control Remediation',
            'priority': 'high',
            'steps': [
                'Implement role-based access control (RBAC)',
                'Validate authorization on every request',
                'Use indirect object references',
                'Log all access control failures'
            ],
            'code_examples': {
                'python': '''# Flask example with RBAC
from functools import wraps
from flask_login import current_user

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return abort(401)
            if not current_user.has_role(role):
                return abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/admin/users')
@role_required('admin')  # Check authorization
def admin_users():
    return render_template('admin_users.html')

# Resource ownership check
@app.route('/documents/<int:doc_id>')
@login_required
def view_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if doc.owner_id != current_user.id and not current_user.is_admin:
        abort(403)  # Not authorized
    return render_template('document.html', doc=doc)'''
            },
            'verification': [
                'Test horizontal privilege escalation',
                'Test vertical privilege escalation',
                'Verify RBAC implementation',
                'Review access control logs'
            ]
        },
        
        'security_misconfiguration': {
            'title': 'Security Misconfiguration Remediation',
            'priority': 'medium',
            'steps': [
                'Disable default accounts and credentials',
                'Remove unnecessary features and services',
                'Implement security headers',
                'Keep all software up to date'
            ],
            'code_examples': {
                'python': '''# Flask security headers
from flask import Flask

app = Flask(__name__)

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response''',
                'nginx': '''# Nginx security configuration
# Hide version
server_tokens off;

# Security headers
add_header X-Frame-Options "DENY";
add_header X-Content-Type-Options "nosniff";
add_header X-XSS-Protection "1; mode=block";
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'''
            },
            'verification': [
                'Run security scanner for misconfigurations',
                'Verify security headers are set',
                'Check for default credentials',
                'Review enabled services and features'
            ]
        },
        
        'missing_rate_limiting': {
            'title': 'Rate Limiting Implementation',
            'priority': 'medium',
            'steps': [
                'Implement rate limiting on authentication endpoints',
                'Add IP-based rate limiting',
                'Monitor for brute force attempts',
                'Implement CAPTCHA for repeated failures'
            ],
            'code_examples': {
                'python': '''# Flask-Limiter example
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per hour"]
)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")  # Strict rate limit for login
def login():
    # Authentication logic
    pass

@app.route('/api/data')
@limiter.limit("100 per hour")
def get_data():
    # Data retrieval logic
    pass''',
                'nginx': '''# Nginx rate limiting
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=api:10m rate=100r/h;

location /api/login {
    limit_req zone=login burst=2 nodelay;
    proxy_pass http://backend;
}

location /api/ {
    limit_req zone=api burst=20 nodelay;
    proxy_pass http://backend;
}'''
            },
            'verification': [
                'Test rate limits with automated tools',
                'Verify 429 status codes are returned',
                'Check rate limit headers',
                'Monitor rate limiting metrics'
            ]
        }
    }
    
    @classmethod
    def get_remediation(cls, vulnerability_type: str) -> Optional[Dict[str, Any]]:
        """Get remediation guide for vulnerability type"""
        vuln_key = vulnerability_type.lower().replace(' ', '_')
        return cls.REMEDIATION_TEMPLATES.get(vuln_key)


class AIRemediationAssistant:
    """
    AI-powered remediation assistant.
    Generates contextualized remediation guidance.
    """
    
    def __init__(self, ollama_client=None):
        self.ollama_client = ollama_client
        
    def generate_fix(
        self,
        finding: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate AI-powered remediation suggestion
        
        Args:
            finding: Security finding
            context: Additional context (framework, language, etc.)
            
        Returns:
            Remediation suggestion with steps and code examples
        """
        
        # Get template-based remediation first
        vuln_type = finding.get('type', '').lower().replace(' ', '_')
        template = RemediationGuide.get_remediation(vuln_type)
        
        if not template:
            template = self._default_remediation(finding)
        
        # Enhance with AI if available
        if self.ollama_client and context:
            ai_enhancement = self._generate_ai_enhancement(finding, context, template)
            if ai_enhancement:
                template['ai_suggestions'] = ai_enhancement
        
        return template
    
    def _generate_ai_enhancement(
        self,
        finding: Dict[str, Any],
        context: Dict[str, Any],
        template: Dict[str, Any]
    ) -> Optional[str]:
        """Generate AI-enhanced remediation suggestions"""
        
        try:
            prompt = f"""
You are a senior security engineer. Provide specific remediation guidance for this vulnerability.

Vulnerability: {finding.get('title', 'Unknown')}
Description: {finding.get('description', 'No description')}
Severity: {finding.get('severity', 'medium')}
Context: {context.get('framework', 'Unknown')} framework, {context.get('language', 'Unknown')} language

Based on the standard remediation steps:
{chr(10).join(f"- {step}" for step in template.get('steps', []))}

Provide 2-3 specific, actionable recommendations tailored to this context.
Keep each recommendation concise (1-2 sentences).
"""
            
            response = self.ollama_client.generate(
                prompt=prompt,
                model=self.ollama_client.default_model
            )
            
            return response if response else None
            
        except Exception as e:
            logger.error(f"AI remediation generation failed: {e}")
            return None
    
    def _default_remediation(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Default remediation for unknown vulnerability types"""
        return {
            'title': f"Remediation for {finding.get('title', 'Unknown Vulnerability')}",
            'priority': finding.get('severity', 'medium'),
            'steps': [
                'Review security best practices for this vulnerability type',
                'Consult vendor documentation and security advisories',
                'Apply security patches and updates',
                'Implement defense-in-depth controls',
                'Test fixes in staging environment before production'
            ],
            'code_examples': {},
            'verification': [
                'Re-run security scanner after remediation',
                'Verify vulnerability is no longer present',
                'Document remediation steps taken'
            ]
        }


def generate_remediation_report(findings: List[Dict[str, Any]], ollama_client=None) -> Dict[str, Any]:
    """
    Generate comprehensive remediation report
    
    Args:
        findings: List of security findings
        ollama_client: Ollama client for AI enhancements (optional)
        
    Returns:
        Remediation report with prioritized actions
    """
    
    assistant = AIRemediationAssistant(ollama_client)
    
    remediation_items = []
    
    # Sort findings by severity
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    sorted_findings = sorted(
        findings,
        key=lambda x: severity_order.get(x.get('severity', 'medium').lower(), 5)
    )
    
    for finding in sorted_findings:
        remediation = assistant.generate_fix(finding)
        remediation_items.append({
            'finding_id': finding.get('id'),
            'finding_title': finding.get('title'),
            'severity': finding.get('severity'),
            'remediation': remediation
        })
    
    return {
        'generated_at': datetime.utcnow().isoformat(),
        'total_items': len(remediation_items),
        'by_priority': {
            'critical': len([r for r in remediation_items if r['severity'] == 'critical']),
            'high': len([r for r in remediation_items if r['severity'] == 'high']),
            'medium': len([r for r in remediation_items if r['severity'] == 'medium']),
            'low': len([r for r in remediation_items if r['severity'] == 'low'])
        },
        'items': remediation_items
    }
