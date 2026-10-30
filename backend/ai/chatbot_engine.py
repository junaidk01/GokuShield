import json
from typing import Dict, Any, List, Optional

class ChatbotEngine:
    """
    Ollama-powered chatbot for GoKushield
    Integrated with security engine for intelligent assistance
    """
    
    def __init__(self, ollama_client):
        self.ollama = ollama_client
        
        self.system_prompt = """You are GokuShield AI Copilot & Customer Support Assistant, an expert in cybersecurity, API protection, and the complete GokuShield platform.

Your Platform Knowledge:
- Platform: GokuShield AI v1.0 (Audit-First Cyber Intelligence).
- Core Philosophy: Audit is always first; 100% free deep surface scan per company domain without signup or credentials. Audit reports are immutable, cryptographically sealed, and deterministic (no AI drift, no hallucinations).
- 4-Layer Defense Stack:
  1. DNS Level: 50-100ms response DDoS protection & DNS firewall, dynamic rate limiting.
  2. Server Level: Automated daily CVE vulnerability scans, sandbox patch testing, zero-downtime rolling updates, auto-rollback.
  3. Database Level: 99.7% SQL injection prevention, <5ms query analysis, context-aware data loss prevention, sensitive data classification.
  4. Application/API Level: 10-minute auto-discovery, AI WAF, adaptive request throttling, 85-95% zero-day threat detection.
- Subscriptions & Services:
  * Audit Tier ($0 one-time): Full domain surface scan, 0-100 risk score, explainable causes, read-only dashboard.
  * Starter Plan ($19/month): Up to 10 APIs, 50,000 requests/month, basic threat detection, email support.
  * Professional Plan ($59/month or $179/month): Up to 50 APIs, 500,000 requests/month, AI threat detection, custom rules, priority support, quarterly SOC 2 / ISO 27001 compliance evidence packs.
  * Enterprise Plan ($179/month API or custom $1,999/month managed): Unlimited APIs, 2M+ requests, SIEM connectors (Splunk, Datadog), dedicated account team, on-prem/air-gap deployment option.
- OWASP Top 10 API Security (2023) Guidance:
  * API1 (BOLA), API2 (Broken Auth), API3 (BOPLA), API4 (Resource Consumption), API5 (BFLA), API6 (Business Flows), API7 (SSRF), API8 (Misconfig), API9 (Improper Inventory), API10 (Unsafe Consumption).

Your Role:
- Answer client and admin queries with high precision and technical accuracy.
- Guide users on running scans, understanding audit reports, and implementing step-by-step remediation.
- Assist admins with platform health checks, outreach triggering, plan management, and audit log reviews.
- Provide friendly, concise, and structured responses with actionable bullet points.
"""
    
    def chat(self, message: str, history: List[Dict] = None, user_context: Dict = None) -> Dict[str, Any]:
        """
        Main chat interface
        """
        
        # Build conversation context
        context = self._build_context(history, user_context)
        
        prompt = f"{context}\n\nUser: {message}\n\nAssistant:"
        
        try:
            response = self.ollama.generate(
                prompt=prompt,
                system=self.system_prompt,
                model="mistral:7b"
            )
            
            if not response:
                return self._fallback_response(message)
            
            # Analyze if requires authentication
            requires_auth = any(word in message.lower() for word in ['scan', 'my', 'account', 'usage', 'history'])
            
            # Generate suggestions
            suggestions = self._generate_suggestions(message, response)
            
            return {
                'message': response,
                'suggestions': suggestions,
                'requires_auth': requires_auth and not user_context
            }
            
        except Exception as e:
            print(f"Chatbot error: {str(e)}")
            return self._fallback_response(message)
    
    def _build_context(self, history: List[Dict], user_context: Dict) -> str:
        """Build conversation context"""
        context_parts = []
        
        if user_context:
            context_parts.append(f"User Plan: {user_context.get('plan', 'Free')}")
        
        if history:
            for msg in history[-5:]:  # Last 5 messages
                role = msg.get('role', 'user')
                content = msg.get('content', '')
                context_parts.append(f"{role.capitalize()}: {content}")
        
        return "\n".join(context_parts)
    
    def _generate_suggestions(self, message: str, response: str) -> List[str]:
        """Generate conversation suggestions"""
        message_lower = message.lower()
        
        if 'scan' in message_lower:
            return [
                "What types of scans do you offer?",
                "How long does a scan take?",
                "Run a security scan"
            ]
        elif 'vulnerability' in message_lower or 'security' in message_lower:
            return [
                "What is OWASP Top 10?",
                "How do I fix this vulnerability?",
                "Show me scan results"
            ]
        elif 'price' in message_lower or 'plan' in message_lower:
            return [
                "Compare pricing plans",
                "What's included in Professional?",
                "Upgrade my plan"
            ]
        else:
            return [
                "What can you help me with?",
                "Run a security scan",
                "Explain API security"
            ]
    
    def _fallback_response(self, message: str) -> Dict[str, Any]:
        """Intelligent, high-reliability fallback when Ollama is offline or cold-starting"""
        msg = message.lower()
        
        if any(w in msg for w in ['price', 'pricing', 'plan', 'cost', 'subscription', 'upgrade']):
            reply = (
                "**GokuShield AI Subscription Plans:**\n\n"
                "1. **Free Security Audit ($0)**: 1 free, deep surface scan per domain. Includes 0-100 risk score and explainable findings. No signup or credit card required.\n"
                "2. **Starter ($19/mo)**: Up to 10 APIs, 50K requests/mo, automated threat detection, and email support.\n"
                "3. **Professional ($59/mo or $179/mo)**: Up to 50 APIs, 500K requests/mo, AI threat detection, custom security rules, and quarterly compliance reports (SOC 2, ISO 27001).\n"
                "4. **Enterprise ($179/mo API or custom managed $1,999/mo)**: Unlimited APIs, 2M+ requests, SIEM connectors (Splunk/Datadog), dedicated team, and on-prem/air-gap options.\n\n"
                "*First 100 users receive 10% off on all paid plans!*"
            )
            sugg = ["Start Free Audit", "View Professional Plan", "Contact Sales"]
        elif any(w in msg for w in ['audit', 'scan', 'test', 'vulnerability']):
            reply = (
                "**GokuShield Audit-First Security:**\n\n"
                "- **Free Initial Audit**: Enter your company domain on the homepage to start an instant, non-intrusive security audit.\n"
                "- **Checks Covered**: Open ports, security headers, SSL/TLS weaknesses, sensitive file exposures, and OWASP API Top 10 vulnerabilities.\n"
                "- **Immutable Results**: Your audit is timestamped, sealed, and accessible via a secure email link.\n"
                "- **No Login Required**: Instant value before any commitment."
            )
            sugg = ["Run Free Audit", "Explain OWASP API Top 10", "Download Report"]
        elif any(w in msg for w in ['owasp', 'injection', 'bola', 'csrf', 'xss', 'ssrf']):
            reply = (
                "**OWASP API Security Top 10 Remediation Guidance:**\n\n"
                "- **API1 (BOLA)**: Enforce user-level authorization checks at every object query level.\n"
                "- **API2 (Broken Authentication)**: Implement rate-limiting on token endpoints and enforce strong JWT rotation.\n"
                "- **API3 (BOPLA)**: Validate input schemas and restrict mass assignment on sensitive endpoints.\n"
                "- **API4 (Resource Consumption)**: Enforce adaptive rate limits, memory/CPU quotas, and pagination limits.\n"
                "- **API8 (Security Misconfiguration)**: Disable verbose stack traces, enforce TLS 1.3, and set strict CSP/CORS headers."
            )
            sugg = ["How to fix BOLA", "Configure Rate Limiting", "Review Scan Findings"]
        elif any(w in msg for w in ['support', 'help', 'contact', 'customer']):
            reply = (
                "**GokuShield 24/7 Customer Support:**\n\n"
                "- **Email Support**: support@gokushield.com\n"
                "- **Admin Contact**: admin@gokushield.com\n"
                "- **Response Times**: Critical alerts: <1 min | High: <5 min | Standard queries: <10 min.\n"
                "- **Dashboard Help**: Check your Client Dashboard under 'Audit Report' for complete remediation instructions."
            )
            sugg = ["Check System Health", "Reset Password", "Contact Support"]
        elif any(w in msg for w in ['admin', 'mfa', 'health', 'outreach', 'log']):
            reply = (
                "**Admin Copilot Assistance:**\n\n"
                "- **System Health**: Verify status of Backend API, Ollama Engine, PostgreSQL, and Redis.\n"
                "- **Audit Logs**: All administrative actions are recorded in the immutable Audit Log UI.\n"
                "- **Outreach Engine**: Automated email campaigns (welcome, audit reports, follow-ups, and cold outreach) can be triggered from the Outreach section.\n"
                "- **Remediation Review**: Approve or inspect suggested fixes in the Remediations queue."
            )
            sugg = ["System Health", "Audit Logs", "Trigger Outreach"]
        else:
            reply = (
                "Welcome to **GokuShield AI** - the Audit-First Cyber Intelligence platform.\n\n"
                "I can assist you with:\n"
                "• Explaining our 4-layer defense architecture (DNS, Server, Database, Application)\n"
                "• Detailing subscription plans and pricing options\n"
                "• Guiding you through free domain security audits and remediation\n"
                "• Troubleshooting customer queries and platform diagnostics\n\n"
                "What would you like assistance with today?"
            )
            sugg = ["Explain Subscription Plans", "How does Free Audit work?", "View 4-Layer Defense"]
            
        return {
            'message': reply,
            'suggestions': sugg,
            'requires_auth': False
        }
    
    def explain_scan_results(self, scan_data: Dict[str, Any]) -> str:
        """Explain scan results in plain language"""
        
        prompt = f"""Explain these security scan results to a non-technical user:

Service: {scan_data.get('service_id', 'Unknown')}
Risk Score: {scan_data.get('risk_score', 0)}/100
Findings: {len(scan_data.get('findings', []))} issues found

Key Issues:
{json.dumps(scan_data.get('findings', [])[:3], indent=2)}

Provide:
1. What these findings mean in simple terms
2. Why they matter for business security
3. Top 3 priority actions to take

Keep it under 150 words, use simple language."""

        try:
            response = self.ollama.generate(
                prompt=prompt,
                system="You are a cybersecurity educator explaining technical findings to business users.",
                model="mistral:7b"
            )
            
            return response if response else self._fallback_explanation(scan_data)
        except:
            return self._fallback_explanation(scan_data)
    
    def _fallback_explanation(self, scan_data: Dict) -> str:
        """Fallback explanation"""
        risk = scan_data.get('risk_score', 0)
        findings_count = len(scan_data.get('findings', []))
        
        risk_level = "High" if risk > 70 else "Medium" if risk > 40 else "Low"
        
        return f"""**Security Assessment Summary**

Your API has a **{risk_level}** risk level (score: {risk}/100) with {findings_count} findings.

**What this means:**
- {findings_count} potential security issues were detected
- Some may require immediate attention
- Others are recommendations for improvement

**Recommended Actions:**
1. Review all critical and high-severity findings first
2. Implement suggested fixes systematically
3. Re-scan after remediation to verify improvements

For detailed technical information, review the full scan report."""
    
    def get_security_advice(self, question: str) -> str:
        """Get general security advice"""
        
        prompt = f"""User question about API security: {question}

Provide practical, actionable advice in under 100 words."""

        try:
            response = self.ollama.generate(
                prompt=prompt,
                system="You are an API security expert providing practical advice.",
                model="mistral:7b"
            )
            
            return response if response else self._fallback_advice()
        except:
            return self._fallback_advice()
    
    def _fallback_advice(self) -> str:
        """Fallback security advice"""
        return """**General API Security Best Practices:**

1. **Authentication**: Always use strong authentication (OAuth 2.0, API keys)
2. **Rate Limiting**: Prevent abuse with request throttling
3. **Input Validation**: Validate and sanitize all inputs
4. **HTTPS Only**: Encrypt all data in transit
5. **Regular Scans**: Test security continuously

For specific advice, try running a security scan!"""
