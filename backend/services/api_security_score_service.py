"""
API Security Score Assessment Service Module
GoKushield AI v1.0
"""

from typing import Dict, List, Any
from datetime import datetime
import json
import requests
from urllib.parse import urlparse
import logging
from services.base_scanner import BaseSecurityScanner

logger = logging.getLogger(__name__)

class ApiSecurityScoreService(BaseSecurityScanner):
    """
    Instant security assessment of domain or API endpoint with comprehensive vulnerability analysis
    """
    
    def __init__(self, ollama_client=None):
        self.ollama_client = ollama_client
        self.service_id = "api_security_score"
        self.name = "API Security Score Assessment"
    
    def scan(self, target: str, options: Dict = None) -> Dict[str, Any]:
        """
        Execute API Security Score Assessment scan
        
        Args:
            target: Target URL or domain
            options: Additional scan options
        
        Returns:
            Scan results with AI analysis
        """
        logger.info(f"Starting API Security Score Assessment scan for {target}")
        
        try:
            # Step 1: Perform technical scan
            scan_data = self._perform_scan(target, options or {})
            
            # Step 2: AI analysis (OLLAMA MANDATORY)

            
            if not self.ollama_client:

            
                raise RuntimeError('Ollama client not configured')

            
            

            
            if not self.ollama_client.is_available():

            
                raise RuntimeError('Ollama AI service unavailable - cannot proceed without AI analysis')

            
            

            
            ai_analysis = self._ai_analyze(target, scan_data)
            
            # Step 3: Generate results
            results = self._format_results(target, scan_data, ai_analysis)
            
            logger.info(f"API Security Score Assessment scan completed for {target}")
            return results
            
        except Exception as e:
            logger.error(f"Scan error: {str(e)}")
            return {
                'error': True,
                'message': f'Scan failed: {str(e)}',
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _perform_scan(self, target: str, options: Dict) -> Dict:
        """Perform technical security scan"""
        scan_data = {
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'checks': []
        }
        
        try:
            parsed = urlparse(target if target.startswith('http') else f'http://{target}')
            base_url = f'{parsed.scheme}://{parsed.netloc}'
            
            # 
            # API security score assessment
            checks = [
                self._check_ssl_configuration(base_url),
                self._check_security_headers(base_url),
                self._check_api_authentication(base_url),
                self._check_api_versioning(base_url),
                self._check_error_handling(base_url)
            ]
            scan_data['checks'] = checks

            
        except Exception as e:
            logger.error(f"Scan execution error: {str(e)}")
            scan_data['error'] = str(e)
        
        return scan_data
    
    def _ai_analyze(self, target: str, scan_data: Dict) -> Dict:
        """AI-powered analysis using Ollama"""
        prompt = f"""
You are a cybersecurity expert analyzing API security for API Security Score Assessment.

Target: {target}
Service: API Security Score Assessment
Description: Produces a single risk score for this endpoint from the combined OWASP API Top 10 checks below.

This analysis should be grounded in the OWASP API Security Top 10 (2023) where relevant:
API1 Broken Object Level Authorization, API2 Broken Authentication, API3 Broken Object Property
Level Authorization, API4 Unrestricted Resource Consumption, API5 Broken Function Level
Authorization, API6 Unrestricted Access to Sensitive Business Flows, API7 Server Side Request
Forgery, API8 Security Misconfiguration, API9 Improper Inventory Management, API10 Unsafe
Consumption of APIs. Cite the specific category a finding maps to when applicable.

Be honest about limitations: do not claim to detect unknown/zero-day vulnerabilities with
certainty, do not claim to "learn" or "remember" past scans unless told this scan includes
prior history, and do not overstate confidence beyond what the scan data supports.

Scan Data:
{json.dumps(scan_data, indent=2)}

Analyze the security posture and provide:
1. Risk assessment (0-100 score)
2. Confidence level (0-100)
3. Key findings with severity levels
4. Technical analysis
5. Actionable recommendations

Respond in JSON format:
{{
    "risk_score": <0-100>,
    "confidence_score": <0-100>,
    "analysis": "<detailed analysis>",
    "technical_summary": "<technical details>",
    "findings": [
        {"severity": "critical/high/medium/low", "issue": "<description>", "impact": "<impact>"}
    ],
    "recommendations": [
        {"priority": "high/medium/low", "action": "<recommendation>", "benefit": "<expected outcome>"}
    ]
}}
"""
        
        try:
            response = self.ollama_client.generate(
                prompt=prompt,
                model='mistral:7b',
                temperature=0.3,
                max_tokens=2000
            )
            
            # Parse AI response
            ai_result = json.loads(response.get('response', '{}'))
            return ai_result
            
        except Exception as e:
            logger.error(f"AI analysis error: {str(e)}")
            return self._fallback_analysis(scan_data)
    
    def _fallback_analysis(self, scan_data: Dict) -> Dict:
        """Fallback analysis when AI is unavailable"""
        issues_count = len([c for c in scan_data.get('checks', []) if c.get('status') == 'fail'])
        total_checks = len(scan_data.get('checks', []))
        
        risk_score = min(100, (issues_count / max(total_checks, 1)) * 100)
        
        return {
            'risk_score': int(risk_score),
            'confidence_score': 70,
            'analysis': f'Found {issues_count} security issues out of {total_checks} checks.',
            'technical_summary': 'Rule-based analysis (AI unavailable)',
            'findings': [
                {
                    'severity': 'high' if c.get('status') == 'fail' else 'info',
                    'issue': c.get('name', 'Security check'),
                    'impact': c.get('message', 'No details')
                }
                for c in scan_data.get('checks', [])[:10]
            ],
            'recommendations': [
                {'priority': 'high', 'action': 'Address identified security issues', 'benefit': 'Improved security posture'}
            ]
        }
    
    def _format_results(self, target: str, scan_data: Dict, ai_analysis: Dict) -> Dict:
        """Format final results"""
        return {
            'version': 'GoKushield AI v1.0',
            'service': self.name,
            'service_id': self.service_id,
            'target': target,
            'status': 'completed',
            'risk_score': ai_analysis.get('risk_score', 0),
            'confidence_score': ai_analysis.get('confidence_score', 0),
            'analysis': ai_analysis.get('analysis', ''),
            'technical_summary': ai_analysis.get('technical_summary', ''),
            'findings': ai_analysis.get('findings', []),
            'recommendations': ai_analysis.get('recommendations', []),
            'raw_scan_data': scan_data,
            'timestamp': datetime.utcnow().isoformat()
        }
