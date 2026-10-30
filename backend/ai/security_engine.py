import requests
from typing import Dict, Any, Optional
from datetime import datetime
import json
import logging

logger = logging.getLogger(__name__)

class OllamaClient:
    def __init__(self, base_url: str, default_model: str, timeout: int = 120):
        self.base_url = base_url.rstrip('/')
        self.default_model = default_model
        self.timeout = timeout
    
    def is_available(self) -> bool:
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def generate(self, prompt: str, model: Optional[str] = None, system: Optional[str] = None) -> Optional[str]:
        model = model or self.default_model
        
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False
        }
        
        if system:
            payload["system"] = system
        
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json().get('response', '')
            return None
        except Exception as e:
            print(f"Ollama generate error: {str(e)}")
            return None
    
    def embed(self, text: str, model: str = "nomic-embed-text") -> Optional[list]:
        try:
            response = requests.post(
                f"{self.base_url}/api/embeddings",
                json={"model": model, "prompt": text},
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json().get('embedding', [])
            return None
        except Exception as e:
            print(f"Ollama embed error: {str(e)}")
            return None

class SecurityEngine:
    def __init__(self, ollama_client: OllamaClient):
        self.ollama = ollama_client
    
    def analyze_security_findings(self, 
                                  service_name: str,
                                  findings: Dict[str, Any],
                                  context: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze security findings using Ollama AI
        """
        
        system_prompt = """You are an expert cybersecurity analyst specializing in API security and threat detection.
Analyze the provided security findings and return a JSON response with:
1. risk_score (0-100): Overall security risk level
2. confidence_score (0-100): Confidence in the analysis
3. analysis: Executive summary in 2-3 sentences
4. technical_summary: Detailed technical analysis
5. top_findings: Array of top 3 critical findings
6. recommendations: Array of specific remediation steps

Be concise, actionable, and focus on the most critical issues."""

        prompt = f"""Service: {service_name}
Target: {findings.get('target', 'Unknown')}

Security Scan Results:
{json.dumps(findings, indent=2)}

{f"Additional Context: {context}" if context else ""}

Provide security analysis in JSON format."""

        try:
            response = self.ollama.generate(
                prompt=prompt,
                system=system_prompt,
                model="mistral:7b"
            )
            
            if not response:
                raise RuntimeError('Ollama returned empty response')
            
            # Response is a string, not a dict
            response_text = response if isinstance(response, str) else str(response)
            
            # Try to parse JSON from response
            try:
                # Extract JSON from markdown code blocks if present
                if "```json" in response_text:
                    json_str = response_text.split("```json")[1].split("```")[0].strip()
                elif "```" in response_text:
                    json_str = response_text.split("```")[1].split("```")[0].strip()
                else:
                    json_str = response_text.strip()
                
                analysis = json.loads(json_str)
                
                # Ensure all required fields
                return {
                    'risk_score': min(100, max(0, analysis.get('risk_score', 50))),
                    'confidence_score': min(100, max(0, analysis.get('confidence_score', 70))),
                    'analysis': analysis.get('analysis', 'Security analysis completed'),
                    'technical_summary': analysis.get('technical_summary', ''),
                    'top_findings': analysis.get('top_findings', [])[:3],
                    'recommendations': analysis.get('recommendations', [])
                }
            except json.JSONDecodeError:
                # If JSON parsing fails, extract key information
                return self._parse_text_response(response_text, findings)
                
        except Exception as e:
            logger.error(f"AI analysis error: {str(e)}")
            raise RuntimeError(f'AI analysis failed: {str(e)}')
    
    def _parse_text_response(self, response: str, findings: Dict) -> Dict[str, Any]:
        """Parse text response when JSON parsing fails"""
        lines = response.split('\n')
        
        risk_score = 50
        confidence_score = 70
        
        # Try to extract scores from text
        for line in lines:
            if 'risk' in line.lower() and any(char.isdigit() for char in line):
                nums = [int(s) for s in line.split() if s.isdigit()]
                if nums:
                    risk_score = min(100, max(0, nums[0]))
            if 'confidence' in line.lower() and any(char.isdigit() for char in line):
                nums = [int(s) for s in line.split() if s.isdigit()]
                if nums:
                    confidence_score = min(100, max(0, nums[0]))
        
        return {
            'risk_score': risk_score,
            'confidence_score': confidence_score,
            'analysis': response[:300] if len(response) > 300 else response,
            'technical_summary': response,
            'top_findings': findings.get('vulnerabilities', [])[:3],
            'recommendations': ['Review security findings', 'Implement recommended fixes', 'Re-scan after remediation']
        }
    
    def _fallback_analysis(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback analysis when AI is unavailable"""
        
        vuln_count = len(findings.get('vulnerabilities', []))
        critical_count = sum(1 for v in findings.get('vulnerabilities', []) 
                           if v.get('severity') in ['critical', 'high'])
        
        risk_score = min(100, critical_count * 20 + vuln_count * 5)
        
        return {
            'risk_score': risk_score,
            'confidence_score': 60,
            'analysis': f"Found {vuln_count} security issues ({critical_count} critical). Immediate attention required for high-severity vulnerabilities.",
            'technical_summary': f"Automated scan detected {vuln_count} vulnerabilities. AI analysis unavailable - using rule-based assessment.",
            'top_findings': findings.get('vulnerabilities', [])[:3],
            'recommendations': [
                'Address critical vulnerabilities immediately',
                'Review all security findings',
                'Implement security best practices',
                'Schedule follow-up scan'
            ]
        }
    
    def generate_report(self, scan_data: Dict[str, Any]) -> str:
        """Generate executive report using AI"""
        
        system_prompt = "You are a cybersecurity report writer. Create concise, executive-level security reports."
        
        prompt = f"""Generate an executive security report based on:

Service: {scan_data.get('service', 'Unknown')}
Target: {scan_data.get('target', 'Unknown')}
Risk Score: {scan_data.get('risk_score', 0)}/100
Findings: {len(scan_data.get('findings', []))}

Key Issues:
{json.dumps(scan_data.get('findings', [])[:5], indent=2)}

Create a brief executive summary (3-4 paragraphs) covering:
1. Overall security posture
2. Critical concerns
3. Business impact
4. Immediate action items"""

        try:
            response = self.ollama.generate(prompt=prompt, system=system_prompt)
            return response if response else "Report generation unavailable. Please review findings manually."
        except:
            return "Report generation unavailable. Please review findings manually."
