"""
Adaptive Threat Intelligence Module
====================================

Enriches security findings with:
- MITRE ATT&CK mapping
- Kill-chain tagging
- AI-powered explanations
- Contextual remediation guidance

This module enhances existing scan results WITHOUT changing scan logic.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger(__name__)


class MITREPhase(Enum):
    """MITRE ATT&CK tactics"""
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class KillChainPhase(Enum):
    """Lockheed Martin Cyber Kill Chain"""
    RECONNAISSANCE = "Reconnaissance"
    WEAPONIZATION = "Weaponization"
    DELIVERY = "Delivery"
    EXPLOITATION = "Exploitation"
    INSTALLATION = "Installation"
    COMMAND_CONTROL = "Command & Control"
    ACTIONS_ON_OBJECTIVES = "Actions on Objectives"


class ThreatIntelligence:
    """
    MITRE ATT&CK mapping database.
    Maps common vulnerabilities to attack techniques.
    """
    
    # Vulnerability pattern to MITRE ATT&CK technique mapping
    MITRE_MAPPING = {
        'sql_injection': {
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application',
            'tactic': MITREPhase.INITIAL_ACCESS,
            'description': 'Attackers may exploit SQL injection to gain unauthorized access to databases'
        },
        'xss': {
            'technique_id': 'T1189',
            'technique_name': 'Drive-by Compromise',
            'tactic': MITREPhase.INITIAL_ACCESS,
            'description': 'Cross-site scripting can be used to compromise user sessions'
        },
        'csrf': {
            'technique_id': 'T1185',
            'technique_name': 'Browser Session Hijacking',
            'tactic': MITREPhase.COLLECTION,
            'description': 'CSRF attacks can hijack authenticated user sessions'
        },
        'authentication_bypass': {
            'technique_id': 'T1078',
            'technique_name': 'Valid Accounts',
            'tactic': MITREPhase.INITIAL_ACCESS,
            'description': 'Weak authentication allows unauthorized account access'
        },
        'insecure_deserialization': {
            'technique_id': 'T1203',
            'technique_name': 'Exploitation for Client Execution',
            'tactic': MITREPhase.EXECUTION,
            'description': 'Deserialization flaws enable remote code execution'
        },
        'xxe': {
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application',
            'tactic': MITREPhase.INITIAL_ACCESS,
            'description': 'XML external entity attacks can expose sensitive data'
        },
        'ssrf': {
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application',
            'tactic': MITREPhase.INITIAL_ACCESS,
            'description': 'Server-side request forgery enables internal network reconnaissance'
        },
        'path_traversal': {
            'technique_id': 'T1083',
            'technique_name': 'File and Directory Discovery',
            'tactic': MITREPhase.DISCOVERY,
            'description': 'Path traversal allows unauthorized file system access'
        },
        'command_injection': {
            'technique_id': 'T1059',
            'technique_name': 'Command and Scripting Interpreter',
            'tactic': MITREPhase.EXECUTION,
            'description': 'Command injection enables arbitrary system command execution'
        },
        'weak_crypto': {
            'technique_id': 'T1557',
            'technique_name': 'Adversary-in-the-Middle',
            'tactic': MITREPhase.CREDENTIAL_ACCESS,
            'description': 'Weak cryptography enables man-in-the-middle attacks'
        },
        'broken_access_control': {
            'technique_id': 'T1548',
            'technique_name': 'Abuse Elevation Control Mechanism',
            'tactic': MITREPhase.PRIVILEGE_ESCALATION,
            'description': 'Broken access controls allow unauthorized privilege escalation'
        },
        'security_misconfiguration': {
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application',
            'tactic': MITREPhase.INITIAL_ACCESS,
            'description': 'Misconfigurations create attack opportunities'
        },
        'sensitive_data_exposure': {
            'technique_id': 'T1530',
            'technique_name': 'Data from Cloud Storage',
            'tactic': MITREPhase.COLLECTION,
            'description': 'Exposed sensitive data enables credential theft'
        },
        'missing_rate_limiting': {
            'technique_id': 'T1110',
            'technique_name': 'Brute Force',
            'tactic': MITREPhase.CREDENTIAL_ACCESS,
            'description': 'Missing rate limits enable brute force attacks'
        },
        'cors_misconfiguration': {
            'technique_id': 'T1185',
            'technique_name': 'Browser Session Hijacking',
            'tactic': MITREPhase.COLLECTION,
            'description': 'CORS misconfigurations allow cross-origin attacks'
        }
    }
    
    @classmethod
    def get_mitre_mapping(cls, vulnerability_type: str) -> Optional[Dict[str, Any]]:
        """Get MITRE ATT&CK mapping for vulnerability type"""
        return cls.MITRE_MAPPING.get(vulnerability_type.lower())
    
    @classmethod
    def map_to_kill_chain(cls, mitre_phase: MITREPhase) -> KillChainPhase:
        """Map MITRE tactic to Kill Chain phase"""
        mapping = {
            MITREPhase.RECONNAISSANCE: KillChainPhase.RECONNAISSANCE,
            MITREPhase.RESOURCE_DEVELOPMENT: KillChainPhase.WEAPONIZATION,
            MITREPhase.INITIAL_ACCESS: KillChainPhase.EXPLOITATION,
            MITREPhase.EXECUTION: KillChainPhase.INSTALLATION,
            MITREPhase.PERSISTENCE: KillChainPhase.INSTALLATION,
            MITREPhase.PRIVILEGE_ESCALATION: KillChainPhase.ACTIONS_ON_OBJECTIVES,
            MITREPhase.DEFENSE_EVASION: KillChainPhase.ACTIONS_ON_OBJECTIVES,
            MITREPhase.CREDENTIAL_ACCESS: KillChainPhase.ACTIONS_ON_OBJECTIVES,
            MITREPhase.DISCOVERY: KillChainPhase.RECONNAISSANCE,
            MITREPhase.LATERAL_MOVEMENT: KillChainPhase.ACTIONS_ON_OBJECTIVES,
            MITREPhase.COLLECTION: KillChainPhase.ACTIONS_ON_OBJECTIVES,
            MITREPhase.COMMAND_AND_CONTROL: KillChainPhase.COMMAND_CONTROL,
            MITREPhase.EXFILTRATION: KillChainPhase.ACTIONS_ON_OBJECTIVES,
            MITREPhase.IMPACT: KillChainPhase.ACTIONS_ON_OBJECTIVES
        }
        return mapping.get(mitre_phase, KillChainPhase.EXPLOITATION)


class ThreatExplainer:
    """
    AI-powered threat explanation engine.
    Generates human-readable explanations using Ollama.
    """
    
    def __init__(self, ollama_client=None):
        self.ollama_client = ollama_client
        
    def explain_threat(
        self,
        vulnerability_type: str,
        severity: str,
        context: Dict[str, Any]
    ) -> Dict[str, str]:
        """
        Generate AI explanation for threat
        
        Returns:
            Dictionary with:
            - why_matters: Why this vulnerability matters
            - how_exploited: How attackers exploit this
            - what_to_do: Recommended actions
        """
        
        if not self.ollama_client:
            return self._fallback_explanation(vulnerability_type, severity)
            
        try:
            prompt = f"""
You are a cybersecurity expert. Explain this vulnerability in clear, actionable terms.

Vulnerability: {vulnerability_type}
Severity: {severity}
Context: {context.get('description', 'No additional context')}

Provide a structured response:

WHY THIS MATTERS:
(Explain the business impact in 2-3 sentences)

HOW ATTACKERS EXPLOIT THIS:
(Describe the attack scenario in 2-3 sentences)

WHAT TO DO NEXT:
(Provide 3 specific remediation steps)

Keep explanations concise and focused on actionable insights.
"""
            
            response = self.ollama_client.generate(
                prompt=prompt,
                model=self.ollama_client.default_model
            )
            
            if response:
                return self._parse_ai_response(response)
            else:
                return self._fallback_explanation(vulnerability_type, severity)
                
        except Exception as e:
            logger.error(f"AI explanation failed: {e}")
            return self._fallback_explanation(vulnerability_type, severity)
    
    def _parse_ai_response(self, response: str) -> Dict[str, str]:
        """Parse structured AI response"""
        sections = {
            'why_matters': '',
            'how_exploited': '',
            'what_to_do': ''
        }
        
        lines = response.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if 'WHY THIS MATTERS' in line:
                current_section = 'why_matters'
            elif 'HOW ATTACKERS' in line:
                current_section = 'how_exploited'
            elif 'WHAT TO DO' in line:
                current_section = 'what_to_do'
            elif current_section and line:
                sections[current_section] += line + ' '
        
        # Clean up sections
        for key in sections:
            sections[key] = sections[key].strip()
            
        return sections
    
    def _fallback_explanation(self, vulnerability_type: str, severity: str) -> Dict[str, str]:
        """Fallback explanation when AI is unavailable"""
        
        explanations = {
            'sql_injection': {
                'why_matters': 'SQL injection vulnerabilities allow attackers to manipulate database queries, potentially exposing all stored data including customer information, credentials, and business-critical records.',
                'how_exploited': 'Attackers inject malicious SQL code through input fields, authentication forms, or URL parameters to bypass security controls and execute unauthorized database commands.',
                'what_to_do': '1. Implement parameterized queries/prepared statements. 2. Validate and sanitize all user inputs. 3. Apply principle of least privilege to database accounts.'
            },
            'xss': {
                'why_matters': 'Cross-site scripting enables attackers to inject malicious scripts that execute in users\' browsers, compromising sessions, stealing credentials, or spreading malware.',
                'how_exploited': 'Attackers inject JavaScript code through unvalidated input fields, which then executes when other users view the compromised page, stealing cookies or redirecting to malicious sites.',
                'what_to_do': '1. Encode all user-generated content before display. 2. Implement Content Security Policy headers. 3. Use modern frameworks with built-in XSS protection.'
            }
        }
        
        default = {
            'why_matters': f'This {severity} severity vulnerability poses significant security risks to your application and users.',
            'how_exploited': 'Attackers can exploit this weakness to compromise security controls and gain unauthorized access.',
            'what_to_do': '1. Review security best practices for this vulnerability type. 2. Apply vendor patches and updates. 3. Implement defense-in-depth controls.'
        }
        
        return explanations.get(vulnerability_type.lower(), default)


def enrich_finding(finding: Dict[str, Any], ollama_client=None) -> Dict[str, Any]:
    """
    Enrich security finding with threat intelligence
    
    Args:
        finding: Original security finding
        ollama_client: Ollama client for AI explanations (optional)
        
    Returns:
        Enriched finding with MITRE mapping and AI explanations
    """
    
    enriched = finding.copy()
    
    # Add MITRE ATT&CK mapping
    vulnerability_type = finding.get('type', '').lower().replace(' ', '_')
    mitre_data = ThreatIntelligence.get_mitre_mapping(vulnerability_type)
    
    if mitre_data:
        enriched['mitre_attack'] = {
            'technique_id': mitre_data['technique_id'],
            'technique_name': mitre_data['technique_name'],
            'tactic': mitre_data['tactic'].value,
            'description': mitre_data['description']
        }
        
        # Add kill chain mapping
        kill_chain = ThreatIntelligence.map_to_kill_chain(mitre_data['tactic'])
        enriched['kill_chain_phase'] = kill_chain.value
    
    # Add AI explanation
    explainer = ThreatExplainer(ollama_client)
    explanation = explainer.explain_threat(
        vulnerability_type=finding.get('type', 'Unknown'),
        severity=finding.get('severity', 'medium'),
        context={'description': finding.get('description', '')}
    )
    
    enriched['threat_intelligence'] = {
        'why_matters': explanation['why_matters'],
        'how_exploited': explanation['how_exploited'],
        'recommended_actions': explanation['what_to_do']
    }
    
    return enriched


def enrich_scan_results(scan_results: Dict[str, Any], ollama_client=None) -> Dict[str, Any]:
    """
    Enrich entire scan results with threat intelligence
    
    Args:
        scan_results: Original scan results
        ollama_client: Ollama client for AI explanations (optional)
        
    Returns:
        Enriched scan results
    """
    
    enriched_results = scan_results.copy()
    
    if 'findings' in enriched_results:
        enriched_findings = []
        for finding in enriched_results['findings']:
            enriched_finding = enrich_finding(finding, ollama_client)
            enriched_findings.append(enriched_finding)
        
        enriched_results['findings'] = enriched_findings
    
    # Add threat summary
    if 'findings' in enriched_results:
        threat_summary = _generate_threat_summary(enriched_results['findings'])
        enriched_results['threat_summary'] = threat_summary
    
    return enriched_results


def _generate_threat_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate summary of threats by MITRE tactics"""
    
    tactics_count = {}
    kill_chain_count = {}
    
    for finding in findings:
        if 'mitre_attack' in finding:
            tactic = finding['mitre_attack']['tactic']
            tactics_count[tactic] = tactics_count.get(tactic, 0) + 1
            
        if 'kill_chain_phase' in finding:
            phase = finding['kill_chain_phase']
            kill_chain_count[phase] = kill_chain_count.get(phase, 0) + 1
    
    return {
        'total_findings': len(findings),
        'mitre_tactics': tactics_count,
        'kill_chain_phases': kill_chain_count,
        'top_tactic': max(tactics_count.items(), key=lambda x: x[1])[0] if tactics_count else None,
        'top_kill_chain_phase': max(kill_chain_count.items(), key=lambda x: x[1])[0] if kill_chain_count else None
    }
