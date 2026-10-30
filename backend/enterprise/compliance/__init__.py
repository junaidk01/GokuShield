"""
Compliance-as-a-Service Module
===============================

Compliance intelligence and reporting WITHOUT enforcement.

Provides:
- SOC 2, ISO 27001, PCI-DSS mapping
- Evidence checklist generation
- Continuous compliance status tracking

NO automated enforcement.
NO compliance automation.

Reports ONLY.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    NIST_CSF = "nist_csf"


class ComplianceStatus(Enum):
    """Compliance status levels"""
    PASS = "pass"
    ATTENTION = "attention"
    RISK = "risk"
    NOT_APPLICABLE = "not_applicable"


class ComplianceControl:
    """Represents a single compliance control"""
    
    def __init__(
        self,
        control_id: str,
        title: str,
        description: str,
        framework: ComplianceFramework,
        category: str
    ):
        self.control_id = control_id
        self.title = title
        self.description = description
        self.framework = framework
        self.category = category


class ComplianceMapping:
    """
    Maps security findings to compliance controls.
    """
    
    # Vulnerability to compliance control mapping
    CONTROL_MAPPINGS = {
        ComplianceFramework.SOC2: {
            'sql_injection': ['CC6.1', 'CC6.6', 'CC7.2'],
            'xss': ['CC6.1', 'CC6.6'],
            'authentication_bypass': ['CC6.1', 'CC6.2', 'CC6.3'],
            'weak_crypto': ['CC6.1', 'CC6.7'],
            'broken_access_control': ['CC6.1', 'CC6.3'],
            'security_misconfiguration': ['CC6.1', 'CC7.2', 'CC8.1'],
            'sensitive_data_exposure': ['CC6.1', 'CC6.7', 'CC6.6'],
            'missing_rate_limiting': ['CC6.1', 'A1.2']
        },
        ComplianceFramework.ISO27001: {
            'sql_injection': ['A.14.2.1', 'A.14.2.5'],
            'xss': ['A.14.2.1', 'A.14.2.5'],
            'authentication_bypass': ['A.9.2.1', 'A.9.4.2', 'A.9.4.3'],
            'weak_crypto': ['A.10.1.1', 'A.10.1.2'],
            'broken_access_control': ['A.9.1.1', 'A.9.2.1', 'A.9.4.1'],
            'security_misconfiguration': ['A.12.6.1', 'A.14.2.1'],
            'sensitive_data_exposure': ['A.10.1.1', 'A.18.1.3'],
            'missing_rate_limiting': ['A.14.2.8']
        },
        ComplianceFramework.PCI_DSS: {
            'sql_injection': ['6.5.1', '6.5.7'],
            'xss': ['6.5.7'],
            'authentication_bypass': ['8.2.1', '8.2.3', '8.2.4'],
            'weak_crypto': ['4.1', '4.1.1'],
            'broken_access_control': ['7.1', '7.2'],
            'security_misconfiguration': ['2.2', '2.2.2'],
            'sensitive_data_exposure': ['3.4', '4.1'],
            'missing_rate_limiting': ['6.5.10']
        }
    }
    
    # Control definitions
    SOC2_CONTROLS = {
        'CC6.1': ComplianceControl(
            'CC6.1',
            'Logical and Physical Access Controls',
            'The entity implements logical access security software, infrastructure, and architectures over protected information assets',
            ComplianceFramework.SOC2,
            'Security'
        ),
        'CC6.2': ComplianceControl(
            'CC6.2',
            'Authentication',
            'Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users',
            ComplianceFramework.SOC2,
            'Security'
        ),
        'CC6.3': ComplianceControl(
            'CC6.3',
            'Authorization',
            'The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets',
            ComplianceFramework.SOC2,
            'Security'
        ),
        'CC6.6': ComplianceControl(
            'CC6.6',
            'Transmission Security',
            'The entity implements controls to protect against security vulnerabilities in the transmission of data',
            ComplianceFramework.SOC2,
            'Security'
        ),
        'CC6.7': ComplianceControl(
            'CC6.7',
            'Encryption',
            'The entity uses encryption to protect data-at-rest and data-in-transit',
            ComplianceFramework.SOC2,
            'Security'
        ),
        'CC7.2': ComplianceControl(
            'CC7.2',
            'System Monitoring',
            'The entity monitors system components and the operation of those components for anomalies',
            ComplianceFramework.SOC2,
            'Monitoring'
        ),
        'CC8.1': ComplianceControl(
            'CC8.1',
            'Change Management',
            'The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes',
            ComplianceFramework.SOC2,
            'Change Management'
        ),
        'A1.2': ComplianceControl(
            'A1.2',
            'Availability Monitoring',
            'The entity monitors availability and performance metrics and evaluates them against defined objectives',
            ComplianceFramework.SOC2,
            'Availability'
        )
    }
    
    @classmethod
    def get_affected_controls(
        cls,
        vulnerability_type: str,
        framework: ComplianceFramework
    ) -> List[str]:
        """Get compliance controls affected by vulnerability"""
        vuln_key = vulnerability_type.lower().replace(' ', '_')
        framework_mappings = cls.CONTROL_MAPPINGS.get(framework, {})
        return framework_mappings.get(vuln_key, [])
    
    @classmethod
    def get_control_details(cls, control_id: str, framework: ComplianceFramework) -> Optional[ComplianceControl]:
        """Get control definition"""
        if framework == ComplianceFramework.SOC2:
            return cls.SOC2_CONTROLS.get(control_id)
        return None


class ComplianceReport:
    """Generates compliance reports from scan findings"""
    
    def __init__(self, framework: ComplianceFramework):
        self.framework = framework
        
    def generate_report(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate compliance report from scan results
        
        Args:
            scan_results: Scan results with findings
            
        Returns:
            Compliance report with status and evidence
        """
        
        findings = scan_results.get('findings', [])
        
        # Map findings to controls
        control_violations = {}
        
        for finding in findings:
            vuln_type = finding.get('type', '').lower().replace(' ', '_')
            affected_controls = ComplianceMapping.get_affected_controls(
                vuln_type,
                self.framework
            )
            
            for control_id in affected_controls:
                if control_id not in control_violations:
                    control_violations[control_id] = []
                control_violations[control_id].append({
                    'finding_id': finding.get('id'),
                    'title': finding.get('title', 'Unknown'),
                    'severity': finding.get('severity', 'medium'),
                    'description': finding.get('description', '')
                })
        
        # Determine overall status
        overall_status = self._calculate_status(control_violations, findings)
        
        # Generate evidence checklist
        evidence_checklist = self._generate_evidence_checklist(control_violations)
        
        report = {
            'framework': self.framework.value,
            'generated_at': datetime.utcnow().isoformat(),
            'overall_status': overall_status.value,
            'summary': {
                'total_findings': len(findings),
                'controls_affected': len(control_violations),
                'critical_findings': len([f for f in findings if f.get('severity') == 'critical']),
                'high_findings': len([f for f in findings if f.get('severity') == 'high'])
            },
            'control_violations': control_violations,
            'evidence_checklist': evidence_checklist,
            'recommendations': self._generate_recommendations(control_violations)
        }
        
        return report
    
    def _calculate_status(
        self,
        control_violations: Dict[str, List],
        findings: List[Dict]
    ) -> ComplianceStatus:
        """Calculate overall compliance status"""
        
        critical_count = len([f for f in findings if f.get('severity') == 'critical'])
        high_count = len([f for f in findings if f.get('severity') == 'high'])
        
        if critical_count > 0:
            return ComplianceStatus.RISK
        elif high_count > 2:
            return ComplianceStatus.RISK
        elif len(control_violations) > 3:
            return ComplianceStatus.ATTENTION
        elif len(control_violations) > 0:
            return ComplianceStatus.ATTENTION
        else:
            return ComplianceStatus.PASS
    
    def _generate_evidence_checklist(
        self,
        control_violations: Dict[str, List]
    ) -> List[Dict[str, Any]]:
        """Generate evidence collection checklist"""
        
        checklist = []
        
        for control_id, violations in control_violations.items():
            control = ComplianceMapping.get_control_details(control_id, self.framework)
            
            if control:
                checklist.append({
                    'control_id': control_id,
                    'control_title': control.title,
                    'status': 'action_required',
                    'violations_count': len(violations),
                    'evidence_needed': [
                        'Documentation of implemented controls',
                        'Screenshots of security configurations',
                        'Remediation timeline and status',
                        'Testing results post-remediation'
                    ]
                })
        
        return checklist
    
    def _generate_recommendations(
        self,
        control_violations: Dict[str, List]
    ) -> List[str]:
        """Generate compliance recommendations"""
        
        recommendations = []
        
        if len(control_violations) > 0:
            recommendations.append(
                f"Address {len(control_violations)} affected compliance controls to improve {self.framework.value.upper()} posture"
            )
        
        if len(control_violations) > 5:
            recommendations.append(
                "Consider engaging a compliance consultant for gap assessment"
            )
        
        recommendations.append(
            "Document all remediation efforts for audit evidence"
        )
        
        recommendations.append(
            "Schedule regular compliance scans to maintain continuous compliance"
        )
        
        return recommendations


def generate_multi_framework_report(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate compliance report across multiple frameworks
    
    Args:
        scan_results: Scan results with findings
        
    Returns:
        Multi-framework compliance report
    """
    
    frameworks = [
        ComplianceFramework.SOC2,
        ComplianceFramework.ISO27001,
        ComplianceFramework.PCI_DSS
    ]
    
    reports = {}
    
    for framework in frameworks:
        reporter = ComplianceReport(framework)
        reports[framework.value] = reporter.generate_report(scan_results)
    
    # Generate cross-framework summary
    summary = {
        'generated_at': datetime.utcnow().isoformat(),
        'frameworks_analyzed': len(frameworks),
        'framework_reports': reports,
        'overall_assessment': _assess_cross_framework(reports)
    }
    
    return summary


def _assess_cross_framework(reports: Dict[str, Dict]) -> Dict[str, Any]:
    """Assess compliance status across all frameworks"""
    
    status_scores = {
        'pass': 3,
        'attention': 2,
        'risk': 1
    }
    
    total_score = 0
    max_score = 0
    
    for framework, report in reports.items():
        status = report.get('overall_status', 'risk')
        total_score += status_scores.get(status, 0)
        max_score += 3
    
    compliance_percentage = (total_score / max_score * 100) if max_score > 0 else 0
    
    return {
        'compliance_percentage': round(compliance_percentage, 2),
        'status': 'pass' if compliance_percentage >= 80 else 'attention' if compliance_percentage >= 60 else 'risk',
        'frameworks_at_risk': [
            framework for framework, report in reports.items()
            if report.get('overall_status') == 'risk'
        ]
    }
