"""
Enterprise Module Test Suite
=============================

Comprehensive tests for all enterprise features.
Run with: pytest backend/enterprise/tests/
"""

import pytest
from datetime import datetime

# Test Threat Intelligence
class TestThreatIntelligence:
    
    def test_mitre_mapping(self):
        from enterprise.intelligence import ThreatIntelligence
        
        mapping = ThreatIntelligence.get_mitre_mapping('sql_injection')
        assert mapping is not None
        assert mapping['technique_id'] == 'T1190'
        assert 'Initial Access' in mapping['tactic'].value
    
    def test_enrich_finding(self):
        from enterprise.intelligence import enrich_finding
        
        finding = {
            'id': 1,
            'type': 'sql_injection',
            'title': 'SQL Injection Vulnerability',
            'severity': 'critical',
            'description': 'Unvalidated input in query'
        }
        
        enriched = enrich_finding(finding)
        
        assert 'mitre_attack' in enriched
        assert 'kill_chain_phase' in enriched
        assert 'threat_intelligence' in enriched
        assert enriched['mitre_attack']['technique_id'] == 'T1190'


# Test Compliance
class TestCompliance:
    
    def test_soc2_control_mapping(self):
        from enterprise.compliance import ComplianceMapping, ComplianceFramework
        
        controls = ComplianceMapping.get_affected_controls(
            'sql_injection',
            ComplianceFramework.SOC2
        )
        
        assert len(controls) > 0
        assert 'CC6.1' in controls
    
    def test_compliance_report(self):
        from enterprise.compliance import ComplianceReport, ComplianceFramework, ComplianceStatus
        
        scan_results = {
            'findings': [
                {
                    'type': 'sql_injection',
                    'severity': 'critical',
                    'title': 'SQL Injection',
                    'description': 'Test'
                }
            ]
        }
        
        reporter = ComplianceReport(ComplianceFramework.SOC2)
        report = reporter.generate_report(scan_results)
        
        assert 'framework' in report
        assert report['framework'] == 'soc2'
        assert 'overall_status' in report
        assert 'control_violations' in report


# Test Remediation
class TestRemediation:
    
    def test_remediation_guide(self):
        from enterprise.remediation import RemediationGuide
        
        guide = RemediationGuide.get_remediation('sql_injection')
        
        assert guide is not None
        assert 'title' in guide
        assert 'steps' in guide
        assert 'code_examples' in guide
        assert len(guide['steps']) > 0
    
    def test_remediation_report(self):
        from enterprise.remediation import generate_remediation_report
        
        findings = [
            {
                'id': 1,
                'type': 'sql_injection',
                'severity': 'critical',
                'title': 'SQL Injection'
            },
            {
                'id': 2,
                'type': 'xss',
                'severity': 'high',
                'title': 'XSS'
            }
        ]
        
        report = generate_remediation_report(findings)
        
        assert 'total_items' in report
        assert report['total_items'] == 2
        assert 'by_priority' in report


# Test Reporting
class TestReporting:
    
    def test_posture_score(self):
        from enterprise.reporting import SecurityPostureScoreCalculator
        
        scan_results = {
            'findings': [
                {'severity': 'critical'},
                {'severity': 'high'},
                {'severity': 'medium'}
            ]
        }
        
        posture = SecurityPostureScoreCalculator.calculate(scan_results)
        
        assert 'score' in posture
        assert 'grade' in posture
        assert 'status' in posture
        assert 0 <= posture['score'] <= 100
        assert posture['grade'] in ['A', 'B', 'C', 'D', 'F']
    
    def test_risk_trends(self):
        from enterprise.reporting import RiskTrendAnalyzer
        
        scan_history = [
            {'findings': [{'severity': 'high'}], 'created_at': '2026-02-13T10:00:00'},
            {'findings': [{'severity': 'high'}, {'severity': 'critical'}], 'created_at': '2026-02-12T10:00:00'},
            {'findings': [{'severity': 'high'}, {'severity': 'high'}], 'created_at': '2026-02-11T10:00:00'}
        ]
        
        trends = RiskTrendAnalyzer.analyze(scan_history)
        
        assert 'trend' in trends
        assert 'current_score' in trends
        assert 'score_change' in trends


# Test Notifications
class TestNotifications:
    
    def test_notification_dispatcher(self):
        from enterprise.notifications import NotificationDispatcher, NotificationChannel, NotificationEvent
        
        dispatcher = NotificationDispatcher()
        assert dispatcher is not None
    
    def test_message_formatting(self):
        from enterprise.notifications.channels.whatsapp_handler import WhatsAppHandler
        from enterprise.notifications import NotificationEvent
        
        handler = WhatsAppHandler()
        
        data = {
            'target': 'example.com',
            'findings_count': 5
        }
        
        message = handler._format_message(NotificationEvent.SCAN_COMPLETED, data)
        
        assert 'GoKushield' in message
        assert 'example.com' in message
        assert '5' in message


# Test SIEM
class TestSIEM:
    
    def test_security_event(self):
        from enterprise.siem import SecurityEvent, EventCategory, EventSeverity
        
        event = SecurityEvent(
            event_id='TEST123',
            timestamp=datetime.utcnow(),
            source='test_source',
            category=EventCategory.AUTHENTICATION,
            severity=EventSeverity.HIGH,
            title='Test Event',
            description='Test description'
        )
        
        assert event.to_json()['event_id'] == 'TEST123'
        assert 'CEF:0' in event.to_cef()
        assert 'LEEF:2.0' in event.to_leef()
    
    def test_siem_manager(self):
        from enterprise.siem import get_siem_manager
        
        manager = get_siem_manager()
        assert manager is not None


# Test Plugins
class TestPlugins:
    
    def test_plugin_registry(self):
        from enterprise.plugins import get_plugin_registry, PluginInterface
        
        registry = get_plugin_registry()
        assert registry is not None
        
        class TestPlugin(PluginInterface):
            @property
            def name(self):
                return 'test_plugin'
            
            @property
            def version(self):
                return '1.0.0'
            
            def initialize(self, config):
                return True
            
            def execute(self, *args, **kwargs):
                return 'executed'
        
        plugin = TestPlugin()
        success = registry.register(plugin)
        assert success
        
        retrieved = registry.get_plugin('test_plugin')
        assert retrieved is not None
        assert retrieved.name == 'test_plugin'


# Integration Tests
class TestIntegration:
    
    def test_full_scan_enrichment(self):
        """Test complete scan enrichment pipeline"""
        from enterprise.intelligence import enrich_scan_results
        from enterprise.compliance import generate_multi_framework_report
        from enterprise.remediation import generate_remediation_report
        from enterprise.reporting import SecurityPostureScoreCalculator
        
        scan_results = {
            'id': 1,
            'target': 'example.com',
            'findings': [
                {
                    'id': 1,
                    'type': 'sql_injection',
                    'severity': 'critical',
                    'title': 'SQL Injection',
                    'description': 'Vulnerability detected'
                },
                {
                    'id': 2,
                    'type': 'xss',
                    'severity': 'high',
                    'title': 'XSS',
                    'description': 'Cross-site scripting'
                }
            ]
        }
        
        # Enrich with threat intelligence
        enriched = enrich_scan_results(scan_results)
        assert 'threat_summary' in enriched
        
        # Generate compliance report
        compliance = generate_multi_framework_report(scan_results)
        assert 'frameworks_analyzed' in compliance
        
        # Generate remediation guide
        remediation = generate_remediation_report(scan_results['findings'])
        assert 'total_items' in remediation
        
        # Calculate security posture
        posture = SecurityPostureScoreCalculator.calculate(scan_results)
        assert 'score' in posture


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
