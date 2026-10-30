"""
Enterprise API Endpoints
========================

REST API for enterprise features.
All endpoints are backward-compatible and optional.
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
import logging

logger = logging.getLogger(__name__)

# Create blueprint
enterprise_bp = Blueprint('enterprise', __name__)


@enterprise_bp.route('/notifications/preferences', methods=['GET'])
@jwt_required()
def get_notification_preferences():
    """Get user notification preferences"""
    from models import User
    from enterprise.models import NotificationPreference
    
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    prefs = NotificationPreference.query.filter_by(user_id=user_id).first()
    
    if not prefs:
        # Create default preferences
        from models import db
        prefs = NotificationPreference(user_id=user_id)
        db.session.add(prefs)
        db.session.commit()
    
    return jsonify(prefs.to_dict()), 200


@enterprise_bp.route('/notifications/preferences', methods=['PUT'])
@jwt_required()
def update_notification_preferences():
    """Update user notification preferences"""
    from models import db, User
    from enterprise.models import NotificationPreference
    
    user_id = get_jwt_identity()
    data = request.get_json()
    
    prefs = NotificationPreference.query.filter_by(user_id=user_id).first()
    
    if not prefs:
        prefs = NotificationPreference(user_id=user_id)
        db.session.add(prefs)
    
    # Update channel preferences
    if 'channels' in data:
        channels = data['channels']
        if 'whatsapp' in channels:
            prefs.whatsapp_enabled = channels['whatsapp'].get('enabled', False)
            prefs.whatsapp_number = channels['whatsapp'].get('number')
        if 'sms' in channels:
            prefs.sms_enabled = channels['sms'].get('enabled', False)
            prefs.sms_number = channels['sms'].get('number')
        if 'email' in channels:
            prefs.email_enabled = channels['email'].get('enabled', True)
    
    # Update event preferences
    if 'events' in data:
        events = data['events']
        prefs.notify_scan_completed = events.get('scan_completed', True)
        prefs.notify_critical_vulnerability = events.get('critical_vulnerability', True)
        prefs.notify_compliance_failure = events.get('compliance_failure', True)
        prefs.notify_domain_abuse = events.get('domain_abuse', True)
    
    db.session.commit()
    
    return jsonify(prefs.to_dict()), 200


@enterprise_bp.route('/intelligence/enrich/<int:scan_id>', methods=['GET'])
@jwt_required()
def enrich_scan_with_intelligence(scan_id):
    """Enrich scan results with threat intelligence"""
    from models import Scan, User
    from enterprise.intelligence import enrich_scan_results
    
    user_id = get_jwt_identity()
    
    scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
    
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    try:
        # Get Ollama client from app context
        from flask import current_app
        ollama_client = current_app.ollama_client if hasattr(current_app, 'ollama_client') else None
        
        # Enrich scan results
        scan_dict = scan.to_dict()
        enriched = enrich_scan_results(scan_dict, ollama_client)
        
        return jsonify(enriched), 200
        
    except Exception as e:
        logger.error(f"Intelligence enrichment failed: {e}")
        return jsonify({'error': 'Enrichment failed'}), 500


@enterprise_bp.route('/compliance/report/<int:scan_id>', methods=['GET'])
@jwt_required()
def generate_compliance_report(scan_id):
    """Generate compliance report for scan"""
    from models import Scan
    from enterprise.compliance import generate_multi_framework_report
    
    user_id = get_jwt_identity()
    framework = request.args.get('framework', 'all')
    
    scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
    
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    try:
        scan_dict = scan.to_dict()
        
        if framework == 'all':
            report = generate_multi_framework_report(scan_dict)
        else:
            from enterprise.compliance import ComplianceReport, ComplianceFramework
            try:
                fw = ComplianceFramework(framework)
                reporter = ComplianceReport(fw)
                report = reporter.generate_report(scan_dict)
            except ValueError:
                return jsonify({'error': 'Invalid framework'}), 400
        
        # Store compliance snapshot
        from models import db
        from enterprise.models import ComplianceSnapshot
        
        if framework != 'all':
            snapshot = ComplianceSnapshot(
                scan_id=scan_id,
                framework=framework,
                overall_status=report.get('overall_status', 'risk'),
                total_findings=report['summary']['total_findings'],
                controls_affected=report['summary']['controls_affected'],
                critical_findings=report['summary']['critical_findings'],
                high_findings=report['summary']['high_findings'],
                control_violations=report.get('control_violations'),
                evidence_checklist=report.get('evidence_checklist'),
                recommendations=report.get('recommendations')
            )
            db.session.add(snapshot)
            db.session.commit()
        
        return jsonify(report), 200
        
    except Exception as e:
        logger.error(f"Compliance report generation failed: {e}")
        return jsonify({'error': 'Report generation failed'}), 500


@enterprise_bp.route('/remediation/guide/<int:scan_id>', methods=['GET'])
@jwt_required()
def get_remediation_guide(scan_id):
    """Get AI-powered remediation guide for scan"""
    from models import Scan
    from enterprise.remediation import generate_remediation_report
    
    user_id = get_jwt_identity()
    
    scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
    
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    try:
        from flask import current_app
        ollama_client = current_app.ollama_client if hasattr(current_app, 'ollama_client') else None
        
        findings = scan.to_dict().get('findings', [])
        report = generate_remediation_report(findings, ollama_client)
        
        return jsonify(report), 200
        
    except Exception as e:
        logger.error(f"Remediation guide generation failed: {e}")
        return jsonify({'error': 'Guide generation failed'}), 500


@enterprise_bp.route('/remediation/queue/<int:scan_id>', methods=['POST'])
@jwt_required()
def queue_remediation_actions(scan_id):
    """
    Generate remediation suggestions for a scan's findings and persist them
    as pending RemediationAction rows for approval. This does not apply any
    change automatically — it only populates the approval queue. Nothing
    here or anywhere else in this codebase modifies live infrastructure.
    """
    from models import db, Scan, RemediationAction
    from enterprise.remediation import generate_remediation_report

    user_id = get_jwt_identity()
    scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()

    if not scan:
        return jsonify({'error': 'Scan not found'}), 404

    findings = scan.to_dict().get('findings', [])
    if not findings:
        return jsonify({'error': 'Scan has no findings to queue'}), 400

    try:
        from flask import current_app
        ollama_client = current_app.ollama_client if hasattr(current_app, 'ollama_client') else None
        report = generate_remediation_report(findings, ollama_client)

        created = []
        for idx, item in enumerate(report.get('items', [])):
            existing = RemediationAction.query.filter_by(
                scan_id=scan_id, finding_index=idx
            ).first()
            if existing:
                continue  # don't duplicate the queue on repeated calls

            remediation = item.get('remediation', {})
            steps = remediation.get('steps', [])
            ai_suggestion = remediation.get('ai_suggestions', '')
            suggested_action = ai_suggestion or '\n'.join(f"- {s}" for s in steps) or 'No specific remediation available.'

            action = RemediationAction(
                scan_id=scan_id,
                finding_index=idx,
                check_name=item.get('finding_title') or 'Unknown finding',
                severity=item.get('severity'),
                suggested_action=suggested_action,
                status='pending'
            )
            db.session.add(action)
            created.append(action)

        db.session.commit()

        return jsonify({
            'scan_id': scan_id,
            'queued': len(created),
            'actions': [a.to_dict() for a in created]
        }), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Remediation queueing failed: {e}")
        return jsonify({'error': 'Queueing failed'}), 500


@enterprise_bp.route('/reporting/posture', methods=['GET'])
@jwt_required()
def get_security_posture():
    """Get current security posture score"""
    from models import Scan
    from enterprise.reporting import SecurityPostureScoreCalculator
    
    user_id = get_jwt_identity()
    
    # Get most recent scan
    scan = Scan.query.filter_by(user_id=user_id).order_by(
        Scan.created_at.desc()
    ).first()
    
    if not scan:
        return jsonify({'error': 'No scans available'}), 404
    
    try:
        scan_dict = scan.to_dict()
        posture = SecurityPostureScoreCalculator.calculate(scan_dict)
        
        # Store history
        from models import db
        from enterprise.models import SecurityPostureHistory
        
        history = SecurityPostureHistory(
            user_id=user_id,
            scan_id=scan.id,
            score=posture['score'],
            grade=posture['grade'],
            status=posture['status'],
            total_findings=posture['total_findings'],
            critical_count=posture['severity_breakdown'].get('critical', 0),
            high_count=posture['severity_breakdown'].get('high', 0),
            medium_count=posture['severity_breakdown'].get('medium', 0),
            low_count=posture['severity_breakdown'].get('low', 0)
        )
        db.session.add(history)
        db.session.commit()
        
        return jsonify(posture), 200
        
    except Exception as e:
        logger.error(f"Posture calculation failed: {e}")
        return jsonify({'error': 'Calculation failed'}), 500


@enterprise_bp.route('/reporting/trends', methods=['GET'])
@jwt_required()
def get_risk_trends():
    """Get risk trend analysis"""
    from models import Scan
    from enterprise.reporting import RiskTrendAnalyzer
    
    user_id = get_jwt_identity()
    limit = request.args.get('limit', 10, type=int)
    
    scans = Scan.query.filter_by(user_id=user_id).order_by(
        Scan.created_at.desc()
    ).limit(limit).all()
    
    if len(scans) < 2:
        return jsonify({'error': 'Need at least 2 scans for trend analysis'}), 400
    
    try:
        scan_dicts = [s.to_dict() for s in scans]
        trends = RiskTrendAnalyzer.analyze(scan_dicts)
        
        return jsonify(trends), 200
        
    except Exception as e:
        logger.error(f"Trend analysis failed: {e}")
        return jsonify({'error': 'Analysis failed'}), 500


@enterprise_bp.route('/reporting/executive', methods=['GET'])
@jwt_required()
def get_executive_report():
    """Get executive summary report"""
    from models import Scan, User
    from enterprise.reporting import ExecutiveReport
    
    user_id = get_jwt_identity()
    
    scans = Scan.query.filter_by(user_id=user_id).order_by(
        Scan.created_at.desc()
    ).limit(10).all()
    
    if not scans:
        return jsonify({'error': 'No scans available'}), 404
    
    try:
        user = User.query.get(user_id)
        user_info = {
            'organization': user.company if user.company else 'N/A'
        }
        
        scan_dicts = [s.to_dict() for s in scans]
        
        report = ExecutiveReport.generate(
            current_scan=scan_dicts[0],
            scan_history=scan_dicts[1:],
            user_info=user_info
        )
        
        return jsonify(report), 200
        
    except Exception as e:
        logger.error(f"Executive report generation failed: {e}")
        return jsonify({'error': 'Report generation failed'}), 500


@enterprise_bp.route('/siem/events', methods=['GET'])
@jwt_required()
def get_siem_events():
    """Get recent SIEM events"""
    from enterprise.models import SIEMEvent
    
    limit = request.args.get('limit', 100, type=int)
    category = request.args.get('category')
    severity = request.args.get('severity')
    
    query = SIEMEvent.query
    
    if category:
        query = query.filter_by(category=category)
    if severity:
        query = query.filter_by(severity=severity)
    
    events = query.order_by(SIEMEvent.timestamp.desc()).limit(limit).all()
    
    return jsonify({
        'total': len(events),
        'events': [e.to_dict() for e in events]
    }), 200


# Enterprise feature status endpoint
@enterprise_bp.route('/features', methods=['GET'])
def get_enterprise_features():
    """Get enterprise feature availability status"""
    from enterprise import ENTERPRISE_FEATURES, is_feature_enabled
    
    return jsonify({
        'features': {
            name: {
                'enabled': enabled,
                'status': 'active' if enabled else 'available'
            }
            for name, enabled in ENTERPRISE_FEATURES.items()
        }
    }), 200
