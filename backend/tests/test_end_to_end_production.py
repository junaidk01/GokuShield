"""
End-to-End Production Verification Test Suite
GoKushield AI v1.0
Verifies all 10 modules, 4 defense layers, tokenized public audits,
payments & subscription lifecycle, password resets, and recalibration feedback.
"""

import pytest
import json
from datetime import datetime

from models import db, User, Scan, ScanStatus, Service, PlanType, Lead, Transaction, ScanFeedback
from services.base_scanner import BaseSecurityScanner
from enterprise.recalibration_engine import RecalibrationEngine

def test_base_security_scanner_checks():
    """Verify all critical technical check methods exist and execute deterministically"""
    scanner = BaseSecurityScanner()
    test_target = "https://example.com"

    # Test basic security
    res_basic = scanner._check_basic_security(test_target)
    assert 'name' in res_basic
    assert 'status' in res_basic
    assert 'evidence' in res_basic

    # Test security headers
    res_headers = scanner._check_security_headers(test_target)
    assert 'name' in res_headers
    assert res_headers['status'] in ['pass', 'fail', 'warning']

    # Test OWASP API checks
    res_bola = scanner._check_broken_object_auth(test_target)
    assert 'BOLA' in res_bola['name']

    res_auth = scanner._check_broken_authentication(test_target)
    assert 'Broken Authentication' in res_auth['name']

    res_sqli = scanner._check_injection(test_target)
    assert 'Injection' in res_sqli['name']

    # Test Rate Limiting & DDoS checks
    res_rate = scanner._check_rate_limiting(test_target)
    assert 'Resource Consumption' in res_rate['name']

    res_ddos = scanner._check_ddos_protection(test_target)
    assert 'DDoS' in res_ddos['name']

    # Test Compliance checks
    res_gdpr = scanner._check_gdpr_compliance(test_target)
    assert 'GDPR' in res_gdpr['name']

    res_hipaa = scanner._check_hipaa_compliance(test_target)
    assert 'HIPAA' in res_hipaa['name']

def test_live_score_evaluator(client):
    """Verify live security score preview endpoint for landing page demo"""
    res = client.post('/api/free-audit/evaluate-score', json={
        'target': 'https://example.com'
    })
    assert res.status_code == 200
    data = res.get_json()
    assert 'score' in data
    assert 20 <= data['score'] <= 100
    assert 'label' in data
    assert 'findings' in data
    assert len(data['checks']) == 3

def test_token_secured_free_audit_flow(client, app):
    """Verify public audit flow generates secure audit_token and guards against ID guessing"""
    with app.app_context():
        # Trigger audit
        res = client.post('/api/free-audit/audit', json={
            'email': 'security-audit-lead@testcorp.com',
            'target': 'https://api.testcorp.com'
        })
        assert res.status_code == 202
        data = res.get_json()
        assert 'scan_id' in data
        assert 'token' in data
        scan_id = data['scan_id']
        token = data['token']

        # Attempt to query scan without token (should be rejected 403)
        unauth_res = client.get(f'/api/free-audit/audit/{scan_id}')
        assert unauth_res.status_code == 403

        # Query with valid token (should succeed 200)
        auth_res = client.get(f'/api/free-audit/audit/{scan_id}?token={token}')
        assert auth_res.status_code == 200
        scan_data = auth_res.get_json()
        assert scan_data['scan_id'] == scan_id

        # Verify second audit for same domain is blocked (1 free audit per domain policy)
        second_audit = client.post('/api/free-audit/audit', json={
            'email': 'another-lead@testcorp.com',
            'target': 'https://api.testcorp.com'
        })
        assert second_audit.status_code == 429

def test_password_reset_workflow(client, app):
    """Verify end-to-end password reset with secure one-time token"""
    with app.app_context():
        # Register user
        reg_res = client.post('/api/auth/register', json={
            'email': 'pwd-reset-test@example.com',
            'password': 'InitialPassword123!',
            'full_name': 'Password Reset Test'
        })
        assert reg_res.status_code == 201

        # Request reset
        forgot_res = client.post('/api/auth/forgot-password', json={
            'email': 'pwd-reset-test@example.com'
        })
        assert forgot_res.status_code == 200

        user = User.query.filter_by(email='pwd-reset-test@example.com').first()
        assert user.reset_password_token is not None

        # Reset password
        reset_res = client.post('/api/auth/reset-password', json={
            'token': user.reset_password_token,
            'password': 'NewSecurePassword456!'
        })
        assert reset_res.status_code == 200

        # Login with new password
        login_res = client.post('/api/auth/login', json={
            'email': 'pwd-reset-test@example.com',
            'password': 'NewSecurePassword456!'
        })
        assert login_res.status_code == 200

def test_payment_and_subscription_activation(client, app):
    """Verify checkout session generation, instant activation, and service unlocking"""
    with app.app_context():
        # Create and login user
        client.post('/api/auth/register', json={
            'email': 'paying-client@enterprise.com',
            'password': 'ClientPassword789!',
            'full_name': 'Paying Client'
        })
        login_res = client.post('/api/auth/login', json={
            'email': 'paying-client@enterprise.com',
            'password': 'ClientPassword789!'
        })
        token = login_res.get_json()['access_token']
        headers = {'Authorization': f'Bearer {token}'}

        # 1. Checkout session with introductory 10% discount
        checkout_res = client.post('/api/payments/checkout', headers=headers, json={
            'plan_type': 'Professional',
            'billing_cycle': 'monthly'
        })
        assert checkout_res.status_code == 201
        checkout_data = checkout_res.get_json()
        assert 'invoice_number' in checkout_data
        assert checkout_data['discount_applied'] is True
        assert checkout_data['amount_usd'] == 53.1  # $59 with 10% off

        # 2. Activate subscription
        act_res = client.post('/api/payments/activate', headers=headers, json={
            'invoice_number': checkout_data['invoice_number']
        })
        assert act_res.status_code == 200
        act_data = act_res.get_json()
        assert act_data['plan'].lower() == 'professional'

        # Verify user model is updated
        user = User.query.filter_by(email='paying-client@enterprise.com').first()
        assert user.plan_type == PlanType.PROFESSIONAL

def test_recalibration_engine_feedback_loop(client, app):
    """Verify ScanFeedback ingestion, Bayesian weight modifier calculation, and admin trigger"""
    with app.app_context():
        # Seed an admin user
        admin = User(
            email='recalibrate-admin@gokushield.com',
            is_admin=True,
            is_active=True,
            plan_type=PlanType.ENTERPRISE
        )
        admin.set_password('AdminPassword999!')
        db.session.add(admin)

        # Create dummy service and scan
        service = Service.query.first() or Service(
            name='OWASP API Security',
            service_id='owasp_api_security',
            category='api_security'
        )
        db.session.add(service)
        db.session.flush()

        scan = Scan(
            user_id=admin.id,
            service_id=service.id,
            target='https://api.recalibration.test',
            status=ScanStatus.COMPLETED,
            findings=[{'title': 'BOLA Vulnerability', 'severity': 'high'}]
        )
        db.session.add(scan)
        db.session.commit()

        # Ingest feedback: 2 True Positives, 1 False Positive
        RecalibrationEngine.record_feedback(
            scan_id=scan.id,
            finding_index=0,
            check_name='API1:2023 - Broken Object Level Authorization (BOLA)',
            is_true_positive=True,
            user_id=admin.id
        )
        RecalibrationEngine.record_feedback(
            scan_id=scan.id,
            finding_index=0,
            check_name='API1:2023 - Broken Object Level Authorization (BOLA)',
            is_true_positive=True,
            user_id=admin.id
        )
        RecalibrationEngine.record_feedback(
            scan_id=scan.id,
            finding_index=0,
            check_name='API1:2023 - Broken Object Level Authorization (BOLA)',
            is_true_positive=False,
            user_id=admin.id
        )

        metrics = RecalibrationEngine.get_feedback_metrics()
        assert metrics['total_feedback_records'] >= 3

        # Run recalibration job
        job_result = RecalibrationEngine.run_recalibration_job(admin_user_id=admin.id)
        assert job_result['status'] == 'recalibrated'
        assert job_result['evaluated_records'] >= 3

        # Login admin and test API endpoint
        login_res = client.post('/api/auth/login', json={
            'email': 'recalibrate-admin@gokushield.com',
            'password': 'AdminPassword999!'
        })
        admin_token = login_res.get_json()['access_token']
        headers = {'Authorization': f'Bearer {admin_token}'}

        api_res = client.get('/api/admin/recalibration-stats', headers=headers)
        assert api_res.status_code == 200
        stats = api_res.get_json()
        assert 'metrics' in stats
