"""
Smoke tests: the app must boot, wire its blueprints, and respond.
These are intentionally shallow — they exist to catch the class of bug
that broke this codebase before (import-time crashes, missing routes),
not to validate business logic in depth.
"""
import json


def test_app_boots(app):
    assert app is not None


def test_health_endpoint(client):
    resp = client.get('/health')
    assert resp.status_code in (200, 503)  # 503 if redis/ollama unreachable in CI, still means app ran
    data = resp.get_json()
    assert 'version' in data


def test_all_blueprints_registered(app):
    rules = {r.rule for r in app.url_map.iter_rules()}
    expected_prefixes = [
        '/api/auth', '/api/client', '/api/admin',
        '/api/scans', '/api', '/api/chatbot', '/api/free-audit',
    ]
    for prefix in expected_prefixes:
        assert any(rule.startswith(prefix) for rule in rules), f"no routes registered under {prefix}"


def test_register_and_login_flow(client):
    register_resp = client.post('/api/auth/register', json={
        'email': 'smoketest@example.com',
        'password': 'a-strong-password-123',
        'full_name': 'Smoke Test',
        'company': 'example.com',
    })
    assert register_resp.status_code in (200, 201), register_resp.get_data(as_text=True)

    login_resp = client.post('/api/auth/login', json={
        'email': 'smoketest@example.com',
        'password': 'a-strong-password-123',
    })
    assert login_resp.status_code == 200, login_resp.get_data(as_text=True)
    body = login_resp.get_json()
    assert 'access_token' in body or 'token' in body


def test_unauthenticated_admin_route_is_rejected(client):
    resp = client.get('/api/admin/users')
    assert resp.status_code in (401, 403, 404)
