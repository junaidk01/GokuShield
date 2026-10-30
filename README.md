# GokuShield AI v1.0 — Autonomous Cyber Defense & Enterprise API Security Platform

[![Version](https://img.shields.io/badge/version-1.0%20LOCKED-dc2626.svg?style=flat-square)](https://github.com/junaidk01/GokuShield)
[![Python](https://img.shields.io/badge/python-3.14%2B-00f0ff.svg?style=flat-square)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/framework-Flask%203.1-000000.svg?style=flat-square&logo=flask)](https://palletsprojects.com/p/flask/)
[![Security](https://img.shields.io/badge/OWASP-API%20Security%20Top%2010-dc2626.svg?style=flat-square)](https://owasp.org/www-project-api-security/)
[![Theme](https://img.shields.io/badge/theme-Dark%20Black%20%2B%20Crimson%20%2B%20Neon%20Cyan-00f0ff.svg?style=flat-square)](https://github.com/junaidk01/GokuShield)
[![Build Status](https://img.shields.io/badge/tests-25%20passed%20%7C%200%20warnings-16a34a.svg?style=flat-square)](https://github.com/junaidk01/GokuShield)

GokuShield AI v1.0 is an enterprise-grade, autonomous API cybersecurity platform delivering proactive threat detection, real-time perimeter audits, compliance mapping (SOC 2, GDPR, HIPAA, PCI-DSS), and Bayesian-recalibrating defense heuristics across multi-cloud and on-premise environments.

---

## 🛡️ Core Architecture & Four Defense Layers

```
                                  [ PUBLIC INTERNET / TARGET CLIENTS ]
                                                   │
                                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       GOKUSHIELD AI v1.0                                        │
├────────────────────────────────┬────────────────────────────────┬───────────────────────────────┤
│    LAYER 1: PERIMETER SHIELD   │   LAYER 2: BEHAVIORAL AUDIT    │  LAYER 3: ADAPTIVE LEARNING   │
│  • Edge TLS 1.3 / Cipher Audit │  • OWASP API Top 10 Deep Scan │  • Bayesian Weight Modifiers  │
│  • Security Headers Inspection │  • Token Enum & Rate Limiting  │  • False Positive Reduction   │
│  • reCAPTCHA v3 & Anti-Abuse   │  • PII & Secret Leak Detection │  • Feedback Loop Integration  │
├────────────────────────────────┴────────────────────────────────┴───────────────────────────────┤
│                               LAYER 4: COMPLIANCE & INTELLIGENCE                                │
│       • MITRE ATT&CK Mapping • Automated Remediation Guides • SOC 2 / HIPAA Posture Score       │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Key Highlights & Capabilities

1. **Immutable Audit-First SaaS Lifecycle:**
   - **Pre-Auth Free Perimeter Audit:** 1 free audit per verified enterprise domain every 24 hours.
   - **Cryptographic Token Access:** Free audit results are locked behind single-use `audit_token` keys (`/api/free-audit/audit/<scan_id>?token=<token>`) to prevent scan enumeration attacks.
   - **Email Report Delivery:** Automated outreach pipeline triggers welcome emails and executive summary PDF dispatches.
   - **Paid Rescan Protection:** Rescans and advanced remediation require an upgraded plan.

2. **Full Technical Check Suite (Zero Stubs):**
   - 38 concrete technical checks implemented in `BaseSecurityScanner` and inherited by all 15 scanner modules.
   - Live socket TLS handshake probes, HTTP header inspections, BOLA/BFLA vulnerability simulations, injection heuristics, and latency benchmarking.

3. **Production Billing & Service Entitlement Gateway:**
   - Instant activation endpoint (`/api/payments/activate`) with transaction tracking.
   - 10% introductory promotional discount: *"Our first 100 users get 10% off on our plans"*.
   - Tier-based service provisioning (`Starter`, `Professional`, `Enterprise`).

4. **Self-Learning Recalibration Engine:**
   - Bayesian precision calculation based on user and analyst feedback (`ScanFeedback`).
   - Dynamic weight adjustments to minimize alert fatigue and false positives across scans.

5. **Aesthetics & Theme:**
   - Futuristic, military-grade interface styled in **Dark Black + Crimson Red + Neon Electric Cyan** (`#00f0ff`).

---

## 📁 Repository Layout

```
.
├── admin-panel/             # MFA-isolated Superadmin Control Center
│   └── admin-panel.html     # Real-time telemetry, user management, and audit logs
├── client-dashboard/        # Authenticated Customer Dashboard
│   └── client-dashboard.html# Plan purchasing, report viewer, and service un-locker
├── frontend/                # Public Landing Page & Perimeter Scanner
│   └── index.html           # Free audit form, chatbot, pricing, and live evaluator
├── backend/                 # Python 3.14 Flask API Backend
│   ├── ai/                  # Ollama integration & inference engine
│   ├── api/                 # Blueprints (auth, free_audit, payments, admin, client, scans)
│   ├── enterprise/          # MITRE, SOC2, SIEM, Remediation & Recalibration Engine
│   ├── middleware/          # Security headers & rate limiting middleware
│   ├── services/            # BaseSecurityScanner & 15 scanning modules
│   ├── tasks/               # Celery asynchronous task definitions
│   ├── utils/               # LeadEngine, OutreachEngine, and decorators
│   ├── app.py               # Main application factory & route registry
│   ├── config.py            # Environment configurations (Dev, Testing, Prod)
│   ├── models.py            # SQLAlchemy database models
│   └── requirements.txt     # Python production dependencies
├── docker-compose.yml       # Complete stack orchestration (DB, Redis, Backend, Workers)
└── README.md                # Project documentation
```

---

## 🚀 Quickstart & Local Setup

### Option 1: Docker Compose (Full Stack)

```bash
# Clone the repository
git clone https://github.com/junaidk01/GokuShield.git
cd GokuShield

# Boot all services (PostgreSQL, Redis, Ollama, Backend, Workers)
docker compose up -d

# Verify health
curl http://localhost:5000/health
```

### Option 2: Standalone Local Development

```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Start backend server (defaults to local SQLite and standalone mode)
python app.py
```

The application automatically serves:
- **Landing Page:** [http://localhost:5000/](http://localhost:5000/)
- **Client Dashboard:** [http://localhost:5000/client-dashboard/](http://localhost:5000/client-dashboard/)
- **Admin Panel:** [http://localhost:5000/admin-panel/](http://localhost:5000/admin-panel/)
- **API Health:** [http://localhost:5000/health](http://localhost:5000/health)

---

## 🧪 Testing

Run the full end-to-end verification test suite:

```bash
cd backend
python -m pytest
```

Expected output:
```text
============================= 25 passed in 38.63s =============================
```

---

## 🔒 Security & Compliance

- **Role-Based Access Control (RBAC):** Scoped JWT tokens with PyJWT RFC 7519 string subjects.
- **MFA Enforcement:** TOTP-based multi-factor authentication on admin panel.
- **OWASP Alignment:** Automated mapping to OWASP API Security Top 10 (2023).
- **Audit Logging:** Immutable administrative actions and scan telemetry logs.

---

## 📄 License

GokuShield AI is proprietary software. All rights reserved. Version 1.0 (LOCKED).
