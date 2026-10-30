# GokuShield AI v1.0 - Production Deployment
# Backend API Configuration Mapping

## CRITICAL RULES
- This file contains MAPPING ONLY
- DO NOT modify business logic
- DO NOT refactor AI reasoning
- Ollama is PRIMARY AI engine (inference-only, stateless)

## API Endpoints Mapping

### Public Website (www.gokushield.com)
- Frontend: Vercel Static Hosting
- No backend calls except for:
  - Free Audit Submission → POST /api/audit/submit
  - Form Submissions → POST /api/forms/{form_type}

### Client Dashboard ({company}.gokushield.com)
- Auth Required: JWT (client-scoped)
- Endpoints:
  - GET /api/audit/{audit_id} → Fetch audit report
  - GET /api/audit/{audit_id}/download → Download PDF
  - GET /api/client/account → Get account details
  - POST /api/client/plan/select → Select plan
  - POST /api/client/password/reset → Reset password

### Admin Panel (admin.gokushield.com)
- Auth Required: JWT (admin-scoped) + MFA
- Isolated session (no shared cookies)
- Endpoints:
  - GET /admin/stats → Dashboard statistics
  - GET /admin/audits → List all audits
  - GET /admin/users → List all users
  - POST /admin/user/add → Add new user
  - PUT /admin/user/{id} → Update user
  - DELETE /admin/user/{id} → Delete user
  - GET /admin/system/health → System health check
  - POST /admin/content/update → Update controlled website content

## Authentication & Security

### JWT Configuration
```yaml
JWT_SECRET: <MUST_BE_SET_IN_ENV>
JWT_ALGORITHM: HS256
JWT_EXPIRATION:
  client: 7d
  admin: 1d
JWT_SCOPE_FIELD: role  # client | admin
JWT_TENANT_FIELD: company_domain  # For client JWTs
```

### Cookie Security
```yaml
COOKIE_DOMAIN_ISOLATION:
  - www.gokushield.com: NO auth cookies
  - {company}.gokushield.com: client JWT only
  - admin.gokushield.com: admin JWT + MFA session
COOKIE_SECURE: true
COOKIE_HTTPONLY: true
COOKIE_SAMESITE: Strict
```

### MFA (Admin Only)
```yaml
MFA_PROVIDER: TOTP (Google Authenticator compatible)
MFA_ISSUER: GokuShield Admin
MFA_REQUIRED: true (for all admin operations)
MFA_SESSION_TIMEOUT: 1h
```

## Audit System Configuration

### Free Audit Rules
```yaml
AUDIT_LIMIT: 1 per company_domain
AUDIT_ID_GENERATION: UUID v4
AUDIT_STORAGE:
  - Backend: Oracle Cloud (immutable)
  - Bound to: company_domain + email
AUDIT_DELIVERY:
  - Email: PDF attachment
  - Dashboard: HTML view + downloadable PDF
AUDIT_RE_RUN: DISABLED (audit_id is immutable)
```

### Audit Workflow
```yaml
1. User submits free audit form (with reCAPTCHA)
2. Backend validates:
   - reCAPTCHA token
   - company_domain not already audited
   - Email format valid
3. Generate audit_id
4. Trigger scanner (backend-only, Ollama inference)
5. Store results (Oracle DB)
6. Send email with:
   - Dashboard URL: https://{company_domain}.gokushield.com
   - Temporary credentials
   - Password reset required on first login
7. Create client JWT with:
   - role: client
   - company_domain: {domain}
   - audit_id: {id}
   - email: {email}
```

## Scanner Integration

### Scanner Architecture
```yaml
SCANNER_LOCATION: Backend (Oracle Cloud)
SCANNER_TRIGGER: API endpoint only (not browser-accessible)
SCANNER_ENGINE: Ollama (local, free models)
SCANNER_MODELS:
  - Primary: llama2 (7B)
  - Fallback: mistral (7B)
NO_GEMINI: true (removed completely)
NO_EXTERNAL_API: true (all scanning is internal)
```

### Scanner API Endpoints
```yaml
POST /api/scanner/headers
  - Description: Real-time header security scan
  - Input: { url: string }
  - Output: { headers: object, analysis: string, score: number }
  - Auth: Public (with rate limiting)
  
POST /api/scanner/full-audit
  - Description: Complete security audit (internal only)
  - Input: { company_domain: string, apis: array }
  - Output: { audit_id: string, report_html: string }
  - Auth: Internal only (called by audit submission handler)
```

### Ollama Configuration
```yaml
OLLAMA_HOST: http://localhost:11434
OLLAMA_MODEL: llama2:latest
OLLAMA_TIMEOUT: 60s
OLLAMA_MAX_TOKENS: 2048
OLLAMA_TEMPERATURE: 0.3  # Deterministic
OLLAMA_USAGE:
  - Inference only
  - Stateless (no memory)
  - No training or learning
  - No fine-tuning
```

## Database Schema (Oracle Cloud)

### Tables (Reference Only - DO NOT modify schema)
```sql
-- Users table
users (
  id UUID PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  company_domain VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255),
  role VARCHAR(50) DEFAULT 'client',
  status VARCHAR(50) DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)

-- Audits table
audits (
  audit_id UUID PRIMARY KEY,
  company_domain VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  report_html TEXT,
  report_pdf_url VARCHAR(512),
  status VARCHAR(50) DEFAULT 'completed',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(company_domain)  -- One audit per domain
)

-- Plans table
plans (
  plan_id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  plan_type VARCHAR(50),  -- starter | professional | enterprise
  status VARCHAR(50),  -- active | inactive | pending
  started_at TIMESTAMP,
  expires_at TIMESTAMP
)
```

## Environment Variables

### Required Production Variables
```bash
# Database
DATABASE_URL=<ORACLE_CLOUD_CONNECTION_STRING>
DATABASE_POOL_SIZE=10

# JWT & Security
JWT_SECRET=<GENERATE_STRONG_SECRET>
JWT_ALGORITHM=HS256
ADMIN_JWT_SECRET=<SEPARATE_ADMIN_SECRET>

# Domains
WEBSITE_DOMAIN=www.gokushield.com
ADMIN_DOMAIN=admin.gokushield.com
CLIENT_DOMAIN_PATTERN=*.gokushield.com

# Email
EMAIL_PROVIDER=<SMTP_OR_SERVICE>
EMAIL_FROM=noreply@gokushield.com
EMAIL_SMTP_HOST=<SMTP_HOST>
EMAIL_SMTP_PORT=587
EMAIL_SMTP_USER=<SMTP_USER>
EMAIL_SMTP_PASS=<SMTP_PASSWORD>

# reCAPTCHA
RECAPTCHA_SITE_KEY=<PUBLIC_KEY>
RECAPTCHA_SECRET_KEY=<SECRET_KEY>

# Ollama
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama2:latest

# Redis (for rate limiting & sessions)
REDIS_URL=<REDIS_CONNECTION_STRING>

# Storage (for PDF reports)
STORAGE_PROVIDER=oracle_cloud_object_storage
STORAGE_BUCKET=gokushield-reports

# Monitoring
LOG_LEVEL=info
SENTRY_DSN=<OPTIONAL_SENTRY_DSN>
```

## Vercel Configuration

### vercel.json for Frontend
```json
{
  "version": 2,
  "builds": [
    {
      "src": "index.html",
      "use": "@vercel/static"
    }
  ],
  "routes": [
    {
      "src": "/(.*)",
      "dest": "/index.html"
    }
  ],
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "X-Frame-Options",
          "value": "DENY"
        },
        {
          "key": "X-Content-Type-Options",
          "value": "nosniff"
        },
        {
          "key": "Referrer-Policy",
          "value": "strict-origin-when-cross-origin"
        },
        {
          "key": "Permissions-Policy",
          "value": "geolocation=(), microphone=(), camera=()"
        }
      ]
    }
  ]
}
```

### vercel.json for Client Dashboard
```json
{
  "version": 2,
  "builds": [
    {
      "src": "client-dashboard.html",
      "use": "@vercel/static"
    }
  ],
  "routes": [
    {
      "src": "/(.*)",
      "dest": "/client-dashboard.html"
    }
  ]
}
```

### vercel.json for Admin Panel
```json
{
  "version": 2,
  "builds": [
    {
      "src": "admin-panel.html",
      "use": "@vercel/static"
    }
  ],
  "routes": [
    {
      "src": "/(.*)",
      "dest": "/admin-panel.html"
    }
  ]
}
```

## Deployment Steps

### 1. Deploy Backend (Oracle Cloud)
```bash
cd backend
pip install -r requirements.txt
# Set environment variables
python app.py
# Backend runs on https://api.gokushield.com
```

### 2. Deploy Frontend (Vercel)
```bash
# Website
cd frontend
vercel --prod
# Set domain: www.gokushield.com

# Client Dashboard
cd client-dashboard
vercel --prod
# Set wildcard domain: *.gokushield.com

# Admin Panel
cd admin-panel
vercel --prod
# Set domain: admin.gokushield.com
```

### 3. Configure DNS
```
www.gokushield.com → Vercel (frontend)
*.gokushield.com → Vercel (client dashboards)
admin.gokushield.com → Vercel (admin panel)
api.gokushield.com → Oracle Cloud (backend)
```

## Rate Limiting

```yaml
RATE_LIMITS:
  - /api/audit/submit: 1 per day per IP
  - /api/scanner/headers: 10 per hour per IP
  - /api/forms/*: 5 per hour per IP
  - Admin endpoints: No rate limit (MFA protected)
```

## CORS Configuration

```yaml
CORS_ALLOWED_ORIGINS:
  - https://www.gokushield.com
  - https://*.gokushield.com
  - https://admin.gokushield.com
CORS_ALLOW_CREDENTIALS: true
CORS_MAX_AGE: 86400
```

## Monitoring & Logging

```yaml
LOG_TARGETS:
  - Console (production)
  - File: /var/log/gokushield/app.log
  - Sentry (errors only)

METRICS:
  - Audit submissions per day
  - Active users
  - Paid conversions
  - Scanner performance
  - Ollama response times
  - API error rates
```

## Production Hardening Checklist

- [x] All secrets in environment variables (not in code)
- [x] HTTPS only (no HTTP)
- [x] JWT secrets are unique and strong
- [x] MFA enforced for admin
- [x] Rate limiting enabled
- [x] CORS properly configured
- [x] Security headers enabled
- [x] No sensitive data in logs
- [x] Database connections pooled
- [x] Error messages sanitized (no stack traces to users)
- [x] Input validation on all endpoints
- [x] reCAPTCHA on public forms
- [x] Audit system enforces one-per-domain rule
- [x] Sessions isolated by domain
- [x] Ollama configured for stateless inference only

---

**END OF CONFIGURATION MAPPING**

For actual backend implementation, refer to:
- `/backend/app.py` (main application)
- `/backend/api/` (API endpoints)
- `/backend/ai/` (AI engine integration)
