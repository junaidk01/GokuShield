# GokuShield AI v1.0 - Complete Deployment Guide

## 🎯 Overview

This is the **PRODUCTION-READY** deployment package for GokuShield AI v1.0.

**Version**: 1.0 (LOCKED - no version changes)  
**Architecture**: Audit-first, multi-tenant SaaS  
**AI Engine**: Ollama (local, stateless, inference-only)

---

## 📦 Package Contents

```
full-deployment/
├── frontend/
│   ├── index.html (modified website)
│   └── vercel.json
├── client-dashboard/
│   ├── client-dashboard.html
│   └── vercel.json
├── admin-panel/
│   ├── admin-panel.html
│   └── vercel.json
├── backend-config/
│   ├── backend-config.md (API mapping & configuration)
│   └── .env.template
└── README_DEPLOY.md (this file)

frontend-only/
└── (same structure, frontend files only)
```

---

## ✅ Changes Made to index.html

### 1. Offer Text Updated
- **Old**: "Limited Time Offer: Get 1 Million API Calls FREE for 14 Days!"
- **New**: "Limited offer: Our first 100 users get 10% off on our plans"

### 2. Field Renamed
- **Old**: "Organization Name"
- **New**: "Company Domain Name"

### 3. Fields Removed (ALL FORMS)
- ❌ "Selected Plan"
- ❌ "Number of APIs"
- ❌ "Number of APIs to Protect"
- ❌ "Number of APIs to Audit"

### 4. reCAPTCHA Added
- Google reCAPTCHA v3 script added
- Applied to all public forms
- **Action Required**: Replace `6LcExample_RECAPTCHA_SITE_KEY` with your actual key

### 5. Bug Fixes
- All existing bugs preserved (none were documented to fix)
- Responsive design maintained

---

## 🏗️ Architecture

### Domain Structure
```
www.gokushield.com          → Marketing + Free Audit (Vercel)
{company}.gokushield.com    → Client Dashboard (Vercel, wildcard)
admin.gokushield.com        → Admin Panel (Vercel, MFA enforced)
api.gokushield.com          → Backend API (Oracle Cloud)
```

### Session Isolation
- **www**: No auth cookies
- **{company}**: Client JWT only (role: client, tenant: company_domain)
- **admin**: Admin JWT + MFA session (completely isolated)

### Audit-First Enforcement
- No login before audit
- No dashboard before audit
- Free audit generates dashboard access
- One audit per company_domain (immutable)

---

## 🚀 Deployment Steps

### Prerequisites
- Vercel account (for frontend deployments)
- Oracle Cloud instance (for backend)
- Ollama installed on backend server
- Domain DNS access
- Google reCAPTCHA keys
- SMTP service for emails

### Step 1: Configure Environment

1. Copy `.env.template` to `.env`:
   ```bash
   cp backend-config/.env.template .env
   ```

2. Fill in all required values:
   - Database credentials
   - JWT secrets (generate with `openssl rand -hex 32`)
   - Email SMTP settings
   - reCAPTCHA keys
   - Storage credentials

3. **NEVER** commit `.env` to version control

### Step 2: Deploy Backend (Oracle Cloud)

1. SSH into your Oracle Cloud instance:
   ```bash
   ssh user@your-oracle-instance
   ```

2. Install dependencies:
   ```bash
   # Install Python 3.9+
   sudo apt update
   sudo apt install python3.9 python3-pip
   
   # Install Ollama
   curl https://ollama.ai/install.sh | sh
   
   # Pull required models
   ollama pull llama2:latest
   ```

3. Upload backend code (from production-locked package):
   ```bash
   scp -r backend/ user@your-oracle-instance:/opt/gokushield/
   ```

4. Install Python dependencies:
   ```bash
   cd /opt/gokushield/backend
   pip3 install -r requirements.txt
   ```

5. Set up environment variables:
   ```bash
   cp /path/to/.env /opt/gokushield/backend/.env
   ```

6. Run database migrations:
   ```bash
   python3 migrate.py
   ```

7. Start the backend:
   ```bash
   # Using gunicorn (production)
   gunicorn -w 4 -b 0.0.0.0:8000 app:app
   
   # Or using systemd service (recommended)
   sudo systemctl enable gokushield-backend
   sudo systemctl start gokushield-backend
   ```

8. Verify backend is running:
   ```bash
   curl http://localhost:8000/health
   ```

### Step 3: Deploy Frontend (Vercel)

#### 3a. Deploy Main Website

1. Navigate to frontend directory:
   ```bash
   cd frontend/
   ```

2. Replace reCAPTCHA key in `index.html`:
   ```bash
   sed -i 's/6LcExample_RECAPTCHA_SITE_KEY/YOUR_ACTUAL_SITE_KEY/g' index.html
   ```

3. Deploy to Vercel:
   ```bash
   vercel --prod
   ```

4. Set custom domain in Vercel dashboard:
   - Domain: `www.gokushield.com`
   - SSL: Auto-enabled

#### 3b. Deploy Client Dashboard

1. Navigate to client dashboard:
   ```bash
   cd client-dashboard/
   ```

2. Deploy to Vercel:
   ```bash
   vercel --prod
   ```

3. Set wildcard domain:
   - Domain: `*.gokushield.com`
   - This allows `company1.gokushield.com`, `company2.gokushield.com`, etc.

#### 3c. Deploy Admin Panel

1. Navigate to admin panel:
   ```bash
   cd admin-panel/
   ```

2. Deploy to Vercel:
   ```bash
   vercel --prod
   ```

3. Set admin domain:
   - Domain: `admin.gokushield.com`

### Step 4: Configure DNS

Add these DNS records to your domain registrar:

```
Type    Name        Value                           TTL
----    ----        -----                           ---
CNAME   www         cname.vercel-dns.com            3600
CNAME   *           cname.vercel-dns.com            3600
CNAME   admin       cname.vercel-dns.com            3600
A       api         <ORACLE_CLOUD_IP_ADDRESS>       3600
```

### Step 5: Configure SSL/TLS

1. Vercel handles SSL automatically for all frontend domains
2. For backend API, set up Let's Encrypt:
   ```bash
   sudo apt install certbot
   sudo certbot --nginx -d api.gokushield.com
   ```

### Step 6: Test Deployment

#### Test Website
```bash
curl -I https://www.gokushield.com
# Should return 200 OK
```

#### Test Backend API
```bash
curl https://api.gokushield.com/health
# Should return: {"status": "healthy"}
```

#### Test Client Dashboard
```bash
curl -I https://example.gokushield.com
# Should return 200 OK (serves client-dashboard.html)
```

#### Test Admin Panel
```bash
curl -I https://admin.gokushield.com
# Should return 200 OK
```

---

## 🔐 Security Checklist

- [ ] All secrets in `.env` (not in code)
- [ ] `.env` file has restricted permissions (600)
- [ ] JWT secrets are strong (32+ chars)
- [ ] HTTPS enforced on all domains
- [ ] MFA configured for admin access
- [ ] reCAPTCHA keys configured
- [ ] Rate limiting enabled
- [ ] CORS properly configured
- [ ] Security headers enabled (via Vercel)
- [ ] Database connection uses SSL
- [ ] Admin endpoints require MFA verification
- [ ] Session cookies are HttpOnly and Secure
- [ ] No wildcard sessions across domains

---

## 🎛️ Post-Deployment Configuration

### Create First Admin User

```bash
cd /opt/gokushield/backend
python3 scripts/create_admin.py
# Follow prompts to create admin user
```

### Configure MFA for Admin

1. Login to admin panel: `https://admin.gokushield.com`
2. Enter credentials
3. Scan QR code with Google Authenticator
4. Enter verification code
5. MFA is now enforced

### Test Free Audit Flow

1. Go to `https://www.gokushield.com`
2. Fill out "Free Audit" form
3. Verify:
   - reCAPTCHA validation works
   - Email is sent with dashboard credentials
   - Dashboard is accessible at `https://{company_domain}.gokushield.com`
   - Audit report is viewable and downloadable

---

## 📊 Monitoring & Logs

### Backend Logs
```bash
tail -f /var/log/gokushield/app.log
```

### Vercel Logs
```bash
vercel logs --prod
```

### Ollama Logs
```bash
sudo journalctl -u ollama -f
```

### Database Monitoring
- Use Oracle Cloud monitoring dashboard
- Set up alerts for connection pool exhaustion

---

## 🔧 Maintenance

### Backup Database
```bash
# Automated backups run daily at 2 AM (configured in .env)
# Manual backup:
python3 scripts/backup_db.py
```

### Update Ollama Model
```bash
ollama pull llama2:latest
sudo systemctl restart gokushield-backend
```

### Rotate JWT Secrets
```bash
# Generate new secrets
openssl rand -hex 32

# Update .env file
# Restart backend
sudo systemctl restart gokushield-backend
```

---

## 🐛 Troubleshooting

### Backend Not Starting
```bash
# Check logs
sudo journalctl -u gokushield-backend -n 50

# Common issues:
# - Database connection failed → Check DATABASE_URL
# - Ollama not running → sudo systemctl start ollama
# - Port already in use → Check with: lsof -i :8000
```

### Frontend Not Loading
```bash
# Check Vercel deployment status
vercel inspect <deployment-url>

# Re-deploy if needed
vercel --prod --force
```

### Emails Not Sending
```bash
# Test SMTP connection
python3 scripts/test_email.py

# Check logs for SMTP errors
grep "SMTP" /var/log/gokushield/app.log
```

### MFA Issues
```bash
# Reset MFA for admin user
python3 scripts/reset_mfa.py admin@gokushield.com
```

---

## 📞 Support

For issues or questions:
- Email: support@gokushield.com
- Documentation: https://docs.gokushield.com
- Status Page: https://status.gokushield.com

---

## 📄 License

GokuShield AI v1.0 - Proprietary  
© 2024 JK TECH. All rights reserved.

---

**END OF DEPLOYMENT GUIDE**
