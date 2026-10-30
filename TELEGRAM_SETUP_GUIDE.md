# Telegram Bot Setup Guide — GokuShield & JK TECH AI Institute

This covers both bots end to end: creating them with BotFather, filling in
every environment variable, and running them via Docker Compose. Follow it
in order — each numbered step depends on the one before it.

---

## Part 1 — Create your bots with BotFather

You need **two separate bots** (they're different products with different
commands). Repeat this twice.

1. Open Telegram, search for **@BotFather**, and start a chat.
2. Send `/newbot`.
3. Give it a display name when asked — e.g. `GokuShield Security` or
   `JK TECH AI Institute`. This can have spaces and isn't the @handle.
4. Give it a username when asked — must end in `bot`, e.g.
   `GokuShieldSecurity_bot` or `JKTechInstitute_bot`. This must be globally
   unique on Telegram; if it's taken, try a variant.
5. BotFather replies with a token that looks like:
   `123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw`
   **This is your `TELEGRAM_BOT_TOKEN`.** Copy it somewhere safe — anyone
   with this token can control the bot as if they were you.
6. Optional but recommended, still in the BotFather chat:
   - `/setdescription` — shown before someone starts the bot
   - `/setabouttext` — shown on the bot's profile
   - `/setuserpic` — upload a logo
   - `/setcommands` — paste a command list so Telegram autocompletes them.
     For GokuShield:
     ```
     scan - Run a free security audit
     status - Check a scan's result
     pending - (admin) list remediation queue
     approve - (admin) approve a remediation
     reject - (admin) reject a remediation
     help - Show available commands
     ```
     For JK TECH AI Institute:
     ```
     register - Create an account
     login - Log in
     courses - Browse available courses
     classroom - Enter your active classroom
     voice_on - Enable spoken replies to typed questions
     voice_off - Disable spoken replies to typed questions
     certs - View your certificates
     portfolio - View your project portfolio
     demo - Try a demo classroom
     help - Show available commands
     ```

You now have two tokens. Keep this chat open — you'll paste these into
`.env` files next.

---

## Part 2 — Find your Telegram numeric user ID (for admin access)

GokuShield's bot restricts `/pending`, `/approve`, `/reject` to specific
Telegram user IDs — not usernames, since usernames can change.

1. Search for **@userinfobot** on Telegram, start a chat, send any message.
2. It replies with your numeric ID, e.g. `Id: 987654321`.
3. Save this — it goes in `ADMIN_TELEGRAM_IDS` (comma-separated if you want
   more than one admin).

---

## Part 3 — GokuShield bot setup

### 3.1 Fill in the environment file

```bash
cd gokushield-v1.0-full-deployment/telegram-bot
cp .env.example .env
nano .env
```

Fill in:

| Variable | Value |
|---|---|
| `TELEGRAM_BOT_TOKEN` | From Part 1 (GokuShield bot) |
| `GOKUSHIELD_API_URL` | `http://backend:5000` if running via the main `docker-compose.yml` (default — leave as-is). If you run the bot standalone against a deployed backend, use that public URL instead. |
| `ADMIN_TELEGRAM_IDS` | Your numeric ID(s) from Part 2 |
| `GOKUSHIELD_ADMIN_EMAIL` | An existing GokuShield admin account's email |
| `GOKUSHIELD_ADMIN_PASSWORD` | That admin account's password |

The bot logs into the real GokuShield admin API with these credentials —
it doesn't get separate elevated access. If you haven't created an admin
account yet, do that through the normal backend flow first.

### 3.2 Run it

The bot is already wired into the main `docker-compose.yml` as the
`telegram-bot` service, alongside the backend, so from the project root:

```bash
docker compose up -d --build telegram-bot
docker compose logs -f telegram-bot
```

You should see `GokuShield bot starting (polling mode)...` in the logs.

### 3.3 Test it

In Telegram, open your GokuShield bot and send `/start`. Try:
- `/scan example.com` — queues a real scan against your backend
- `/status <scan_id>` — the ID it gave you
- Send any plain message — goes to the security chatbot
- `/pending` — as an admin, lists the remediation queue

If `/scan` replies "Couldn't reach the scanning service," the backend
isn't reachable at `GOKUSHIELD_API_URL` — check `docker compose ps` and
`docker compose logs backend`.

### 3.4 Note on scope

This bot deliberately does **not** apply remediations to your live
infrastructure — `/approve` only records a decision via the admin API,
the same as clicking approve anywhere else would. See
`STATUS_REPORT.md` for why that's intentional.

---

## Part 4 — JK TECH AI Institute bot setup

### 4.1 Fill in the environment file

```bash
cd jktech-remediated
cp .env.example .env    # if not present, create it from README.md's variable list
nano .env
```

At minimum, for the bot itself to start:

| Variable | Value |
|---|---|
| `TELEGRAM_BOT_TOKEN` | From Part 1 (AI Institute bot) |
| `TELEGRAM_WEBHOOK_URL` | Leave unset to use polling (simplest for first run); set to your public HTTPS domain later if you want webhook mode |
| `DATABASE_URL` / `DATABASE_URL_SYNC` | Your Postgres connection strings |
| `REDIS_URL`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND` | Redis connection strings |
| `OPENAI_API_KEY` | **Required** — powers both the AI teacher and the new voice features (Whisper for speech-to-text, TTS for spoken replies). Get one at platform.openai.com. |
| `SMTP_*` | Needed for OTP/registration emails |
| `CERT_ISSUER_URL`, `CERT_SECRET_KEY` | Required — deployment fails without these (see README.md) |
| `SECRET_KEY`, `ENCRYPTION_KEY`, `ADMIN_SECRET_KEY` | Generate with `openssl rand -hex 32` each |

Payment variables (`PAYPAL_*`, `GOOGLE_PAY_*`) are only needed if you're
taking real payments — leave placeholders if you're testing the classroom
flow first.

### 4.2 Run it

```bash
docker compose up -d --build
docker compose exec bot python3 -c "
import asyncio
from src.database.engine import init_db_engine, create_all_tables
from src.config import settings
init_db_engine(settings.DATABASE_URL)
asyncio.run(create_all_tables())
print('Database ready.')
"
```

### 4.3 Test the voice features specifically

1. In Telegram, `/register` to create an account, then `/login`.
2. `/demo` to enter a demo classroom, or enroll in a real course.
3. **Type** a question — you get a text reply. Send `/voice_on`, ask
   again — now you also get a spoken reply (OpenAI TTS).
4. **Record and send a voice note** asking a question — the bot
   transcribes it (OpenAI Whisper), answers, and always replies with
   voice for a voice question (regardless of the `/voice_on` toggle).
5. If transcription or speech fails, check `OPENAI_API_KEY` is valid and
   has API credit — the bot falls back to a text-only error rather than
   hanging.

### 4.4 Feeding it your own course material

As an admin, you now have three ingestion endpoints (previously missing —
added in this pass):

```bash
# YouTube video
curl -X POST https://your-admin-domain/admin/knowledge/youtube \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"course_id": "...", "video_url": "https://youtube.com/watch?v=...", "title": "Intro to X", "approved_topics": ["topic1", "topic2"]}'

# Raw text
curl -X POST https://your-admin-domain/admin/knowledge/text \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"course_id": "...", "text_content": "...", "title": "Notes", "approved_topics": ["topic1"]}'

# PDF
curl -X POST https://your-admin-domain/admin/knowledge/pdf \
  -H "Authorization: Bearer <admin_token>" \
  -F "course_id=..." -F "title=Textbook Ch.1" -F "approved_topics=topic1,topic2" \
  -F "file=@/path/to/file.pdf"
```

Every ingested item lands as **pending** — it won't reach students or the
AI teacher until you approve it:

```bash
GET  /admin/knowledge/pending
POST /admin/knowledge/decide   {"knowledge_id": "...", "decision": "approve"}
```

This approval gate is deliberate — it's what keeps the AI teacher's
"knowledge base" to only what you've actually vetted, and it's why the
system can honestly say it teaches from approved material.

---

## Part 5 — Webhook vs. polling (production note)

Both bots default to **polling** (they ask Telegram for updates), which
works anywhere with outbound internet and needs no public HTTPS endpoint —
good for getting started.

For production at scale, **webhook mode** is more efficient (Telegram
pushes updates to you instead): set `TELEGRAM_WEBHOOK_URL` to a public
HTTPS domain pointing at your deployment, and your reverse proxy (Nginx,
Caddy, etc.) needs to route that path to the bot service. GokuShield's
bot in this package is polling-only for now — switching it to webhook
mode is a small, contained change if you want it once you're ready to
scale past polling.

---

## Common issues

| Symptom | Likely cause |
|---|---|
| Bot doesn't respond at all | Wrong/expired token, or the container isn't running — check `docker compose logs <service>` |
| "Couldn't reach the scanning/admin service" | Backend container down, or `GOKUSHIELD_API_URL` wrong |
| Voice replies never arrive | `OPENAI_API_KEY` missing/invalid, or out of API credit |
| `/pending` says "admin-only" | Your Telegram numeric ID isn't in `ADMIN_TELEGRAM_IDS` — re-check Part 2 |
| Registration emails never arrive | `SMTP_*` variables wrong — test with a throwaway Gmail app password first |
