"""
GokuShield Telegram Bot
========================

Scoped, honest capability set — a thin wrapper around GokuShield's existing
public/authenticated API, not a reimplementation of it. It does:

  - Free security audits (/scan <url>) via the same audit-first flow the
    website uses (one audit per domain per 24h — same limit, enforced
    server-side, not duplicated here)
  - Result lookup (/status <scan_id>)
  - A conversational security Q&A chat (any text message not starting with /)
  - Admin-only: list and act on the remediation approval queue
    (/pending, /approve <id>, /reject <id>) — see api/admin.py's
    /api/admin/remediations endpoints. Nothing here applies a fix to your
    infrastructure automatically; approving just records a decision.

Requires GOKUSHIELD_API_URL to point at a running backend (see
docker-compose.yml — usually http://backend:5000 inside the compose
network, or your public domain if run standalone).
"""
import logging
import os

from telegram import Update
from telegram.ext import (
    Application, CommandHandler, MessageHandler, ContextTypes, filters
)

from client import GokuShieldClient
from config import BotConfig

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    level=logging.INFO
)
logger = logging.getLogger("gokushield-bot")

config = BotConfig.from_env()
api = GokuShieldClient(config.api_url)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️ *GokuShield Security Bot*\n\n"
        "I run API/website security scans grounded in the OWASP API "
        "Security Top 10, and I can answer security questions.\n\n"
        "*Commands:*\n"
        "/scan <url or domain> — run a free security audit\n"
        "/status <scan_id> — check a scan's result\n"
        "/help — show this again\n\n"
        "Or just send me a message to ask a security question.\n\n"
        "_One free audit per domain per 24 hours — same limit as the "
        "website, enforced by the same backend._",
        parse_mode="Markdown",
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await start(update, context)


async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Usage: `/scan example.com` or `/scan https://api.example.com`",
            parse_mode="Markdown",
        )
        return

    target = context.args[0].strip()
    chat_id = update.effective_chat.id

    # GokuShield's audit flow needs an email on file for the lead record —
    # Telegram doesn't give us one, so we use a bot-scoped placeholder tied
    # to the chat ID. This means audit-permission limits are tracked per
    # Telegram chat, not merged with any real email-based account the
    # person might also have on the website.
    placeholder_email = f"telegram-{chat_id}@bot.gokushield.local"

    await update.message.reply_text(f"🔍 Starting scan of `{target}`...", parse_mode="Markdown")

    try:
        result = await api.start_free_audit(email=placeholder_email, target=target)
    except Exception as e:
        logger.error(f"[SCAN] request failed: {e}")
        await update.message.reply_text(
            "⚠️ Couldn't reach the scanning service. Please try again shortly."
        )
        return

    if "error" in result:
        reason = result.get("reason") or result.get("error")
        await update.message.reply_text(f"❌ {reason}")
        return

    scan_id = result.get("scan_id")
    context.chat_data.setdefault("scan_ids", []).append(scan_id)

    await update.message.reply_text(
        f"✅ Scan queued (ID: `{scan_id}`).\n"
        f"This runs against the OWASP API Security Top 10 and common "
        f"misconfiguration checks — usually done within a minute or two.\n\n"
        f"Check it with `/status {scan_id}`",
        parse_mode="Markdown",
    )


async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: `/status <scan_id>`", parse_mode="Markdown")
        return

    try:
        scan_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("scan_id must be a number.")
        return

    try:
        result = await api.get_audit_result(scan_id)
    except Exception as e:
        logger.error(f"[STATUS] request failed: {e}")
        await update.message.reply_text("⚠️ Couldn't reach the scanning service.")
        return

    if "error" in result:
        await update.message.reply_text(f"❌ {result['error']}")
        return

    status = result.get("status")
    if status == "completed":
        risk = result.get("risk_score", "N/A")
        findings = result.get("findings") or []
        summary = result.get("technical_summary") or result.get("analysis") or "No summary available."

        text = f"📋 *Scan #{scan_id} — Complete*\n\n" \
               f"Risk score: {risk}\n" \
               f"Findings: {len(findings)}\n\n" \
               f"{summary[:1500]}"
        await update.message.reply_text(text, parse_mode="Markdown")
    elif status == "failed":
        await update.message.reply_text(f"❌ Scan failed: {result.get('error', 'unknown error')}")
    else:
        await update.message.reply_text(f"⏳ Scan #{scan_id} is still {status}. Check again shortly.")


async def chat_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Any non-command text goes to the security chatbot."""
    message = update.message.text
    history = context.chat_data.get("chat_history", [])

    try:
        result = await api.chat(message=message, history=history)
    except Exception as e:
        logger.error(f"[CHAT] request failed: {e}")
        await update.message.reply_text(
            "⚠️ The security assistant is temporarily unavailable."
        )
        return

    reply = result.get("response") or result.get("message") or "I didn't get a usable response — please try rephrasing."

    history.append({"role": "user", "content": message})
    history.append({"role": "assistant", "content": reply})
    context.chat_data["chat_history"] = history[-20:]

    await update.message.reply_text(reply)


async def pending_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin-only: list pending remediation actions."""
    tg_id = update.effective_user.id
    if tg_id not in config.admin_telegram_ids:
        await update.message.reply_text("This command is admin-only.")
        return

    try:
        result = await api.list_pending_remediations(config.admin_email, config.admin_password)
    except Exception as e:
        logger.error(f"[PENDING] request failed: {e}")
        await update.message.reply_text("⚠️ Couldn't reach the admin API.")
        return

    actions = result.get("actions", [])
    if not actions:
        await update.message.reply_text("✅ No pending remediation actions.")
        return

    lines = ["📋 *Pending Remediation Actions*\n"]
    for a in actions[:15]:
        lines.append(
            f"`#{a['id']}` — {a['check_name']} (severity: {a.get('severity', 'n/a')})\n"
            f"  Scan #{a['scan_id']} · `/approve {a['id']}` · `/reject {a['id']}`"
        )
    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")


async def _review_action(update: Update, context: ContextTypes.DEFAULT_TYPE, status: str):
    tg_id = update.effective_user.id
    if tg_id not in config.admin_telegram_ids:
        await update.message.reply_text("This command is admin-only.")
        return

    if not context.args:
        await update.message.reply_text(f"Usage: `/{status} <action_id>`", parse_mode="Markdown")
        return

    try:
        action_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("action_id must be a number.")
        return

    try:
        result = await api.review_remediation(config.admin_email, config.admin_password, action_id, status)
    except Exception as e:
        logger.error(f"[REVIEW] request failed: {e}")
        await update.message.reply_text("⚠️ Couldn't reach the admin API.")
        return

    if "error" in result:
        await update.message.reply_text(f"❌ {result['error']}")
        return

    await update.message.reply_text(
        f"✅ Action #{action_id} marked *{status}*.\n"
        f"Reminder: this only records the decision — applying an "
        f"`approved` fix to your actual infrastructure is still a manual step.",
        parse_mode="Markdown",
    )


async def approve_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await _review_action(update, context, "approved")


async def reject_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await _review_action(update, context, "rejected")


def main():
    if not config.telegram_token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not set.")

    app = Application.builder().token(config.telegram_token).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("scan", scan_command))
    app.add_handler(CommandHandler("status", status_command))
    app.add_handler(CommandHandler("pending", pending_command))
    app.add_handler(CommandHandler("approve", approve_command))
    app.add_handler(CommandHandler("reject", reject_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, chat_message))

    logger.info("GokuShield bot starting (polling mode)...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
