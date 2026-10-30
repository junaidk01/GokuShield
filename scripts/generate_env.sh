#!/usr/bin/env bash
# Generates backend/.env from backend/.env.example with real random secrets
# filled in for every REPLACE_WITH_* placeholder. Run once before first deploy.
set -euo pipefail

cd "$(dirname "$0")/.."

SRC="backend/.env.example"
DST="backend/.env"

if [ -f "$DST" ]; then
    echo "backend/.env already exists — refusing to overwrite. Delete it first if you really want to regenerate." >&2
    exit 1
fi

cp "$SRC" "$DST"

fill() {
    local key="$1"
    local value
    value="$(openssl rand -hex 32)"
    # Portable in-place edit for both GNU and BSD sed
    sed -i.bak "s#${key}=REPLACE_WITH.*#${key}=${value}#" "$DST"
    rm -f "${DST}.bak"
}

grep -oE '^[A-Z_]+=REPLACE_WITH[A-Z_0-9]*' "$SRC" | cut -d= -f1 | while read -r key; do
    fill "$key"
done

chmod 600 "$DST"

echo "Wrote $DST with generated secrets."
echo "Still fill in manually: DATABASE_URL, EMAIL_* / SMTP creds, reCAPTCHA keys, and any third-party API keys."
