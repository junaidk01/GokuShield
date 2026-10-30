#!/bin/sh
set -e

# Wait for the database to accept connections before running migrations.
python - <<'PYEOF'
import os, sys, time
import psycopg2

url = os.environ.get("DATABASE_URL")
if not url or not url.startswith("postgresql"):
    sys.exit(0)  # Oracle or unset: skip the wait, migrations step will surface real errors

for attempt in range(30):
    try:
        psycopg2.connect(url).close()
        sys.exit(0)
    except Exception:
        time.sleep(2)
print("Database did not become ready in time", file=sys.stderr)
sys.exit(1)
PYEOF

if [ "$RUN_MIGRATIONS" = "1" ]; then
    echo "Running database migrations..."
    flask db upgrade
fi

exec "$@"
