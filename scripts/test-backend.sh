#!/usr/bin/env bash
set -euo pipefail
smon_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
smon_temp=$(mktemp -d /tmp/smon-test.XXXXXXXX)
smon_container="smon-test-$(basename "$smon_temp" | tr '[:upper:]' '[:lower:]')"
cleanup() {
  docker rm -f "$smon_container" >/dev/null 2>&1 || true
  rm -rf -- "$smon_temp"
}
trap cleanup EXIT
umask 077
python3 - "$smon_temp" <<'PY'
import base64, pathlib, secrets, sys
root = pathlib.Path(sys.argv[1])
(root / 'password').write_text(secrets.token_hex(24))
(root / 'key').write_bytes(base64.urlsafe_b64encode(secrets.token_bytes(32)))
(root / 'setup_token').write_text(secrets.token_urlsafe(32))
PY
docker run --detach --rm --name "$smon_container" \
  --label app=apache-status-monitor-test \
  --publish 127.0.0.1::5432 --mount "type=bind,source=$smon_temp/password,target=/run/secrets/password,readonly" \
  --env POSTGRES_USER=smon_test --env POSTGRES_DB=smon_test \
  --env POSTGRES_PASSWORD_FILE=/run/secrets/password \
  postgres:18-alpine@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2 >/dev/null
for smon_attempt in $(seq 1 30); do
  if docker exec "$smon_container" pg_isready -U smon_test -d smon_test >/dev/null 2>&1; then break; fi
  sleep 1
done
smon_port=$(docker port "$smon_container" 5432/tcp)
export SMON_ENVIRONMENT=testing SMON_PUBLIC_ORIGIN=http://localhost:4173
export SMON_ENCRYPTION_KEY_FILE="$smon_temp/key"
export SMON_SETUP_TOKEN_FILE="$smon_temp/setup_token"
export SMON_DATABASE_URL="postgresql+psycopg://smon_test:$(cat "$smon_temp/password")@127.0.0.1:${smon_port##*:}/smon_test"
export SMON_ALLOWED_MONITOR_ORIGINS='["https://web.example.test","http://metrics.example.test"]'
export SMON_ALLOWED_HTTP_ORIGINS='["http://metrics.example.test"]'
cd "$smon_root/backend"
.venv/bin/alembic upgrade head
.venv/bin/alembic check
.venv/bin/pytest -q --tb=short
.venv/bin/alembic downgrade base
.venv/bin/alembic upgrade head
.venv/bin/alembic check
if [ "${SMON_RUN_E2E:-0}" = 1 ]; then
  export SMON_E2E_PASSWORD
  SMON_E2E_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
  cd "$smon_root/frontend"
  npm run test:e2e
fi
