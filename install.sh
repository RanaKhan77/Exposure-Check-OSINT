#!/usr/bin/env bash
# ============================================================================
# Exposure-Check-OSINT (Community Edition) — one-command setup
#
#   git clone https://github.com/RanaKhan77/Exposure-Check-OSINT.git
#   cd Exposure-Check-OSINT
#   ./install.sh
#
# What it does (all automatic):
#   1. Checks Docker + Docker Compose v2
#   2. Creates .env with a RANDOM admin password (no manual editing needed)
#   3. Builds + boots the single-container stack (Apache + PHP + SQLite)
#   4. Runs migrations inside the container
#   5. Health-checks and prints your sign-in URL + password
#
# Optional flags:
#   --port 9090     HTTP port (default 8080)
#   --password X    set a specific admin password instead of a random one
# ============================================================================
set -euo pipefail

say()  { printf '\n==> %s\n' "$*"; }
ok()   { printf '     %s\n' "$*"; }
die()  { printf '     ERROR: %s\n' "$*" >&2; exit 1; }

COMPOSE="docker compose --project-directory . -f docker/docker-compose.yml"
APP_PORT="8080"; ADMIN_PASSWORD=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)     APP_PORT="${2:?}"; shift 2 ;;
    --password) ADMIN_PASSWORD="${2:?}"; shift 2 ;;
    *) die "Unknown option: $1 (supported: --port, --password)" ;;
  esac
done

say "Checking prerequisites"
command -v docker >/dev/null 2>&1 || die "Docker is not installed. Install it first: https://docs.docker.com/engine/install/"
docker info >/dev/null 2>&1 || die "Docker daemon is not running (or you lack permissions). Start it / re-login, then re-run."
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required (plugin: 'docker compose version' must work)."
[[ -f docker/docker-compose.yml ]] || die "Run this script from the repository root."
ok "Docker $(docker --version | cut -d, -f1) + Compose v2"

say "Creating .env"
[[ -f .env.example ]] || die ".env.example not found."
if [[ -f .env ]]; then
  ok ".env already exists — keeping it (delete .env to re-install fresh)"
else
  if [[ -z "$ADMIN_PASSWORD" ]]; then
    ADMIN_PASSWORD="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 20)"
  fi
  # REPLACE the placeholder line - never append (phpdotenv is first-wins)
  sed -e "s|^APP_PORT=.*|APP_PORT=${APP_PORT}|" \
      -e "s|^ADMIN_PASSWORD=.*|ADMIN_PASSWORD=${ADMIN_PASSWORD}|" \
      .env.example > .env
  ok "Generated random admin password (also shown at the end)"
fi

say "Building the image (first build takes 1-3 minutes)"
$COMPOSE build

say "Booting the container"
$COMPOSE up -d

say "Running migrations inside the container"
$COMPOSE exec -T app php artisan migrate --force || true

say "Waiting for the health check"
for i in $(seq 1 30); do
  if $COMPOSE exec -T app curl -fsS http://localhost/up >/dev/null 2>&1; then
    ok "Healthy"; break
  fi
  [[ $i -eq 30 ]] && die "Container did not become healthy in 30s — check: $COMPOSE logs"
  sleep 2
done

echo
echo "=============================================================="
echo " Exposure-Check-OSINT is running"
echo ""
echo "   Sign-in URL : http://localhost:${APP_PORT}/login"
if [[ -f .env ]] && grep -q '^ADMIN_PASSWORD=' .env; then
  echo "   Password    : $(grep '^ADMIN_PASSWORD=' .env | cut -d= -f2-)"
fi
echo ""
echo "   Data lives in docker volumes ec-db + ec-storage."
echo "   Stop:  $COMPOSE down"
echo "   Logs:  $COMPOSE logs -f"
echo "=============================================================="
