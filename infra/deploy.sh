#!/usr/bin/env bash
# deploy the latest main on this server:
#   sudo bash infra/deploy.sh <trap|core> [env-file]
# env-file defaults to /opt/hacktx2026/.env and gets copied to infra/<role>/.env.
# runs as root because root owns the github deploy key.
set -euo pipefail

STATE_DIR=/var/lib/hacktx

step() { printf '\n==> %s\n' "$*"; }
die() { printf '\nerror: %s\n' "$*" >&2; exit 1; }

# value of KEY in a dotenv file, quotes stripped
env_get() {
  { grep -E "^$1=" "$2" || true; } | tail -n 1 | cut -d= -f2- | sed -E "s/^\"(.*)\"\$/\1/; s/^'(.*)'\$/\1/"
}

pull() {
  local role=$1 before after
  before="$(git rev-parse HEAD)"
  step "pull latest main"
  git fetch --quiet origin main
  git checkout --quiet main
  git pull --ff-only --quiet origin main
  after="$(git rev-parse HEAD)"
  install -d -m 700 "$STATE_DIR"
  # previous-<role> is what rollback goes back to
  if [[ $before != "$after" ]]; then
    echo "$before" > "$STATE_DIR/previous-$role"
  fi
  echo "$(date -u +%FT%TZ) $role $after" >> "$STATE_DIR/deploys.log"
  echo "$before -> $after"
}

copy_env() {
  local role=$1 src=$2 dst=$3
  step "env: $src -> $dst"
  [[ -f $src ]] || die "no env file at $src"
  if [[ "$(realpath "$src")" != "$(realpath -m "$dst")" ]]; then
    install -m 600 "$src" "$dst"
  fi
  chmod 600 "$dst"
  # a .env saved on windows has crlf endings
  sed -i 's/\r$//' "$dst"

  local need missing=()
  if [[ $role == trap ]]; then
    need=(CORE_URL INGEST_TOKEN)
  else
    need=(DOMAIN INGEST_TOKEN IP_HASH_SALT TIGER_DATABASE_URL REDIS_PASSWORD)
  fi
  for key in "${need[@]}"; do
    [[ -n "$(env_get "$key" "$dst")" ]] || missing+=("$key")
  done
  (( ${#missing[@]} == 0 )) || die "missing in $src: ${missing[*]}"

  if [[ $role == core ]]; then
    local geo
    geo="$(env_get GEOIP_HOST_DIR "$dst")"
    geo="${geo:-/opt/geoip}"
    for f in GeoLite2-City.mmdb GeoLite2-ASN.mmdb; do
      [[ -f $geo/$f ]] || die "missing $geo/$f"
    done
    # brain runs as uid 10001 and has to read them
    chmod a+rx "$geo"
    chmod a+r "$geo/GeoLite2-City.mmdb" "$geo/GeoLite2-ASN.mmdb"
  fi
}

# every container running, and healthy if it has a healthcheck
wait_healthy() {
  local deadline=$((SECONDS + 150)) bad=""
  step "waiting for containers"
  while (( SECONDS < deadline )); do
    bad="$("${COMPOSE[@]}" ps -a --format '{{.Service}} {{.State}} {{.Health}}' \
      | awk '$2 != "running" || ($3 != "" && $3 != "healthy")')"
    [[ -z $bad ]] && return 0
    sleep 3
  done
  echo "not ready:"
  echo "$bad"
  return 1
}

health_core() {
  local domain=$1 i out
  step "https://api.$domain/health (through caddy)"
  for i in $(seq 1 20); do
    if out="$(curl -fsS --max-time 10 --resolve "api.$domain:443:127.0.0.1" "https://api.$domain/health" 2>&1)"; then
      echo "$out"
      return 0
    fi
    sleep 3
  done
  echo "$out"
  return 1
}

health_trap() {
  step "ssh banner from inside the container"
  "${COMPOSE[@]}" exec -T trap python -c \
    "import socket; s = socket.create_connection(('127.0.0.1', 22), 3); print(s.recv(64).decode().strip())"
}

main() {
  local role="${1:-}" env_src="${2:-/opt/hacktx2026/.env}"
  [[ $role == trap || $role == core ]] || die "usage: sudo bash infra/deploy.sh <trap|core> [env-file]"
  [[ $EUID -eq 0 ]] || die "run with sudo, root owns the deploy key"

  local repo dir
  repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  dir="$repo/infra/$role"
  cd "$repo"

  # pull, then rerun the fresh copy of this script so new deploy logic applies right away
  if [[ -z ${HACKTX_PULLED:-} ]]; then
    pull "$role"
    HACKTX_PULLED=1 exec bash "$repo/infra/deploy.sh" "$@"
  fi

  copy_env "$role" "$env_src" "$dir/.env"

  COMPOSE=(docker compose -f "$dir/docker-compose.yml")
  step "docker compose up -d --build ($role)"
  "${COMPOSE[@]}" up -d --build --remove-orphans

  local ok=1
  wait_healthy || ok=0
  if (( ok )); then
    if [[ $role == core ]]; then
      health_core "$(env_get DOMAIN "$dir/.env")" || ok=0
    else
      health_trap || ok=0
    fi
  fi

  step "status"
  "${COMPOSE[@]}" ps
  if (( ! ok )); then
    step "last 50 log lines"
    "${COMPOSE[@]}" logs --tail 50 --no-color
    die "deploy of $(git rev-parse --short HEAD) is not healthy. see infra/README.md for rollback"
  fi
  step "deployed $role at $(git rev-parse --short HEAD)"
}

# everything runs from main, so git pull rewriting this file can't break the running copy
main "$@"
