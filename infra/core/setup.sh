#!/usr/bin/env bash
# one-time setup for the core server. run as root:
#   ADMIN_PUBKEY="ssh-ed25519 AAAA... you@pc" bash infra/core/setup.sh
# without ADMIN_PUBKEY it copies root's authorized_keys.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

setup_ufw() {
  log "ufw"
  ufw --force reset >/dev/null
  ufw default deny incoming
  # core talks to tiger data, the llm api, serpapi and let's encrypt
  ufw default allow outgoing

  ufw allow 80/tcp comment 'caddy http + acme'
  ufw allow 443/tcp comment 'caddy https'
  ufw allow "$ADMIN_PORT/tcp" comment 'admin ssh'

  ufw --force enable
  ufw status verbose
}

main() {
  require_root
  apt_base
  create_admin
  harden_ssh
  install_docker
  enable_unattended
  enable_fail2ban
  setup_ufw
  finish_message
}

main "$@"
