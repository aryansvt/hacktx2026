#!/usr/bin/env bash
# one-time setup for the trap server. run as root:
#   ADMIN_PUBKEY="ssh-ed25519 AAAA... you@pc" bash infra/trap/setup.sh
# without ADMIN_PUBKEY it copies root's authorized_keys.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

AFTER_RULES=/etc/ufw/after.rules
BEGIN_MARK="# BEGIN hacktx docker egress"
END_MARK="# END hacktx docker egress"

# docker's forwarded traffic never hits ufw's outbound rules, so containers get
# their own lock in DOCKER-USER: new connections only to dns and https.
# attacker -> container 22 comes in on the public interface, so it isn't matched.
docker_egress_block() {
  cat <<EOF
$BEGIN_MARK
# managed by infra/trap/setup.sh
*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -i docker0 -o docker0 -j RETURN
-A DOCKER-USER -i br-+ -o br-+ -j RETURN
-A DOCKER-USER -i docker0 -p udp --dport 53 -j RETURN
-A DOCKER-USER -i docker0 -p tcp --dport 53 -j RETURN
-A DOCKER-USER -i docker0 -p tcp --dport 443 -j RETURN
-A DOCKER-USER -i br-+ -p udp --dport 53 -j RETURN
-A DOCKER-USER -i br-+ -p tcp --dport 53 -j RETURN
-A DOCKER-USER -i br-+ -p tcp --dport 443 -j RETURN
-A DOCKER-USER -i docker0 -j DROP
-A DOCKER-USER -i br-+ -j DROP
-A DOCKER-USER -j RETURN
COMMIT
$END_MARK
EOF
}

setup_ufw() {
  log "ufw"
  ufw --force reset >/dev/null
  ufw default deny incoming
  ufw default deny outgoing

  ufw allow 22/tcp comment 'honeypot ssh'
  ufw allow 80/tcp comment 'honeypot web'
  ufw allow "$ADMIN_PORT/tcp" comment 'admin ssh'

  ufw allow out 53 comment 'dns'
  ufw allow out 443/tcp comment 'https: core, llm, git, docker'
  # host only, the container can't use these
  ufw allow out 80/tcp comment 'apt mirrors'
  ufw allow out 123/udp comment 'ntp'
  ufw allow out 67/udp comment 'dhcp renew'

  # reset restores the stock after.rules, so the block goes in after it
  sed -i "/^$BEGIN_MARK\$/,/^$END_MARK\$/d" "$AFTER_RULES"
  docker_egress_block >> "$AFTER_RULES"

  ufw --force enable
  ufw status verbose
  echo
  iptables -S DOCKER-USER
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
