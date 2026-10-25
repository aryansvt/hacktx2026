#!/usr/bin/env bash
# shared setup steps for trap and core. sourced by infra/<role>/setup.sh.
# every step is safe to rerun.

ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PORT=2222
SSHD_DROPIN=/etc/ssh/sshd_config.d/00-hacktx.conf

export DEBIAN_FRONTEND=noninteractive
# keep needrestart from stopping to ask questions
export NEEDRESTART_SUSPEND=1

log() { printf '\n==> %s\n' "$*"; }
die() { printf '\nerror: %s\n' "$*" >&2; exit 1; }

require_root() {
  [[ $EUID -eq 0 ]] || die "run as root: sudo bash $0"
  grep -q 'VERSION_ID="24.04"' /etc/os-release || echo "warning: built for ubuntu 24.04"
}

public_ip() {
  ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}'
}

apt_base() {
  log "apt packages"
  apt-get update -q
  apt-get install -yq ca-certificates curl git ufw fail2ban python3-systemd unattended-upgrades
}

create_admin() {
  log "admin user: $ADMIN_USER"
  local keys="${ADMIN_PUBKEY:-}"
  if [[ -z $keys && -s /root/.ssh/authorized_keys ]]; then
    keys="$(grep -vE '^[[:space:]]*(#|$)' /root/.ssh/authorized_keys || true)"
    echo "no ADMIN_PUBKEY given, copying root's authorized_keys"
  fi
  [[ -n $keys ]] || die 'no ssh key. rerun with ADMIN_PUBKEY="ssh-ed25519 AAAA... you@pc"'

  id "$ADMIN_USER" &>/dev/null || useradd --create-home --shell /bin/bash "$ADMIN_USER"
  usermod -aG sudo "$ADMIN_USER"

  local home ak
  home="$(getent passwd "$ADMIN_USER" | cut -d: -f6)"
  ak="$home/.ssh/authorized_keys"
  install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$home/.ssh"
  touch "$ak"
  while IFS= read -r key; do
    [[ -z $key ]] && continue
    grep -qxF "$key" "$ak" || printf '%s\n' "$key" >> "$ak"
  done <<< "$keys"
  chown "$ADMIN_USER:$ADMIN_USER" "$ak"
  chmod 600 "$ak"
  ssh-keygen -lf "$ak" || die "$ak has no valid public key"

  # the account has no password, so sudo can't ask for one
  echo "$ADMIN_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/90-hacktx-admin
  chmod 440 /etc/sudoers.d/90-hacktx-admin
  visudo -cf /etc/sudoers.d/90-hacktx-admin >/dev/null || die "bad sudoers file"
}

# 24.04 starts sshd from ssh.socket, which ignores Port. use the plain service instead.
ssh_use_service() {
  if systemctl is-enabled --quiet ssh.socket 2>/dev/null || systemctl is-active --quiet ssh.socket; then
    systemctl disable --now ssh.socket
  fi
  rm -f /etc/systemd/system/ssh.service.d/00-socket.conf /etc/systemd/system/ssh.socket.d/addresses.conf
  systemctl daemon-reload
  systemctl enable ssh.service
}

sshd_restart() {
  /usr/sbin/sshd -t || die "sshd config is invalid, not restarting it"
  systemctl restart ssh.service
}

# stage 1: listen on 22 and 2222. no auth changes yet.
ssh_stage1() {
  log "sshd: listen on 22 and $ADMIN_PORT"
  ssh_use_service
  cat > "$SSHD_DROPIN" <<EOF
# hacktx: temporary. 22 goes away once $ADMIN_PORT is confirmed.
Port 22
Port $ADMIN_PORT
EOF
  if ufw status | grep -q '^Status: active'; then
    ufw allow "$ADMIN_PORT/tcp"
  fi
  sshd_restart
  ss -ltn | grep -E ":(22|$ADMIN_PORT) " || true
}

confirm_admin_login() {
  local ip
  ip="$(public_ip)"
  cat <<EOF

------------------------------------------------------------------
Keep this root session open. In a NEW terminal on your PC run:

  ssh -p $ADMIN_PORT -o PreferredAuthentications=publickey $ADMIN_USER@${ip:-<server-ip>} "sudo -n true && echo admin-ok"

It should print admin-ok. If it hangs, a Vultr firewall group is
probably blocking TCP $ADMIN_PORT. Nothing on port 22 has changed yet.
------------------------------------------------------------------
EOF
  local answer=""
  read -r -p "Type yes once you saw admin-ok: " answer < /dev/tty
  [[ $answer == yes ]] || die "not confirmed. port 22 is unchanged. fix it and rerun"
}

# stage 2: 2222 only, keys only, no root.
ssh_stage2() {
  log "sshd: port $ADMIN_PORT only, keys only, no root"
  # Port lines add up across files, so drop any in the main config
  sed -i -E 's/^[[:space:]]*Port[[:space:]]/#&/' /etc/ssh/sshd_config
  # 00- sorts first, and sshd keeps the first value it sees, so this beats 50-cloud-init.conf
  cat > "$SSHD_DROPIN" <<EOF
# hacktx admin ssh. port 22 belongs to the honeypot.
Port $ADMIN_PORT
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
AllowUsers $ADMIN_USER
MaxAuthTries 3
X11Forwarding no
EOF
  local ports
  ports="$(/usr/sbin/sshd -T | awk '$1 == "port" {print $2}' | sort -u | xargs)"
  [[ $ports == "$ADMIN_PORT" ]] || die "sshd would still listen on: $ports"
  sshd_restart
  /usr/sbin/sshd -T | grep -E '^(port|pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|permitrootlogin|allowusers) '
}

# on a rerun after hardening, stage 1 would put sshd back on 22, which the
# honeypot owns by then. so skip straight to stage 2.
harden_ssh() {
  if grep -q '^PasswordAuthentication no' "$SSHD_DROPIN" 2>/dev/null; then
    log "sshd already hardened, rewriting stage 2 config only"
    ssh_stage2
    return
  fi
  ssh_stage1
  confirm_admin_login
  ssh_stage2
}

install_docker() {
  log "docker"
  if ! command -v docker >/dev/null; then
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    local codename
    codename="$(. /etc/os-release && echo "$VERSION_CODENAME")"
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $codename stable" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update -q
    apt-get install -yq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  fi

  # log rotation for anything compose doesn't cover. no userland proxy, so published
  # ports only go through iptables dnat and containers always see the real client ip
  local want
  want='{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "5" },
  "userland-proxy": false
}'
  install -d /etc/docker
  if [[ "$(cat /etc/docker/daemon.json 2>/dev/null)" != "$want" ]]; then
    printf '%s\n' "$want" > /etc/docker/daemon.json
    systemctl restart docker
  fi
  systemctl enable --now docker
  docker --version
  docker compose version
}

enable_unattended() {
  log "unattended security updates"
  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  # a reboot would drop live sessions; reboot by hand when it says so
  cat > /etc/apt/apt.conf.d/52hacktx-unattended <<'EOF'
Unattended-Upgrade::Automatic-Reboot "false";
EOF
  systemctl enable --now unattended-upgrades
}

enable_fail2ban() {
  log "fail2ban on port $ADMIN_PORT"
  cat > /etc/fail2ban/jail.d/hacktx.local <<EOF
# admin ssh only. port 22 is the honeypot and must never be banned.
[sshd]
enabled  = true
port     = $ADMIN_PORT
backend  = systemd
maxretry = 5
findtime = 10m
bantime  = 1h
EOF
  systemctl enable fail2ban
  systemctl restart fail2ban
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    fail2ban-client ping >/dev/null 2>&1 && break
    sleep 1
  done
  fail2ban-client status sshd
}

finish_message() {
  cat <<EOF

------------------------------------------------------------------
Setup done. Before closing this root session, check again from a
NEW terminal on your PC:

  ssh -p $ADMIN_PORT $ADMIN_USER@$(public_ip)

From now on that is the only way in (or the Vultr web console).
------------------------------------------------------------------
EOF
}
