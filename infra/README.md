# infra

Deployment for the two Vultr servers (Ubuntu 24.04).

```
infra/
  lib/common.sh            shared setup steps (admin user, sshd, docker, updates, fail2ban)
  trap/setup.sh            one-time setup for trap
  trap/docker-compose.yml  the honeypot on host port 22
  core/setup.sh            one-time setup for core
  core/docker-compose.yml  caddy, backend, brain, redis
  core/Caddyfile           api.<domain> -> backend, automatic https
  deploy.sh                pull main, copy .env, compose up, health check
```

Both servers have the repo at `/opt/hacktx2026` (read-only deploy key over `ssh.github.com:443`) and the env file at `/opt/hacktx2026/.env`. GeoLite2 files sit in `/opt/geoip/` on core.

## What ends up where

| | trap | core |
| --- | --- | --- |
| admin ssh | 2222, keys only, no root, user `admin` | same |
| inbound | 22 (honeypot), 80, 2222 | 80, 443, 2222 |
| outbound (host) | 53, 443, plus 80 (apt), 123/udp (ntp), 67/udp (dhcp) | anything |
| outbound (containers) | 53 and 443 only, via `DOCKER-USER` | anything |
| fail2ban | 2222 only | 2222 only |
| unattended security updates | on, no auto reboot | on, no auto reboot |

Docker-published ports and container traffic skip ufw. That's why trap's container egress is locked in the `DOCKER-USER` chain (written into `/etc/ufw/after.rules`), and why on core only Caddy has a `ports:` entry. Redis and backend are reachable only on Docker networks. Docker runs with `userland-proxy: false` on both, so containers always see the real client ip.

## Order of operations

Core first, so trap has somewhere to send events.

### 0. Before you start

- DNS: an `A` record for `api.<domain>` pointing at the core ip. No `AAAA`. Caddy needs it to get a cert.
- Vultr firewall groups: if either server has one, allow TCP 2222 in it too. Otherwise the 2222 test hangs.
- Core `.env`: add a redis password.
  ```sh
  printf '\nREDIS_PASSWORD=%s\n' "$(openssl rand -hex 32)" >> /opt/hacktx2026/.env
  ```
- Trap `.env`: `CORE_URL=https://api.<domain>` and the same `INGEST_TOKEN` as core.

### 1. Core setup (once)

Logged in as root on port 22:

```sh
cd /opt/hacktx2026 && git pull
ADMIN_PUBKEY="ssh-ed25519 AAAA... you@pc" bash infra/core/setup.sh
```

Without `ADMIN_PUBKEY` it copies root's `authorized_keys`. `ADMIN_USER=name` changes the user name.

Halfway through it stops and asks you to log in on 2222 from a new terminal. Port 22 is untouched until you type `yes`. After that it moves sshd to 2222 only, installs Docker, turns on updates and fail2ban, and sets ufw. Test `ssh -p 2222 admin@<core-ip>` once more before closing the root session.

### 2. Core deploy

```sh
ssh -p 2222 admin@<core-ip>
sudo bash /opt/hacktx2026/infra/deploy.sh core
```

It ends with the output of `https://api.<domain>/health`.

### 3. Trap setup (once)

Same flow on the trap server:

```sh
cd /opt/hacktx2026 && git pull
ADMIN_PUBKEY="ssh-ed25519 AAAA... you@pc" bash infra/trap/setup.sh
```

### 4. Trap deploy

```sh
ssh -p 2222 admin@<trap-ip>
sudo bash /opt/hacktx2026/infra/deploy.sh trap
```

It ends with the SSH banner the honeypot sends.

### Later deploys

```sh
sudo bash /opt/hacktx2026/infra/deploy.sh <trap|core> [env-file]
```

It runs `git pull --ff-only` on main, copies the env file (default `/opt/hacktx2026/.env`) to `infra/<role>/.env`, runs `docker compose up -d --build`, waits for health and prints it. On failure it prints the last 50 log lines and exits nonzero.

## Verification checklist (from your PC)

PowerShell works for all of these.

1. **Weak password on trap lands in the fake shell.**
   ```sh
   ssh -p 22 -o PubkeyAuthentication=no root@<trap-ip>
   ```
   Password `123456`. You get a shell prompt. Try `uname -a`, `ls /`, then `exit`. Within a few seconds your session should be in the list (real attackers may be there too):
   ```sh
   curl.exe "https://api.<domain>/sessions?limit=5"
   ```
2. **Health is ok.**
   ```sh
   curl.exe https://api.<domain>/health
   ```
   Expect `{"status":"ok","redis":"ok","db":"ok"}`.
3. **Redis and backend aren't reachable from outside.**
   ```powershell
   Test-NetConnection <core-ip> -Port 6379
   Test-NetConnection <core-ip> -Port 8000
   ```
   Both should say `TcpTestSucceeded : False`.
4. **2222 refuses passwords and root** (run against both servers).
   ```sh
   ssh -p 2222 -o PubkeyAuthentication=no admin@<ip>
   ssh -p 2222 root@<ip>
   ```
   Both should end in `Permission denied (publickey)` without ever asking for a password.
5. **Trap containers can only reach dns and https** (on the trap server).
   ```sh
   sudo docker run --rm curlimages/curl -m 5 -sI http://example.com    # times out
   sudo docker run --rm curlimages/curl -m 5 -sI https://example.com   # HTTP/2 200
   ```

## Rollback

Each deploy that changes the commit saves the old one in `/var/lib/hacktx/previous-<role>`. Every deploy is logged in `/var/lib/hacktx/deploys.log`.

```sh
cd /opt/hacktx2026
prev=$(cat /var/lib/hacktx/previous-<role>)
sudo docker compose -f infra/<role>/docker-compose.yml down
sudo git checkout "$prev"
sudo docker compose -f infra/<role>/docker-compose.yml up -d --build
```

The repo is now on a detached commit. Running `deploy.sh` again goes back to the latest main. Named volumes (trap host keys and spool, redis data, caddy certs) survive `down`. Never run `down -v`: it deletes them, the trap gets a new host key fingerprint, and caddy has to get new certs.

## Troubleshooting

- Logs: `sudo docker compose -f /opt/hacktx2026/infra/<role>/docker-compose.yml logs -f --tail 100 [service]`
- Locked out of 2222: use the Vultr web console and log in as root there.
- Caddy can't get a cert: the `A` record isn't pointing at core yet, or port 80 is blocked by a Vultr firewall group.
- Backend unhealthy with `db: down`: check `TIGER_DATABASE_URL`.
- A secret with `$` in it: compose treats `$` in `.env` as a variable. Write it as `$$` or wrap the value in single quotes.
- Rerunning a `setup.sh` is safe. Once sshd is hardened it skips the 22/2222 handover.
