# Demo runbook

Everything you need at the table. Commands run from the repo root on the demo PC. On Windows use `curl.exe` in PowerShell, or plain `curl` in Git Bash.

## 1. Before judges arrive (2 minutes)

Health:

```
curl.exe https://api.followthebreadcrumbs.tech/health
```

Expect `{"status":"ok","redis":"ok","db":"ok"}`. Anything else: see "If something breaks" below.

Stats (wild traffic only, so our own demo sessions never show up here):

```
curl.exe https://api.followthebreadcrumbs.tech/stats
```

`total_sessions` should keep climbing and `active_now` is usually above 0.

Latest sessions, to confirm events are flowing:

```
curl.exe "https://api.followthebreadcrumbs.tech/sessions?limit=5"
```

## 2. Judge station

The judge types this on the station PC:

```
ssh -o PubkeyAuthentication=no guest@207.148.6.48 -p 22
```

The password is `GUEST_SSH_PASSWORD` in the team `.env`. It is never written in the repo.

If ssh asks to trust a new host key, type `yes`. That's the trap's real key.

What to suggest they try: `ls`, `cat README.md`, `whoami`, `uname -a`, `ls /opt/app`, then `exit`. Nothing they type ever runs; the shell is fake.

What they'll see on the globe within a few seconds:

- a guest knight at our table in Austin (the globe draws every guest as a knight)
- under it, brain always labels a guest login human, with "logged in at the judge station (known human)" as the first reason and the classifier's own guess from behavior as the second
- a short story a few seconds after they type `exit`

Check it landed:

```
curl.exe "https://api.followthebreadcrumbs.tech/sessions?source=guest&limit=3"
```

The newest entry should have `"source":"guest"`, `"kind":"human"` and `"city":"Austin"`.

## 3. The creature show

One-time setup on the demo PC:

```
python -m venv .venv
.venv\Scripts\activate             # git bash: source .venv/Scripts/activate
pip install -r scripts/sim/requirements.txt
```

The sims read `TRAP_HOST`, `CORE_URL`, `TEAM_SSH_USER`, `TEAM_SSH_PASSWORD` and `ANTHROPIC_API_KEY` from `.env`. They only ever connect to `TRAP_HOST` and log in as the team user, so they're `source=team` and never count in stats.

Full show, six acts with 20 seconds between them (about 7 minutes):

```
python scripts/sim/demo_show.py
python scripts/sim/demo_show.py --gap 30 --family mirai
```

Single acts:

| creature | command | takes |
| --- | --- | --- |
| clay golem (bot) | `python scripts/sim/sim_bot.py` | 3 s |
| stone golem (malicious bot) | `python scripts/sim/sim_bot.py --family mirai` | 3 s, plus a few seconds for the lookup |
| dark mage (human) | `python scripts/sim/sim_human.py` (or `--short` for 30 s) | about 2 min |
| fae (AI agent) | `python scripts/sim/demo_agent.py` | about 1 to 1.5 min |
| slime (AI agent that says hi) | `python scripts/sim/demo_agent.py --polite` | about 1 to 1.5 min |
| dragon (critical) | `python scripts/sim/demo_escalation.py` | about 80 s |

`demo_escalation.py --pause 10` slows the climb down for narration. `demo_agent.py --steps 10` makes an agent run shorter.

## 4. If something breaks

**The demo_agent act stops after a line like `[the model declined to continue: cyber]`.** The model's safety check sometimes stops a security audit early. Rerun that act once:

```
python scripts/sim/demo_agent.py            # or with --polite
```

If it's refused again, skip it and move on. The other agent act, or the fae from an earlier run on the globe, tells the same story.

**Stories read like a template** ("came knocking at our gate ... vanished back into the night"). The hourly LLM cap (`LLM_HOURLY_CAP` on core) is used up, usually by wild bot traffic. It resets at the top of the hour. Everything else (labels, threat, creatures) still works.

**The stone golem shows as a clay golem.** The web lookup is capped too (`SERPAPI_HOURLY_CAP`). Lookups are cached for 7 days, so after one successful run `--family mirai` stays malicious.

**Health isn't ok, or the globe stops updating.** On core:

```
ssh -p 2222 admin@<core-ip>
sudo docker compose -f /opt/hacktx2026/infra/core/docker-compose.yml ps
sudo docker compose -f /opt/hacktx2026/infra/core/docker-compose.yml logs --tail 50 brain backend
sudo bash /opt/hacktx2026/infra/deploy.sh core    # redeploys main and prints health
```

**The guest ssh login hangs or is refused.** Check the trap is up from any machine with `ssh -p 22 guest@207.148.6.48` (it should ask for a password), then see `infra/README.md` for the trap deploy.
