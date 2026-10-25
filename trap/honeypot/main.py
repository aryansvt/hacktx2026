"""entry point: python -m honeypot"""

from __future__ import annotations

import asyncio
import logging

from .auth import Auth
from .config import Settings
from .events import JsonlSink
from .llm.fallback import LLMFallback
from .llm.provider import make_provider
from .sender import Sender
from .shell.engine import load_system
from .ssh_server import TrapApp
from .web import WebServer

log = logging.getLogger("honeypot")


async def serve(settings: Settings) -> None:
    # built before the server starts so the cursor is checked before new writes
    sender = Sender(settings)
    provider = make_provider(settings)
    fallback = LLMFallback(provider, load_system(), settings.llm_hourly_cap, settings.llm_log_path) if provider else None
    # ssh and http share one spool, so one sender ships both
    sink = JsonlSink(settings.spool_path)
    app = TrapApp(settings, Auth.load(settings), sink, fallback=fallback)
    server = await app.start()
    log.info("ssh trap listening on %s:%s, spool %s", settings.ssh_host, settings.ssh_port, settings.spool_path)
    web = WebServer(settings, sink, app.auth.team_ips, app.canaries)
    if await web.start():
        log.info("http trap listening on %s:%s", settings.ssh_host, web.port)
    task = asyncio.create_task(sender.run()) if sender.enabled else None
    if task:
        log.info("sending events to %s/ingest", settings.core_url)
    if fallback:
        log.info("llm fallback on, %d calls an hour, log %s", settings.llm_hourly_cap, settings.llm_log_path)
    try:
        await server.wait_closed()
    finally:
        server.close()
        await web.close()
        if task:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await sender.close()
        if fallback:
            await fallback.close()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # asyncssh logs every connection at info; keep it to warnings
    logging.getLogger("asyncssh").setLevel(logging.WARNING)
    # and httpx logs every request
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpx2").setLevel(logging.WARNING)
    try:
        asyncio.run(serve(Settings.from_env()))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
