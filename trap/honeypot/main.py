"""entry point: python -m honeypot"""

from __future__ import annotations

import asyncio
import logging

from .auth import Auth
from .config import Settings
from .events import JsonlSink
from .sender import Sender
from .ssh_server import TrapApp

log = logging.getLogger("honeypot")


async def serve(settings: Settings) -> None:
    # built before the server starts so the cursor is checked before new writes
    sender = Sender(settings)
    app = TrapApp(settings, Auth.load(settings), JsonlSink(settings.spool_path))
    server = await app.start()
    log.info("ssh trap listening on %s:%s, spool %s", settings.ssh_host, settings.ssh_port, settings.spool_path)
    task = asyncio.create_task(sender.run()) if sender.enabled else None
    if task:
        log.info("sending events to %s/ingest", settings.core_url)
    try:
        await server.wait_closed()
    finally:
        server.close()
        if task:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await sender.close()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # asyncssh logs every connection at info; keep it to warnings
    logging.getLogger("asyncssh").setLevel(logging.WARNING)
    # and httpx logs every request
    logging.getLogger("httpx").setLevel(logging.WARNING)
    try:
        asyncio.run(serve(Settings.from_env()))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
