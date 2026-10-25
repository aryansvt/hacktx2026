"""ws /live fan out. broadcast never awaits a socket; slow clients get dropped."""

import asyncio
import contextlib
import json
import logging
import time
from typing import Any

log = logging.getLogger(__name__)

PING = json.dumps({"type": "ping"})
# close code for "try again later"
CLOSE_TOO_SLOW = 1013


class Client:
    def __init__(self, ws: Any, queue_size: int):
        self.ws = ws
        self.queue: asyncio.Queue[str] = asyncio.Queue(maxsize=queue_size)
        self.dropped = asyncio.Event()


class Hub:
    def __init__(self, ping_interval: float = 20.0, send_timeout: float = 5.0, queue_size: int = 256):
        self.ping_interval = ping_interval
        self.send_timeout = send_timeout
        self.queue_size = queue_size
        self.clients: set[Client] = set()

    def broadcast(self, message: str) -> None:
        for client in list(self.clients):
            try:
                client.queue.put_nowait(message)
            except asyncio.QueueFull:
                log.info("dropping slow ws client")
                self._drop(client)

    def _drop(self, client: Client) -> None:
        self.clients.discard(client)
        client.dropped.set()

    async def serve(self, ws: Any) -> None:
        """run one websocket connection until it closes or gets dropped."""
        await ws.accept()
        client = Client(ws, self.queue_size)
        self.clients.add(client)
        tasks = [
            asyncio.create_task(self._send_loop(client)),
            asyncio.create_task(self._recv_loop(client)),
            asyncio.create_task(client.dropped.wait()),
        ]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self.clients.discard(client)
            with contextlib.suppress(Exception):
                await asyncio.wait_for(ws.close(code=CLOSE_TOO_SLOW), self.send_timeout)

    async def _send_loop(self, client: Client) -> None:
        next_ping = time.monotonic() + self.ping_interval
        while True:
            wait = max(0.0, next_ping - time.monotonic())
            try:
                message = await asyncio.wait_for(client.queue.get(), wait)
            except asyncio.TimeoutError:
                message = PING
                next_ping = time.monotonic() + self.ping_interval
            try:
                await asyncio.wait_for(client.ws.send_text(message), self.send_timeout)
            except Exception:
                # timeout or closed socket: this client is done
                return

    async def _recv_loop(self, client: Client) -> None:
        # we ignore what clients send; this just notices disconnects
        while True:
            message = await client.ws.receive()
            if message.get("type") == "websocket.disconnect":
                return
