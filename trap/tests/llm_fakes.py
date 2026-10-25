"""a scripted llm provider. nothing here touches the network."""

import asyncio
import json

from honeypot.llm.provider import Reply


class FakeLLM:
    """replies in order; the last one repeats. a reply can be a dict (sent as json),
    a raw string, a Reply, an exception to raise, or a function of the messages."""

    model = "fake-model"

    def __init__(self, *replies, delay: float = 0.0, ms: int = 42):
        self.replies = list(replies)
        self.delay = delay
        self.ms = ms
        self.calls: list[list[dict]] = []
        self.systems: list[str] = []
        self.warms = 0
        self.closed = False

    async def complete(self, system, messages, schema):
        self.systems.append(system)
        self.calls.append([dict(m) for m in messages])
        if self.delay:
            await asyncio.sleep(self.delay)
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if callable(reply):
            reply = reply(messages)
        if isinstance(reply, Exception):
            raise reply
        if isinstance(reply, Reply):
            return reply
        text = reply if isinstance(reply, str) else json.dumps(reply)
        return Reply(text, self.ms, "end_turn", 900, 30)

    async def warm(self):
        self.warms += 1
        return 7

    async def close(self):
        self.closed = True


def answer(stdout="", *changes):
    return {"stdout": stdout, "fs_changes": [{"op": op, "path": path, "content": content} for op, path, content in changes]}
