"""a scripted llm provider. nothing here touches the network."""

import asyncio
import json


class FakeLLM:
    """replies in order; the last one repeats. a reply can be a dict (sent as json),
    a raw string, an exception to raise, or a function of the messages."""

    def __init__(self, *replies, delay: float = 0.0):
        self.replies = list(replies)
        self.delay = delay
        self.calls: list[list[dict]] = []
        self.systems: list[str] = []

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
        return reply if isinstance(reply, str) else json.dumps(reply)

    async def close(self):
        pass


def answer(stdout="", *changes):
    return {"stdout": stdout, "fs_changes": [{"op": op, "path": path, "content": content} for op, path, content in changes]}
