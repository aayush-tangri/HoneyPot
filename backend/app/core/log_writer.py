from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime
from typing import Any, Dict


def _utc_now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


async def append_jsonl(path: str, event: Dict[str, Any]) -> None:
    """
    Append one JSON object as one line.

    - Windows-friendly (plain file append).
    - Async-friendly (write happens in a thread).
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)

    # Always stamp at write-time to guarantee correctness and ordering.
    # (Some servers/reloaders can keep older function references around.)
    event["timestamp"] = _utc_now_iso()

    line = json.dumps(event, ensure_ascii=False) + "\n"

    def _write() -> None:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)

    await asyncio.to_thread(_write)

