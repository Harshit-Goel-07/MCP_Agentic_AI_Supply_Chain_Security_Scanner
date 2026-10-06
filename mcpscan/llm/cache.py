"""Content-addressed cache for LLM responses.

Caching keeps scans reproducible (identical inputs -> identical verdicts) and controls cost. The
cache key is a hash of (provider, model, prompt).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


class ResponseCache:
    def __init__(self, directory: Path) -> None:
        self._dir = directory
        self._dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _key(provider: str, model: str, prompt: str) -> str:
        payload = json.dumps({"p": provider, "m": model, "prompt": prompt}, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    def get(self, provider: str, model: str, prompt: str) -> str | None:
        path = self._dir / f"{self._key(provider, model, prompt)}.json"
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8")).get("response")
        return None

    def put(self, provider: str, model: str, prompt: str, response: str) -> None:
        path = self._dir / f"{self._key(provider, model, prompt)}.json"
        path.write_text(json.dumps({"response": response}), encoding="utf-8")
