"""
Fracture traffic logger — streams all proxied traffic to a .jsonl file.
"""

import base64
import json
import threading
from datetime import datetime, timezone
from pathlib import Path


class TrafficLogger:
    """Append-only JSONL traffic logger. Thread-safe."""

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self._path.open("a", encoding="utf-8")
        self._lock = threading.Lock()
        self._open = True

    def log_entry(self, req, resp) -> None:
        if not self._open:
            return
        try:
            record = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "method": getattr(req, "method", ""),
                "host": getattr(req, "host", ""),
                "path": getattr(req, "path", ""),
                "status": getattr(resp, "status_code", None) if resp else None,
                "req_len": len(getattr(req, "raw", b"")),
                "resp_len": len(getattr(resp, "raw", b"")) if resp else 0,
                "request": base64.b64encode(getattr(req, "raw", b"")).decode("ascii"),
                "response": base64.b64encode(getattr(resp, "raw", b"")).decode("ascii") if resp else "",
            }
            line = json.dumps(record, separators=(",", ":")) + "\n"
            with self._lock:
                if self._open:
                    self._file.write(line)
                    self._file.flush()
        except Exception as e:
            print(f"[logger] error: {e}")

    def close(self) -> None:
        with self._lock:
            if self._open:
                self._file.close()
                self._open = False

    def is_open(self) -> bool:
        return self._open

    @property
    def path(self) -> str:
        return str(self._path)
