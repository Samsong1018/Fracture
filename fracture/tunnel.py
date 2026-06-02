"""
Local tunnel launcher — spawns ngrok or cloudflared as a subprocess and
parses the public URL from its output.  The tunnel forwards traffic to
the local Collaborator listener so internet-bound targets can reach it.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import threading
import time
from typing import Callable, Optional


_NGROK_URL_RE = re.compile(
    rb"url=https?://([A-Za-z0-9._-]+)|started tunnel.*url=https?://([A-Za-z0-9._-]+)"
)
_CLOUDFLARED_URL_RE = re.compile(rb"https://([a-z0-9-]+\.trycloudflare\.com)")


def detect_tools() -> dict[str, Optional[str]]:
    """Return absolute paths for known tunnel tools, or None if missing."""
    return {
        "ngrok": shutil.which("ngrok"),
        "cloudflared": shutil.which("cloudflared"),
    }


class TunnelProcess:
    """Wrap a single tunnel subprocess and stream-read its stdout."""

    def __init__(self) -> None:
        self._proc: Optional[subprocess.Popen] = None
        self._public_host: str = ""
        self._scheme: str = "https"
        self._tool: str = ""
        self._on_host: Optional[Callable[[str, str], None]] = None
        self._reader_thread: Optional[threading.Thread] = None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    @property
    def public_host(self) -> str:
        return self._public_host

    @property
    def scheme(self) -> str:
        return self._scheme

    @property
    def tool(self) -> str:
        return self._tool

    def start_ngrok(self, port: int, on_host: Callable[[str, str], None]) -> tuple[bool, str]:
        path = shutil.which("ngrok")
        if not path:
            return False, "ngrok binary not found on PATH"
        self._tool = "ngrok"
        self._on_host = on_host
        cmd = [path, "http", str(port), "--log=stdout", "--log-format=logfmt"]
        return self._spawn(cmd, _NGROK_URL_RE)

    def start_cloudflared(self, port: int, on_host: Callable[[str, str], None]
                          ) -> tuple[bool, str]:
        path = shutil.which("cloudflared")
        if not path:
            return False, "cloudflared binary not found on PATH"
        self._tool = "cloudflared"
        self._on_host = on_host
        cmd = [path, "tunnel", "--url", f"http://127.0.0.1:{port}", "--no-autoupdate"]
        return self._spawn(cmd, _CLOUDFLARED_URL_RE)

    def _spawn(self, cmd: list[str], url_re: re.Pattern) -> tuple[bool, str]:
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
            )
        except Exception as e:
            return False, f"Failed to spawn: {e}"

        self._reader_thread = threading.Thread(
            target=self._read_loop, args=(url_re,), daemon=True
        )
        self._reader_thread.start()
        return True, "Tunnel starting…"

    def _read_loop(self, url_re: re.Pattern) -> None:
        if self._proc is None or self._proc.stdout is None:
            return
        for raw_line in self._proc.stdout:
            m = url_re.search(raw_line)
            if m and not self._public_host:
                host = next((g for g in m.groups() if g), b"").decode("ascii", "replace")
                if host:
                    self._public_host = host
                    self._scheme = "https"
                    if self._on_host:
                        try:
                            self._on_host(host, "https")
                        except Exception:
                            pass

    def stop(self) -> None:
        if self._proc is None:
            return
        try:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        except Exception:
            pass
        self._proc = None
        self._public_host = ""
