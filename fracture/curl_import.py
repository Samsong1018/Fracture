"""
curl-command importer.

Parses a `curl …` shell command and produces an HttpRequest suitable for
loading into Repeater.  Supports the common flags: -H, -d/--data,
--data-urlencode, --data-raw, --data-binary, -X, -b, -u, -G.
"""

from __future__ import annotations

import base64
import shlex
import urllib.parse
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .proxy import HttpRequest


def parse_curl(command: str) -> HttpRequest:
    """Parse a `curl ...` command line into an HttpRequest. Raises ValueError on failure."""
    cmd = command.strip()
    if cmd.startswith("$ "):
        cmd = cmd[2:]
    # Strip backslash-newline line continuations
    cmd = cmd.replace("\\\n", " ").replace("\\\r\n", " ")
    tokens = shlex.split(cmd, posix=True)
    if not tokens or tokens[0] != "curl":
        if tokens and tokens[0].endswith("curl"):
            pass  # allow /usr/bin/curl etc.
        else:
            raise ValueError("Command must start with 'curl'")
    tokens = tokens[1:]

    url: Optional[str] = None
    method: Optional[str] = None
    headers: dict[str, str] = {}
    data_parts: list[str] = []
    data_urlencode_parts: list[str] = []
    data_binary: Optional[str] = None
    use_get_query = False
    cookies: list[str] = []
    user: Optional[str] = None

    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in ("-H", "--header"):
            i += 1
            if i < len(tokens) and ":" in tokens[i]:
                k, _, v = tokens[i].partition(":")
                headers[k.strip()] = v.strip()
        elif t in ("-X", "--request"):
            i += 1
            if i < len(tokens):
                method = tokens[i].upper()
        elif t in ("-d", "--data", "--data-ascii"):
            i += 1
            if i < len(tokens):
                data_parts.append(tokens[i])
        elif t == "--data-raw":
            i += 1
            if i < len(tokens):
                data_parts.append(tokens[i])
        elif t == "--data-binary":
            i += 1
            if i < len(tokens):
                data_binary = tokens[i]
        elif t == "--data-urlencode":
            i += 1
            if i < len(tokens):
                data_urlencode_parts.append(tokens[i])
        elif t in ("-b", "--cookie"):
            i += 1
            if i < len(tokens):
                cookies.append(tokens[i])
        elif t in ("-u", "--user"):
            i += 1
            if i < len(tokens):
                user = tokens[i]
        elif t in ("-G", "--get"):
            use_get_query = True
        elif t in ("-A", "--user-agent"):
            i += 1
            if i < len(tokens):
                headers.setdefault("User-Agent", tokens[i])
        elif t in ("-e", "--referer"):
            i += 1
            if i < len(tokens):
                headers.setdefault("Referer", tokens[i])
        elif t in ("--url",):
            i += 1
            if i < len(tokens):
                url = tokens[i]
        elif t.startswith("-"):
            # silent ignore for flags like -k, -L, -s, -v, -i, -o, --compressed
            # consume value-bearing flags by best effort
            value_flags = {"-o", "--output", "-w", "--write-out", "--cacert", "--cert",
                           "--key", "--resolve", "--max-time", "-m", "--connect-timeout",
                           "--proxy", "-x", "--referer"}
            if t in value_flags:
                i += 1
        else:
            if url is None:
                url = t
        i += 1

    if url is None:
        raise ValueError("No URL found in curl command")

    # Assemble cookie header
    if cookies:
        existing = headers.get("Cookie")
        joined = "; ".join(cookies)
        headers["Cookie"] = f"{existing}; {joined}" if existing else joined

    # Basic auth
    if user:
        token = base64.b64encode(user.encode()).decode()
        headers.setdefault("Authorization", f"Basic {token}")

    # Build body
    body = b""
    if data_binary is not None:
        body = data_binary.encode()
    elif data_urlencode_parts:
        pieces: list[str] = []
        for part in data_urlencode_parts:
            if "=" in part:
                k, _, v = part.partition("=")
                pieces.append(f"{urllib.parse.quote(k)}={urllib.parse.quote(v)}")
            else:
                pieces.append(urllib.parse.quote(part))
        body = "&".join(pieces).encode()
    elif data_parts:
        body = "&".join(data_parts).encode()

    # Resolve method
    if method is None:
        method = "POST" if body and not use_get_query else "GET"

    # If -G was passed with data, fold body into query string
    parsed = urllib.parse.urlsplit(url)
    if use_get_query and body:
        existing_q = parsed.query
        new_q = body.decode(errors="replace")
        query = f"{existing_q}&{new_q}" if existing_q else new_q
        parsed = parsed._replace(query=query)
        body = b""

    scheme = parsed.scheme.lower() or "http"
    host = parsed.hostname or ""
    if not host:
        raise ValueError("Could not parse host from URL")
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    headers.setdefault("Host", host if port in (80, 443) else f"{host}:{port}")
    if body and "content-length" not in {k.lower() for k in headers}:
        headers["Content-Length"] = str(len(body))
    if body and "content-type" not in {k.lower() for k in headers}:
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    # Build raw bytes
    lines = [f"{method} {path} HTTP/1.1"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode() + body

    return HttpRequest(
        id=0,
        method=method,
        host=host,
        port=port,
        path=path,
        version="1.1",
        headers=headers,
        body=body,
        is_https=(scheme == "https"),
        raw=raw,
    )


class CurlImportDialog(QDialog):
    """Dialog that lets a user paste a curl command and returns an HttpRequest."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Import from curl")
        self.setMinimumSize(720, 360)
        self._request: Optional[HttpRequest] = None

        root = QVBoxLayout(self)
        root.addWidget(QLabel("Paste a curl command:"))

        self.text = QTextEdit()
        self.text.setStyleSheet(
            "QTextEdit { background: #181825; border: 1px solid #313244; "
            "color: #cdd6f4; font-family: monospace; font-size: 12px; }"
        )
        root.addWidget(self.text, 1)

        self.error_label = QLabel("")
        self.error_label.setStyleSheet("color: #f38ba8;")
        root.addWidget(self.error_label)

        btns = QHBoxLayout()
        btns.addStretch()
        ok = QPushButton("Import → Repeater")
        ok.setStyleSheet(
            "QPushButton { background: #313244; border: 1px solid #45475a; "
            "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
            "QPushButton:hover { background: #45475a; }"
        )
        ok.clicked.connect(self._accept)
        btns.addWidget(ok)

        cancel = QPushButton("Cancel")
        cancel.setStyleSheet(ok.styleSheet())
        cancel.clicked.connect(self.reject)
        btns.addWidget(cancel)
        root.addLayout(btns)

    def _accept(self) -> None:
        try:
            self._request = parse_curl(self.text.toPlainText())
        except Exception as exc:
            self.error_label.setText(f"Parse error: {exc}")
            return
        self.accept()

    def request(self) -> Optional[HttpRequest]:
        return self._request
