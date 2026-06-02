"""
Engagement tools: certificate viewer and find-* utilities.

Each find_* function takes the proxy history and returns a list of textual hits;
they're presented in a simple read-only dialog.
"""

from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime
from typing import Iterable, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .proxy import HttpRequest, HttpResponse


HistoryEntry = tuple[HttpRequest, Optional[HttpResponse]]


# ---------------------------------------------------------------------------
# Find-* utilities
# ---------------------------------------------------------------------------

_COMMENT_RE = re.compile(rb"<!--(.*?)-->", re.DOTALL)
_SCRIPT_TAG_RE = re.compile(
    rb"<script\b([^>]*)>(.*?)</script>", re.DOTALL | re.IGNORECASE
)
_SRC_ATTR_RE = re.compile(
    rb"""src\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s'">]+))""",
    re.IGNORECASE,
)
_LINK_RE = re.compile(
    rb"""(?:href|action)\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s'">]+))""",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(
    rb"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)


def _iter_response_bodies(history: Iterable[HistoryEntry]):
    for req, resp in history:
        if resp is not None and resp.body:
            yield req, resp.body


def find_comments(history: Iterable[HistoryEntry]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for req, body in _iter_response_bodies(history):
        for m in _COMMENT_RE.finditer(body):
            txt = m.group(1).decode(errors="replace").strip()
            if not txt:
                continue
            key = f"{req.host}|{txt}"
            if key in seen:
                continue
            seen.add(key)
            out.append(f"[{req.host}{req.path}]  <!--{txt[:300]}-->")
    return out


def find_scripts(history: Iterable[HistoryEntry]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for req, body in _iter_response_bodies(history):
        for m in _SCRIPT_TAG_RE.finditer(body):
            attrs = m.group(1) or b""
            src_match = _SRC_ATTR_RE.search(attrs)
            if src_match:
                src_bytes = next((g for g in src_match.groups() if g), b"")
                src = src_bytes.decode(errors="replace")
                key = f"src|{src}"
                if key in seen:
                    continue
                seen.add(key)
                out.append(f"[external] {src}  (seen on {req.host}{req.path})")
            else:
                inline = m.group(2).decode(errors="replace").strip()
                if inline:
                    snippet = inline[:200].replace("\n", " ")
                    key = f"inline|{req.host}|{snippet}"
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(f"[inline @ {req.host}{req.path}] {snippet}")
    return out


def find_references(history: Iterable[HistoryEntry]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for req, body in _iter_response_bodies(history):
        for m in _LINK_RE.finditer(body):
            link_bytes = next((g for g in m.groups() if g), b"")
            link = link_bytes.decode(errors="replace")
            if link in seen:
                continue
            seen.add(link)
            out.append(f"{link}  (from {req.host}{req.path})")
    return out


def find_emails(history: Iterable[HistoryEntry]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for req, body in _iter_response_bodies(history):
        for m in _EMAIL_RE.finditer(body):
            addr = m.group(0).decode(errors="replace")
            if addr in seen:
                continue
            seen.add(addr)
            out.append(f"{addr}  (seen on {req.host}{req.path})")
    return out


# ---------------------------------------------------------------------------
# Read-only results dialog
# ---------------------------------------------------------------------------

class FindResultsDialog(QDialog):
    def __init__(self, title: str, lines: list[str], parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(800, 500)

        root = QVBoxLayout(self)
        root.addWidget(QLabel(f"{len(lines)} result{'s' if len(lines) != 1 else ''}"))

        view = QTextEdit()
        view.setReadOnly(True)
        view.setStyleSheet(
            "QTextEdit { background: #181825; border: 1px solid #313244; "
            "color: #cdd6f4; font-family: monospace; font-size: 12px; }"
        )
        view.setPlainText("\n".join(lines) if lines else "(none)")
        root.addWidget(view, 1)

        close = QPushButton("Close")
        close.setStyleSheet(
            "QPushButton { background: #313244; border: 1px solid #45475a; "
            "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
            "QPushButton:hover { background: #45475a; }"
        )
        close.clicked.connect(self.accept)
        root.addWidget(close, alignment=Qt.AlignmentFlag.Right)


# ---------------------------------------------------------------------------
# Certificate viewer
# ---------------------------------------------------------------------------

def _fetch_cert_chain(host: str, port: int) -> list[dict]:
    """Return a list of dicts describing each cert in the chain."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    chain: list[dict] = []
    with socket.create_connection((host, port), timeout=8) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as sock:
            # Peer cert (decoded)
            peer = sock.getpeercert() or {}
            der = sock.getpeercert(binary_form=True)
            chain.append(_describe_cert(peer, der))
    return chain


def _describe_cert(decoded: dict, der: Optional[bytes]) -> dict:
    def _flatten(seq):
        out = {}
        for entry in seq:
            for k, v in entry:
                out[k] = v
        return out

    subject = _flatten(decoded.get("subject", []))
    issuer = _flatten(decoded.get("issuer", []))

    sans = []
    for typ, val in decoded.get("subjectAltName", []) or []:
        sans.append(f"{typ}:{val}")

    fingerprint = ""
    if der:
        import hashlib
        fingerprint = hashlib.sha256(der).hexdigest()
        fingerprint = ":".join(
            fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2)
        ).upper()

    return {
        "subject": subject,
        "issuer": issuer,
        "not_before": decoded.get("notBefore", ""),
        "not_after": decoded.get("notAfter", ""),
        "serial": decoded.get("serialNumber", ""),
        "san": sans,
        "version": decoded.get("version", ""),
        "fingerprint_sha256": fingerprint,
    }


def format_cert(cert: dict) -> str:
    def _fmt(d: dict) -> str:
        return ", ".join(f"{k}={v}" for k, v in d.items()) or "(empty)"

    lines = [
        f"Subject:    {_fmt(cert['subject'])}",
        f"Issuer:     {_fmt(cert['issuer'])}",
        f"Version:    {cert.get('version', '')}",
        f"Serial:     {cert.get('serial', '')}",
        f"Not Before: {cert.get('not_before', '')}",
        f"Not After:  {cert.get('not_after', '')}",
        "",
        "Subject Alternative Names:",
    ]
    sans = cert.get("san") or []
    if sans:
        for s in sans:
            lines.append(f"  • {s}")
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append(f"SHA-256 fingerprint:")
    lines.append(f"  {cert.get('fingerprint_sha256', '')}")
    return "\n".join(lines)


class CertViewerDialog(QDialog):
    def __init__(self, host: str, port: int, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"TLS Certificate — {host}:{port}")
        self.resize(720, 480)

        root = QVBoxLayout(self)
        header = QLabel(f"{host}:{port}    (fetched {datetime.now().strftime('%Y-%m-%d %H:%M:%S')})")
        root.addWidget(header)

        view = QTextEdit()
        view.setReadOnly(True)
        view.setStyleSheet(
            "QTextEdit { background: #181825; border: 1px solid #313244; "
            "color: #cdd6f4; font-family: monospace; font-size: 12px; }"
        )

        try:
            chain = _fetch_cert_chain(host, port)
            blocks = [format_cert(c) for c in chain]
            view.setPlainText("\n\n----- chain entry -----\n\n".join(blocks))
        except Exception as exc:
            view.setPlainText(f"Failed to fetch certificate: {exc}")

        root.addWidget(view, 1)

        close = QPushButton("Close")
        close.setStyleSheet(
            "QPushButton { background: #313244; border: 1px solid #45475a; "
            "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
            "QPushButton:hover { background: #45475a; }"
        )
        close.clicked.connect(self.accept)
        root.addWidget(close, alignment=Qt.AlignmentFlag.Right)
