"""
Security Headers Checker tab.
Analyze HTTP response headers for common security misconfigurations.
"""

from __future__ import annotations

import re
import urllib.request
import urllib.error
from typing import Optional

from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

# ── Check definitions ────────────────────────────────────────────────────────

# (header_name, display_name, check_fn, risk_level, description, recommendation)
# check_fn(value: str | None) -> (status: "pass"|"warn"|"fail", detail: str)

def _check_hsts(val: str | None) -> tuple[str, str]:
    if not val:
        return "fail", "Header missing — browsers will not enforce HTTPS"
    age = re.search(r"max-age=(\d+)", val, re.I)
    if not age:
        return "warn", "max-age not found in HSTS value"
    secs = int(age.group(1))
    if secs < 31536000:
        return "warn", f"max-age={secs} is less than 1 year (31536000 recommended)"
    return "pass", f"max-age={secs}" + (" includeSubDomains" if "includeSubDomains" in val else "")


def _check_csp(val: str | None) -> tuple[str, str]:
    if not val:
        return "fail", "Header missing — XSS and injection attacks not mitigated"
    issues = []
    if "'unsafe-inline'" in val:
        issues.append("'unsafe-inline' allows inline scripts")
    if "'unsafe-eval'" in val:
        issues.append("'unsafe-eval' allows eval()")
    if "default-src *" in val or "script-src *" in val:
        issues.append("wildcard source (*) defeats CSP")
    if issues:
        return "warn", "; ".join(issues)
    return "pass", "CSP present (review directives manually)"


def _check_xframe(val: str | None) -> tuple[str, str]:
    if not val:
        return "fail", "Header missing — clickjacking possible"
    v = val.strip().upper()
    if v in ("DENY", "SAMEORIGIN"):
        return "pass", val
    if "ALLOW-FROM" in v:
        return "warn", "ALLOW-FROM is deprecated; use CSP frame-ancestors instead"
    return "warn", f"Unexpected value: {val}"


def _check_xcto(val: str | None) -> tuple[str, str]:
    if not val:
        return "fail", "Header missing — MIME-type sniffing enabled"
    if val.strip().lower() == "nosniff":
        return "pass", "nosniff"
    return "warn", f"Unexpected value: {val}"


def _check_referrer(val: str | None) -> tuple[str, str]:
    if not val:
        return "warn", "Header missing — browser default may leak referrer URL"
    safe = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin",
            "no-referrer-when-downgrade", "same-origin"}
    if val.strip().lower() in safe:
        return "pass", val
    return "warn", f"{val} — may leak origin/path"


def _check_cors(val: str | None) -> tuple[str, str]:
    if not val:
        return "pass", "Header absent (no CORS policy exposed)"
    if val.strip() == "*":
        return "fail", "Wildcard * — any origin can read responses"
    return "pass", f"Restricted to: {val}"


def _check_permissions(val: str | None) -> tuple[str, str]:
    if not val:
        return "warn", "Header missing — browser features not restricted"
    return "pass", val[:80] + ("…" if len(val) > 80 else "")


def _check_cache(val: str | None) -> tuple[str, str]:
    if not val:
        return "warn", "No Cache-Control header — sensitive responses may be cached"
    v = val.lower()
    if "no-store" in v:
        return "pass", val
    if "private" in v:
        return "warn", "private prevents CDN caching but browser may still store"
    return "warn", f"Review: {val}"


def _check_server(val: str | None) -> tuple[str, str]:
    if not val:
        return "pass", "Server header absent (good)"
    version_re = re.search(r"\d+\.\d+", val)
    if version_re:
        return "warn", f"Version disclosed: {val}"
    return "warn", f"Server banner exposed: {val}"


def _check_xpowered(val: str | None) -> tuple[str, str]:
    if not val:
        return "pass", "Header absent (good)"
    return "warn", f"Technology disclosed: {val}"


_CHECKS = [
    ("Strict-Transport-Security",   "HSTS",                    _check_hsts,        "Critical",
     "Forces HTTPS for future requests.",
     "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),

    ("Content-Security-Policy",     "Content Security Policy", _check_csp,         "High",
     "Restricts sources for scripts, styles, and other resources.",
     "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'"),

    ("X-Frame-Options",             "X-Frame-Options",         _check_xframe,      "High",
     "Prevents clickjacking by controlling iframe embedding.",
     "X-Frame-Options: DENY  (or use CSP frame-ancestors 'none')"),

    ("X-Content-Type-Options",      "X-Content-Type-Options",  _check_xcto,        "Medium",
     "Prevents MIME-type sniffing.",
     "X-Content-Type-Options: nosniff"),

    ("Referrer-Policy",             "Referrer Policy",         _check_referrer,    "Medium",
     "Controls how much referrer info is sent with requests.",
     "Referrer-Policy: strict-origin-when-cross-origin"),

    ("Access-Control-Allow-Origin", "CORS Allow-Origin",       _check_cors,        "High",
     "Controls which origins can read cross-origin responses.",
     "Limit to specific origins or omit if CORS is not required"),

    ("Permissions-Policy",          "Permissions Policy",      _check_permissions, "Low",
     "Restricts browser feature usage (camera, mic, geolocation…).",
     "Permissions-Policy: camera=(), microphone=(), geolocation=()"),

    ("Cache-Control",               "Cache-Control",           _check_cache,       "Medium",
     "Controls browser and proxy caching of responses.",
     "Cache-Control: no-store  (for sensitive pages)"),

    ("Server",                      "Server Banner",           _check_server,      "Low",
     "Should not disclose server software version.",
     "Remove or replace: Server: (blank)"),

    ("X-Powered-By",                "X-Powered-By",            _check_xpowered,    "Low",
     "Should not disclose framework/language.",
     "Remove: unset X-Powered-By in your framework config"),
]

_STATUS_COLORS = {
    "pass": "#a6e3a1",
    "warn": "#f9e2af",
    "fail": "#f38ba8",
}
_STATUS_ICONS = {
    "pass": "✓",
    "warn": "⚠",
    "fail": "✗",
}

# ── Worker ───────────────────────────────────────────────────────────────────

class _FetchWorker(QThread):
    result = pyqtSignal(dict)   # header_name → value
    error  = pyqtSignal(str)

    def __init__(self, url: str):
        super().__init__()
        self._url = url

    def run(self):
        url = self._url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Fracture-SecHeaders/1.0"},
                method="HEAD",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
            self.result.emit(headers)
        except urllib.error.HTTPError as e:
            # Still grab headers from error responses
            headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            self.result.emit(headers)
        except Exception as e:
            self.error.emit(str(e))


# ── Result row widget ────────────────────────────────────────────────────────

class _ResultRow(QWidget):
    def __init__(self, name: str, status: str, detail: str, risk: str, desc: str, rec: str):
        super().__init__()
        row = QHBoxLayout(self)
        row.setContentsMargins(10, 6, 10, 6)
        row.setSpacing(12)

        color = _STATUS_COLORS.get(status, "#cdd6f4")
        icon = _STATUS_ICONS.get(status, "?")

        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet(f"color: {color}; font-size: 16px; font-weight: bold;")
        icon_lbl.setFixedWidth(20)
        row.addWidget(icon_lbl)

        info = QVBoxLayout()
        top_row = QHBoxLayout()
        name_lbl = QLabel(name)
        name_lbl.setStyleSheet("color: #cdd6f4; font-weight: bold; font-size: 12px;")
        risk_lbl = QLabel(risk)
        risk_lbl.setStyleSheet(
            f"color: {color}; font-size: 10px; font-weight: bold; "
            "border: 1px solid currentColor; border-radius: 3px; padding: 1px 5px;"
        )
        top_row.addWidget(name_lbl)
        top_row.addWidget(risk_lbl)
        top_row.addStretch()
        info.addLayout(top_row)

        detail_lbl = QLabel(detail)
        detail_lbl.setStyleSheet("color: #a6adc8; font-size: 11px;")
        detail_lbl.setWordWrap(True)
        info.addWidget(detail_lbl)

        row.addLayout(info, 1)
        self.setStyleSheet(f"background: {'#1e2a1e' if status=='pass' else '#2a1e1e' if status=='fail' else '#2a2a1e'}; border-radius: 6px;")


# ── Main widget ──────────────────────────────────────────────────────────────

class SecHeadersTab(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._worker: Optional[_FetchWorker] = None

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 12)
        root.setSpacing(10)

        # ── Input ──────────────────────────────────────────────────────
        root.addWidget(QLabel("TARGET URL").also(lambda l: l.setStyleSheet("color: #a6adc8; font-size: 11px; font-weight: bold;")))

        input_row = QHBoxLayout()
        self._url = QLineEdit()
        self._url.setStyleSheet(
            "QLineEdit { background: #181825; color: #cdd6f4; border: 1px solid #313244; "
            "border-radius: 4px; padding: 5px 8px; }"
            "QLineEdit:focus { border-color: #89b4fa; }"
        )
        self._url.setPlaceholderText("https://example.com")
        self._url.returnPressed.connect(self._fetch)
        input_row.addWidget(self._url, 1)

        go = QPushButton("Check Headers")
        go.setStyleSheet(
            "QPushButton { background: #89b4fa; color: #1e1e2e; font-weight: bold; "
            "border: none; border-radius: 4px; padding: 5px 16px; }"
            "QPushButton:hover { background: #b4befe; }"
        )
        go.clicked.connect(self._fetch)
        input_row.addWidget(go)
        root.addLayout(input_row)

        # ── OR paste raw headers ───────────────────────────────────────
        root.addWidget(QLabel("OR PASTE RAW RESPONSE HEADERS").also(lambda l: l.setStyleSheet("color: #a6adc8; font-size: 11px; font-weight: bold;")))
        self._raw = QPlainTextEdit()
        self._raw.setStyleSheet(
            "QPlainTextEdit { background: #181825; color: #cdd6f4; "
            "font-family: monospace; font-size: 11px; border: 1px solid #313244; "
            "border-radius: 4px; padding: 6px; }"
        )
        self._raw.setPlaceholderText("HTTP/1.1 200 OK\nContent-Type: text/html\nStrict-Transport-Security: max-age=31536000\n…")
        self._raw.setMaximumHeight(100)
        root.addWidget(self._raw)

        parse_btn = QPushButton("Analyze Pasted Headers")
        parse_btn.setStyleSheet(
            "QPushButton { background: #313244; color: #cdd6f4; border: none; "
            "border-radius: 4px; padding: 5px 14px; }"
            "QPushButton:hover { background: #45475a; }"
        )
        parse_btn.clicked.connect(self._parse_raw)
        root.addWidget(parse_btn, alignment=Qt.AlignmentFlag.AlignLeft)

        # ── Results area ───────────────────────────────────────────────
        self._status_lbl = QLabel("")
        self._status_lbl.setStyleSheet("color: #a6adc8; font-size: 11px;")
        root.addWidget(self._status_lbl)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        self._results_widget = QWidget()
        self._results_layout = QVBoxLayout(self._results_widget)
        self._results_layout.setSpacing(6)
        self._results_layout.setContentsMargins(0, 0, 0, 0)
        self._results_layout.addStretch()
        scroll.setWidget(self._results_widget)
        root.addWidget(scroll, 1)

    def _fetch(self):
        url = self._url.text().strip()
        if not url:
            return
        self._status_lbl.setText(f"[*] Fetching headers from {url}…")
        self._clear_results()
        self._worker = _FetchWorker(url)
        self._worker.result.connect(self._analyze)
        self._worker.error.connect(lambda e: self._status_lbl.setText(f"[!] {e}"))
        self._worker.start()

    def _parse_raw(self):
        raw = self._raw.toPlainText()
        headers: dict[str, str] = {}
        for line in raw.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        if headers:
            self._analyze(headers)
        else:
            self._status_lbl.setText("[!] No headers found in pasted text.")

    def _analyze(self, headers: dict[str, str]):
        self._clear_results()
        passes = warns = fails = 0

        for header_key, display, check_fn, risk, desc, rec in _CHECKS:
            val = headers.get(header_key.lower())
            status, detail = check_fn(val)
            if status == "pass":
                passes += 1
            elif status == "warn":
                warns += 1
            else:
                fails += 1

            row = _ResultRow(display, status, detail, risk, desc, rec)
            self._results_layout.insertWidget(self._results_layout.count() - 1, row)

        self._status_lbl.setText(
            f"Results: {passes} passed  ·  {warns} warnings  ·  {fails} failed"
        )

    def _clear_results(self):
        while self._results_layout.count() > 1:
            item = self._results_layout.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()


# Tiny helper (same as in payload_lib)
try:
    QLabel.also  # type: ignore[attr-defined]
except AttributeError:
    def _also(self, fn):
        fn(self)
        return self
    QLabel.also = _also  # type: ignore[attr-defined]
