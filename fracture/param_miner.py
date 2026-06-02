"""
Param Miner — fuzzes hidden query/body/header parameter names against a target
request, looking for params that cause a behavioural difference in the response.
"""

from __future__ import annotations

import socket
import ssl
import time
import urllib.parse
from typing import Optional

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .proxy import HttpRequest


# Catppuccin Mocha
_BG = "#1e1e2e"
_SURFACE = "#181825"
_OVERLAY = "#313244"
_TEXT = "#cdd6f4"

_TEXTEDIT_SS = (
    "QTextEdit { background: #181825; border: 1px solid #313244; "
    "color: #cdd6f4; font-family: monospace; font-size: 12px; }"
)
_LINEEDIT_SS = (
    "QLineEdit { background: #181825; border: 1px solid #313244; "
    "padding: 4px; color: #cdd6f4; }"
)
_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
    "QPushButton:hover { background: #45475a; }"
    "QPushButton:disabled { color: #585b70; }"
)


# Default wordlist of common hidden parameter names.
DEFAULT_PARAMS: list[str] = [
    "debug", "test", "admin", "id", "user", "uid", "userid", "user_id",
    "page", "p", "q", "query", "search", "s", "redirect", "url", "next",
    "return", "return_url", "callback", "cb", "jsonp", "format", "type",
    "action", "cmd", "command", "exec", "include", "file", "path", "dir",
    "lang", "language", "locale", "view", "template", "theme", "skin",
    "preview", "edit", "verbose", "trace", "log", "logging", "level",
    "token", "key", "api_key", "apikey", "access_token", "session",
    "sessionid", "session_id", "auth", "authorization", "role", "is_admin",
    "isadmin", "admin_id", "su", "sudo", "su_user", "X-Forwarded-For",
    "X-Original-URL", "X-Rewrite-URL", "X-Real-IP", "X-Client-IP",
    "X-Forwarded-Host", "X-Host", "X-Custom-IP-Authorization",
]


_BUFFER = 65536


def _send_raw(host: str, port: int, is_https: bool, request_bytes: bytes
              ) -> tuple[int, int, bytes]:
    """Returns (status_code, length, raw_response)."""
    try:
        sock = socket.create_connection((host, port), timeout=10)
        if is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(request_bytes)
        data = b""
        sock.settimeout(5)
        while True:
            try:
                chunk = sock.recv(_BUFFER)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break
        sock.close()
        status = 0
        if data:
            first = data.split(b"\r\n", 1)[0].decode(errors="replace")
            parts = first.split(" ", 2)
            if len(parts) >= 2:
                try:
                    status = int(parts[1])
                except ValueError:
                    pass
        return status, len(data), data
    except Exception:
        return 0, 0, b""


def _replace_query_param(path: str, name: str, value: str) -> str:
    """Replace the value of `name` in the query string of `path`. If absent, append."""
    if "?" not in path:
        return f"{path}?{urllib.parse.quote(name)}={urllib.parse.quote(value)}"
    base, qs = path.split("?", 1)
    parts = []
    found = False
    for part in qs.split("&"):
        if "=" in part:
            k, _, _v = part.partition("=")
            if urllib.parse.unquote_plus(k) == name:
                parts.append(f"{k}={urllib.parse.quote(value)}")
                found = True
            else:
                parts.append(part)
        else:
            if urllib.parse.unquote_plus(part) == name:
                parts.append(f"{urllib.parse.quote(name)}={urllib.parse.quote(value)}")
                found = True
            else:
                parts.append(part)
    if not found:
        parts.append(f"{urllib.parse.quote(name)}={urllib.parse.quote(value)}")
    return base + "?" + "&".join(parts)


def _replace_form_param(body: bytes, name: str, value: str) -> bytes:
    """Replace the value of form param `name` in body. If absent, append."""
    text = body.decode(errors="replace") if body else ""
    parts = []
    found = False
    if text:
        for part in text.split("&"):
            if "=" in part:
                k, _, _v = part.partition("=")
                if urllib.parse.unquote_plus(k) == name:
                    parts.append(f"{k}={urllib.parse.quote(value)}")
                    found = True
                else:
                    parts.append(part)
            else:
                if urllib.parse.unquote_plus(part) == name:
                    parts.append(f"{urllib.parse.quote(name)}={urllib.parse.quote(value)}")
                    found = True
                else:
                    parts.append(part)
    if not found:
        parts.append(f"{urllib.parse.quote(name)}={urllib.parse.quote(value)}")
    return "&".join(parts).encode()


def _build_request(
    req: HttpRequest,
    mode: str,
    name: str,
    value: str,
    target_param: str = "",
) -> bytes:
    """Build a raw HTTP request inserting parameter `name=value` per mode.

    When mode begins with "values:" (e.g. "values:query"), this fuzzes the VALUE
    of `target_param` instead, setting it to `name` (the wordlist entry).
    """
    method = req.method
    path = req.path
    headers = dict(req.headers)
    body = req.body or b""

    # Values mode: fuzz the VALUE of target_param using `name` as the value
    if mode.startswith("values"):
        # submode after colon, defaults to query
        sub = mode.split(":", 1)[1] if ":" in mode else "query"
        tp = target_param or ""
        new_value = name  # in values mode, the wordlist entry is the value
        if not tp:
            # No target param specified; fall back to no-op baseline-like request
            pass
        elif sub == "query":
            path = _replace_query_param(path, tp, new_value)
        elif sub == "header":
            headers[tp] = new_value
        elif sub == "body":
            ct = ""
            for k, v in headers.items():
                if k.lower() == "content-type":
                    ct = v.lower()
            if "application/json" in ct:
                import json
                try:
                    obj = json.loads(body.decode("utf-8", errors="replace") or "{}")
                    if isinstance(obj, dict):
                        obj[tp] = new_value
                        body = json.dumps(obj).encode()
                except Exception:
                    body = _replace_form_param(body, tp, new_value)
            else:
                body = _replace_form_param(body, tp, new_value)
                if "content-type" not in {k.lower() for k in headers}:
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers = {k: v for k, v in headers.items() if k.lower() != "content-length"}
            headers["Content-Length"] = str(len(body))

        lines = [f"{method} {path} HTTP/1.1"]
        if "host" not in {k.lower() for k in headers}:
            lines.append(f"Host: {req.host}")
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode() + body
        return raw

    if mode == "query":
        sep = "&" if "?" in path else "?"
        path = f"{path}{sep}{urllib.parse.quote(name)}={urllib.parse.quote(value)}"
    elif mode == "header":
        headers[name] = value
    elif mode == "body":
        ct = ""
        for k, v in headers.items():
            if k.lower() == "content-type":
                ct = v.lower()
        if "application/json" in ct:
            import json
            try:
                obj = json.loads(body.decode("utf-8", errors="replace") or "{}")
                if isinstance(obj, dict):
                    obj[name] = value
                    body = json.dumps(obj).encode()
            except Exception:
                body = (
                    body + (b"&" if body else b"")
                    + f"{urllib.parse.quote(name)}={urllib.parse.quote(value)}".encode()
                )
        else:
            extra = f"{urllib.parse.quote(name)}={urllib.parse.quote(value)}".encode()
            body = body + (b"&" if body else b"") + extra
            if "content-type" not in {k.lower() for k in headers}:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers = {k: v for k, v in headers.items() if k.lower() != "content-length"}
        headers["Content-Length"] = str(len(body))

    lines = [f"{method} {path} HTTP/1.1"]
    if "host" not in {k.lower() for k in headers}:
        lines.append(f"Host: {req.host}")
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode() + body
    return raw


class ParamMinerWorker(QThread):
    """Issues a baseline request then one request per candidate param name."""

    baseline_done = pyqtSignal(int, int)         # status, length
    progress = pyqtSignal(int, int)              # current, total
    hit = pyqtSignal(str, int, int, int)         # name, status, length, delta
    finished_ok = pyqtSignal()

    def __init__(
        self,
        req: HttpRequest,
        mode: str,
        wordlist: list[str],
        value: str = "coughprobe",
        threshold: int = 32,
        throttle_ms: int = 0,
        target_param_name: str = "",
        parent: Optional[QThread] = None,
    ) -> None:
        super().__init__(parent)
        self._req = req
        self._mode = mode
        self._wordlist = list(dict.fromkeys(wordlist))  # dedupe, preserve order
        self._value = value
        self._threshold = max(0, threshold)
        self._throttle_ms = max(0, throttle_ms)
        self._target_param_name = target_param_name
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        req = self._req
        host, port, https = req.host, req.port, req.is_https
        baseline_raw = req.raw or _build_request(req, "noop", "", "")
        b_status, b_len, _ = _send_raw(host, port, https, baseline_raw)
        self.baseline_done.emit(b_status, b_len)

        total = len(self._wordlist)
        for i, name in enumerate(self._wordlist):
            if self._stop:
                break
            self.progress.emit(i + 1, total)
            raw = _build_request(
                req, self._mode, name, self._value, self._target_param_name
            )
            status, length, _ = _send_raw(host, port, https, raw)
            delta = length - b_len
            if status != b_status or abs(delta) >= self._threshold:
                self.hit.emit(name, status, length, delta)
            if self._throttle_ms:
                time.sleep(self._throttle_ms / 1000.0)
        self.finished_ok.emit()


class ParamMinerTab(QWidget):
    """UI for the param-miner tool."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._req: Optional[HttpRequest] = None
        self._worker: Optional[ParamMinerWorker] = None

        root = QVBoxLayout(self)

        # Top: target summary + load hint
        self.target_label = QLabel("No request loaded. Right-click a history entry → Send to Param Miner.")
        self.target_label.setStyleSheet(f"color: {_TEXT};")
        root.addWidget(self.target_label)

        # Controls row
        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Mode:"))
        self.mode_combo = QComboBox()
        # "names" submodes fuzz parameter NAMES. "values:<sub>" fuzzes VALUE of a known param.
        self.mode_combo.addItems([
            "query", "body", "header",
            "values:query", "values:body", "values:header",
        ])
        self.mode_combo.currentTextChanged.connect(self._on_mode_changed)
        ctrl.addWidget(self.mode_combo)

        self.target_param_label = QLabel("Target param:")
        ctrl.addWidget(self.target_param_label)
        self.target_param_edit = QLineEdit()
        self.target_param_edit.setStyleSheet(_LINEEDIT_SS)
        self.target_param_edit.setFixedWidth(120)
        self.target_param_edit.setPlaceholderText("param name")
        ctrl.addWidget(self.target_param_edit)
        # Hidden by default (names mode)
        self.target_param_label.setVisible(False)
        self.target_param_edit.setVisible(False)

        self.value_label = QLabel("Value:")
        ctrl.addWidget(self.value_label)
        self.value_edit = QLineEdit("coughprobe")
        self.value_edit.setStyleSheet(_LINEEDIT_SS)
        self.value_edit.setFixedWidth(120)
        ctrl.addWidget(self.value_edit)

        ctrl.addWidget(QLabel("Δlen ≥"))
        self.threshold_spin = QSpinBox()
        self.threshold_spin.setRange(0, 100000)
        self.threshold_spin.setValue(32)
        ctrl.addWidget(self.threshold_spin)

        ctrl.addWidget(QLabel("Throttle ms:"))
        self.throttle_spin = QSpinBox()
        self.throttle_spin.setRange(0, 10000)
        self.throttle_spin.setValue(0)
        ctrl.addWidget(self.throttle_spin)

        self.start_btn = QPushButton("Start")
        self.start_btn.setStyleSheet(_BTN_SS)
        self.start_btn.clicked.connect(self._start)
        ctrl.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setStyleSheet(_BTN_SS)
        self.stop_btn.clicked.connect(self._stop)
        self.stop_btn.setEnabled(False)
        ctrl.addWidget(self.stop_btn)

        ctrl.addStretch()
        root.addLayout(ctrl)

        # Wordlist editor
        self.wordlist_label = QLabel("Wordlist (one per line):")
        root.addWidget(self.wordlist_label)
        self.wordlist_edit = QTextEdit()
        self.wordlist_edit.setStyleSheet(_TEXTEDIT_SS)
        self.wordlist_edit.setPlainText("\n".join(DEFAULT_PARAMS))
        self.wordlist_edit.setMaximumHeight(140)
        root.addWidget(self.wordlist_edit)

        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        root.addWidget(self.progress_bar)

        # Results table
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Param", "Status", "Length", "Δ vs baseline"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setStyleSheet(
            "QTableWidget { background: #181825; gridline-color: #313244; color: #cdd6f4; }"
            "QHeaderView::section { background: #313244; color: #cdd6f4; border: 0; padding: 4px; }"
        )
        root.addWidget(self.table, 1)

    # ------------------------------------------------------------------
    def load_request(self, req: HttpRequest) -> None:
        self._req = req
        scheme = "https" if req.is_https else "http"
        self.target_label.setText(f"Target: {req.method} {scheme}://{req.host}:{req.port}{req.path}")

    def _wordlist(self) -> list[str]:
        return [
            line.strip()
            for line in self.wordlist_edit.toPlainText().splitlines()
            if line.strip()
        ]

    def _start(self) -> None:
        if self._req is None:
            self.target_label.setText("No request loaded.")
            return
        self.table.setRowCount(0)
        self.progress_bar.setValue(0)
        words = self._wordlist()
        if not words:
            return
        self.progress_bar.setRange(0, len(words))

        self._worker = ParamMinerWorker(
            req=self._req,
            mode=self.mode_combo.currentText(),
            wordlist=words,
            value=self.value_edit.text() or "coughprobe",
            threshold=self.threshold_spin.value(),
            throttle_ms=self.throttle_spin.value(),
            target_param_name=self.target_param_edit.text().strip(),
        )
        self._worker.baseline_done.connect(self._on_baseline)
        self._worker.progress.connect(self._on_progress)
        self._worker.hit.connect(self._on_hit)
        self._worker.finished_ok.connect(self._on_done)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._worker.start()

    def _stop(self) -> None:
        if self._worker:
            self._worker.stop()

    def _on_baseline(self, status: int, length: int) -> None:
        self.target_label.setText(
            self.target_label.text() + f"   |   baseline: {status} ({length} bytes)"
        )

    def _on_progress(self, current: int, total: int) -> None:
        self.progress_bar.setValue(current)
        self.progress_bar.setFormat(f"{current} / {total}")

    def _on_hit(self, name: str, status: int, length: int, delta: int) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(name))
        self.table.setItem(row, 1, QTableWidgetItem(str(status)))
        self.table.setItem(row, 2, QTableWidgetItem(str(length)))
        self.table.setItem(row, 3, QTableWidgetItem(f"{delta:+d}"))

    def _on_done(self) -> None:
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _on_mode_changed(self, mode: str) -> None:
        is_values = mode.startswith("values")
        self.target_param_label.setVisible(is_values)
        self.target_param_edit.setVisible(is_values)
        if is_values:
            self.wordlist_label.setText("Values to try (one per line):")
            # In values mode the per-iteration `value` arg is unused.
            self.value_label.setVisible(False)
            self.value_edit.setVisible(False)
        else:
            self.wordlist_label.setText("Wordlist (one per line):")
            self.value_label.setVisible(True)
            self.value_edit.setVisible(True)
