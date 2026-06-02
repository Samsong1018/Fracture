"""
Authorization testing tab — Autorize-style.

Stream every proxied request through a replay path using a second session
(cookies / Authorization header / arbitrary header overrides).  Diff the
status code + length + body hash vs. the original response; classify each
as BYPASSED, ENFORCED, or SAME.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
from typing import Optional

from PyQt6.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .proxy import HttpRequest, HttpResponse


_BUFFER = 65536


_TEXTEDIT_SS = (
    "QTextEdit { background: #181825; border: 1px solid #313244; "
    "color: #cdd6f4; font-family: monospace; font-size: 12px; }"
)
_PLAIN_SS = (
    "QPlainTextEdit { background: #181825; border: 1px solid #313244; "
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
)
_TABLE_SS = (
    "QTableWidget { background: #181825; gridline-color: #313244; color: #cdd6f4; }"
    "QTableWidget::item:selected { background: #45475a; }"
    "QHeaderView::section { background: #313244; color: #cdd6f4; border: 0; padding: 4px; }"
)


def _build_raw_request(req: HttpRequest, header_overrides: dict[str, str]) -> bytes:
    """Rebuild a raw HTTP request swapping in/overriding headers."""
    headers = dict(req.headers)
    # case-insensitive override
    lower_overrides = {k.lower(): (k, v) for k, v in header_overrides.items()}
    headers = {
        k: v for k, v in headers.items()
        if k.lower() not in lower_overrides
    }
    for _, (k, v) in lower_overrides.items():
        headers[k] = v
    if "host" not in {k.lower() for k in headers}:
        headers["Host"] = req.host
    lines = [f"{req.method} {req.path} HTTP/1.1"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode() + (req.body or b"")
    return raw


def _send_raw(host: str, port: int, is_https: bool, data: bytes
              ) -> tuple[int, bytes, bytes]:
    """Returns (status, body, headers_block)."""
    try:
        sock = socket.create_connection((host, port), timeout=10)
        if is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(data)
        buf = b""
        sock.settimeout(5)
        while True:
            try:
                chunk = sock.recv(_BUFFER)
                if not chunk:
                    break
                buf += chunk
            except socket.timeout:
                break
        sock.close()
    except Exception:
        return 0, b"", b""

    if b"\r\n\r\n" in buf:
        head, body = buf.split(b"\r\n\r\n", 1)
    else:
        head, body = buf, b""
    status = 0
    try:
        first = head.split(b"\r\n", 1)[0].decode(errors="replace")
        status = int(first.split(" ", 2)[1])
    except Exception:
        pass
    return status, body, head


def classify(orig_status: int, orig_body: bytes,
             new_status: int, new_body: bytes,
             threshold: int = 32) -> str:
    """Compare original vs. replayed response and return a verdict."""
    if new_status == 0:
        return "ERROR"
    if new_status in (401, 403):
        return "ENFORCED"
    # If response is now an auth redirect, treat as enforced
    if new_status in (302, 303, 307) and orig_status not in (302, 303, 307):
        return "ENFORCED"
    orig_hash = hashlib.sha1(orig_body).hexdigest()
    new_hash = hashlib.sha1(new_body).hexdigest()
    same_size = abs(len(orig_body) - len(new_body)) < threshold
    same_status = orig_status == new_status
    if orig_hash == new_hash:
        return "BYPASSED"
    if same_status and same_size:
        return "BYPASSED"
    if same_status and not same_size:
        return "PARTIAL"
    return "SAME"


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

class AuthzReplayWorker(QObject):
    """One replay per incoming proxied request."""

    # req, new_status, new_len, verdict, orig_status, orig_len
    result = pyqtSignal(object, int, int, str, int, int)

    def __init__(self, header_overrides: dict[str, str]) -> None:
        super().__init__()
        self._overrides = header_overrides

    def replay(self, req: HttpRequest, resp: Optional[HttpResponse]) -> None:
        if not self._overrides or resp is None:
            return
        try:
            raw = _build_raw_request(req, self._overrides)
        except Exception:
            return
        status, body, _ = _send_raw(req.host, req.port, req.is_https, raw)
        verdict = classify(resp.status_code, resp.body or b"", status, body)
        self.result.emit(
            req, status, len(body), verdict,
            resp.status_code, len(resp.body or b""),
        )


class AuthzTab(QWidget):
    """Authorization-testing tab."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._enabled = False
        self._scope: str = ""
        self._overrides: dict[str, str] = {}
        self._worker: Optional[AuthzReplayWorker] = None
        self._thread: Optional[QThread] = None
        self._rows: dict[int, int] = {}  # req.id -> table row
        self._report_rows: list[dict] = []  # captured for export

        root = QVBoxLayout(self)

        # Configure secondary session
        cfg = QVBoxLayout()
        cfg.addWidget(QLabel("Secondary session — header overrides (one per line, 'Name: value'):"))

        self.headers_edit = QPlainTextEdit()
        self.headers_edit.setStyleSheet(_PLAIN_SS)
        self.headers_edit.setPlaceholderText(
            "Cookie: session=abc123\nAuthorization: Bearer eyJ..."
        )
        self.headers_edit.setMaximumHeight(110)
        cfg.addWidget(self.headers_edit)

        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Scope (host substring; blank = all):"))
        self.scope_edit = QLineEdit()
        self.scope_edit.setStyleSheet(_LINEEDIT_SS)
        ctrl.addWidget(self.scope_edit)

        self.enable_check = QCheckBox("Enable replay")
        self.enable_check.setStyleSheet("color: #cdd6f4;")
        self.enable_check.stateChanged.connect(self._on_enable)
        ctrl.addWidget(self.enable_check)

        clear_btn = QPushButton("Clear results")
        clear_btn.setStyleSheet(_BTN_SS)
        clear_btn.clicked.connect(self._clear_results)
        ctrl.addWidget(clear_btn)

        report_btn = QPushButton("Generate Report…")
        report_btn.setStyleSheet(_BTN_SS)
        report_btn.clicked.connect(self._generate_report)
        ctrl.addWidget(report_btn)
        ctrl.addStretch()
        cfg.addLayout(ctrl)
        root.addLayout(cfg)

        # Results table
        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels(
            ["#", "Host", "Path", "Orig", "Replay", "Verdict"]
        )
        self._table.setStyleSheet(_TABLE_SS)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._table.setEditTriggers(self._table.EditTrigger.NoEditTriggers)
        root.addWidget(self._table, 1)

    # ------------------------------------------------------------------
    def _on_enable(self, state: int) -> None:
        self._enabled = bool(state)
        self._overrides = self._parse_headers()
        self._scope = self.scope_edit.text().strip().lower()
        if self._enabled and self._worker is None:
            self._thread = QThread()
            self._worker = AuthzReplayWorker(self._overrides)
            self._worker.moveToThread(self._thread)
            self._worker.result.connect(self._on_result)
            self._thread.start()

    def _parse_headers(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for line in self.headers_edit.toPlainText().splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                out[k.strip()] = v.strip()
        return out

    def _clear_results(self) -> None:
        self._table.setRowCount(0)
        self._rows.clear()
        self._report_rows.clear()

    def _generate_report(self) -> None:
        from PyQt6.QtWidgets import QFileDialog, QMessageBox
        from .scanner_report import generate_authz_html_report
        if not self._report_rows:
            QMessageBox.information(self, "Authz report", "No results to export.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Authz report", "authz_report.html", "HTML (*.html)"
        )
        if not path:
            return
        try:
            generate_authz_html_report(self._report_rows, path)
        except Exception as e:
            QMessageBox.critical(self, "Authz report", f"Failed: {e}")
            return
        QMessageBox.information(self, "Authz report", f"Saved {len(self._report_rows)} rows to:\n{path}")

    # ------------------------------------------------------------------
    def add_entry(self, req: HttpRequest, resp: Optional[HttpResponse]) -> None:
        """Hook this into the proxy history pipeline."""
        if not self._enabled or self._worker is None or resp is None:
            return
        if self._scope and self._scope not in req.host.lower():
            return
        # Skip if request already carries our override header (avoid replay loop)
        for k in self._overrides:
            if k.lower() in {hk.lower() for hk in req.headers}:
                if req.headers[next(hk for hk in req.headers if hk.lower() == k.lower())] == self._overrides[k]:
                    return
        # Refresh overrides from live UI in case user edited mid-session
        self._worker._overrides = self._parse_headers()
        # Run replay on the worker thread
        self._worker.replay(req, resp)

    def _on_result(self, req, new_status: int, new_len: int, verdict: str,
                   orig_status: int = 0, orig_len: int = 0) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)
        items = [
            QTableWidgetItem(str(req.id)),
            QTableWidgetItem(req.host),
            QTableWidgetItem(req.path),
            QTableWidgetItem(f"{orig_status} ({orig_len}b)"),
            QTableWidgetItem(f"{new_status} ({new_len}b)"),
            QTableWidgetItem(verdict),
        ]
        color = {
            "BYPASSED": "#f38ba8",
            "PARTIAL":  "#f9e2af",
            "ENFORCED": "#a6e3a1",
            "SAME":     "#a6adc8",
            "ERROR":    "#585b70",
        }.get(verdict, "#cdd6f4")
        items[5].setForeground(QColor(color))
        for col, it in enumerate(items):
            self._table.setItem(row, col, it)
        self._rows[req.id] = row
        self._report_rows.append({
            "id": req.id,
            "method": req.method,
            "host": req.host,
            "path": req.path,
            "orig_status": orig_status,
            "orig_len": orig_len,
            "replay_status": new_status,
            "replay_len": new_len,
            "verdict": verdict,
        })
