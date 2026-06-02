"""
Turbo Intruder — high-throughput attack engine.

Uses a pool of persistent keep-alive connections to issue many requests in
parallel.  Results are funnelled through a QAbstractTableModel so the table
stays responsive even with hundreds of thousands of rows.
"""

from __future__ import annotations

import re
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableView,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .hackvertor import transform as _hv_transform
from .payload_generators import PayloadGeneratorDialog
from .proxy import HttpRequest


_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
    "QPushButton:hover { background: #45475a; }"
    "QPushButton:disabled { color: #585b70; }"
)
_LINEEDIT_SS = (
    "QLineEdit { background: #181825; border: 1px solid #313244; "
    "padding: 4px; color: #cdd6f4; }"
)
_TEXTEDIT_SS = (
    "QTextEdit { background: #181825; border: 1px solid #313244; "
    "color: #cdd6f4; font-family: monospace; font-size: 12px; }"
)
_TABLE_SS = (
    "QTableView { background: #181825; gridline-color: #313244; color: #cdd6f4; }"
    "QHeaderView::section { background: #313244; color: #cdd6f4; border: 0; padding: 4px; }"
)


_MARKER_RE = re.compile(r"§([^§]*)§")


def _substitute(template: str, payload: str) -> str:
    """Replace each §...§ marker with the payload."""
    return _MARKER_RE.sub(payload, template)


# ---------------------------------------------------------------------------
# Connection pool with keepalive
# ---------------------------------------------------------------------------

class _Connection:
    """One persistent socket to host:port, supports send + read-response."""

    def __init__(self, host: str, port: int, is_https: bool) -> None:
        self._host = host
        self._port = port
        self._is_https = is_https
        self._sock: Optional[socket.socket] = None

    def _connect(self) -> None:
        sock = socket.create_connection((self._host, self._port), timeout=10)
        if self._is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=self._host)
        sock.settimeout(5)
        self._sock = sock

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def send_and_read(self, request: bytes) -> tuple[int, int, float, bytes]:
        """Send a request and read one HTTP response from the same socket."""
        start = time.monotonic()
        for attempt in range(2):
            try:
                if self._sock is None:
                    self._connect()
                assert self._sock is not None
                self._sock.sendall(request)
                response = self._read_response(self._sock)
                elapsed = (time.monotonic() - start) * 1000.0
                status = _parse_status(response)
                return status, len(response), elapsed, response
            except Exception:
                self.close()
                if attempt == 1:
                    return 0, 0, (time.monotonic() - start) * 1000.0, b""
        return 0, 0, 0.0, b""

    @staticmethod
    def _read_response(sock: socket.socket) -> bytes:
        """Read one HTTP/1.1 response off the socket without closing it."""
        buf = b""
        # Read until end of headers
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(8192)
            if not chunk:
                return buf
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        head_lower = head.lower()

        # Determine framing
        content_length = -1
        chunked = b"transfer-encoding: chunked" in head_lower
        for line in head_lower.split(b"\r\n"):
            if line.startswith(b"content-length:"):
                try:
                    content_length = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    pass
                break

        body = rest
        if chunked:
            while not body.endswith(b"0\r\n\r\n"):
                chunk = sock.recv(8192)
                if not chunk:
                    break
                body += chunk
        elif content_length >= 0:
            while len(body) < content_length:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                body += chunk
        else:
            # No framing — single short read with low timeout
            try:
                sock.settimeout(0.3)
                while True:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    body += chunk
            except socket.timeout:
                pass
            finally:
                sock.settimeout(5)

        return head + b"\r\n\r\n" + body


def _parse_status(raw: bytes) -> int:
    if not raw:
        return 0
    first = raw.split(b"\r\n", 1)[0].decode(errors="replace")
    parts = first.split(" ", 2)
    if len(parts) >= 2:
        try:
            return int(parts[1])
        except ValueError:
            return 0
    return 0


def _ensure_keepalive(raw: str) -> str:
    """Force Connection: keep-alive on the request."""
    lines = raw.split("\r\n") if "\r\n" in raw else raw.split("\n")
    found = False
    for i, line in enumerate(lines):
        if line.lower().startswith("connection:"):
            lines[i] = "Connection: keep-alive"
            found = True
            break
    if not found:
        # Insert after the request line
        insert_at = 1
        lines.insert(insert_at, "Connection: keep-alive")
    return "\r\n".join(lines)


# ---------------------------------------------------------------------------
# Attack worker
# ---------------------------------------------------------------------------

class TurboWorker(QThread):
    """High-throughput attack worker."""

    result = pyqtSignal(str, int, int, float)
    progress = pyqtSignal(int, int)
    finished_ok = pyqtSignal()

    def __init__(
        self,
        raw_request: str,
        payloads: list[str],
        host: str,
        port: int,
        is_https: bool,
        concurrency: int = 20,
        rate_limit_ms: int = 0,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._raw = _ensure_keepalive(raw_request)
        self._payloads = payloads
        self._host = host
        self._port = port
        self._is_https = is_https
        self._concurrency = max(1, concurrency)
        self._rate_limit_ms = max(0, rate_limit_ms)
        self._stop = False
        self._emit_lock = threading.Lock()
        self._sent = 0

    def stop(self) -> None:
        self._stop = True

    def _worker_loop(self, jobs: list[tuple[int, str]], total: int) -> None:
        conn = _Connection(self._host, self._port, self._is_https)
        try:
            for _, payload in jobs:
                if self._stop:
                    break
                processed = _hv_transform(payload)
                substituted = _substitute(self._raw, processed)
                request_bytes = substituted.encode(errors="replace")
                status, length, elapsed, _ = conn.send_and_read(request_bytes)
                with self._emit_lock:
                    self.result.emit(processed, status, length, elapsed)
                    self._sent += 1
                    self.progress.emit(self._sent, total)
                if self._rate_limit_ms:
                    time.sleep(self._rate_limit_ms / 1000.0)
        finally:
            conn.close()

    def run(self) -> None:
        total = len(self._payloads)
        # Round-robin payloads across workers so each thread reuses its socket.
        buckets: list[list[tuple[int, str]]] = [[] for _ in range(self._concurrency)]
        for i, p in enumerate(self._payloads):
            buckets[i % self._concurrency].append((i, p))

        with ThreadPoolExecutor(max_workers=self._concurrency) as pool:
            futures = [pool.submit(self._worker_loop, b, total) for b in buckets]
            for f in futures:
                try:
                    f.result()
                except Exception:
                    pass
        self.finished_ok.emit()


# ---------------------------------------------------------------------------
# Table model (virtualized)
# ---------------------------------------------------------------------------

class _ResultsModel(QAbstractTableModel):
    """Light-weight model that holds rows as tuples — scales to 100k+ rows."""

    HEADERS = ["#", "Payload", "Status", "Length", "Time (ms)"]

    def __init__(self) -> None:
        super().__init__()
        self._rows: list[tuple[int, str, int, int, float]] = []

    def append(self, payload: str, status: int, length: int, elapsed: float) -> None:
        idx = len(self._rows) + 1
        self.beginInsertRows(QModelIndex(), len(self._rows), len(self._rows))
        self._rows.append((idx, payload, status, length, elapsed))
        self.endInsertRows()

    def clear(self) -> None:
        self.beginResetModel()
        self._rows.clear()
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.HEADERS)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None
        row = self._rows[index.row()]
        col = index.column()
        if col == 4:
            return f"{row[col]:.1f}"
        return row[col]

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section]
        return section + 1


# ---------------------------------------------------------------------------
# Tab
# ---------------------------------------------------------------------------

class TurboIntruderTab(QWidget):
    """UI for the Turbo Intruder engine."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._worker: Optional[TurboWorker] = None
        self._model = _ResultsModel()

        root = QVBoxLayout(self)

        # Target bar
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Host:"))
        self._host_edit = QLineEdit()
        self._host_edit.setStyleSheet(_LINEEDIT_SS)
        self._host_edit.setFixedWidth(200)
        bar.addWidget(self._host_edit)
        bar.addWidget(QLabel("Port:"))
        self._port_edit = QLineEdit("443")
        self._port_edit.setStyleSheet(_LINEEDIT_SS)
        self._port_edit.setFixedWidth(70)
        bar.addWidget(self._port_edit)
        self._https_check = QCheckBox("HTTPS")
        self._https_check.setStyleSheet("color: #cdd6f4;")
        self._https_check.setChecked(True)
        bar.addWidget(self._https_check)

        bar.addSpacing(20)
        bar.addWidget(QLabel("Concurrency:"))
        self._concurrency_spin = QSpinBox()
        self._concurrency_spin.setRange(1, 256)
        self._concurrency_spin.setValue(20)
        bar.addWidget(self._concurrency_spin)

        bar.addWidget(QLabel("Rate (ms):"))
        self._rate_spin = QSpinBox()
        self._rate_spin.setRange(0, 10000)
        self._rate_spin.setValue(0)
        bar.addWidget(self._rate_spin)

        self._start_btn = QPushButton("Start")
        self._start_btn.setStyleSheet(_BTN_SS)
        self._start_btn.clicked.connect(self._start)
        bar.addWidget(self._start_btn)

        self._stop_btn = QPushButton("Stop")
        self._stop_btn.setStyleSheet(_BTN_SS)
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop)
        bar.addWidget(self._stop_btn)

        bar.addStretch()
        root.addLayout(bar)

        # Request template + payloads side by side
        split = QSplitter(Qt.Orientation.Horizontal)

        req_wrap = QWidget()
        req_v = QVBoxLayout(req_wrap)
        req_v.setContentsMargins(0, 0, 0, 0)
        req_v.addWidget(QLabel("Request template — use §marker§ for injection point:"))
        self._request_edit = QTextEdit()
        self._request_edit.setStyleSheet(_TEXTEDIT_SS)
        req_v.addWidget(self._request_edit)
        split.addWidget(req_wrap)

        pay_wrap = QWidget()
        pay_v = QVBoxLayout(pay_wrap)
        pay_v.setContentsMargins(0, 0, 0, 0)
        pay_header = QHBoxLayout()
        pay_header.addWidget(QLabel("Payloads (one per line):"))
        pay_header.addStretch()
        gen_btn = QPushButton("Generate…")
        gen_btn.setStyleSheet(_BTN_SS)
        gen_btn.clicked.connect(self._open_payload_generator)
        pay_header.addWidget(gen_btn)
        pay_v.addLayout(pay_header)
        self._payloads_edit = QTextEdit()
        self._payloads_edit.setStyleSheet(_TEXTEDIT_SS)
        pay_v.addWidget(self._payloads_edit)
        split.addWidget(pay_wrap)

        split.setSizes([520, 260])
        root.addWidget(split, 1)

        # Progress + results
        self._progress = QProgressBar()
        root.addWidget(self._progress)

        self._table = QTableView()
        self._table.setModel(self._model)
        self._table.setStyleSheet(_TABLE_SS)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        # Virtualized: only paints visible rows
        self._table.setVerticalScrollMode(QTableView.ScrollMode.ScrollPerPixel)
        root.addWidget(self._table, 1)

    # ------------------------------------------------------------------
    def _open_payload_generator(self) -> None:
        dlg = PayloadGeneratorDialog(self)
        if dlg.exec():
            payloads = dlg.payloads()
            if payloads:
                self._payloads_edit.setPlainText("\n".join(payloads))

    def load_request(self, req: HttpRequest) -> None:
        self._host_edit.setText(req.host)
        self._port_edit.setText(str(req.port))
        self._https_check.setChecked(req.is_https)
        self._request_edit.setPlainText(req.raw.decode(errors="replace"))

    def _start(self) -> None:
        host = self._host_edit.text().strip()
        if not host:
            return
        try:
            port = int(self._port_edit.text().strip())
        except ValueError:
            port = 443 if self._https_check.isChecked() else 80

        raw = self._request_edit.toPlainText()
        if not raw.strip():
            return
        payloads = [
            line for line in self._payloads_edit.toPlainText().splitlines()
            if line.strip()
        ]
        if not payloads:
            payloads = [""]  # at least one shot

        self._model.clear()
        self._progress.setRange(0, len(payloads))
        self._progress.setValue(0)

        self._worker = TurboWorker(
            raw_request=raw,
            payloads=payloads,
            host=host,
            port=port,
            is_https=self._https_check.isChecked(),
            concurrency=self._concurrency_spin.value(),
            rate_limit_ms=self._rate_spin.value(),
        )
        self._worker.result.connect(self._on_result)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished_ok.connect(self._on_done)
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._worker.start()

    def _stop(self) -> None:
        if self._worker:
            self._worker.stop()

    def _on_result(self, payload: str, status: int, length: int, elapsed: float) -> None:
        self._model.append(payload, status, length, elapsed)

    def _on_progress(self, sent: int, total: int) -> None:
        self._progress.setValue(sent)
        self._progress.setFormat(f"{sent} / {total}")

    def _on_done(self) -> None:
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
