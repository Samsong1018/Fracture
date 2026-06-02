"""
WebSocket Intruder tab — automated payload injection into WebSocket frames.

Mirrors the HTTP intruder.py style for attack types, marker substitution,
and Catppuccin Mocha theming.

Supports:
  - Sniper        — each payload into each marker position in turn
  - Battering Ram — same payload into ALL marker positions simultaneously
  - Pitchfork     — one payload list per position, iterated in lockstep

Connection layer:
  Tries the optional ``websocket-client`` package first; falls back to a
  raw socket + RFC 6455 implementation that reuses the masking helper
  from ws_tab._build_text_frame.
"""

from __future__ import annotations

import base64
import os
import socket
import ssl
import struct
import time
import urllib.parse
from typing import Optional

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .intruder import (
    MARKER_RE,
    _positions_count,
    _substitute_all,
    _substitute_at_index,
    _substitute_pitchfork,
)
from .ws_tab import _build_text_frame

# ---------------------------------------------------------------------------
# Optional websocket-client import
# ---------------------------------------------------------------------------

try:  # pragma: no cover - import probe
    import websocket as _wsclient  # type: ignore

    _HAS_WSCLIENT = True
except ImportError:
    _wsclient = None  # type: ignore[assignment]
    _HAS_WSCLIENT = False


# ---------------------------------------------------------------------------
# Catppuccin Mocha palette — same tokens as intruder.py / ws_tab.py
# ---------------------------------------------------------------------------

_BG = "#1e1e2e"
_SURFACE = "#181825"
_OVERLAY = "#313244"
_HIGHLIGHT = "#45475a"
_TEXT = "#cdd6f4"
_GREEN = "#a6e3a1"
_BLUE = "#89b4fa"
_RED = "#f38ba8"
_YELLOW = "#f9e2af"
_MUTED = "#585b70"

ATTACK_TYPES = ["Sniper", "Battering Ram", "Pitchfork"]

_REPLY_TRUNCATE = 240


# ---------------------------------------------------------------------------
# Raw RFC 6455 frame helpers (fallback when websocket-client absent)
# ---------------------------------------------------------------------------

def _parse_url(url: str) -> tuple[str, int, str, bool]:
    """Return (host, port, path, is_wss). Raises ValueError on bad URL."""
    parsed = urllib.parse.urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("ws", "wss"):
        raise ValueError(f"Unsupported scheme: {parsed.scheme!r} (expected ws/wss)")
    is_wss = scheme == "wss"
    host = parsed.hostname or ""
    if not host:
        raise ValueError("URL missing host")
    port = parsed.port or (443 if is_wss else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return host, port, path, is_wss


def _ws_handshake(host: str, port: int, path: str, is_wss: bool) -> socket.socket:
    """Perform RFC 6455 client handshake and return the connected socket."""
    sock = socket.create_connection((host, port), timeout=10)
    if is_wss:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)

    key = base64.b64encode(os.urandom(16)).decode("ascii")
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    ).encode("ascii")
    sock.sendall(req)

    # Read until end of HTTP header
    buf = b""
    sock.settimeout(10)
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed during handshake")
        buf += chunk
        if len(buf) > 65536:
            raise ConnectionError("Handshake response too large")
    header_blob = buf.split(b"\r\n\r\n", 1)[0].decode(errors="replace")
    first_line = header_blob.split("\r\n", 1)[0]
    if "101" not in first_line:
        raise ConnectionError(f"Handshake failed: {first_line}")
    return sock


def _read_one_frame_payload(sock: socket.socket, timeout: float) -> bytes:
    """
    Read a single RFC 6455 frame from the (already-upgraded) socket and
    return its decoded payload bytes. Returns b'' on timeout / close.
    Server frames are not masked.
    """
    sock.settimeout(timeout)
    try:
        header = _recv_exact(sock, 2)
    except (socket.timeout, OSError):
        return b""
    if len(header) < 2:
        return b""

    b1 = header[1]
    masked = (b1 >> 7) & 1
    length = b1 & 0x7F
    if length == 126:
        ext = _recv_exact(sock, 2)
        length = int.from_bytes(ext, "big")
    elif length == 127:
        ext = _recv_exact(sock, 8)
        length = int.from_bytes(ext, "big")

    mask_key = b""
    if masked:
        mask_key = _recv_exact(sock, 4)

    payload = _recv_exact(sock, length) if length else b""
    if masked and mask_key:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return payload


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes (or as many as we can before close/timeout)."""
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        try:
            chunk = sock.recv(remaining)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# Connection abstraction (websocket-client preferred, raw socket fallback)
# ---------------------------------------------------------------------------

class _WSConnection:
    """
    Thin connection wrapper exposing send_text / recv_text / close.
    Uses websocket-client when available, else raw socket frames.
    """

    def __init__(self, url: str) -> None:
        self._url = url
        self._ws = None  # websocket.WebSocket instance
        self._sock: Optional[socket.socket] = None
        self._using_lib = False

    def connect(self) -> None:
        if _HAS_WSCLIENT:
            try:
                ws = _wsclient.create_connection(  # type: ignore[union-attr]
                    self._url,
                    timeout=10,
                    sslopt={"cert_reqs": ssl.CERT_NONE, "check_hostname": False},
                )
                self._ws = ws
                self._using_lib = True
                return
            except Exception:
                # Fall through to raw implementation
                self._ws = None
                self._using_lib = False

        host, port, path, is_wss = _parse_url(self._url)
        self._sock = _ws_handshake(host, port, path, is_wss)

    def send_text(self, payload: str) -> None:
        if self._using_lib and self._ws is not None:
            self._ws.send(payload)
            return
        if self._sock is None:
            raise ConnectionError("Not connected")
        frame = _build_text_frame(payload.encode("utf-8", errors="replace"))
        self._sock.sendall(frame)

    def recv_text(self, timeout: float) -> str:
        if self._using_lib and self._ws is not None:
            try:
                self._ws.settimeout(timeout)
                data = self._ws.recv()
            except Exception:
                return ""
            if isinstance(data, bytes):
                return data.decode("utf-8", errors="replace")
            return data or ""
        if self._sock is None:
            return ""
        payload = _read_one_frame_payload(self._sock, timeout)
        return payload.decode("utf-8", errors="replace")

    def close(self) -> None:
        if self._using_lib and self._ws is not None:
            try:
                self._ws.close()
            except Exception:
                pass
            self._ws = None
        elif self._sock is not None:
            try:
                # Best-effort CLOSE frame (opcode 0x8, masked, empty)
                mask = os.urandom(4)
                self._sock.sendall(bytes([0x88, 0x80]) + mask)
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    @property
    def connected(self) -> bool:
        return (self._using_lib and self._ws is not None) or self._sock is not None


# ---------------------------------------------------------------------------
# Attack worker
# ---------------------------------------------------------------------------

class WSAttackWorker(QThread):
    """
    Iterates over payload sets, substitutes them into the template frame,
    sends each over the WebSocket, and waits briefly for a reply.

    Emits ``result(index, payload_label, reply_preview, elapsed_ms)`` per
    sent frame, and ``finished`` when the job completes.
    """

    result = pyqtSignal(int, str, str, float)
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(
        self,
        url: str,
        template: str,
        payload_sets: list[list[str]],
        attack_type: str,
        recv_timeout_ms: int = 500,
        throttle_ms: int = 0,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._url = url
        self._template = template
        self._payload_sets = payload_sets
        self._attack_type = attack_type
        self._recv_timeout_s = max(recv_timeout_ms, 0) / 1000.0
        self._throttle_ms = max(throttle_ms, 0)
        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True

    def _jobs(self):
        """Yield (label, substituted_frame) jobs for the active attack type."""
        attack = self._attack_type
        payloads0 = self._payload_sets[0] if self._payload_sets else []

        if attack == "Sniper":
            n_positions = _positions_count(self._template)
            if n_positions == 0:
                for payload in payloads0:
                    yield payload, self._template
            else:
                for pos_idx in range(n_positions):
                    for payload in payloads0:
                        substituted = _substitute_at_index(
                            self._template, pos_idx, payload
                        )
                        yield f"[pos{pos_idx + 1}] {payload}", substituted

        elif attack == "Battering Ram":
            for payload in payloads0:
                yield payload, _substitute_all(self._template, payload)

        elif attack == "Pitchfork":
            for combo in zip(*self._payload_sets):
                yield " | ".join(combo), _substitute_pitchfork(
                    self._template, list(combo)
                )

    def run(self) -> None:  # noqa: D401 - QThread entry point
        conn = _WSConnection(self._url)
        try:
            conn.connect()
        except Exception as exc:
            self.error.emit(f"Connect failed: {exc}")
            self.finished.emit()
            return

        idx = 0
        try:
            for label, frame in self._jobs():
                if self._stop_requested:
                    break
                idx += 1
                start = time.monotonic()
                try:
                    conn.send_text(frame)
                except Exception as exc:
                    self.result.emit(
                        idx, label, f"<send error: {exc}>", 0.0
                    )
                    break

                reply = ""
                if self._recv_timeout_s > 0:
                    try:
                        reply = conn.recv_text(self._recv_timeout_s)
                    except Exception as exc:
                        reply = f"<recv error: {exc}>"

                elapsed_ms = (time.monotonic() - start) * 1000.0
                if len(reply) > _REPLY_TRUNCATE:
                    reply = reply[:_REPLY_TRUNCATE] + "…"
                self.result.emit(idx, label, reply, elapsed_ms)

                if self._throttle_ms > 0 and not self._stop_requested:
                    time.sleep(self._throttle_ms / 1000.0)
        finally:
            conn.close()
            self.finished.emit()


# ---------------------------------------------------------------------------
# Stylesheet helpers (mirrors intruder.py exactly)
# ---------------------------------------------------------------------------

def _ss_line_edit() -> str:
    return (
        f"QLineEdit {{ background: {_SURFACE}; border: 1px solid {_OVERLAY}; "
        f"padding: 4px; border-radius: 3px; color: {_TEXT}; }}"
    )


def _ss_spinbox() -> str:
    return (
        f"QSpinBox {{ background: {_SURFACE}; border: 1px solid {_OVERLAY}; "
        f"padding: 3px; border-radius: 3px; color: {_TEXT}; }}"
    )


def _ss_button(bold: bool = False) -> str:
    weight = "font-weight: bold;" if bold else ""
    return (
        f"QPushButton {{ background: {_OVERLAY}; border: 1px solid {_HIGHLIGHT}; "
        f"padding: 4px 10px; border-radius: 4px; color: {_TEXT}; {weight} }}"
        f"QPushButton:hover {{ background: {_HIGHLIGHT}; }}"
        f"QPushButton:disabled {{ color: {_MUTED}; border-color: {_OVERLAY}; }}"
    )


def _ss_text_edit() -> str:
    return (
        f"QTextEdit {{ background: {_SURFACE}; border: 1px solid {_OVERLAY}; "
        f"color: {_TEXT}; }}"
    )


def _ss_combo() -> str:
    return (
        f"QComboBox {{ background: {_SURFACE}; border: 1px solid {_OVERLAY}; "
        f"padding: 4px; border-radius: 3px; color: {_TEXT}; }}"
        f"QComboBox::drop-down {{ border: none; }}"
        f"QComboBox QAbstractItemView {{ background: {_SURFACE}; color: {_TEXT}; "
        f"selection-background-color: {_HIGHLIGHT}; }}"
    )


def _ss_table() -> str:
    return (
        f"QTableWidget {{ background: {_SURFACE}; border: 1px solid {_OVERLAY}; "
        f"gridline-color: {_OVERLAY}; color: {_TEXT}; }}"
        f"QHeaderView::section {{ background: {_OVERLAY}; padding: 4px; "
        f"border: 1px solid {_HIGHLIGHT}; color: {_TEXT}; }}"
        f"QTableWidget::item:selected {{ background: {_HIGHLIGHT}; }}"
    )


# ---------------------------------------------------------------------------
# Main tab
# ---------------------------------------------------------------------------

class WebSocketIntruderTab(QWidget):
    """
    WebSocket Intruder tab — Catppuccin Mocha theme.

    Public API:
      - load_url(url): set the URL field from the WS history tab
    """

    # Columns
    COL_IDX = 0
    COL_PAYLOAD = 1
    COL_REPLY = 2
    COL_TIME = 3

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._worker: Optional[WSAttackWorker] = None
        self.setStyleSheet(
            f"QWidget {{ background: {_BG}; color: {_TEXT}; }}"
            f"QLabel  {{ color: {_TEXT}; }}"
        )
        self._setup_ui()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_url(self, url: str) -> None:
        """Populate the URL field — used by the WS history tab's 'send to'."""
        self._url_edit.setText(url)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setSpacing(6)
        root.setContentsMargins(8, 8, 8, 8)

        root.addLayout(self._build_target_bar())
        root.addLayout(self._build_attack_bar())

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_left_panel())
        splitter.addWidget(self._build_right_panel())
        splitter.setSizes([480, 720])
        root.addWidget(splitter, stretch=1)

    # ---- target bar ----

    def _build_target_bar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(8)

        bar.addWidget(QLabel("URL:"))
        self._url_edit = QLineEdit()
        self._url_edit.setPlaceholderText("ws://example.com:8080/socket or wss://...")
        self._url_edit.setStyleSheet(_ss_line_edit())
        bar.addWidget(self._url_edit, stretch=1)

        self._connect_btn = QPushButton("Test Connect")
        self._connect_btn.setStyleSheet(_ss_button())
        self._connect_btn.setToolTip("Open + close a probe connection to validate the URL")
        self._connect_btn.clicked.connect(self._test_connect)
        bar.addWidget(self._connect_btn)

        bar.addSpacing(10)
        bar.addWidget(QLabel("Recv wait:"))
        self._recv_spin = QSpinBox()
        self._recv_spin.setRange(0, 30000)
        self._recv_spin.setValue(500)
        self._recv_spin.setSuffix(" ms")
        self._recv_spin.setFixedWidth(90)
        self._recv_spin.setStyleSheet(_ss_spinbox())
        bar.addWidget(self._recv_spin)

        bar.addWidget(QLabel("Throttle:"))
        self._throttle_spin = QSpinBox()
        self._throttle_spin.setRange(0, 10000)
        self._throttle_spin.setValue(0)
        self._throttle_spin.setSuffix(" ms")
        self._throttle_spin.setFixedWidth(90)
        self._throttle_spin.setStyleSheet(_ss_spinbox())
        bar.addWidget(self._throttle_spin)

        self._status_lbl = QLabel(
            "websocket-client" if _HAS_WSCLIENT else "raw RFC6455"
        )
        self._status_lbl.setStyleSheet(f"color: {_MUTED}; font-size: 10px;")
        bar.addSpacing(10)
        bar.addWidget(self._status_lbl)
        bar.addStretch()
        return bar

    # ---- attack type bar ----

    def _build_attack_bar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(8)

        lbl = QLabel("Attack Type:")
        lbl.setStyleSheet(f"color: {_TEXT}; font-weight: bold;")
        bar.addWidget(lbl)

        self._attack_combo = QComboBox()
        self._attack_combo.addItems(ATTACK_TYPES)
        self._attack_combo.setFixedWidth(160)
        self._attack_combo.setStyleSheet(_ss_combo())
        self._attack_combo.currentTextChanged.connect(self._on_attack_type_changed)
        bar.addWidget(self._attack_combo)

        self._parse_btn = QPushButton("Parse Positions")
        self._parse_btn.setStyleSheet(_ss_button())
        self._parse_btn.clicked.connect(self._parse_positions)
        bar.addWidget(self._parse_btn)

        self._positions_lbl = QLabel("(no positions parsed)")
        self._positions_lbl.setStyleSheet(f"color: {_MUTED};")
        bar.addWidget(self._positions_lbl)

        bar.addStretch()
        return bar

    # ---- left panel ----

    def _build_left_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        tpl_lbl = QLabel("Template Frame  (wrap injection points with §markers§)")
        tpl_lbl.setStyleSheet(f"color: {_TEXT}; font-weight: bold;")
        layout.addWidget(tpl_lbl)

        self._template_editor = QTextEdit()
        self._template_editor.setFont(QFont("Monospace", 9))
        self._template_editor.setPlaceholderText(
            '{"action":"login","user":"§admin§","pass":"§password§"}'
        )
        self._template_editor.setStyleSheet(_ss_text_edit())
        layout.addWidget(self._template_editor, stretch=3)

        payload_lbl = QLabel("Payloads")
        payload_lbl.setStyleSheet(f"color: {_TEXT}; font-weight: bold;")
        layout.addWidget(payload_lbl)

        self._payload_editor = QTextEdit()
        self._payload_editor.setFont(QFont("Monospace", 9))
        self._payload_editor.setPlaceholderText("payload1\npayload2\n...")
        self._payload_editor.setStyleSheet(_ss_text_edit())
        layout.addWidget(self._payload_editor, stretch=2)

        self._payload_tabs = QTabWidget()
        self._payload_tabs.setStyleSheet(
            f"QTabWidget::pane {{ background: {_BG}; border: 1px solid {_OVERLAY}; }}"
            f"QTabBar::tab {{ background: {_OVERLAY}; color: {_TEXT}; "
            f"padding: 4px 10px; border: 1px solid {_HIGHLIGHT}; "
            f"border-bottom: none; margin-right: 2px; }}"
            f"QTabBar::tab:selected {{ background: {_HIGHLIGHT}; }}"
        )
        self._payload_tabs.setVisible(False)
        layout.addWidget(self._payload_tabs, stretch=2)

        # Action buttons
        btn_row = QHBoxLayout()
        self._start_btn = QPushButton("Start Attack")
        self._start_btn.setStyleSheet(_ss_button(bold=True))
        self._start_btn.clicked.connect(self._start_attack)
        btn_row.addWidget(self._start_btn)

        self._stop_btn = QPushButton("Stop")
        self._stop_btn.setEnabled(False)
        self._stop_btn.setStyleSheet(_ss_button())
        self._stop_btn.clicked.connect(self._stop_attack)
        btn_row.addWidget(self._stop_btn)

        self._clear_btn = QPushButton("Clear Results")
        self._clear_btn.setStyleSheet(_ss_button())
        self._clear_btn.clicked.connect(self._clear_results)
        btn_row.addWidget(self._clear_btn)

        btn_row.addStretch()
        layout.addLayout(btn_row)

        return panel

    # ---- right panel ----

    def _build_right_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        hdr = QLabel("Results")
        hdr.setStyleSheet(f"color: {_TEXT}; font-weight: bold;")
        layout.addWidget(hdr)

        self._results_table = QTableWidget(0, 4)
        self._results_table.setHorizontalHeaderLabels(
            ["#", "Payload", "Reply", "Time (ms)"]
        )
        self._results_table.setFont(QFont("Monospace", 9))
        self._results_table.setStyleSheet(_ss_table())
        self._results_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._results_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._results_table.verticalHeader().setVisible(False)
        header = self._results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self._results_table, stretch=1)

        self._activity_lbl = QLabel("")
        self._activity_lbl.setStyleSheet(f"color: {_MUTED}; font-size: 10px;")
        layout.addWidget(self._activity_lbl)

        return panel

    # ------------------------------------------------------------------
    # Attack-type / position handling
    # ------------------------------------------------------------------

    def _on_attack_type_changed(self, attack_type: str) -> None:
        multi = attack_type == "Pitchfork"
        self._payload_editor.setVisible(not multi)
        self._payload_tabs.setVisible(multi)

    def _parse_positions(self) -> None:
        n = _positions_count(self._template_editor.toPlainText())
        self._positions_lbl.setText(f"{n} position(s) found")
        self._positions_lbl.setStyleSheet(f"color: {_GREEN};")
        if self._attack_combo.currentText() == "Pitchfork":
            self._rebuild_payload_tabs(n)

    def _rebuild_payload_tabs(self, n_positions: int) -> None:
        existing: list[str] = []
        for i in range(self._payload_tabs.count()):
            widget = self._payload_tabs.widget(i)
            if isinstance(widget, QTextEdit):
                existing.append(widget.toPlainText())
        self._payload_tabs.clear()
        for i in range(max(n_positions, 1)):
            editor = QTextEdit()
            editor.setFont(QFont("Monospace", 9))
            editor.setPlaceholderText(f"Payloads for position {i + 1} (one per line)")
            editor.setStyleSheet(
                f"QTextEdit {{ background: {_BG}; border: none; color: {_TEXT}; }}"
            )
            if i < len(existing):
                editor.setPlainText(existing[i])
            self._payload_tabs.addTab(editor, f"Position {i + 1}")

    def _get_payload_sets(self) -> list[list[str]]:
        attack = self._attack_combo.currentText()
        if attack in ("Sniper", "Battering Ram"):
            text = self._payload_editor.toPlainText()
            return [[p for p in text.splitlines() if p]]
        sets: list[list[str]] = []
        for i in range(self._payload_tabs.count()):
            widget = self._payload_tabs.widget(i)
            if isinstance(widget, QTextEdit):
                sets.append(
                    [p for p in widget.toPlainText().splitlines() if p]
                )
            else:
                sets.append([])
        return sets

    # ------------------------------------------------------------------
    # Attack lifecycle
    # ------------------------------------------------------------------

    def _test_connect(self) -> None:
        url = self._url_edit.text().strip()
        if not url:
            self._set_activity("URL is empty.", error=True)
            return
        conn = _WSConnection(url)
        try:
            conn.connect()
        except Exception as exc:
            self._set_activity(f"Connect failed: {exc}", error=True)
            return
        finally:
            conn.close()
        self._set_activity("Connect OK.", error=False)

    def _start_attack(self) -> None:
        url = self._url_edit.text().strip()
        if not url:
            self._set_activity("URL is empty.", error=True)
            return
        template = self._template_editor.toPlainText()
        if not template:
            self._set_activity("Template frame is empty.", error=True)
            return

        payload_sets = self._get_payload_sets()
        if not any(payload_sets):
            self._set_activity("Provide at least one payload.", error=True)
            return

        attack_type = self._attack_combo.currentText()
        if attack_type == "Pitchfork" and len(payload_sets) < _positions_count(template):
            self._set_activity(
                "Pitchfork: payload-list count must match position count "
                "(click Parse Positions).",
                error=True,
            )
            return

        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._set_activity("Running…", error=False)

        self._worker = WSAttackWorker(
            url=url,
            template=template,
            payload_sets=payload_sets,
            attack_type=attack_type,
            recv_timeout_ms=self._recv_spin.value(),
            throttle_ms=self._throttle_spin.value(),
            parent=self,
        )
        self._worker.result.connect(self._on_result)
        self._worker.error.connect(self._on_error)
        self._worker.finished.connect(self._on_attack_finished)
        self._worker.start()

    def _stop_attack(self) -> None:
        if self._worker is not None:
            self._worker.stop()

    def _clear_results(self) -> None:
        self._results_table.setRowCount(0)
        self._set_activity("", error=False)

    # ------------------------------------------------------------------
    # Worker slots
    # ------------------------------------------------------------------

    def _on_result(
        self, idx: int, payload_label: str, reply: str, elapsed_ms: float
    ) -> None:
        row = self._results_table.rowCount()
        self._results_table.insertRow(row)

        idx_item = QTableWidgetItem(str(idx))
        idx_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self._results_table.setItem(row, self.COL_IDX, idx_item)

        self._results_table.setItem(
            row, self.COL_PAYLOAD, QTableWidgetItem(payload_label)
        )

        reply_item = QTableWidgetItem(reply.replace("\n", " ").replace("\r", " "))
        if reply.startswith("<send error") or reply.startswith("<recv error"):
            reply_item.setForeground(QColor(_RED))
        elif reply:
            reply_item.setForeground(QColor(_BLUE))
        else:
            reply_item.setForeground(QColor(_MUTED))
        self._results_table.setItem(row, self.COL_REPLY, reply_item)

        time_item = QTableWidgetItem(f"{elapsed_ms:.1f}")
        time_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self._results_table.setItem(row, self.COL_TIME, time_item)

        self._results_table.scrollToBottom()

    def _on_error(self, message: str) -> None:
        self._set_activity(message, error=True)

    def _on_attack_finished(self) -> None:
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        if not self._activity_lbl.text().startswith("Connect failed"):
            self._set_activity("Done.", error=False)
        self._worker = None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _set_activity(self, text: str, *, error: bool) -> None:
        color = _RED if error else _GREEN
        if not text:
            color = _MUTED
        self._activity_lbl.setText(text)
        self._activity_lbl.setStyleSheet(f"color: {color}; font-size: 10px;")
