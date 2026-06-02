"""
WebSocket tab for Fracture.

Layout:
  Left  — QListWidget of WebSocketSessions
  Right top  — QListWidget of frames for the selected session
  Right bottom — Frame detail panel (payload, replay button, direction)

Updates live via QTimer polling ws_handler.get_sessions() every 500 ms.
"""

import socket
import struct

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .ws_handler import (
    WsDirection,
    WsFrame,
    WsOpcode,
    WebSocketSession,
    get_sessions,
)


# ---------------------------------------------------------------------------
# Catppuccin Mocha palette
# ---------------------------------------------------------------------------

_BG        = "#1e1e2e"
_SURFACE   = "#181825"
_OVERLAY   = "#313244"
_HIGHLIGHT = "#45475a"
_TEXT      = "#cdd6f4"
_GREEN     = "#a6e3a1"   # → client-to-server
_BLUE      = "#89b4fa"   # ← server-to-client
_RED       = "#f38ba8"   # CLOSE / error
_MUTED     = "#585b70"

_SS_BASE = f"""
QWidget      {{ background: {_BG};      color: {_TEXT}; }}
QListWidget  {{ background: {_SURFACE}; border: 1px solid {_OVERLAY}; }}
QListWidget::item:selected {{ background: {_HIGHLIGHT}; }}
QTextEdit    {{ background: {_SURFACE}; border: 1px solid {_OVERLAY};
                font-family: monospace; font-size: 11px; }}
QPushButton  {{ background: {_OVERLAY}; border: 1px solid {_HIGHLIGHT};
                padding: 4px 10px; border-radius: 4px; color: {_TEXT}; }}
QPushButton:hover {{ background: {_HIGHLIGHT}; }}
QPushButton:disabled {{ color: {_MUTED}; }}
QLabel       {{ color: {_TEXT}; }}
QDialog      {{ background: {_BG}; color: {_TEXT}; }}
"""


# ---------------------------------------------------------------------------
# Helper: build a raw WS text frame (client-masking) for replay
# ---------------------------------------------------------------------------

def _build_text_frame(payload: bytes) -> bytes:
    """
    Build a masked WebSocket TEXT frame containing *payload*.
    Uses a zero mask key (0x00 × 4) for simplicity — XOR with zero is identity.
    """
    import os
    mask_key = os.urandom(4)
    masked_payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

    length = len(payload)
    if length <= 125:
        header = bytes([0x81, 0x80 | length])  # FIN + TEXT opcode, MASK bit set
    elif length <= 65535:
        header = bytes([0x81, 0xFE]) + struct.pack(">H", length)
    else:
        header = bytes([0x81, 0xFF]) + struct.pack(">Q", length)

    return header + mask_key + masked_payload


# ---------------------------------------------------------------------------
# Replay dialog
# ---------------------------------------------------------------------------

class _ReplayDialog(QDialog):
    """Small dialog to edit and resend a WS frame payload."""

    def __init__(self, frame: WsFrame, session: WebSocketSession, parent=None):
        super().__init__(parent)
        self.frame = frame
        self.session = session
        self.setWindowTitle("Replay WebSocket Frame")
        self.setMinimumSize(520, 280)
        self.setStyleSheet(_SS_BASE)

        layout = QVBoxLayout(self)

        lbl = QLabel(
            f"Session {session.session_id} — {session.host}:{session.port}  "
            f"| Direction: {frame.direction.value}  | Opcode: {frame.opcode.name}"
        )
        lbl.setStyleSheet(f"color: {_MUTED}; font-size: 10px;")
        layout.addWidget(lbl)

        # Editable payload
        try:
            initial = frame.payload.decode("utf-8")
        except UnicodeDecodeError:
            initial = frame.payload.hex()

        self.editor = QTextEdit()
        self.editor.setPlainText(initial)
        layout.addWidget(self.editor)

        # Status line
        self.status_lbl = QLabel("")
        self.status_lbl.setStyleSheet(f"color: {_MUTED}; font-size: 10px;")
        layout.addWidget(self.status_lbl)

        btn_row = QHBoxLayout()
        send_btn = QPushButton("Send")
        send_btn.clicked.connect(self._send)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_row.addStretch()
        btn_row.addWidget(send_btn)
        btn_row.addWidget(cancel_btn)
        layout.addLayout(btn_row)

    def _send(self) -> None:
        text = self.editor.toPlainText()
        payload = text.encode("utf-8")
        raw_frame = _build_text_frame(payload)

        server_sock = self.session.server_sock
        if server_sock is None:
            self.status_lbl.setText("Error: no server socket available (session may be closed).")
            self.status_lbl.setStyleSheet(f"color: {_RED}; font-size: 10px;")
            return

        try:
            server_sock.sendall(raw_frame)
            self.status_lbl.setText(f"Sent {len(payload)} bytes.")
            self.status_lbl.setStyleSheet(f"color: {_GREEN}; font-size: 10px;")
        except OSError as exc:
            self.status_lbl.setText(f"Error: {exc}")
            self.status_lbl.setStyleSheet(f"color: {_RED}; font-size: 10px;")


# ---------------------------------------------------------------------------
# Main tab
# ---------------------------------------------------------------------------

class WebSocketTab(QWidget):
    """
    WebSocket history tab — lists sessions and their frames with live updates.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setStyleSheet(_SS_BASE)

        # Internal state
        self._sessions: list[WebSocketSession] = []   # sessions we know about
        self._selected_session: WebSocketSession | None = None
        self._selected_frame: WsFrame | None = None

        self._setup_ui()
        self._setup_timer()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        root = QHBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(4)

        # ── Outer splitter: left (sessions) | right (frames + detail) ──
        outer_splitter = QSplitter(Qt.Orientation.Horizontal)

        # ── Left: session list ──────────────────────────────────────────
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(4)

        sessions_lbl = QLabel("WebSocket Sessions")
        sessions_lbl.setStyleSheet(f"color: {_MUTED}; font-size: 10px; padding: 2px;")
        left_layout.addWidget(sessions_lbl)

        self.session_list = QListWidget()
        self.session_list.setFont(QFont("Monospace", 9))
        self.session_list.currentRowChanged.connect(self._on_session_selected)
        left_layout.addWidget(self.session_list)

        outer_splitter.addWidget(left_panel)

        # ── Right: vertical splitter (frames | detail) ─────────────────
        right_splitter = QSplitter(Qt.Orientation.Vertical)

        # Frame list
        frame_panel = QWidget()
        frame_layout = QVBoxLayout(frame_panel)
        frame_layout.setContentsMargins(0, 0, 0, 0)
        frame_layout.setSpacing(4)

        frames_lbl = QLabel("Frames")
        frames_lbl.setStyleSheet(f"color: {_MUTED}; font-size: 10px; padding: 2px;")
        frame_layout.addWidget(frames_lbl)

        self.frame_list = QListWidget()
        self.frame_list.setFont(QFont("Monospace", 9))
        self.frame_list.currentRowChanged.connect(self._on_frame_selected)
        frame_layout.addWidget(self.frame_list)

        right_splitter.addWidget(frame_panel)

        # Detail panel
        detail_panel = QWidget()
        detail_layout = QVBoxLayout(detail_panel)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(4)

        # Direction / opcode indicator row
        info_row = QHBoxLayout()
        self.direction_lbl = QLabel("")
        self.direction_lbl.setStyleSheet(f"color: {_MUTED}; font-size: 10px;")
        self.opcode_lbl = QLabel("")
        self.opcode_lbl.setStyleSheet(f"color: {_MUTED}; font-size: 10px;")
        self.ts_lbl = QLabel("")
        self.ts_lbl.setStyleSheet(f"color: {_MUTED}; font-size: 10px;")
        info_row.addWidget(self.direction_lbl)
        info_row.addWidget(self.opcode_lbl)
        info_row.addWidget(self.ts_lbl)
        info_row.addStretch()
        detail_layout.addLayout(info_row)

        # Payload view
        self.payload_view = QTextEdit()
        self.payload_view.setReadOnly(True)
        self.payload_view.setPlaceholderText("Select a frame to view its payload")
        detail_layout.addWidget(self.payload_view)

        # Replay button
        btn_row = QHBoxLayout()
        self.replay_btn = QPushButton("Replay Frame")
        self.replay_btn.setEnabled(False)
        self.replay_btn.clicked.connect(self._replay_frame)
        btn_row.addStretch()
        btn_row.addWidget(self.replay_btn)
        detail_layout.addLayout(btn_row)

        right_splitter.addWidget(detail_panel)
        right_splitter.setSizes([250, 200])

        outer_splitter.addWidget(right_splitter)
        outer_splitter.setSizes([220, 780])

        root.addWidget(outer_splitter)

    # ------------------------------------------------------------------
    # Live-update timer
    # ------------------------------------------------------------------

    def _setup_timer(self) -> None:
        self._timer = QTimer(self)
        self._timer.setInterval(500)
        self._timer.timeout.connect(self._poll_sessions)
        self._timer.start()

    def _poll_sessions(self) -> None:
        """Check for new sessions or new frames on the current session."""
        all_sessions = get_sessions()

        # Detect new sessions
        if len(all_sessions) > len(self._sessions):
            for sess in all_sessions[len(self._sessions):]:
                self._sessions.append(sess)
                self._add_session_item(sess)
                # Register a frame callback so we can refresh the frame list
                # when this session is selected.
                sess.add_frame_callback(self._on_new_frame)

        # Refresh the frame count in each session row
        for i, sess in enumerate(self._sessions):
            item = self.session_list.item(i)
            if item is not None:
                item.setText(self._session_label(sess))

        # If a session is selected, refresh its frame list for new frames
        if self._selected_session is not None:
            current_count = self.frame_list.count()
            total_frames = len(self._selected_session.frames)
            if total_frames > current_count:
                for frame in self._selected_session.frames[current_count:]:
                    self._add_frame_item(frame)

    # ------------------------------------------------------------------
    # Session list helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _session_label(sess: WebSocketSession) -> str:
        scheme = "wss" if sess.is_wss else "ws"
        return f"Session {sess.session_id} — {scheme}://{sess.host}:{sess.port} ({len(sess.frames)} frames)"

    def _add_session_item(self, sess: WebSocketSession) -> None:
        item = QListWidgetItem(self._session_label(sess))
        item.setForeground(QColor(_TEXT))
        self.session_list.addItem(item)

    def _on_session_selected(self, row: int) -> None:
        if row < 0 or row >= len(self._sessions):
            self._selected_session = None
            self.frame_list.clear()
            self._clear_detail()
            return

        self._selected_session = self._sessions[row]
        self._reload_frames()

    def _reload_frames(self) -> None:
        self.frame_list.clear()
        self._clear_detail()
        if self._selected_session is None:
            return
        for frame in self._selected_session.frames:
            self._add_frame_item(frame)

    # ------------------------------------------------------------------
    # Frame list helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _frame_label(frame: WsFrame) -> str:
        direction = frame.direction.value
        opcode = frame.opcode.name
        size = len(frame.payload)
        if frame.opcode == WsOpcode.TEXT:
            try:
                preview = frame.payload.decode("utf-8")[:60]
                if len(frame.payload) > 60:
                    preview += "…"
            except UnicodeDecodeError:
                preview = frame.payload[:30].hex()
        elif frame.opcode == WsOpcode.BINARY:
            preview = frame.payload[:30].hex()
        else:
            preview = ""
        label = f"[{direction}] [{opcode}]"
        if preview:
            label += f"  {preview}"
        label += f"  ({size} bytes)"
        return label

    def _frame_color(self, frame: WsFrame) -> str:
        if frame.opcode in (WsOpcode.CLOSE,):
            return _RED
        if frame.direction == WsDirection.CLIENT_TO_SERVER:
            return _GREEN
        return _BLUE

    def _add_frame_item(self, frame: WsFrame) -> None:
        item = QListWidgetItem(self._frame_label(frame))
        item.setForeground(QColor(self._frame_color(frame)))
        item.setData(Qt.ItemDataRole.UserRole, frame)
        self.frame_list.addItem(item)

    def _on_frame_selected(self, row: int) -> None:
        item = self.frame_list.item(row)
        if item is None:
            self._clear_detail()
            return

        frame: WsFrame = item.data(Qt.ItemDataRole.UserRole)
        if frame is None:
            self._clear_detail()
            return

        self._selected_frame = frame
        self._show_frame_detail(frame)

    def _show_frame_detail(self, frame: WsFrame) -> None:
        # Direction label
        color = self._frame_color(frame)
        self.direction_lbl.setText(f"Direction: {frame.direction.value}")
        self.direction_lbl.setStyleSheet(f"color: {color}; font-size: 10px;")

        self.opcode_lbl.setText(f"Opcode: {frame.opcode.name}")
        self.opcode_lbl.setStyleSheet(f"color: {_MUTED}; font-size: 10px;")

        ts = frame.timestamp.strftime("%H:%M:%S.%f")[:-3]
        self.ts_lbl.setText(f"Time: {ts}  |  Masked: {frame.masked}  |  Size: {len(frame.payload)} bytes")
        self.ts_lbl.setStyleSheet(f"color: {_MUTED}; font-size: 10px;")

        # Payload
        if frame.opcode == WsOpcode.BINARY:
            text = frame.payload.hex(" ")
        else:
            try:
                text = frame.payload.decode("utf-8")
            except UnicodeDecodeError:
                text = frame.payload.hex(" ")

        self.payload_view.setPlainText(text)

        # Enable replay only for TEXT/BINARY when server socket exists
        can_replay = (
            frame.opcode in (WsOpcode.TEXT, WsOpcode.BINARY)
            and self._selected_session is not None
            and self._selected_session.server_sock is not None
        )
        self.replay_btn.setEnabled(can_replay)

    def _clear_detail(self) -> None:
        self._selected_frame = None
        self.direction_lbl.setText("")
        self.opcode_lbl.setText("")
        self.ts_lbl.setText("")
        self.payload_view.clear()
        self.replay_btn.setEnabled(False)

    # ------------------------------------------------------------------
    # Replay
    # ------------------------------------------------------------------

    def _replay_frame(self) -> None:
        if self._selected_frame is None or self._selected_session is None:
            return
        dlg = _ReplayDialog(self._selected_frame, self._selected_session, parent=self)
        dlg.exec()

    # ------------------------------------------------------------------
    # Frame callback (called from relay thread — safe because timer polls)
    # ------------------------------------------------------------------

    def _on_new_frame(self, frame: WsFrame) -> None:
        """
        Called by the relay thread when a new frame arrives.
        We do not touch Qt widgets from here — the polling timer handles
        UI updates on the main thread.
        """
        pass  # polling handles the refresh
