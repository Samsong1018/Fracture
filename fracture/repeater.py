"""
Repeater tab — manually edit and resend HTTP/HTTPS requests.

Features:
  - Multiple named tabs (inner QTabWidget), renameable, closeable
  - Per-session send history with prev/next navigation
  - Follow-redirects (up to 10 hops, handled in SendWorker)
  - Raw / Pretty response toggle (JSON pretty-print, HTML text-strip)
"""

import html
import html.parser
import json
import re
import socket
import ssl
from typing import List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from PyQt6.QtCore import QThread, Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTabBar,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

try:
    from PyQt6.QtWebEngineWidgets import QWebEngineView as _QWebEngineView
    _WEBENGINE_AVAILABLE = True
except ImportError:
    _QWebEngineView = None  # type: ignore[assignment,misc]
    _WEBENGINE_AVAILABLE = False

from .proxy import HttpRequest
from .inspector import InspectorWidget
from .editor_ext import (
    HttpSyntaxHighlighter,
    format_http_message,
    install_find_replace,
)
from .hackvertor import transform as _hv_transform
from .multipart_editor import MultipartEditorDialog
from .request_signing import RequestSigningDialog, apply_signing

BUFFER = 65536
MAX_REDIRECTS = 10

# ---------------------------------------------------------------------------
# Stylesheet helpers (Catppuccin Mocha)
# ---------------------------------------------------------------------------

_TEXTEDIT_SS = "QTextEdit { background: #181825; border: 1px solid #313244; }"
_LINEEDIT_SS = "QLineEdit { background: #181825; border: 1px solid #313244; padding: 4px; }"
_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
    "QPushButton:hover { background: #45475a; }"
    "QPushButton:disabled { color: #585b70; }"
    "QPushButton:checked { background: #45475a; border: 1px solid #89b4fa; }"
)
_LABEL_SS = "color: #585b70; font-size: 10px;"
_HIST_LABEL_SS = "color: #a6adc8; font-size: 10px; padding: 0 4px;"


# ---------------------------------------------------------------------------
# HTML tag stripper
# ---------------------------------------------------------------------------

class _HTMLStripper(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._parts: List[str] = []

    def handle_data(self, data: str) -> None:
        self._parts.append(data)

    def get_text(self) -> str:
        return "".join(self._parts)


def _strip_html(text: str) -> str:
    stripper = _HTMLStripper()
    try:
        stripper.feed(text)
        return stripper.get_text()
    except Exception:
        # Fallback: crude regex
        return re.sub(r"<[^>]+>", "", text)


# ---------------------------------------------------------------------------
# Response pretty-printer
# ---------------------------------------------------------------------------

def _pretty_response(raw_response: str) -> str:
    """Return a human-friendly version of *raw_response* based on Content-Type."""
    # Split headers from body
    if "\r\n\r\n" in raw_response:
        head, body = raw_response.split("\r\n\r\n", 1)
    elif "\n\n" in raw_response:
        head, body = raw_response.split("\n\n", 1)
    else:
        return raw_response  # Can't split — return as-is

    content_type = ""
    for line in head.splitlines():
        if line.lower().startswith("content-type:"):
            content_type = line.split(":", 1)[1].strip().lower()
            break

    if "application/json" in content_type:
        try:
            obj = json.loads(body)
            return head + "\r\n\r\n" + json.dumps(obj, indent=2)
        except json.JSONDecodeError:
            return raw_response

    if "text/html" in content_type:
        readable = _strip_html(body)
        # Collapse excessive blank lines
        readable = re.sub(r"\n{3,}", "\n\n", readable).strip()
        return head + "\r\n\r\n" + readable

    return raw_response


# ---------------------------------------------------------------------------
# Worker thread
# ---------------------------------------------------------------------------

def _send_raw(host: str, port: int, is_https: bool, raw_request: bytes) -> bytes:
    """Low-level send and receive; raises on error."""
    sock = socket.create_connection((host, port), timeout=10)
    if is_https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    sock.sendall(raw_request)
    response_data = b""
    sock.settimeout(5)
    while True:
        try:
            chunk = sock.recv(BUFFER)
            if not chunk:
                break
            response_data += chunk
        except socket.timeout:
            break
    sock.close()
    return response_data


def _extract_status_code(response: bytes) -> int:
    """Return the HTTP status code from the first line of *response*."""
    try:
        first_line = response.split(b"\r\n", 1)[0]
        parts = first_line.split(b" ", 2)
        return int(parts[1])
    except Exception:
        return 0


def _extract_location(response: bytes) -> Optional[str]:
    """Return the value of the Location header, or None."""
    try:
        header_section = response.split(b"\r\n\r\n", 1)[0]
        for line in header_section.split(b"\r\n"):
            if line.lower().startswith(b"location:"):
                return line.split(b":", 1)[1].strip().decode(errors="replace")
    except Exception:
        pass
    return None


def _build_get_request(host: str, path: str) -> bytes:
    """Build a minimal GET request for *path* on *host*."""
    if not path:
        path = "/"
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    return request.encode()


class SendWorker(QThread):
    """Send a raw HTTP(S) request in a background thread, optionally following redirects."""

    finished = pyqtSignal(bytes)
    error = pyqtSignal(str)

    def __init__(
        self,
        host: str,
        port: int,
        is_https: bool,
        raw_request: bytes,
        follow_redirects: bool = False,
        parent: Optional[QThread] = None,
    ) -> None:
        super().__init__(parent)
        self._host = host
        self._port = port
        self._is_https = is_https
        self._raw_request = raw_request
        self._follow_redirects = follow_redirects

    def run(self) -> None:
        try:
            host = self._host
            port = self._port
            is_https = self._is_https
            raw_request = self._raw_request

            response_data = _send_raw(host, port, is_https, raw_request)

            if self._follow_redirects:
                for _ in range(MAX_REDIRECTS):
                    status = _extract_status_code(response_data)
                    if status not in (301, 302, 303, 307, 308):
                        break
                    location = _extract_location(response_data)
                    if not location:
                        break

                    # Resolve absolute or relative URL
                    base_url = f"{'https' if is_https else 'http'}://{host}{':' + str(port) if (is_https and port != 443) or (not is_https and port != 80) else ''}"
                    absolute_url = urljoin(base_url, location)
                    parsed = urlparse(absolute_url)

                    new_is_https = parsed.scheme == "https"
                    new_host = parsed.hostname or host
                    if parsed.port:
                        new_port = parsed.port
                    else:
                        new_port = 443 if new_is_https else 80
                    new_path = parsed.path or "/"
                    if parsed.query:
                        new_path = new_path + "?" + parsed.query

                    new_request = _build_get_request(new_host, new_path)
                    response_data = _send_raw(new_host, new_port, new_is_https, new_request)

                    host = new_host
                    port = new_port
                    is_https = new_is_https

            self.finished.emit(response_data)
        except Exception as exc:
            self.error.emit(str(exc))


# ---------------------------------------------------------------------------
# RepeaterSession — one self-contained request/response pane
# ---------------------------------------------------------------------------

class RepeaterSession(QWidget):
    """A single repeater session with its own editors, history, and controls."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._worker: Optional[SendWorker] = None
        # history: list of (request_text, response_raw_bytes_decoded)
        self._history: List[Tuple[str, str]] = []
        self._history_pos: int = -1  # points to current position in history
        self._raw_response: str = ""
        self._setup_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(6)

        # --- Target bar ---------------------------------------------------
        target_bar = QHBoxLayout()
        target_bar.setSpacing(6)

        target_bar.addWidget(QLabel("Target:"))

        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("host")
        self.host_edit.setFixedWidth(220)
        self.host_edit.setStyleSheet(_LINEEDIT_SS)
        target_bar.addWidget(self.host_edit)

        target_bar.addWidget(QLabel(":"))

        self.port_edit = QLineEdit()
        self.port_edit.setPlaceholderText("port")
        self.port_edit.setFixedWidth(60)
        self.port_edit.setStyleSheet(_LINEEDIT_SS)
        target_bar.addWidget(self.port_edit)

        self.https_check = QCheckBox("HTTPS")
        self.https_check.setStyleSheet("QCheckBox { spacing: 6px; color: #cdd6f4; }")
        target_bar.addWidget(self.https_check)

        self.follow_redirects_check = QCheckBox("Follow Redirects")
        self.follow_redirects_check.setStyleSheet(
            "QCheckBox { spacing: 6px; color: #cdd6f4; }"
        )
        target_bar.addWidget(self.follow_redirects_check)

        target_bar.addStretch()

        # History navigation
        self._prev_btn = QPushButton("◀")
        self._prev_btn.setFixedWidth(28)
        self._prev_btn.setStyleSheet(_BTN_SS)
        self._prev_btn.setToolTip("Previous request in history")
        self._prev_btn.clicked.connect(self._history_prev)
        self._prev_btn.setEnabled(False)
        target_bar.addWidget(self._prev_btn)

        self._hist_label = QLabel("0 / 0")
        self._hist_label.setStyleSheet(_HIST_LABEL_SS)
        self._hist_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._hist_label.setFixedWidth(50)
        target_bar.addWidget(self._hist_label)

        self._next_btn = QPushButton("▶")
        self._next_btn.setFixedWidth(28)
        self._next_btn.setStyleSheet(_BTN_SS)
        self._next_btn.setToolTip("Next request in history")
        self._next_btn.clicked.connect(self._history_next)
        self._next_btn.setEnabled(False)
        target_bar.addWidget(self._next_btn)

        target_bar.addSpacing(8)

        self.send_btn = QPushButton("Send")
        self.send_btn.setFixedWidth(80)
        self.send_btn.setStyleSheet(_BTN_SS)
        self.send_btn.clicked.connect(self._send)
        target_bar.addWidget(self.send_btn)

        self.format_btn = QPushButton("Format")
        self.format_btn.setFixedWidth(70)
        self.format_btn.setStyleSheet(_BTN_SS)
        self.format_btn.setToolTip("Pretty-print JSON or XML body in the request editor")
        self.format_btn.clicked.connect(self._format_request)
        target_bar.addWidget(self.format_btn)

        self.transform_btn = QPushButton("Transform")
        self.transform_btn.setFixedWidth(80)
        self.transform_btn.setStyleSheet(_BTN_SS)
        self.transform_btn.setToolTip(
            "Evaluate Hackvertor-style <@base64>...</@base64> tags in the request editor"
        )
        self.transform_btn.clicked.connect(self._transform_request)
        target_bar.addWidget(self.transform_btn)

        self.multipart_btn = QPushButton("Multipart")
        self.multipart_btn.setFixedWidth(80)
        self.multipart_btn.setStyleSheet(_BTN_SS)
        self.multipart_btn.setToolTip("Edit a multipart/form-data body via per-part table")
        self.multipart_btn.clicked.connect(self._edit_multipart)
        target_bar.addWidget(self.multipart_btn)

        self.signing_btn = QPushButton("Signing…")
        self.signing_btn.setFixedWidth(80)
        self.signing_btn.setStyleSheet(_BTN_SS)
        self.signing_btn.setToolTip("Configure AWS SigV4 / HMAC signing for this tab")
        self.signing_btn.clicked.connect(self._open_signing)
        target_bar.addWidget(self.signing_btn)

        # Per-tab signing config — applied automatically on every Send.
        self._signing_config: dict = {"aws": None, "hmac": None}

        root.addLayout(target_bar)

        # --- Outer horizontal splitter: left=request+response, right=inspector ---
        outer_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left pane: vertical splitter (request / response)
        left_splitter = QSplitter(Qt.Orientation.Vertical)

        self.request_editor = QTextEdit()
        self.request_editor.setFont(QFont("Monospace", 9))
        self.request_editor.setPlaceholderText(
            "Paste or load a request here, then click Send."
        )
        self.request_editor.setStyleSheet(_TEXTEDIT_SS)
        self.request_editor.textChanged.connect(self._on_request_text_changed)

        req_container = QWidget()
        req_layout = QVBoxLayout(req_container)
        req_layout.setContentsMargins(0, 0, 0, 0)
        req_layout.setSpacing(2)
        req_lbl = QLabel("Request")
        req_lbl.setStyleSheet(_LABEL_SS)
        req_layout.addWidget(req_lbl)
        # Syntax highlighting + Ctrl+F / Ctrl+H find/replace bar
        self._req_highlighter = HttpSyntaxHighlighter(self.request_editor.document())
        self._req_find_bar = install_find_replace(self.request_editor)
        req_layout.addWidget(self._req_find_bar)
        req_layout.addWidget(self.request_editor)
        left_splitter.addWidget(req_container)

        # Response area: QTabWidget with Raw / Pretty / Render tabs
        _resp_tab_style = (
            "QTabWidget::pane { border: 1px solid #313244; background: #1e1e2e; }"
            "QTabBar::tab { background: #181825; color: #a6adc8; padding: 4px 10px; "
            "border: 1px solid #313244; border-bottom: none; margin-right: 2px; }"
            "QTabBar::tab:selected { background: #313244; color: #cdd6f4; }"
            "QTabBar::tab:hover { background: #45475a; color: #cdd6f4; }"
        )

        self._resp_tabs = QTabWidget()
        self._resp_tabs.setStyleSheet(_resp_tab_style)

        # Raw tab
        self.response_view = QTextEdit()
        self.response_view.setFont(QFont("Monospace", 9))
        self.response_view.setReadOnly(True)
        self.response_view.setPlaceholderText("Response will appear here.")
        self.response_view.setStyleSheet(_TEXTEDIT_SS)
        self._resp_tabs.addTab(self.response_view, "Raw")

        # Pretty tab
        self._pretty_view = QTextEdit()
        self._pretty_view.setFont(QFont("Monospace", 9))
        self._pretty_view.setReadOnly(True)
        self._pretty_view.setPlaceholderText("Pretty response will appear here.")
        self._pretty_view.setStyleSheet(_TEXTEDIT_SS)
        self._resp_tabs.addTab(self._pretty_view, "Pretty")

        # Render tab
        if _WEBENGINE_AVAILABLE:
            self._render_view = _QWebEngineView()
            self._render_view.setStyleSheet(
                "QWebEngineView { background: #1e1e2e; border: none; }"
            )
        else:
            self._render_view = QLabel(
                "Install PyQt6-WebEngine to enable this view"
            )
            self._render_view.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._render_view.setStyleSheet("color: #585b70; font-size: 11px;")
        self._resp_tabs.addTab(self._render_view, "Render")

        # Update pretty/render content when the user switches tabs
        self._resp_tabs.currentChanged.connect(self._on_resp_tab_changed)

        # Syntax highlight + find on the raw response view
        self._resp_highlighter = HttpSyntaxHighlighter(self.response_view.document())
        self._resp_find_bar = install_find_replace(self.response_view)

        resp_container = QWidget()
        resp_layout = QVBoxLayout(resp_container)
        resp_layout.setContentsMargins(0, 0, 0, 0)
        resp_layout.setSpacing(2)
        resp_lbl = QLabel("Response")
        resp_lbl.setStyleSheet(_LABEL_SS)
        resp_layout.addWidget(resp_lbl)
        resp_layout.addWidget(self._resp_find_bar)
        resp_layout.addWidget(self._resp_tabs)

        left_splitter.addWidget(resp_container)
        left_splitter.setSizes([350, 350])

        outer_splitter.addWidget(left_splitter)

        # Right pane: InspectorWidget
        self._inspector = InspectorWidget()
        self._inspector.content_modified.connect(self._on_inspector_modified)
        outer_splitter.addWidget(self._inspector)

        outer_splitter.setSizes([700, 300])
        root.addWidget(outer_splitter)

    # ------------------------------------------------------------------
    # Response tab / inspector handlers
    # ------------------------------------------------------------------

    def _on_resp_tab_changed(self, index: int) -> None:
        """Populate Pretty or Render tab lazily when the user switches to it."""
        if index == 1:  # Pretty
            self._pretty_view.setPlainText(_pretty_response(self._raw_response))
        elif index == 2 and _WEBENGINE_AVAILABLE:  # Render
            raw = self._raw_response
            body = raw
            if "\r\n\r\n" in raw:
                body = raw.split("\r\n\r\n", 1)[1]
            elif "\n\n" in raw:
                body = raw.split("\n\n", 1)[1]
            self._render_view.setHtml(body)

    def _on_request_text_changed(self) -> None:
        """Feed the request editor text into the inspector on every change."""
        text = self.request_editor.toPlainText()
        if text.strip():
            self._inspector.load(text.encode(errors="replace"), is_request=True)
        else:
            self._inspector.clear()

    def _format_request(self) -> None:
        """Pretty-print the JSON / XML body of the current request, in place."""
        raw = self.request_editor.toPlainText()
        formatted = format_http_message(raw)
        if formatted != raw:
            self.request_editor.setPlainText(formatted)

    def _transform_request(self) -> None:
        """Evaluate Hackvertor tags in the request editor in place."""
        raw = self.request_editor.toPlainText()
        transformed = _hv_transform(raw)
        if transformed != raw:
            self.request_editor.setPlainText(transformed)

    def _edit_multipart(self) -> None:
        """Open the multipart editor for the current request body."""
        raw = self.request_editor.toPlainText()
        if "\r\n\r\n" in raw:
            head, _, body_str = raw.partition("\r\n\r\n")
            sep = "\r\n\r\n"
        elif "\n\n" in raw:
            head, _, body_str = raw.partition("\n\n")
            sep = "\n\n"
        else:
            head, body_str, sep = raw, "", "\r\n\r\n"

        # Extract content-type header
        content_type = ""
        for line in head.split("\n"):
            if line.lower().startswith("content-type:"):
                content_type = line.partition(":")[2].strip()
                break

        dlg = MultipartEditorDialog(body_str.encode(errors="replace"), content_type, parent=self)
        if not dlg.exec():
            return
        new_body = dlg.serialized()
        new_ct = f"multipart/form-data; boundary={dlg.boundary()}"

        # Rebuild head: replace Content-Type + Content-Length
        new_lines = []
        seen_ct = seen_cl = False
        for line in head.split("\n"):
            stripped = line.rstrip("\r")
            low = stripped.lower()
            if low.startswith("content-type:"):
                new_lines.append(f"Content-Type: {new_ct}")
                seen_ct = True
            elif low.startswith("content-length:"):
                new_lines.append(f"Content-Length: {len(new_body)}")
                seen_cl = True
            else:
                new_lines.append(stripped)
        if not seen_ct:
            new_lines.append(f"Content-Type: {new_ct}")
        if not seen_cl:
            new_lines.append(f"Content-Length: {len(new_body)}")

        rebuilt = "\r\n".join(new_lines) + sep + new_body.decode("latin-1")
        self.request_editor.setPlainText(rebuilt)

    def _open_signing(self) -> None:
        dlg = RequestSigningDialog(self, initial=self._signing_config)
        if dlg.exec():
            self._signing_config = dlg.config()

    def _on_inspector_modified(self, raw: bytes) -> None:
        """Apply inspector edits back to the request editor without a feedback loop."""
        self.request_editor.blockSignals(True)
        try:
            cursor_pos = self.request_editor.textCursor().position()
            self.request_editor.setPlainText(raw.decode(errors="replace"))
            cursor = self.request_editor.textCursor()
            cursor.setPosition(min(cursor_pos, len(self.request_editor.toPlainText())))
            self.request_editor.setTextCursor(cursor)
        finally:
            self.request_editor.blockSignals(False)

    # ------------------------------------------------------------------
    # History navigation
    # ------------------------------------------------------------------

    def _update_history_ui(self) -> None:
        total = len(self._history)
        if total == 0:
            self._hist_label.setText("0 / 0")
            self._prev_btn.setEnabled(False)
            self._next_btn.setEnabled(False)
            return
        pos_display = self._history_pos + 1  # 1-based
        self._hist_label.setText(f"{pos_display} / {total}")
        self._prev_btn.setEnabled(self._history_pos > 0)
        self._next_btn.setEnabled(self._history_pos < total - 1)

    def _load_history_entry(self, pos: int) -> None:
        req_text, resp_text = self._history[pos]
        self._history_pos = pos
        self.request_editor.setPlainText(req_text)
        self._raw_response = resp_text
        self.response_view.setPlainText(resp_text)
        # If Pretty tab is currently active, refresh it too
        if self._resp_tabs.currentIndex() == 1:
            self._pretty_view.setPlainText(_pretty_response(resp_text))
        self._update_history_ui()

    def _history_prev(self) -> None:
        if self._history_pos > 0:
            self._load_history_entry(self._history_pos - 1)

    def _history_next(self) -> None:
        if self._history_pos < len(self._history) - 1:
            self._load_history_entry(self._history_pos + 1)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_request(self, req: HttpRequest) -> None:
        """Populate the editor from a proxy history entry."""
        raw_text = req.raw.decode(errors="replace") if req.raw else str(req)
        self.request_editor.setPlainText(raw_text)
        self.host_edit.setText(req.host)
        self.port_edit.setText(str(req.port))
        self.https_check.setChecked(req.is_https)
        self.response_view.clear()
        self._pretty_view.clear()
        self._raw_response = ""
        self._inspector.load(raw_text.encode(errors="replace"), is_request=True)

    # ------------------------------------------------------------------
    # Send logic
    # ------------------------------------------------------------------

    def _send(self) -> None:
        host = self.host_edit.text().strip()
        port_text = self.port_edit.text().strip()
        is_https = self.https_check.isChecked()
        follow_redirects = self.follow_redirects_check.isChecked()
        raw_text = self.request_editor.toPlainText()

        if not host:
            self.response_view.setPlainText("[Error] Host is empty.")
            return

        try:
            port = int(port_text) if port_text else (443 if is_https else 80)
        except ValueError:
            self.response_view.setPlainText(f"[Error] Invalid port: {port_text!r}")
            return

        if not raw_text.strip():
            self.response_view.setPlainText("[Error] Request editor is empty.")
            return

        # Apply per-tab AWS SigV4 / HMAC signing (no-op if disabled).
        raw_text = apply_signing(raw_text, host, is_https, self._signing_config)
        raw_bytes = raw_text.encode(errors="replace")

        self.send_btn.setEnabled(False)
        self.response_view.setPlainText("Sending…")

        self._worker = SendWorker(host, port, is_https, raw_bytes, follow_redirects)
        self._worker.finished.connect(self._on_response)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_response(self, data: bytes) -> None:
        self.send_btn.setEnabled(True)

        # Auto-decompress per Content-Encoding so the viewer is readable.
        from .decompress import decompress as _decompress
        head, _, body = data.partition(b"\r\n\r\n") if b"\r\n\r\n" in data else (data, b"", b"")
        resp_headers: dict[str, str] = {}
        for line in head.split(b"\r\n")[1:]:
            if b":" in line:
                k, _, v = line.partition(b":")
                resp_headers[k.decode(errors="replace").strip()] = v.decode(errors="replace").strip()
        decoded_body, label = _decompress(body, resp_headers)
        if label and "failed" not in label and "unavailable" not in label and "unknown" not in label:
            note = f"X-Fracture-Decoded: {label}\r\n".encode()
            display_data = head + b"\r\n" + note + b"\r\n" + decoded_body
        else:
            display_data = data

        resp_text = display_data.decode(errors="replace")
        self._raw_response = resp_text

        # Append to history
        req_text = self.request_editor.toPlainText()
        self._history.append((req_text, resp_text))
        self._history_pos = len(self._history) - 1

        self.response_view.setPlainText(resp_text)
        # If Pretty tab is currently visible, refresh it immediately
        if self._resp_tabs.currentIndex() == 1:
            self._pretty_view.setPlainText(_pretty_response(resp_text))
        self._update_history_ui()

    def _on_error(self, message: str) -> None:
        self.send_btn.setEnabled(True)
        self.response_view.setPlainText(f"[Error] {message}")


# ---------------------------------------------------------------------------
# RepeaterTab — outer widget with inner QTabWidget of sessions
# ---------------------------------------------------------------------------

class RepeaterTab(QWidget):
    """
    Outer Repeater tab.

    Manages an inner QTabWidget where each tab is a RepeaterSession.
    Public interface: load_request(req: HttpRequest) — loads into the active session.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._session_counter: int = 0
        self._setup_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Toolbar with "+" button
        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(6, 4, 6, 0)
        toolbar.setSpacing(6)

        add_btn = QPushButton("+ New Tab")
        add_btn.setFixedHeight(24)
        add_btn.setStyleSheet(_BTN_SS)
        add_btn.clicked.connect(self._add_session)
        toolbar.addWidget(add_btn)
        toolbar.addStretch()

        root.addLayout(toolbar)

        # Inner tab widget
        self._tabs = QTabWidget()
        self._tabs.setTabsClosable(True)
        self._tabs.tabCloseRequested.connect(self._close_tab)
        self._tabs.tabBarDoubleClicked.connect(self._rename_tab)
        self._tabs.setStyleSheet(
            "QTabWidget::pane { border: 1px solid #313244; background: #1e1e2e; }"
            "QTabBar::tab { background: #181825; color: #a6adc8; padding: 4px 12px; "
            "border: 1px solid #313244; border-bottom: none; margin-right: 2px; }"
            "QTabBar::tab:selected { background: #313244; color: #cdd6f4; }"
            "QTabBar::tab:hover { background: #45475a; color: #cdd6f4; }"
            "QTabBar::scroller { width: 20px; }"
        )
        root.addWidget(self._tabs)

        # Create the first session
        self._add_session()

    # ------------------------------------------------------------------
    # Tab management
    # ------------------------------------------------------------------

    def _add_session(self) -> int:
        """Add a new RepeaterSession tab and return its index."""
        self._session_counter += 1
        session = RepeaterSession()
        label = f"Repeater {self._session_counter}"
        idx = self._tabs.addTab(session, label)
        self._tabs.setCurrentIndex(idx)
        return idx

    def _close_tab(self, index: int) -> None:
        """Close a tab, but keep at least one tab open."""
        if self._tabs.count() <= 1:
            return
        self._tabs.removeTab(index)

    def _rename_tab(self, index: int) -> None:
        """Prompt the user to rename the tab at *index*."""
        if index < 0:
            return
        current_name = self._tabs.tabText(index)
        new_name, ok = QInputDialog.getText(
            self,
            "Rename Tab",
            "Tab name:",
            text=current_name,
        )
        if ok and new_name.strip():
            self._tabs.setTabText(index, new_name.strip())

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_request(self, req: HttpRequest) -> None:
        """Load *req* into the currently active inner session."""
        session: RepeaterSession = self._tabs.currentWidget()  # type: ignore[assignment]
        if session is not None:
            session.load_request(req)
