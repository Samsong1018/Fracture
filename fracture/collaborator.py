"""
Collaborator tab — out-of-band interaction server for detecting blind/OOB vulnerabilities.

Runs a local HTTP server on a random port and an optional DNS server on UDP port 15353.
Testers generate unique tokens per test, embed the callback URL/domain in payloads
(XSS, SSRF, blind SQLi, XXE, …), and Fracture logs incoming interactions.
"""

import http.server
import socket
import threading
import uuid
from datetime import datetime, timezone
from typing import Callable

try:
    import dnslib  # type: ignore[import]
    import dnslib.dns  # type: ignore[import]
    _DNS_AVAILABLE = True
except ImportError:
    dnslib = None  # type: ignore[assignment]
    _DNS_AVAILABLE = False

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QClipboard, QFont
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

# ---------------------------------------------------------------------------
# Catppuccin Mocha stylesheet constants
# ---------------------------------------------------------------------------

_TEXTEDIT_SS = (
    "QTextEdit { background: #181825; border: 1px solid #313244; "
    "color: #cdd6f4; font-family: monospace; }"
)
_LIST_SS = (
    "QListWidget { background: #181825; border: 1px solid #313244; "
    "color: #cdd6f4; }"
)
_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
    "QPushButton:hover { background: #45475a; }"
    "QPushButton:disabled { color: #585b70; }"
)
_LABEL_SS = "color: #cdd6f4;"
_STATUS_ON_SS = "color: #a6e3a1; font-weight: bold;"
_STATUS_OFF_SS = "color: #f38ba8; font-weight: bold;"


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------


class _CollaboratorHandler(http.server.BaseHTTPRequestHandler):
    """Minimal handler that captures every incoming HTTP request."""

    # Injected by CollaboratorServer after binding
    collaborator: "CollaboratorServer"

    # Silence default access log
    def log_message(self, fmt: str, *args: object) -> None:  # noqa: N802
        pass

    def _handle(self) -> None:
        """Common entry point for all HTTP methods."""
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""

        # Extract token: first non-empty path segment (strip query string)
        raw_path = self.path.split("?")[0].split("#")[0]
        parts = [p for p in raw_path.split("/") if p]
        token = parts[0] if parts else ""

        source_ip = self.client_address[0] if self.client_address else "unknown"

        interaction: dict = {
            "token": token,
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": source_ip,
        }

        self.collaborator._record_interaction(interaction)

        # Respond with 200 so the caller doesn't retry
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_GET(self) -> None:  # noqa: N802
        self._handle()

    def do_POST(self) -> None:  # noqa: N802
        self._handle()

    def do_PUT(self) -> None:  # noqa: N802
        self._handle()

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle()

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._handle()

    def do_PATCH(self) -> None:  # noqa: N802
        self._handle()


# ---------------------------------------------------------------------------
# CollaboratorServer
# ---------------------------------------------------------------------------


class CollaboratorServer:
    """Local HTTP listener that tracks callback interactions by token."""

    def __init__(self) -> None:
        self._port: int = 0
        self._server: http.server.HTTPServer | None = None
        self._tokens: dict[str, dict] = {}       # token → {label, created_at}
        self._interactions: list[dict] = []       # every recorded hit
        self._callbacks: list[Callable] = []      # called with each new interaction
        self._lock = threading.Lock()
        self._running = False
        # Optional public hostname (e.g. an ngrok / Cloudflare tunnel that
        # forwards back to the local listener).  When set, generated payload
        # URLs use this host so that internet-bound targets can reach us.
        self._public_host: str = ""
        self._public_scheme: str = "https"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> int:
        """Bind to 127.0.0.1 on a random port, start serving in a daemon thread.

        Returns the bound port number.
        """
        if self._running:
            return self._port

        # Build a handler class that carries a reference to this server
        server_ref = self

        class _Handler(_CollaboratorHandler):
            collaborator = server_ref

        self._server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        self._port = self._server.server_address[1]
        self._running = True

        thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        thread.start()
        return self._port

    def stop(self) -> None:
        """Shut down the HTTP server."""
        if self._server and self._running:
            self._server.shutdown()
            self._server = None
            self._running = False
            self._port = 0

    @property
    def running(self) -> bool:
        return self._running

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    def generate_token(self, label: str = "") -> str:
        """Return a short UUID token string and register it."""
        token = uuid.uuid4().hex[:16]
        with self._lock:
            self._tokens[token] = {
                "label": label,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        return token

    def set_public_host(self, host: str, scheme: str = "https") -> None:
        """Configure a public hostname for callback URLs.

        Pass an empty string to revert to localhost-only mode.
        """
        self._public_host = host.strip()
        if scheme in ("http", "https"):
            self._public_scheme = scheme

    def get_public_host(self) -> str:
        return self._public_host

    def get_url(self, token: str) -> str:
        """Return the callback URL for *token*.

        Uses the public host when configured, falling back to localhost.
        """
        if self._public_host:
            return f"{self._public_scheme}://{self._public_host}/{token}"
        return f"http://127.0.0.1:{self._port}/{token}"

    def get_payloads(self, token: str) -> dict[str, str]:
        """Return ready-to-use payload templates for *token*."""
        url = self.get_url(token)
        return {
            "URL": url,
            "XSS (img)": f'<img src="{url}">',
            "XSS (script)": f'<script src="{url}"></script>',
            "SSRF param": f"url={url}",
            "XXE": (
                f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{url}">]>'
                f"<foo>&xxe;</foo>"
            ),
        }

    # ------------------------------------------------------------------
    # Interaction log
    # ------------------------------------------------------------------

    def get_interactions(self, token: str | None = None) -> list[dict]:
        """Return all interactions, or only those matching *token*."""
        with self._lock:
            if token is None:
                return list(self._interactions)
            return [i for i in self._interactions if i["token"] == token]

    def hit_count(self, token: str) -> int:
        """Return the number of interactions recorded for *token*."""
        return len(self.get_interactions(token))

    def get_tokens(self) -> dict[str, dict]:
        """Return a shallow copy of the registered tokens dict."""
        with self._lock:
            return dict(self._tokens)

    def add_callback(self, cb: Callable) -> None:
        """Register *cb* to be called with each new interaction dict."""
        self._callbacks.append(cb)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _record_interaction(self, interaction: dict) -> None:
        with self._lock:
            self._interactions.append(interaction)
            callbacks = list(self._callbacks)
        for cb in callbacks:
            try:
                cb(interaction)
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# DNS Collaborator Server
# ---------------------------------------------------------------------------


class DNSCollaboratorServer:
    """UDP DNS server that logs queries for *.collab.local as OOB interactions."""

    def __init__(self, interaction_callback: Callable) -> None:
        self._callback = interaction_callback
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._port = 0

    @property
    def available(self) -> bool:
        return _DNS_AVAILABLE

    @property
    def running(self) -> bool:
        return self._running

    def start(self) -> int:
        """Bind to UDP and start serving. Returns port or 0 if unavailable."""
        if not _DNS_AVAILABLE or self._running:
            return self._port
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Try preferred port, fall back to OS-assigned
            for attempt in [15353, 0]:
                try:
                    self._sock.bind(("127.0.0.1", attempt))
                    break
                except OSError:
                    continue
            self._port = self._sock.getsockname()[1]
            self._running = True
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()
        except Exception:
            self._running = False
            self._port = 0
        return self._port

    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def get_port(self) -> int:
        return self._port

    def _serve(self) -> None:
        assert self._sock is not None
        self._sock.settimeout(1.0)
        while self._running:
            try:
                data, addr = self._sock.recvfrom(512)
            except socket.timeout:
                continue
            except Exception:
                break
            try:
                request = dnslib.dns.DNSRecord.parse(data)
                qname = str(request.q.qname).rstrip(".")
                if qname.endswith(".collab.local"):
                    token = qname.split(".")[0]
                    self._callback({
                        "type": "DNS",
                        "token": token,
                        "query": qname,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "source_ip": addr[0],
                    })
                # Return NXDOMAIN
                reply = request.reply()
                reply.header.rcode = dnslib.dns.RCODE.NXDOMAIN
                self._sock.sendto(reply.pack(), addr)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# CollaboratorTab (PyQt6 widget)
# ---------------------------------------------------------------------------


class CollaboratorTab(QWidget):
    """Collaborator UI tab embedded in the main Fracture window."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._server = CollaboratorServer()
        self._server.add_callback(self._on_new_interaction)
        self._dns_server = DNSCollaboratorServer(self._on_new_interaction)
        self._pending_interactions: list[dict] = []
        self._pending_lock = threading.Lock()
        # Lazy import to avoid circular dependencies at module load.
        from .tunnel import TunnelProcess
        self.tunnel = TunnelProcess()

        self._build_ui()
        self._apply_styles()

        # Auto-refresh every second
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(1000)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        # ---- Toolbar ----
        toolbar = QHBoxLayout()
        self._btn_toggle = QPushButton("Start")
        self._btn_toggle.clicked.connect(self._toggle_server)
        toolbar.addWidget(self._btn_toggle)

        self._lbl_status = QLabel("Stopped")
        self._lbl_status.setStyleSheet(_STATUS_OFF_SS)
        toolbar.addWidget(self._lbl_status)

        toolbar.addStretch()

        # DNS status label
        if self._dns_server.available:
            dns_port = self._dns_server.start()
            self._lbl_dns = QLabel(f"DNS: UDP :{dns_port}")
            self._lbl_dns.setStyleSheet(_STATUS_ON_SS)
        else:
            self._lbl_dns = QLabel("DNS: not available (install dnslib)")
            self._lbl_dns.setStyleSheet(_STATUS_OFF_SS)
        toolbar.addWidget(self._lbl_dns)

        toolbar.addStretch()

        self._btn_dns_payload = QPushButton("DNS Payload")
        self._btn_dns_payload.setEnabled(False)
        self._btn_dns_payload.clicked.connect(self._copy_dns_payload)
        toolbar.addWidget(self._btn_dns_payload)

        self._btn_copy_url = QPushButton("Copy URL")
        self._btn_copy_url.setEnabled(False)
        self._btn_copy_url.clicked.connect(self._copy_url)
        toolbar.addWidget(self._btn_copy_url)

        root.addLayout(toolbar)

        # ---- Main splitter (left / right) ----
        main_splitter = QSplitter(Qt.Orientation.Horizontal)

        # ---- Left panel ----
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(4)

        lbl_tokens = QLabel("Tokens")
        lbl_tokens.setStyleSheet(_LABEL_SS)
        left_layout.addWidget(lbl_tokens)

        self._token_list = QListWidget()
        self._token_list.currentRowChanged.connect(self._on_token_selected)
        left_layout.addWidget(self._token_list)

        gen_row = QHBoxLayout()
        self._token_label_input = QLabel("")  # hidden; label comes from dialog
        self._btn_gen = QPushButton("Generate Token")
        self._btn_gen.setEnabled(False)
        self._btn_gen.clicked.connect(self._generate_token)
        gen_row.addWidget(self._btn_gen)
        left_layout.addLayout(gen_row)

        main_splitter.addWidget(left_widget)

        # ---- Right panel ----
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(4)

        right_splitter = QSplitter(Qt.Orientation.Vertical)

        # Interactions list
        interactions_top = QWidget()
        interactions_layout = QVBoxLayout(interactions_top)
        interactions_layout.setContentsMargins(0, 0, 0, 0)
        interactions_layout.setSpacing(2)

        lbl_interactions = QLabel("Interactions")
        lbl_interactions.setStyleSheet(_LABEL_SS)
        interactions_layout.addWidget(lbl_interactions)

        self._interaction_list = QListWidget()
        self._interaction_list.currentRowChanged.connect(self._on_interaction_selected)
        interactions_layout.addWidget(self._interaction_list)

        right_splitter.addWidget(interactions_top)

        # Interaction detail
        detail_top = QWidget()
        detail_layout = QVBoxLayout(detail_top)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(2)

        lbl_detail = QLabel("Interaction Detail")
        lbl_detail.setStyleSheet(_LABEL_SS)
        detail_layout.addWidget(lbl_detail)

        self._detail_view = QTextEdit()
        self._detail_view.setReadOnly(True)
        self._detail_view.setFont(QFont("Monospace", 9))
        detail_layout.addWidget(self._detail_view)

        right_splitter.addWidget(detail_top)

        # Payloads panel
        payloads_top = QWidget()
        payloads_layout = QVBoxLayout(payloads_top)
        payloads_layout.setContentsMargins(0, 0, 0, 0)
        payloads_layout.setSpacing(2)

        payload_header = QHBoxLayout()
        lbl_payloads = QLabel("Payload Templates")
        lbl_payloads.setStyleSheet(_LABEL_SS)
        payload_header.addWidget(lbl_payloads)
        payload_header.addStretch()
        self._btn_copy_payload = QPushButton("Copy All")
        self._btn_copy_payload.setEnabled(False)
        self._btn_copy_payload.clicked.connect(self._copy_all_payloads)
        payload_header.addWidget(self._btn_copy_payload)
        payloads_layout.addLayout(payload_header)

        self._payloads_view = QTextEdit()
        self._payloads_view.setReadOnly(True)
        self._payloads_view.setFont(QFont("Monospace", 9))
        self._payloads_view.setMaximumHeight(150)
        payloads_layout.addWidget(self._payloads_view)

        right_splitter.addWidget(payloads_top)

        right_splitter.setSizes([200, 200, 150])
        right_layout.addWidget(right_splitter)

        main_splitter.addWidget(right_widget)
        main_splitter.setSizes([200, 600])

        root.addWidget(main_splitter)

    def _apply_styles(self) -> None:
        self.setStyleSheet(
            "QWidget { background: #1e1e2e; color: #cdd6f4; }"
            + _LIST_SS
            + _TEXTEDIT_SS
            + _BTN_SS
        )

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    def _toggle_server(self) -> None:
        if self._server.running:
            self._server.stop()
            self._btn_toggle.setText("Start")
            self._lbl_status.setText("Stopped")
            self._lbl_status.setStyleSheet(_STATUS_OFF_SS)
            self._btn_gen.setEnabled(False)
            self._btn_copy_url.setEnabled(False)
        else:
            port = self._server.start()
            self._btn_toggle.setText("Stop")
            self._lbl_status.setText(f"Listening on http://127.0.0.1:{port}")
            self._lbl_status.setStyleSheet(_STATUS_ON_SS)
            self._btn_gen.setEnabled(True)

    # ------------------------------------------------------------------
    # Token operations
    # ------------------------------------------------------------------

    def _generate_token(self) -> None:
        label, ok = QInputDialog.getText(
            self,
            "Generate Token",
            "Optional label for this token:",
        )
        if not ok:
            return
        token = self._server.generate_token(label.strip())
        self._rebuild_token_list()
        # Select the newly created token
        tokens = list(self._server.get_tokens().keys())
        if token in tokens:
            idx = tokens.index(token)
            self._token_list.setCurrentRow(idx)

    def _rebuild_token_list(self) -> None:
        """Re-render the token list, preserving selection if possible."""
        current_token = self._current_token()
        self._token_list.clear()
        for token, meta in self._server.get_tokens().items():
            label = meta.get("label") or ""
            hits = self._server.hit_count(token)
            display = f"{token}  —  {label}  ({hits} hits)" if label else f"{token}  ({hits} hits)"
            item = QListWidgetItem(display)
            item.setData(Qt.ItemDataRole.UserRole, token)
            self._token_list.addItem(item)
        # Restore selection
        if current_token:
            for i in range(self._token_list.count()):
                if self._token_list.item(i).data(Qt.ItemDataRole.UserRole) == current_token:
                    self._token_list.setCurrentRow(i)
                    break

    def _current_token(self) -> str | None:
        item = self._token_list.currentItem()
        if item:
            return item.data(Qt.ItemDataRole.UserRole)
        return None

    def _on_token_selected(self, _row: int) -> None:
        token = self._current_token()
        active = token is not None and self._server.running
        self._btn_copy_url.setEnabled(active)
        self._btn_copy_payload.setEnabled(active)
        self._btn_dns_payload.setEnabled(active and self._dns_server.available)
        self._rebuild_interaction_list()
        self._update_payloads_panel()

    def _copy_dns_payload(self) -> None:
        token = self._current_token()
        if not token:
            return
        dns_port = self._dns_server.get_port()
        domain = f"{token}.collab.local"
        lines = [
            f"# DNS Collaborator payloads for token: {token}",
            f"# DNS server: 127.0.0.1:{dns_port}",
            "",
            f"nslookup {domain} 127.0.0.1:{dns_port}",
            f"$(nslookup {domain})",
            f"`nslookup {domain}`",
            f"${{jndi:dns://{domain}/a}}",
            f'<img src="http://{domain}">',
        ]
        QApplication.clipboard().setText("\n".join(lines))

    def _copy_url(self) -> None:
        token = self._current_token()
        if token and self._server.running:
            url = self._server.get_url(token)
            QApplication.clipboard().setText(url)

    def _copy_all_payloads(self) -> None:
        QApplication.clipboard().setText(self._payloads_view.toPlainText())

    # ------------------------------------------------------------------
    # Interaction list
    # ------------------------------------------------------------------

    def _rebuild_interaction_list(self) -> None:
        token = self._current_token()
        current_row = self._interaction_list.currentRow()
        self._interaction_list.clear()
        if not token:
            return
        for interaction in self._server.get_interactions(token):
            ts = interaction.get("timestamp", "")[:19].replace("T", " ")
            source = interaction.get("source_ip", "?")
            if interaction.get("type") == "DNS":
                query = interaction.get("query", "?")
                display = f"[{ts}] DNS  {query}  from {source}"
            else:
                method = interaction.get("method", "?")
                path = interaction.get("path", "/")
                display = f"[{ts}] {method} {path}  from {source}"
            item = QListWidgetItem(display)
            item.setData(Qt.ItemDataRole.UserRole, interaction)
            self._interaction_list.addItem(item)
        # Restore row if still valid
        count = self._interaction_list.count()
        if count > 0:
            self._interaction_list.setCurrentRow(
                min(current_row, count - 1) if current_row >= 0 else count - 1
            )

    def _on_interaction_selected(self, _row: int) -> None:
        item = self._interaction_list.currentItem()
        if not item:
            self._detail_view.clear()
            return
        interaction: dict = item.data(Qt.ItemDataRole.UserRole)
        self._render_detail(interaction)

    def _render_detail(self, interaction: dict) -> None:
        if interaction.get("type") == "DNS":
            lines = [
                "Type:      DNS",
                f"Query:     {interaction.get('query', '')}",
                f"Token:     {interaction.get('token', '')}",
                f"Source IP: {interaction.get('source_ip', '')}",
                f"Timestamp: {interaction.get('timestamp', '')}",
            ]
        else:
            lines = [
                f"Method:    {interaction.get('method', '')}",
                f"Path:      {interaction.get('path', '')}",
                f"Source IP: {interaction.get('source_ip', '')}",
                f"Timestamp: {interaction.get('timestamp', '')}",
                f"Token:     {interaction.get('token', '')}",
                "",
                "Headers:",
            ]
            for name, value in (interaction.get("headers") or {}).items():
                lines.append(f"  {name}: {value}")
            body = interaction.get("body", "")
            if body:
                lines += ["", "Body:", body]
        self._detail_view.setPlainText("\n".join(lines))

    # ------------------------------------------------------------------
    # Payloads panel
    # ------------------------------------------------------------------

    def _update_payloads_panel(self) -> None:
        token = self._current_token()
        if not token or not self._server.running:
            self._payloads_view.clear()
            return
        payloads = self._server.get_payloads(token)
        lines = [f"{name}:\n  {value}" for name, value in payloads.items()]
        self._payloads_view.setPlainText("\n\n".join(lines))

    # ------------------------------------------------------------------
    # Auto-refresh (QTimer callback — runs on the GUI thread)
    # ------------------------------------------------------------------

    def _on_new_interaction(self, interaction: dict) -> None:
        """Called from the HTTP server thread; just queue the interaction."""
        with self._pending_lock:
            self._pending_interactions.append(interaction)

    def _refresh(self) -> None:
        """Drain pending interactions and refresh UI once per second."""
        with self._pending_lock:
            pending = list(self._pending_interactions)
            self._pending_interactions.clear()

        if not pending:
            return

        # Rebuild token list to update hit counts
        self._rebuild_token_list()

        # Rebuild interaction list for selected token
        self._rebuild_interaction_list()
