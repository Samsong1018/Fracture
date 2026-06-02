"""
Intruder tab — automated payload injection against marked positions.

Supports four attack types:
  Sniper       — single payload list, each payload inserted into each position in turn
  Battering Ram — single payload list, same payload inserted into ALL positions simultaneously
  Pitchfork    — one payload list per position, iterated in lockstep
  Cluster Bomb — one payload list per position, cartesian product

Payload processing rules are applied in order before each payload is sent.
Grep Match / Grep Extract can be applied to results.
Request throttling (ms delay between requests) is configurable.
"""

import base64
import hashlib
import itertools
import re
import socket
import ssl
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from PyQt6.QtCore import QThread, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
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

from .proxy import HttpRequest
from .hackvertor import transform as _hv_transform
from .payload_generators import PayloadGeneratorDialog

BUFFER = 65536
MARKER_RE = re.compile(r"§([^§]*)§")

ATTACK_TYPES = ["Sniper", "Battering Ram", "Pitchfork", "Cluster Bomb"]

PROCESSING_RULE_TYPES = [
    "Base64 Encode",
    "Base64 Decode",
    "URL Encode",
    "URL Decode",
    "MD5 Hash",
    "SHA1 Hash",
    "Trim Whitespace",
    "Prefix",
    "Suffix",
]

# Column indices for the results table (base columns always present)
COL_NUM = 0
COL_PAYLOAD = 1
COL_STATUS = 2
COL_LENGTH = 3
COL_TIME = 4
BASE_COLS = 5  # number of always-present columns


# ---------------------------------------------------------------------------
# Processing helpers
# ---------------------------------------------------------------------------

def apply_processing(payload: str, rules: list[dict]) -> str:
    """Apply a sequence of processing rules to a payload string."""
    result = payload
    for rule in rules:
        rule_type = rule.get("type", "")
        if rule_type == "Base64 Encode":
            result = base64.b64encode(result.encode()).decode()
        elif rule_type == "Base64 Decode":
            try:
                result = base64.b64decode(result.encode()).decode(errors="replace")
            except Exception:
                pass
        elif rule_type == "URL Encode":
            result = urllib.parse.quote(result, safe="")
        elif rule_type == "URL Decode":
            result = urllib.parse.unquote(result)
        elif rule_type == "MD5 Hash":
            result = hashlib.md5(result.encode()).hexdigest()
        elif rule_type == "SHA1 Hash":
            result = hashlib.sha1(result.encode()).hexdigest()
        elif rule_type == "Trim Whitespace":
            result = result.strip()
        elif rule_type == "Prefix":
            result = rule.get("value", "") + result
        elif rule_type == "Suffix":
            result = result + rule.get("value", "")
    return result


# ---------------------------------------------------------------------------
# Request building helpers
# ---------------------------------------------------------------------------

def _positions_count(raw_request: str) -> int:
    """Return the number of distinct §...§ markers in the request."""
    return len(MARKER_RE.findall(raw_request))


def _substitute_at_index(raw_request: str, index: int, payload: str) -> str:
    """
    Replace only the (index)-th §...§ occurrence with payload.
    All other occurrences are replaced with their original inner text.
    """
    matches = list(MARKER_RE.finditer(raw_request))
    result = raw_request
    # Replace right-to-left to keep offsets valid
    for i in reversed(range(len(matches))):
        m = matches[i]
        replacement = payload if i == index else m.group(1)
        result = result[: m.start()] + replacement + result[m.end():]
    return result


def _substitute_all(raw_request: str, payload: str) -> str:
    """Replace ALL §...§ markers with the same payload."""
    return MARKER_RE.sub(payload, raw_request)


def _substitute_pitchfork(raw_request: str, payloads: list[str]) -> str:
    """Replace each §...§ marker with the corresponding payload by position index."""
    matches = list(MARKER_RE.finditer(raw_request))
    result = raw_request
    for i in reversed(range(len(matches))):
        m = matches[i]
        replacement = payloads[i] if i < len(payloads) else m.group(1)
        result = result[: m.start()] + replacement + result[m.end():]
    return result


# ---------------------------------------------------------------------------
# Network helper
# ---------------------------------------------------------------------------

def _send_request(
    host: str, port: int, is_https: bool, request_bytes: bytes
) -> tuple[int, int, float, bytes]:
    """Send raw HTTP request bytes.  Returns (status_code, length, elapsed_ms, raw_response)."""
    start = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=10)
        if is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        sock.sendall(request_bytes)

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

        elapsed_ms = (time.monotonic() - start) * 1000.0

        status_code = 0
        if response_data:
            first_line = response_data.split(b"\r\n", 1)[0].decode(errors="replace")
            parts = first_line.split(" ", 2)
            if len(parts) >= 2:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    pass

        return status_code, len(response_data), elapsed_ms, response_data

    except Exception as exc:
        elapsed_ms = (time.monotonic() - start) * 1000.0
        print(f"[intruder] send error: {exc}")
        return 0, 0, elapsed_ms, b""


# ---------------------------------------------------------------------------
# Attack worker
# ---------------------------------------------------------------------------

class AttackWorker(QThread):
    """Runs the attack in a background thread, emitting one signal per result."""

    # payload_label, status_code, length, elapsed_ms, raw_response
    result = pyqtSignal(str, int, int, float, bytes)
    finished = pyqtSignal()

    def __init__(
        self,
        raw_request: str,
        payload_sets: list[list[str]],
        host: str,
        port: int,
        is_https: bool,
        attack_type: str = "Sniper",
        processing_rules: Optional[list[dict]] = None,
        throttle_ms: int = 0,
        concurrency: int = 1,
        primer: Optional[dict] = None,
    ) -> None:
        super().__init__()
        self._raw_request = raw_request
        self._payload_sets = payload_sets
        self._host = host
        self._port = port
        self._is_https = is_https
        self._attack_type = attack_type
        self._processing_rules = processing_rules or []
        self._throttle_ms = throttle_ms
        self._concurrency = max(1, concurrency)
        self._stop_requested = False
        self._emit_lock = threading.Lock()
        # primer = {"path": "/login", "method": "GET", "host": optional,
        #           "regex": r'name="csrf" value="([^"]+)"', "marker": "§csrf§"}
        self._primer = primer or {}

    def stop(self) -> None:
        self._stop_requested = True

    # ------------------------------------------------------------------

    def _grab_primer_token(self) -> Optional[str]:
        """Fire the primer request and return the captured token, or None."""
        primer = self._primer
        if not primer or not primer.get("regex") or not primer.get("path"):
            return None
        method = primer.get("method", "GET").upper()
        host = primer.get("host") or self._host
        path = primer["path"]
        primer_req = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        _, _, _, raw = _send_request(self._host, self._port, self._is_https, primer_req)
        try:
            m = re.search(primer["regex"].encode(), raw)
        except re.error:
            return None
        if not m:
            return None
        try:
            return m.group(1).decode(errors="replace")
        except IndexError:
            return m.group(0).decode(errors="replace")

    def _emit_request(self, label: str, substituted: str) -> None:
        """Send one substituted request and emit the result signal."""
        # Primer (CSRF token grab) — substitute the captured value into the marker.
        if self._primer and self._primer.get("regex"):
            token = self._grab_primer_token()
            marker = self._primer.get("marker", "§token§")
            if token is not None and marker:
                substituted = substituted.replace(marker, token)
        # Resolve any Hackvertor tags in the final substituted request.
        substituted = _hv_transform(substituted)
        request_bytes = substituted.encode(errors="replace")
        status_code, length, elapsed_ms, raw = _send_request(
            self._host, self._port, self._is_https, request_bytes
        )
        # Serialise the signal emission so the UI receives results cleanly
        # even when multiple worker threads finish at once.
        with self._emit_lock:
            self.result.emit(label, status_code, length, elapsed_ms, raw)

    def _dispatch(self, jobs):
        """Run a sequence of (label, substituted) jobs respecting concurrency."""
        if self._concurrency <= 1:
            for label, substituted in jobs:
                if self._stop_requested:
                    return
                self._emit_request(label, substituted)
                if self._throttle_ms > 0:
                    time.sleep(self._throttle_ms / 1000.0)
            return

        with ThreadPoolExecutor(max_workers=self._concurrency) as pool:
            futures = []
            for label, substituted in jobs:
                if self._stop_requested:
                    break
                futures.append(pool.submit(self._emit_request, label, substituted))
                if self._throttle_ms > 0:
                    time.sleep(self._throttle_ms / 1000.0)
            for f in futures:
                if self._stop_requested:
                    break
                try:
                    f.result()
                except Exception:
                    pass

    def _apply_rules(self, payload: str) -> str:
        return apply_processing(payload, self._processing_rules)

    def _jobs(self):
        """Yield (label, substituted_request) jobs for the active attack type."""
        attack = self._attack_type
        payloads0 = self._payload_sets[0] if self._payload_sets else []

        if attack == "Sniper":
            n_positions = _positions_count(self._raw_request)
            if n_positions == 0:
                for payload in payloads0:
                    processed = self._apply_rules(payload)
                    yield processed, self._raw_request
            else:
                for pos_idx in range(n_positions):
                    for payload in payloads0:
                        processed = self._apply_rules(payload)
                        substituted = _substitute_at_index(
                            self._raw_request, pos_idx, processed
                        )
                        yield f"[pos{pos_idx + 1}] {processed}", substituted

        elif attack == "Battering Ram":
            for payload in payloads0:
                processed = self._apply_rules(payload)
                substituted = _substitute_all(self._raw_request, processed)
                yield processed, substituted

        elif attack == "Pitchfork":
            for combo in zip(*self._payload_sets):
                processed = [self._apply_rules(p) for p in combo]
                substituted = _substitute_pitchfork(self._raw_request, processed)
                yield " | ".join(processed), substituted

        elif attack == "Cluster Bomb":
            for combo in itertools.product(*self._payload_sets):
                processed = [self._apply_rules(p) for p in combo]
                substituted = _substitute_pitchfork(self._raw_request, processed)
                yield " | ".join(processed), substituted

    def run(self) -> None:
        self._dispatch(self._jobs())
        self.finished.emit()


# ---------------------------------------------------------------------------
# Add-rule dialog
# ---------------------------------------------------------------------------

class AddRuleDialog(QDialog):
    """Small dialog for creating a processing rule."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add Processing Rule")
        self.setModal(True)
        self.setFixedWidth(360)
        self.setStyleSheet(
            "QDialog { background: #1e1e2e; color: #cdd6f4; }"
            "QLabel { color: #cdd6f4; }"
            "QComboBox, QLineEdit { background: #181825; border: 1px solid #313244; "
            "padding: 4px; border-radius: 3px; color: #cdd6f4; }"
            "QPushButton { background: #313244; border: 1px solid #45475a; "
            "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
            "QPushButton:hover { background: #45475a; }"
        )

        layout = QFormLayout(self)

        self._type_combo = QComboBox()
        self._type_combo.addItems(PROCESSING_RULE_TYPES)
        self._type_combo.currentTextChanged.connect(self._on_type_changed)
        layout.addRow("Type:", self._type_combo)

        self._value_edit = QLineEdit()
        self._value_edit.setPlaceholderText("Value (for Prefix / Suffix)")
        self._value_label = QLabel("Value:")
        layout.addRow(self._value_label, self._value_edit)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

        self._on_type_changed(self._type_combo.currentText())

    def _on_type_changed(self, text: str) -> None:
        needs_value = text in ("Prefix", "Suffix")
        self._value_edit.setVisible(needs_value)
        self._value_label.setVisible(needs_value)

    def get_rule(self) -> dict:
        return {
            "type": self._type_combo.currentText(),
            "value": self._value_edit.text(),
        }


# ---------------------------------------------------------------------------
# IntruderTab
# ---------------------------------------------------------------------------

class IntruderTab(QWidget):
    """Intruder tab widget — Catppuccin Mocha theme."""

    def __init__(self) -> None:
        super().__init__()
        self._worker: Optional[AttackWorker] = None
        self._result_count = 0
        self._processing_rules: list[dict] = []
        # Store raw response bytes per row for grep
        self._result_raw_responses: list[bytes] = []
        # Track current extra columns
        self._grep_match_col: Optional[int] = None
        self._grep_extract_col: Optional[int] = None
        self._setup_ui()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_request(self, req: HttpRequest) -> None:
        """Populate the editor from an HttpRequest captured by the proxy."""
        self._host_edit.setText(req.host)
        self._port_edit.setText(str(req.port))
        self._https_check.setChecked(req.is_https)
        raw_text = req.raw.decode(errors="replace")
        self._request_editor.setPlainText(raw_text)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setSpacing(6)
        root.setContentsMargins(8, 8, 8, 8)

        root.addLayout(self._build_target_bar())
        root.addLayout(self._build_attack_type_bar())
        root.addLayout(self._build_primer_bar())

        # Main horizontal splitter: left = request+payloads+processing, right = results+grep
        splitter = QSplitter(Qt.Orientation.Horizontal)

        splitter.addWidget(self._build_left_panel())
        splitter.addWidget(self._build_right_panel())
        splitter.setSizes([520, 680])

        root.addWidget(splitter, stretch=1)

    # ---- target bar ----

    def _build_target_bar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(8)

        host_label = QLabel("Host:")
        host_label.setStyleSheet("color: #cdd6f4;")
        bar.addWidget(host_label)

        self._host_edit = QLineEdit()
        self._host_edit.setPlaceholderText("example.com")
        self._host_edit.setFixedWidth(220)
        self._host_edit.setStyleSheet(
            "QLineEdit { background: #181825; border: 1px solid #313244; "
            "padding: 4px; border-radius: 3px; color: #cdd6f4; }"
        )
        bar.addWidget(self._host_edit)

        port_label = QLabel("Port:")
        port_label.setStyleSheet("color: #cdd6f4;")
        bar.addWidget(port_label)

        self._port_edit = QLineEdit("80")
        self._port_edit.setFixedWidth(60)
        self._port_edit.setStyleSheet(
            "QLineEdit { background: #181825; border: 1px solid #313244; "
            "padding: 4px; border-radius: 3px; color: #cdd6f4; }"
        )
        bar.addWidget(self._port_edit)

        self._https_check = QCheckBox("HTTPS")
        self._https_check.setStyleSheet("QCheckBox { spacing: 6px; color: #cdd6f4; }")
        self._https_check.stateChanged.connect(self._on_https_toggled)
        bar.addWidget(self._https_check)

        bar.addSpacing(16)

        throttle_label = QLabel("Throttle:")
        throttle_label.setStyleSheet("color: #cdd6f4;")
        bar.addWidget(throttle_label)

        self._throttle_spin = QSpinBox()
        self._throttle_spin.setRange(0, 10000)
        self._throttle_spin.setValue(0)
        self._throttle_spin.setSuffix(" ms")
        self._throttle_spin.setFixedWidth(90)
        self._throttle_spin.setStyleSheet(
            "QSpinBox { background: #181825; border: 1px solid #313244; "
            "padding: 3px; border-radius: 3px; color: #cdd6f4; }"
        )
        bar.addWidget(self._throttle_spin)

        bar.addSpacing(16)

        pool_label = QLabel("Pool:")
        pool_label.setStyleSheet("color: #cdd6f4;")
        pool_label.setToolTip("Resource pool — max concurrent requests for this attack")
        bar.addWidget(pool_label)

        self._concurrency_spin = QSpinBox()
        self._concurrency_spin.setRange(1, 64)
        self._concurrency_spin.setValue(1)
        self._concurrency_spin.setFixedWidth(70)
        self._concurrency_spin.setToolTip(
            "Resource pool — max concurrent in-flight requests (1 = sequential)"
        )
        self._concurrency_spin.setStyleSheet(
            "QSpinBox { background: #181825; border: 1px solid #313244; "
            "padding: 3px; border-radius: 3px; color: #cdd6f4; }"
        )
        bar.addWidget(self._concurrency_spin)

        bar.addStretch()
        return bar

    # ---- attack type bar ----

    def _build_primer_bar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(6)

        self._primer_check = QCheckBox("Primer (CSRF token grab):")
        self._primer_check.setStyleSheet("QCheckBox { spacing: 6px; color: #cdd6f4; }")
        self._primer_check.setToolTip(
            "Before each attack request, fetch a primer URL and substitute the\n"
            "regex-captured value into the marker below."
        )
        bar.addWidget(self._primer_check)

        bar.addWidget(QLabel("Path:"))
        self._primer_path = QLineEdit()
        self._primer_path.setPlaceholderText("/login")
        self._primer_path.setFixedWidth(160)
        self._primer_path.setStyleSheet(
            "QLineEdit { background: #181825; border: 1px solid #313244; "
            "padding: 3px; border-radius: 3px; color: #cdd6f4; }"
        )
        bar.addWidget(self._primer_path)

        bar.addWidget(QLabel("Regex:"))
        self._primer_regex = QLineEdit()
        self._primer_regex.setPlaceholderText(r'name="csrf" value="([^"]+)"')
        self._primer_regex.setStyleSheet(self._primer_path.styleSheet())
        bar.addWidget(self._primer_regex, 1)

        bar.addWidget(QLabel("Marker:"))
        self._primer_marker = QLineEdit("§token§")
        self._primer_marker.setFixedWidth(80)
        self._primer_marker.setStyleSheet(self._primer_path.styleSheet())
        bar.addWidget(self._primer_marker)

        return bar

    def _primer_config(self) -> Optional[dict]:
        if not self._primer_check.isChecked():
            return None
        path = self._primer_path.text().strip()
        regex = self._primer_regex.text().strip()
        marker = self._primer_marker.text().strip() or "§token§"
        if not path or not regex:
            return None
        return {"path": path, "method": "GET", "regex": regex, "marker": marker}

    def _build_attack_type_bar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(8)

        type_label = QLabel("Attack Type:")
        type_label.setStyleSheet("color: #cdd6f4; font-weight: bold;")
        bar.addWidget(type_label)

        self._attack_type_combo = QComboBox()
        self._attack_type_combo.addItems(ATTACK_TYPES)
        self._attack_type_combo.setFixedWidth(160)
        self._attack_type_combo.setStyleSheet(
            "QComboBox { background: #181825; border: 1px solid #313244; "
            "padding: 4px; border-radius: 3px; color: #cdd6f4; }"
            "QComboBox::drop-down { border: none; }"
            "QComboBox QAbstractItemView { background: #181825; color: #cdd6f4; "
            "selection-background-color: #45475a; }"
        )
        self._attack_type_combo.currentTextChanged.connect(self._on_attack_type_changed)
        bar.addWidget(self._attack_type_combo)

        self._parse_positions_btn = QPushButton("Parse Positions")
        self._parse_positions_btn.setStyleSheet(
            "QPushButton { background: #313244; border: 1px solid #45475a; "
            "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
            "QPushButton:hover { background: #45475a; }"
        )
        self._parse_positions_btn.clicked.connect(self._parse_positions)
        bar.addWidget(self._parse_positions_btn)

        self._positions_label = QLabel("(no positions parsed)")
        self._positions_label.setStyleSheet("color: #585b70;")
        bar.addWidget(self._positions_label)

        bar.addStretch()
        return bar

    # ---- left panel ----

    def _build_left_panel(self) -> QWidget:
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(6)

        req_label = QLabel("Request  (wrap injection points with §markers§)")
        req_label.setStyleSheet("color: #cdd6f4; font-weight: bold;")
        left_layout.addWidget(req_label)

        self._request_editor = QTextEdit()
        self._request_editor.setFont(QFont("Monospace", 9))
        self._request_editor.setPlaceholderText(
            "Paste raw HTTP request here.\nWrap injection points: password=§admin§"
        )
        self._request_editor.setStyleSheet(
            "QTextEdit { background: #181825; border: 1px solid #313244; color: #cdd6f4; }"
        )
        left_layout.addWidget(self._request_editor, stretch=3)

        # Payload area — single editor (Sniper/BatteringRam) or tabbed (Pitchfork/ClusterBomb)
        payload_row = QHBoxLayout()
        payload_header = QLabel("Payloads")
        payload_header.setStyleSheet("color: #cdd6f4; font-weight: bold;")
        payload_row.addWidget(payload_header)
        payload_row.addStretch()
        self._payload_gen_btn = QPushButton("Generate…")
        self._payload_gen_btn.setStyleSheet(
            "QPushButton { background: #313244; border: 1px solid #45475a; "
            "padding: 2px 8px; border-radius: 3px; color: #cdd6f4; }"
            "QPushButton:hover { background: #45475a; }"
        )
        self._payload_gen_btn.setToolTip("Numbers / Brute / CSV / Username generator")
        self._payload_gen_btn.clicked.connect(self._open_payload_generator)
        payload_row.addWidget(self._payload_gen_btn)
        left_layout.addLayout(payload_row)

        # Single payload editor (shown for Sniper / Battering Ram)
        self._payload_editor = QTextEdit()
        self._payload_editor.setFont(QFont("Monospace", 9))
        self._payload_editor.setPlaceholderText("admin\nroot\npassword\n123456\n...")
        self._payload_editor.setStyleSheet(
            "QTextEdit { background: #181825; border: 1px solid #313244; color: #cdd6f4; }"
        )
        left_layout.addWidget(self._payload_editor, stretch=2)

        # Multi-tab payload editor (shown for Pitchfork / Cluster Bomb)
        self._payload_tabs = QTabWidget()
        self._payload_tabs.setStyleSheet(
            "QTabWidget::pane { background: #1e1e2e; border: 1px solid #313244; }"
            "QTabBar::tab { background: #313244; color: #cdd6f4; padding: 4px 10px; "
            "border: 1px solid #45475a; border-bottom: none; margin-right: 2px; }"
            "QTabBar::tab:selected { background: #45475a; }"
        )
        self._payload_tabs.setVisible(False)
        left_layout.addWidget(self._payload_tabs, stretch=2)

        # Processing panel
        left_layout.addWidget(self._build_processing_panel())

        # Buttons
        btn_row = QHBoxLayout()
        self._attack_btn = QPushButton("Start Attack")
        self._attack_btn.setStyleSheet(
            "QPushButton { background: #313244; border: 1px solid #45475a; "
            "padding: 4px 10px; border-radius: 4px; font-weight: bold; color: #cdd6f4; }"
            "QPushButton:hover { background: #45475a; }"
        )
        self._attack_btn.clicked.connect(self._start_attack)

        self._stop_btn = QPushButton("Stop")
        self._stop_btn.setEnabled(False)
        self._stop_btn.setStyleSheet(
            "QPushButton { background: #313244; border: 1px solid #45475a; "
            "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
            "QPushButton:hover { background: #45475a; }"
            "QPushButton:disabled { color: #585b70; border-color: #313244; }"
        )
        self._stop_btn.clicked.connect(self._stop_attack)

        self._clear_btn = QPushButton("Clear Results")
        self._clear_btn.setStyleSheet(
            "QPushButton { background: #313244; border: 1px solid #45475a; "
            "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
            "QPushButton:hover { background: #45475a; }"
        )
        self._clear_btn.clicked.connect(self._clear_results)

        btn_row.addWidget(self._attack_btn)
        btn_row.addWidget(self._stop_btn)
        btn_row.addWidget(self._clear_btn)
        btn_row.addStretch()
        left_layout.addLayout(btn_row)

        return left_panel

    def _build_processing_panel(self) -> QWidget:
        frame = QWidget()
        frame.setStyleSheet(
            "QWidget { background: #181825; border: 1px solid #313244; border-radius: 4px; }"
        )
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(4)

        header_row = QHBoxLayout()
        hdr = QLabel("Processing Rules")
        hdr.setStyleSheet("color: #cdd6f4; font-weight: bold; border: none;")
        header_row.addWidget(hdr)
        header_row.addStretch()

        add_rule_btn = QPushButton("Add Rule")
        add_rule_btn.setStyleSheet(
            "QPushButton { background: #313244; border: 1px solid #45475a; "
            "padding: 3px 8px; border-radius: 3px; color: #cdd6f4; }"
            "QPushButton:hover { background: #45475a; }"
        )
        add_rule_btn.clicked.connect(self._add_processing_rule)
        header_row.addWidget(add_rule_btn)

        remove_rule_btn = QPushButton("Remove")
        remove_rule_btn.setStyleSheet(
            "QPushButton { background: #313244; border: 1px solid #45475a; "
            "padding: 3px 8px; border-radius: 3px; color: #cdd6f4; }"
            "QPushButton:hover { background: #45475a; }"
        )
        remove_rule_btn.clicked.connect(self._remove_processing_rule)
        header_row.addWidget(remove_rule_btn)

        layout.addLayout(header_row)

        self._rules_list = QListWidget()
        self._rules_list.setFixedHeight(80)
        self._rules_list.setStyleSheet(
            "QListWidget { background: #1e1e2e; border: 1px solid #313244; "
            "color: #cdd6f4; border-radius: 3px; }"
            "QListWidget::item:selected { background: #45475a; }"
        )
        layout.addWidget(self._rules_list)

        return frame

    # ---- right panel ----

    def _build_right_panel(self) -> QWidget:
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(4)

        results_label = QLabel("Results")
        results_label.setStyleSheet("color: #cdd6f4; font-weight: bold;")
        right_layout.addWidget(results_label)

        self._results_table = QTableWidget(0, BASE_COLS)
        self._results_table.setHorizontalHeaderLabels(
            ["#", "Payload", "Status", "Length", "Time (ms)"]
        )
        self._results_table.setFont(QFont("Monospace", 9))
        self._results_table.setStyleSheet(
            "QTableWidget { background: #181825; border: 1px solid #313244; "
            "gridline-color: #313244; color: #cdd6f4; }"
            "QHeaderView::section { background: #313244; padding: 4px; "
            "border: 1px solid #45475a; color: #cdd6f4; }"
            "QTableWidget::item:selected { background: #45475a; }"
        )
        self._results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._results_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._results_table.verticalHeader().setVisible(False)
        header = self._results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        right_layout.addWidget(self._results_table, stretch=1)

        # Grep panel
        right_layout.addWidget(self._build_grep_panel())

        return right_panel

    def _build_grep_panel(self) -> QWidget:
        frame = QWidget()
        frame.setStyleSheet(
            "QWidget { background: #181825; border: 1px solid #313244; border-radius: 4px; }"
        )
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(4)

        hdr = QLabel("Grep / Extract")
        hdr.setStyleSheet("color: #cdd6f4; font-weight: bold; border: none;")
        layout.addWidget(hdr)

        match_row = QHBoxLayout()
        match_lbl = QLabel("Grep Match (regex):")
        match_lbl.setStyleSheet("color: #cdd6f4; border: none;")
        match_row.addWidget(match_lbl)

        self._grep_match_edit = QLineEdit()
        self._grep_match_edit.setPlaceholderText("e.g. success|logged in")
        self._grep_match_edit.setStyleSheet(
            "QLineEdit { background: #1e1e2e; border: 1px solid #313244; "
            "padding: 4px; border-radius: 3px; color: #cdd6f4; }"
        )
        match_row.addWidget(self._grep_match_edit)
        layout.addLayout(match_row)

        extract_row = QHBoxLayout()
        extract_lbl = QLabel("Grep Extract (regex):")
        extract_lbl.setStyleSheet("color: #cdd6f4; border: none;")
        extract_row.addWidget(extract_lbl)

        self._grep_extract_edit = QLineEdit()
        self._grep_extract_edit.setPlaceholderText("e.g. token=([A-Za-z0-9]+)")
        self._grep_extract_edit.setStyleSheet(
            "QLineEdit { background: #1e1e2e; border: 1px solid #313244; "
            "padding: 4px; border-radius: 3px; color: #cdd6f4; }"
        )
        extract_row.addWidget(self._grep_extract_edit)
        layout.addLayout(extract_row)

        regrep_btn = QPushButton("Re-Grep")
        regrep_btn.setStyleSheet(
            "QPushButton { background: #313244; border: 1px solid #45475a; "
            "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
            "QPushButton:hover { background: #45475a; }"
        )
        regrep_btn.clicked.connect(self._regrep_all)
        layout.addWidget(regrep_btn)

        return frame

    # ------------------------------------------------------------------
    # Attack type / position tab management
    # ------------------------------------------------------------------

    def _open_payload_generator(self) -> None:
        dlg = PayloadGeneratorDialog(self)
        if dlg.exec():
            payloads = dlg.payloads()
            if payloads:
                self._payload_editor.setPlainText("\n".join(payloads))

    def _on_attack_type_changed(self, attack_type: str) -> None:
        multi = attack_type in ("Pitchfork", "Cluster Bomb")
        self._payload_editor.setVisible(not multi)
        self._payload_tabs.setVisible(multi)

    def _parse_positions(self) -> None:
        """Scan request editor for §...§ markers and update payload tabs."""
        raw = self._request_editor.toPlainText()
        n = _positions_count(raw)
        attack = self._attack_type_combo.currentText()

        self._positions_label.setText(f"{n} position(s) found")
        self._positions_label.setStyleSheet("color: #a6e3a1;")

        if attack in ("Pitchfork", "Cluster Bomb"):
            self._rebuild_payload_tabs(n)

    def _rebuild_payload_tabs(self, n_positions: int) -> None:
        """Rebuild the tab widget to have exactly n_positions tabs."""
        # Preserve existing text
        existing_texts: list[str] = []
        for i in range(self._payload_tabs.count()):
            widget = self._payload_tabs.widget(i)
            if isinstance(widget, QTextEdit):
                existing_texts.append(widget.toPlainText())

        self._payload_tabs.clear()

        for i in range(max(n_positions, 1)):
            editor = QTextEdit()
            editor.setFont(QFont("Monospace", 9))
            editor.setPlaceholderText(f"Payloads for position {i + 1} (one per line)")
            editor.setStyleSheet(
                "QTextEdit { background: #1e1e2e; border: none; color: #cdd6f4; }"
            )
            if i < len(existing_texts):
                editor.setPlainText(existing_texts[i])
            self._payload_tabs.addTab(editor, f"Position {i + 1}")

    def _get_payload_sets(self) -> list[list[str]]:
        """Return payload sets according to current attack type UI state."""
        attack = self._attack_type_combo.currentText()
        if attack in ("Sniper", "Battering Ram"):
            text = self._payload_editor.toPlainText()
            return [[p for p in text.splitlines() if p]]
        else:
            sets: list[list[str]] = []
            for i in range(self._payload_tabs.count()):
                widget = self._payload_tabs.widget(i)
                if isinstance(widget, QTextEdit):
                    sets.append([p for p in widget.toPlainText().splitlines() if p])
                else:
                    sets.append([])
            return sets

    # ------------------------------------------------------------------
    # Processing rules
    # ------------------------------------------------------------------

    def _add_processing_rule(self) -> None:
        dlg = AddRuleDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            rule = dlg.get_rule()
            self._processing_rules.append(rule)
            label = rule["type"]
            if rule["type"] in ("Prefix", "Suffix") and rule.get("value"):
                label += f': "{rule["value"]}"'
            self._rules_list.addItem(label)

    def _remove_processing_rule(self) -> None:
        row = self._rules_list.currentRow()
        if row >= 0:
            self._rules_list.takeItem(row)
            self._processing_rules.pop(row)

    # ------------------------------------------------------------------
    # Grep helpers
    # ------------------------------------------------------------------

    def _ensure_grep_columns(self) -> None:
        """Add Match/Extract columns to the table if they don't exist yet."""
        headers = []
        for c in range(self._results_table.columnCount()):
            item = self._results_table.horizontalHeaderItem(c)
            headers.append(item.text() if item else "")

        if self._grep_match_edit.text().strip() and "Match" not in headers:
            col = self._results_table.columnCount()
            self._results_table.setColumnCount(col + 1)
            self._results_table.setHorizontalHeaderItem(col, QTableWidgetItem("Match"))
            self._results_table.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents
            )
            self._grep_match_col = col

        if self._grep_extract_edit.text().strip() and "Extract" not in headers:
            col = self._results_table.columnCount()
            self._results_table.setColumnCount(col + 1)
            self._results_table.setHorizontalHeaderItem(col, QTableWidgetItem("Extract"))
            self._results_table.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeMode.Stretch
            )
            self._grep_extract_col = col

    def _apply_grep_to_row(self, row: int, raw_response: bytes) -> None:
        """Fill Match/Extract cells for a single row."""
        body = raw_response.decode(errors="replace")

        match_pattern = self._grep_match_edit.text().strip()
        if match_pattern and self._grep_match_col is not None:
            try:
                matched = bool(re.search(match_pattern, body))
            except re.error:
                matched = False
            item = QTableWidgetItem("✓" if matched else "")
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if matched:
                item.setForeground(QColor("#a6e3a1"))
            self._results_table.setItem(row, self._grep_match_col, item)

        extract_pattern = self._grep_extract_edit.text().strip()
        if extract_pattern and self._grep_extract_col is not None:
            extracted = ""
            try:
                m = re.search(extract_pattern, body)
                if m and m.lastindex and m.lastindex >= 1:
                    extracted = m.group(1)
                elif m:
                    extracted = m.group(0)
            except re.error:
                pass
            item = QTableWidgetItem(extracted)
            self._results_table.setItem(row, self._grep_extract_col, item)

    def _regrep_all(self) -> None:
        """Re-apply current grep patterns to all existing result rows."""
        # Reset column tracking so columns are re-discovered / re-created as needed
        self._grep_match_col = None
        self._grep_extract_col = None

        # Remove existing Match / Extract columns (from right to left)
        cols_to_remove = []
        for c in range(self._results_table.columnCount() - 1, BASE_COLS - 1, -1):
            item = self._results_table.horizontalHeaderItem(c)
            if item and item.text() in ("Match", "Extract"):
                cols_to_remove.append(c)
        for c in cols_to_remove:
            self._results_table.removeColumn(c)

        if not self._result_raw_responses:
            return

        self._ensure_grep_columns()

        for row, raw in enumerate(self._result_raw_responses):
            self._apply_grep_to_row(row, raw)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_https_toggled(self, state: int) -> None:
        current_port = self._port_edit.text().strip()
        if state == Qt.CheckState.Checked.value:
            if current_port in ("", "80"):
                self._port_edit.setText("443")
        else:
            if current_port in ("", "443"):
                self._port_edit.setText("80")

    def _start_attack(self) -> None:
        host = self._host_edit.text().strip()
        if not host:
            return

        try:
            port = int(self._port_edit.text().strip())
        except ValueError:
            port = 443 if self._https_check.isChecked() else 80

        is_https = self._https_check.isChecked()
        raw_request = self._request_editor.toPlainText()
        if not raw_request.strip():
            return

        payload_sets = self._get_payload_sets()
        if not any(payload_sets):
            return

        throttle_ms = self._throttle_spin.value()
        attack_type = self._attack_type_combo.currentText()

        self._attack_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)

        # Prepare grep columns before attack starts
        self._ensure_grep_columns()

        self._worker = AttackWorker(
            raw_request,
            payload_sets,
            host,
            port,
            is_https,
            attack_type=attack_type,
            processing_rules=list(self._processing_rules),
            throttle_ms=throttle_ms,
            concurrency=self._concurrency_spin.value(),
            primer=self._primer_config(),
        )
        self._worker.result.connect(self._on_result)
        self._worker.finished.connect(self._on_attack_finished)
        self._worker.start()

    def _stop_attack(self) -> None:
        if self._worker is not None:
            self._worker.stop()

    def _clear_results(self) -> None:
        self._results_table.setRowCount(0)
        self._result_count = 0
        self._result_raw_responses.clear()

    def _on_result(
        self,
        payload: str,
        status_code: int,
        length: int,
        elapsed_ms: float,
        raw_response: bytes,
    ) -> None:
        self._result_count += 1
        self._result_raw_responses.append(raw_response)

        row = self._results_table.rowCount()
        self._results_table.insertRow(row)

        num_item = QTableWidgetItem(str(self._result_count))
        num_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        status_item = QTableWidgetItem(str(status_code) if status_code else "ERR")
        status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        if 200 <= status_code < 300:
            status_item.setForeground(QColor("#a6e3a1"))
        elif 300 <= status_code < 400:
            status_item.setForeground(QColor("#89b4fa"))
        elif 400 <= status_code < 500:
            status_item.setForeground(QColor("#fab387"))
        elif status_code >= 500:
            status_item.setForeground(QColor("#f38ba8"))

        length_item = QTableWidgetItem(str(length))
        length_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        time_item = QTableWidgetItem(f"{elapsed_ms:.1f}")
        time_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        self._results_table.setItem(row, COL_NUM, num_item)
        self._results_table.setItem(row, COL_PAYLOAD, QTableWidgetItem(payload))
        self._results_table.setItem(row, COL_STATUS, status_item)
        self._results_table.setItem(row, COL_LENGTH, length_item)
        self._results_table.setItem(row, COL_TIME, time_item)

        self._apply_grep_to_row(row, raw_response)

        self._results_table.scrollToBottom()

    def _on_attack_finished(self) -> None:
        self._attack_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._worker = None
