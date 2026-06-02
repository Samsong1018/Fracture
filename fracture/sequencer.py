"""
Sequencer tab — analyze the randomness/entropy of tokens.

Sends a request N times, extracts a token from each response using a
user-supplied regex, then reports entropy statistics to help identify
weak or predictable session IDs, CSRF tokens, and API keys.
"""

import math
import re
import socket
import ssl
from collections import Counter
from typing import List, Optional

from PyQt6.QtCore import QThread, Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .proxy import HttpRequest

BUFFER = 65536

# ---------------------------------------------------------------------------
# Catppuccin Mocha stylesheet constants
# ---------------------------------------------------------------------------

_TEXTEDIT_SS = "QTextEdit { background: #181825; border: 1px solid #313244; }"
_LINEEDIT_SS = "QLineEdit { background: #181825; border: 1px solid #313244; padding: 4px; }"
_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
    "QPushButton:hover { background: #45475a; }"
    "QPushButton:disabled { color: #585b70; }"
)
_SPINBOX_SS = (
    "QSpinBox { background: #181825; border: 1px solid #313244; "
    "padding: 4px; color: #cdd6f4; }"
)
_PROGRESS_SS = (
    "QProgressBar { background: #181825; border: 1px solid #313244; "
    "color: #cdd6f4; text-align: center; }"
    "QProgressBar::chunk { background: #89b4fa; }"
)
_LIST_SS = "QListWidget { background: #181825; border: 1px solid #313244; color: #cdd6f4; }"
_LABEL_SS = "color: #a6adc8;"
_SMALL_LABEL_SS = "color: #585b70; font-size: 10px;"
_TABS_SS = (
    "QTabWidget::pane { border: 1px solid #313244; background: #1e1e2e; }"
    "QTabBar::tab { background: #181825; color: #a6adc8; padding: 4px 12px; "
    "border: 1px solid #313244; border-bottom: none; margin-right: 2px; }"
    "QTabBar::tab:selected { background: #313244; color: #cdd6f4; }"
    "QTabBar::tab:hover { background: #45475a; color: #cdd6f4; }"
)
_CHECKBOX_SS = "QCheckBox { spacing: 6px; color: #cdd6f4; }"

# Verdict colours
_COLOR_STRONG = "#a6e3a1"
_COLOR_MODERATE = "#fab387"
_COLOR_WEAK = "#f38ba8"


# ---------------------------------------------------------------------------
# Entropy helpers
# ---------------------------------------------------------------------------

def shannon_entropy(tokens: List[str]) -> float:
    """Return the Shannon entropy (bits per character) of the combined token string."""
    combined = "".join(tokens)
    if not combined:
        return 0.0
    counts = Counter(combined)
    total = len(combined)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def detect_charset(tokens: List[str]) -> str:
    """Return a human-readable description of the character set used across all tokens."""
    combined = "".join(tokens)
    if not combined:
        return "unknown"
    chars = set(combined)
    hex_chars = set("0123456789abcdefABCDEF")
    b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    alnum_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    numeric_chars = set("0123456789")

    if chars <= numeric_chars:
        return "numeric"
    if chars <= hex_chars:
        return "hexadecimal"
    if chars <= alnum_chars:
        return "alphanumeric"
    if chars <= b64_chars:
        return "base64"
    return "mixed"


def ascii_histogram(tokens: List[str], top_n: int = 10) -> str:
    """Return an ASCII bar chart of the top *top_n* most frequent characters."""
    combined = "".join(tokens)
    if not combined:
        return "(no data)"

    counts = Counter(combined)
    most_common = counts.most_common(top_n)
    max_count = most_common[0][1] if most_common else 1
    bar_width = 30

    lines = ["Character frequency (top {top_n}):".format(top_n=min(top_n, len(most_common)))]
    lines.append("-" * 50)
    for char, count in most_common:
        display = repr(char) if char in ("\r", "\n", "\t", " ") else char
        bar_len = int((count / max_count) * bar_width)
        bar = "█" * bar_len
        pct = (count / len(combined)) * 100
        lines.append(f"  {display!s:>4}  {bar:<{bar_width}}  {count:>5}  ({pct:.1f}%)")
    return "\n".join(lines)


def compute_verdict(entropy: float, tokens: List[str]) -> tuple[str, str]:
    """Return (verdict_text, color_hex) based on entropy and uniqueness."""
    if not tokens:
        return "N/A", _COLOR_MODERATE

    unique_ratio = len(set(tokens)) / len(tokens)

    if entropy >= 3.5 and unique_ratio == 1.0:
        return "STRONG", _COLOR_STRONG
    if entropy < 2.0 or unique_ratio < 1.0:
        return "WEAK", _COLOR_WEAK
    return "MODERATE", _COLOR_MODERATE


# ---------------------------------------------------------------------------
# Worker thread
# ---------------------------------------------------------------------------

def _send_raw(host: str, port: int, is_https: bool, request_bytes: bytes) -> bytes:
    """Open a raw TCP/TLS connection, send *request_bytes*, return the full response."""
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
    return response_data


class SampleWorker(QThread):
    """Send the target request *sample_size* times and emit each extracted token."""

    token_collected = pyqtSignal(str)   # one token per emission
    finished = pyqtSignal()
    error = pyqtSignal(str)
    progress = pyqtSignal(int, int)     # current, total

    def __init__(
        self,
        host: str,
        port: int,
        is_https: bool,
        request_bytes: bytes,
        regex: str,
        sample_size: int,
        parent: Optional[QThread] = None,
    ) -> None:
        super().__init__(parent)
        self._host = host
        self._port = port
        self._is_https = is_https
        self._request_bytes = request_bytes
        self._regex = regex
        self._sample_size = sample_size
        self._stop_flag = False
        self._no_match_count = 0

    def stop(self) -> None:
        self._stop_flag = True

    def run(self) -> None:
        try:
            pattern = re.compile(self._regex)
        except re.error as exc:
            self.error.emit(f"Invalid regex: {exc}")
            return

        collected = 0
        self._no_match_count = 0

        for i in range(self._sample_size):
            if self._stop_flag:
                break

            self.progress.emit(i, self._sample_size)

            try:
                raw_response = _send_raw(
                    self._host, self._port, self._is_https, self._request_bytes
                )
            except Exception as exc:
                self.error.emit(f"Request {i + 1} failed: {exc}")
                continue

            response_text = raw_response.decode(errors="replace")
            match = pattern.search(response_text)
            if match:
                groups = match.groups()
                token = groups[0] if groups else match.group(0)
                self.token_collected.emit(token)
                collected += 1
            else:
                self._no_match_count += 1

        self.progress.emit(self._sample_size, self._sample_size)

        # Warn if more than 10% of responses yielded no token
        if self._sample_size > 0:
            miss_pct = (self._no_match_count / self._sample_size) * 100
            if miss_pct > 10:
                self.error.emit(
                    f"Warning: {self._no_match_count}/{self._sample_size} responses "
                    f"({miss_pct:.0f}%) did not match the regex."
                )

        self.finished.emit()


# ---------------------------------------------------------------------------
# SequencerTab
# ---------------------------------------------------------------------------

class SequencerTab(QWidget):
    """
    Sequencer — collect and analyze token entropy.

    Public API:
        load_request(req: HttpRequest) — pre-populate the editor and target fields.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._tokens: List[str] = []
        self._worker: Optional[SampleWorker] = None
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

        target_bar.addWidget(QLabel("Host:"))
        self._host_edit = QLineEdit()
        self._host_edit.setPlaceholderText("hostname or IP")
        self._host_edit.setFixedWidth(220)
        self._host_edit.setStyleSheet(_LINEEDIT_SS)
        target_bar.addWidget(self._host_edit)

        target_bar.addWidget(QLabel(":"))
        self._port_edit = QLineEdit()
        self._port_edit.setPlaceholderText("port")
        self._port_edit.setFixedWidth(60)
        self._port_edit.setStyleSheet(_LINEEDIT_SS)
        target_bar.addWidget(self._port_edit)

        self._https_check = QCheckBox("HTTPS")
        self._https_check.setStyleSheet(_CHECKBOX_SS)
        target_bar.addWidget(self._https_check)
        target_bar.addStretch()
        root.addLayout(target_bar)

        # --- Request editor -----------------------------------------------
        req_lbl = QLabel("Request")
        req_lbl.setStyleSheet(_SMALL_LABEL_SS)
        root.addWidget(req_lbl)

        self._request_editor = QTextEdit()
        self._request_editor.setFont(QFont("Monospace", 9))
        self._request_editor.setPlaceholderText(
            "Paste or load a raw HTTP request here."
        )
        self._request_editor.setStyleSheet(_TEXTEDIT_SS)
        self._request_editor.setMinimumHeight(140)
        root.addWidget(self._request_editor)

        # --- Token extraction row -----------------------------------------
        extraction_row = QHBoxLayout()
        extraction_row.setSpacing(6)

        extraction_row.addWidget(QLabel("Extract token with regex:"))
        self._regex_edit = QLineEdit()
        self._regex_edit.setPlaceholderText(
            'e.g.  Set-Cookie: session=([A-Za-z0-9]+)  or  "csrf_token":"([^"]+)"'
        )
        self._regex_edit.setStyleSheet(_LINEEDIT_SS)
        extraction_row.addWidget(self._regex_edit, stretch=1)

        self._test_btn = QPushButton("Test")
        self._test_btn.setStyleSheet(_BTN_SS)
        self._test_btn.setToolTip(
            "Send the request once and show what the regex would extract."
        )
        self._test_btn.clicked.connect(self._test_regex)
        extraction_row.addWidget(self._test_btn)
        root.addLayout(extraction_row)

        # --- Config row ---------------------------------------------------
        config_row = QHBoxLayout()
        config_row.setSpacing(6)

        config_row.addWidget(QLabel("Sample size:"))
        self._sample_spin = QSpinBox()
        self._sample_spin.setRange(10, 2000)
        self._sample_spin.setValue(100)
        self._sample_spin.setStyleSheet(_SPINBOX_SS)
        self._sample_spin.setFixedWidth(80)
        config_row.addWidget(self._sample_spin)

        config_row.addStretch()

        self._start_btn = QPushButton("Start")
        self._start_btn.setStyleSheet(_BTN_SS)
        self._start_btn.clicked.connect(self._start)
        config_row.addWidget(self._start_btn)

        self._stop_btn = QPushButton("Stop")
        self._stop_btn.setStyleSheet(_BTN_SS)
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop)
        config_row.addWidget(self._stop_btn)

        root.addLayout(config_row)

        # --- Progress bar -------------------------------------------------
        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setStyleSheet(_PROGRESS_SS)
        self._progress.setFixedHeight(16)
        root.addWidget(self._progress)

        # --- Results area -------------------------------------------------
        self._results_tabs = QTabWidget()
        self._results_tabs.setStyleSheet(_TABS_SS)

        # Tokens tab
        tokens_widget = QWidget()
        tokens_layout = QVBoxLayout(tokens_widget)
        tokens_layout.setContentsMargins(4, 4, 4, 4)
        tokens_layout.setSpacing(4)

        self._token_list = QListWidget()
        self._token_list.setFont(QFont("Monospace", 9))
        self._token_list.setStyleSheet(_LIST_SS)
        tokens_layout.addWidget(self._token_list)

        copy_all_btn = QPushButton("Copy All")
        copy_all_btn.setStyleSheet(_BTN_SS)
        copy_all_btn.setFixedWidth(90)
        copy_all_btn.clicked.connect(self._copy_all_tokens)
        tokens_layout.addWidget(copy_all_btn, alignment=Qt.AlignmentFlag.AlignLeft)

        self._results_tabs.addTab(tokens_widget, "Tokens")

        # Analysis tab
        analysis_widget = QWidget()
        analysis_layout = QVBoxLayout(analysis_widget)
        analysis_layout.setContentsMargins(4, 4, 4, 4)

        self._analysis_view = QTextEdit()
        self._analysis_view.setFont(QFont("Monospace", 9))
        self._analysis_view.setReadOnly(True)
        self._analysis_view.setStyleSheet(_TEXTEDIT_SS)
        analysis_layout.addWidget(self._analysis_view)

        self._results_tabs.addTab(analysis_widget, "Analysis")

        root.addWidget(self._results_tabs, stretch=1)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_request(self, req: HttpRequest) -> None:
        """Pre-populate the request editor and target fields from *req*."""
        raw_text = req.raw.decode(errors="replace") if req.raw else str(req)
        self._request_editor.setPlainText(raw_text)
        self._host_edit.setText(req.host)
        self._port_edit.setText(str(req.port))
        self._https_check.setChecked(req.is_https)

    # ------------------------------------------------------------------
    # Test regex
    # ------------------------------------------------------------------

    def _test_regex(self) -> None:
        """Send the request once and display the regex match result."""
        host, port, is_https, raw_bytes, regex_str = self._collect_params()
        if raw_bytes is None:
            return

        try:
            pattern = re.compile(regex_str)
        except re.error as exc:
            self._analysis_view.setPlainText(f"[Error] Invalid regex: {exc}")
            self._results_tabs.setCurrentIndex(1)
            return

        self._test_btn.setEnabled(False)
        self._analysis_view.setPlainText("Sending test request…")
        self._results_tabs.setCurrentIndex(1)

        try:
            raw_response = _send_raw(host, port, is_https, raw_bytes)
        except Exception as exc:
            self._analysis_view.setPlainText(f"[Error] {exc}")
            self._test_btn.setEnabled(True)
            return

        response_text = raw_response.decode(errors="replace")
        match = pattern.search(response_text)
        if match:
            groups = match.groups()
            token = groups[0] if groups else match.group(0)
            self._analysis_view.setPlainText(
                f"Test result: token extracted successfully.\n\nToken: {token!r}"
            )
        else:
            self._analysis_view.setPlainText(
                "Test result: no match found.\n\n"
                "Adjust your regex and try again.\n\n"
                f"Response (first 2000 chars):\n{response_text[:2000]}"
            )

        self._test_btn.setEnabled(True)

    # ------------------------------------------------------------------
    # Start / Stop
    # ------------------------------------------------------------------

    def _collect_params(
        self,
    ) -> tuple:
        """Validate and return (host, port, is_https, raw_bytes, regex_str).

        Returns (None, None, None, None, None) and sets an error message on
        validation failure.
        """
        host = self._host_edit.text().strip()
        port_text = self._port_edit.text().strip()
        is_https = self._https_check.isChecked()
        raw_text = self._request_editor.toPlainText()
        regex_str = self._regex_edit.text().strip()

        err_target = self._analysis_view

        if not host:
            err_target.setPlainText("[Error] Host is empty.")
            self._results_tabs.setCurrentIndex(1)
            return None, None, None, None, None

        try:
            port = int(port_text) if port_text else (443 if is_https else 80)
        except ValueError:
            err_target.setPlainText(f"[Error] Invalid port: {port_text!r}")
            self._results_tabs.setCurrentIndex(1)
            return None, None, None, None, None

        if not raw_text.strip():
            err_target.setPlainText("[Error] Request editor is empty.")
            self._results_tabs.setCurrentIndex(1)
            return None, None, None, None, None

        if not regex_str:
            err_target.setPlainText("[Error] Extraction regex is empty.")
            self._results_tabs.setCurrentIndex(1)
            return None, None, None, None, None

        raw_bytes = raw_text.encode(errors="replace")
        return host, port, is_https, raw_bytes, regex_str

    def _start(self) -> None:
        """Begin collecting token samples."""
        host, port, is_https, raw_bytes, regex_str = self._collect_params()
        if raw_bytes is None:
            return

        sample_size = self._sample_spin.value()

        # Reset state
        self._tokens = []
        self._token_list.clear()
        self._analysis_view.setPlainText("")
        self._progress.setValue(0)
        self._progress.setRange(0, sample_size)

        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._test_btn.setEnabled(False)

        self._worker = SampleWorker(
            host, port, is_https, raw_bytes, regex_str, sample_size
        )
        self._worker.token_collected.connect(self._on_token)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(self._on_error)
        self._worker.progress.connect(self._on_progress)
        self._worker.start()

    def _stop(self) -> None:
        """Signal the worker to stop after the current request."""
        if self._worker is not None:
            self._worker.stop()
        self._stop_btn.setEnabled(False)

    # ------------------------------------------------------------------
    # Worker callbacks
    # ------------------------------------------------------------------

    def _on_token(self, token: str) -> None:
        idx = len(self._tokens) + 1
        self._tokens.append(token)
        item = QListWidgetItem(f"{idx:>4}.  {token}")
        self._token_list.addItem(item)

    def _on_progress(self, current: int, total: int) -> None:
        self._progress.setRange(0, total)
        self._progress.setValue(current)

    def _on_finished(self) -> None:
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._test_btn.setEnabled(True)
        self._progress.setValue(self._progress.maximum())
        self._render_analysis()

    def _on_error(self, message: str) -> None:
        current = self._analysis_view.toPlainText()
        if current:
            self._analysis_view.setPlainText(current + f"\n\n[Warning] {message}")
        else:
            self._analysis_view.setPlainText(f"[Warning] {message}")
        self._results_tabs.setCurrentIndex(1)

    # ------------------------------------------------------------------
    # Analysis rendering
    # ------------------------------------------------------------------

    def _render_analysis(self) -> None:
        """Compute and display analysis statistics for collected tokens."""
        tokens = self._tokens
        if not tokens:
            self._analysis_view.setPlainText("No tokens collected.")
            self._results_tabs.setCurrentIndex(1)
            return

        total = len(tokens)
        unique = len(set(tokens))
        unique_pct = (unique / total) * 100 if total else 0

        lengths = [len(t) for t in tokens]
        len_min = min(lengths)
        len_max = max(lengths)
        len_mean = sum(lengths) / len(lengths)

        charset = detect_charset(tokens)
        entropy = shannon_entropy(tokens)
        verdict_text, verdict_color = compute_verdict(entropy, tokens)
        histogram = ascii_histogram(tokens)

        lines = [
            "=== Sequencer Analysis ===",
            "",
            f"Total tokens collected : {total}",
            f"Unique tokens          : {unique}  ({unique_pct:.1f}%)",
            "",
            f"Token length — min     : {len_min}",
            f"Token length — max     : {len_max}",
            f"Token length — mean    : {len_mean:.1f}",
            "",
            f"Character set detected : {charset}",
            f"Shannon entropy        : {entropy:.4f} bits/char",
            "",
        ]

        verdict_line = f"Verdict: {verdict_text}"
        lines.append(verdict_line)
        lines.append("")
        lines.append(histogram)

        analysis_text = "\n".join(lines)

        # Render with colored verdict line using HTML
        html_lines = []
        for line in lines:
            escaped = (
                line.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace(" ", "&nbsp;")
            )
            if line.startswith("Verdict:"):
                html_lines.append(
                    f'<span style="color: {verdict_color}; font-weight: bold;">'
                    f"{escaped}</span>"
                )
            else:
                html_lines.append(f'<span style="color: #cdd6f4;">{escaped}</span>')

        html_body = "<br>".join(html_lines)
        full_html = (
            '<html><body style="background-color: #181825; '
            'font-family: monospace; font-size: 9pt;">'
            f"{html_body}"
            "</body></html>"
        )
        self._analysis_view.setHtml(full_html)
        self._results_tabs.setCurrentIndex(1)

    # ------------------------------------------------------------------
    # Copy all tokens
    # ------------------------------------------------------------------

    def _copy_all_tokens(self) -> None:
        """Copy all collected tokens to the system clipboard, one per line."""
        if not self._tokens:
            return
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText("\n".join(self._tokens))
