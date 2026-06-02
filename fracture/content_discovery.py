"""
Content Discovery tab for Fracture.

Probes a target web server with a wordlist of common paths to find
hidden endpoints, backup files, and administrative interfaces.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from PyQt6.QtCore import QThread, Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QButtonGroup,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

# ---------------------------------------------------------------------------
# Catppuccin Mocha constants
# ---------------------------------------------------------------------------

_BG = "#1e1e2e"
_SURFACE = "#181825"
_OVERLAY = "#313244"
_HIGHLIGHT = "#45475a"
_TEXT = "#cdd6f4"
_TEXTEDIT_SS = "QTextEdit { background: #181825; border: 1px solid #313244; color: #cdd6f4; }"
_LINEEDIT_SS = "QLineEdit { background: #181825; border: 1px solid #313244; padding: 4px; color: #cdd6f4; }"
_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
    "QPushButton:hover { background: #45475a; }"
    "QPushButton:disabled { color: #585b70; }"
)
_TABLE_SS = (
    "QTableWidget { background: #181825; border: 1px solid #313244; "
    "gridline-color: #313244; color: #cdd6f4; }"
    "QHeaderView::section { background: #313244; color: #cdd6f4; padding: 4px; "
    "border: none; border-right: 1px solid #45475a; }"
    "QTableWidget::item:selected { background: #45475a; }"
)
_SPINBOX_SS = "QSpinBox { background: #181825; border: 1px solid #313244; padding: 4px; color: #cdd6f4; }"
_RADIO_SS = "QRadioButton { color: #cdd6f4; spacing: 6px; }"

# ---------------------------------------------------------------------------
# Built-in wordlist
# ---------------------------------------------------------------------------

BUILTIN_WORDLIST = [
    "admin", "login", "dashboard", "api", "api/v1", "api/v2", "config",
    "backup", "test", "dev", "staging", "old", "tmp", "temp", "uploads",
    "files", "static", "assets", "js", "css", "images", "img", "media",
    "docs", "documentation", "swagger", "swagger-ui", "openapi.json",
    "api/swagger.json", "api/docs", "robots.txt", "sitemap.xml",
    ".git/HEAD", ".env", "web.config", "phpinfo.php", "info.php",
    "admin/login", "admin/dashboard", "wp-admin", "wp-login.php",
    "wp-config.php", "xmlrpc.php", "wp-json", "wp-json/wp/v2/users",
    "administrator", "phpmyadmin", "pma", "mysql", "database",
    "server-status", "server-info", "status", "health", "ping", "version",
    "metrics", "actuator", "actuator/health", "actuator/env", "actuator/mappings",
    "console", "shell", "cmd", "execute", ".htaccess", ".htpasswd",
    "passwd", "shadow", "etc/passwd", "proc/self/environ",
    "crossdomain.xml", "clientaccesspolicy.xml", "security.txt", ".well-known/security.txt",
    "manifest.json", "package.json", "composer.json", "Gemfile",
    "Makefile", "Dockerfile", "docker-compose.yml", ".travis.yml",
    "users", "user", "account", "accounts", "profile", "register",
    "signup", "signin", "logout", "oauth", "oauth2", "token", "auth",
    "search", "query", "graphql", "websocket", "ws", "socket.io",
    "upload", "download", "export", "import", "report", "reports",
    "debug", "trace", "error", "errors", "logs", "log",
    "cgi-bin", "cgi-bin/test.cgi", "cgi-bin/printenv.pl",
]


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

class ContentDiscoveryWorker(QThread):
    result_found = pyqtSignal(str, int, int)   # path, status, length
    finished = pyqtSignal()
    progress = pyqtSignal(int, int)            # done, total

    def __init__(
        self,
        base_url: str,
        wordlist: list[str],
        status_filter: set[int],
        parent: Optional[QThread] = None,
    ) -> None:
        super().__init__(parent)
        self._base_url = base_url.rstrip("/")
        self._wordlist = wordlist
        self._status_filter = status_filter
        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True

    def run(self) -> None:
        total = len(self._wordlist)
        opener = urllib.request.build_opener()
        opener.addheaders = [("User-Agent", "Fracture-ContentDiscovery/1.0")]

        for i, path in enumerate(self._wordlist):
            if self._stop_requested:
                break

            self.progress.emit(i, total)
            url = f"{self._base_url}/{path}"

            try:
                with opener.open(url, timeout=6) as resp:
                    status = resp.status
                    body = resp.read(65536)
                    length = len(body)
            except urllib.error.HTTPError as exc:
                status = exc.code
                length = 0
            except Exception:
                self.progress.emit(i + 1, total)
                continue

            if self._status_filter:
                if status in self._status_filter:
                    self.result_found.emit(path, status, length)
            else:
                if status != 404:
                    self.result_found.emit(path, status, length)

            self.progress.emit(i + 1, total)

        self.finished.emit()


# ---------------------------------------------------------------------------
# ContentDiscoveryTab
# ---------------------------------------------------------------------------

class ContentDiscoveryTab(QWidget):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._worker: Optional[ContentDiscoveryWorker] = None
        self._custom_wordlist: list[str] = []
        self._setup_ui()

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(6)

        # Top bar
        top = QHBoxLayout()
        top.setSpacing(6)

        top.addWidget(QLabel("Target URL:"))
        self._url_edit = QLineEdit()
        self._url_edit.setPlaceholderText("https://example.com")
        self._url_edit.setStyleSheet(_LINEEDIT_SS)
        top.addWidget(self._url_edit, stretch=1)

        top.addWidget(QLabel("Threads:"))
        self._threads_spin = QSpinBox()
        self._threads_spin.setRange(1, 20)
        self._threads_spin.setValue(5)
        self._threads_spin.setStyleSheet(_SPINBOX_SS)
        self._threads_spin.setFixedWidth(60)
        top.addWidget(self._threads_spin)

        top.addWidget(QLabel("Status Filter:"))
        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("200,301,302,403")
        self._filter_edit.setStyleSheet(_LINEEDIT_SS)
        self._filter_edit.setFixedWidth(120)
        top.addWidget(self._filter_edit)

        self._start_btn = QPushButton("Start")
        self._start_btn.setStyleSheet(_BTN_SS)
        self._start_btn.clicked.connect(self._start)
        top.addWidget(self._start_btn)

        self._stop_btn = QPushButton("Stop")
        self._stop_btn.setStyleSheet(_BTN_SS)
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop)
        top.addWidget(self._stop_btn)

        self._clear_btn = QPushButton("Clear")
        self._clear_btn.setStyleSheet(_BTN_SS)
        self._clear_btn.clicked.connect(self._clear)
        top.addWidget(self._clear_btn)

        root.addLayout(top)

        # Wordlist section
        wl_row = QHBoxLayout()
        wl_row.setSpacing(8)

        self._builtin_radio = QRadioButton("Built-in")
        self._builtin_radio.setStyleSheet(_RADIO_SS)
        self._builtin_radio.setChecked(True)
        self._custom_radio = QRadioButton("Custom:")
        self._custom_radio.setStyleSheet(_RADIO_SS)

        self._wl_group = QButtonGroup(self)
        self._wl_group.addButton(self._builtin_radio)
        self._wl_group.addButton(self._custom_radio)

        self._custom_path_edit = QLineEdit()
        self._custom_path_edit.setPlaceholderText("Path to wordlist file...")
        self._custom_path_edit.setStyleSheet(_LINEEDIT_SS)
        self._custom_path_edit.setEnabled(False)

        browse_btn = QPushButton("Browse")
        browse_btn.setStyleSheet(_BTN_SS)
        browse_btn.clicked.connect(self._browse_wordlist)
        browse_btn.setEnabled(False)

        self._custom_radio.toggled.connect(self._custom_path_edit.setEnabled)
        self._custom_radio.toggled.connect(browse_btn.setEnabled)

        wl_row.addWidget(QLabel("Wordlist:"))
        wl_row.addWidget(self._builtin_radio)
        wl_row.addWidget(self._custom_radio)
        wl_row.addWidget(self._custom_path_edit, stretch=1)
        wl_row.addWidget(browse_btn)
        root.addLayout(wl_row)

        # Progress label
        self._progress_label = QLabel("0 / 0 requests")
        self._progress_label.setStyleSheet("color: #a6adc8;")
        root.addWidget(self._progress_label)

        # Results table
        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Path", "Status", "Length", "Note"])
        self._table.setStyleSheet(_TABLE_SS)
        self._table.setFont(QFont("Monospace", 9))
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._table.verticalHeader().setVisible(False)
        root.addWidget(self._table, stretch=1)

        # Status bar
        self._status_label = QLabel("Ready.")
        self._status_label.setStyleSheet("color: #585b70; font-size: 10px;")
        root.addWidget(self._status_label)

    def _browse_wordlist(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open Wordlist", "", "Text Files (*.txt);;All Files (*)")
        if path:
            self._custom_path_edit.setText(path)
            try:
                with open(path, "r", errors="replace") as f:
                    self._custom_wordlist = [line.strip() for line in f if line.strip()]
            except Exception as exc:
                self._status_label.setText(f"Failed to load wordlist: {exc}")

    def _parse_status_filter(self) -> set[int]:
        text = self._filter_edit.text().strip()
        if not text:
            return set()
        result: set[int] = set()
        for part in text.split(","):
            part = part.strip()
            try:
                result.add(int(part))
            except ValueError:
                pass
        return result

    def _start(self) -> None:
        url = self._url_edit.text().strip()
        if not url:
            self._status_label.setText("Enter a target URL first.")
            return

        if self._custom_radio.isChecked():
            wordlist = self._custom_wordlist
            if not wordlist:
                self._status_label.setText("Load a custom wordlist first.")
                return
        else:
            wordlist = BUILTIN_WORDLIST

        status_filter = self._parse_status_filter()
        self._table.setRowCount(0)
        self._progress_label.setText(f"0 / {len(wordlist)} requests")
        self._status_label.setText("Running...")
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)

        self._worker = ContentDiscoveryWorker(url, wordlist, status_filter)
        self._worker.result_found.connect(self._on_result)
        self._worker.finished.connect(self._on_finished)
        self._worker.progress.connect(self._on_progress)
        self._worker.start()

    def _stop(self) -> None:
        if self._worker:
            self._worker.stop()
        self._stop_btn.setEnabled(False)
        self._status_label.setText("Stopping...")

    def _clear(self) -> None:
        self._table.setRowCount(0)
        self._progress_label.setText("0 / 0 requests")
        self._status_label.setText("Cleared.")

    def _on_result(self, path: str, status: int, length: int) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)

        note = ""
        if status in (401, 403):
            note = "Auth required"
        elif status in (301, 302, 307, 308):
            note = "Redirect"
        elif status == 200:
            note = "Found"

        path_item = QTableWidgetItem(path)
        status_item = QTableWidgetItem(str(status))
        length_item = QTableWidgetItem(str(length))
        note_item = QTableWidgetItem(note)

        status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        length_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        self._table.setItem(row, 0, path_item)
        self._table.setItem(row, 1, status_item)
        self._table.setItem(row, 2, length_item)
        self._table.setItem(row, 3, note_item)

    def _on_progress(self, done: int, total: int) -> None:
        self._progress_label.setText(f"{done} / {total} requests")

    def _on_finished(self) -> None:
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        count = self._table.rowCount()
        self._status_label.setText(f"Done. {count} results found.")
