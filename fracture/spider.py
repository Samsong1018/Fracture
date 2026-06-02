"""
Spider/Crawler tab for Fracture.

BFS crawl of a target web application using only stdlib networking.
"""

from __future__ import annotations

import html.parser
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from typing import Optional

from PyQt6.QtCore import QThread, Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
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


# ---------------------------------------------------------------------------
# HTML link extractor
# ---------------------------------------------------------------------------

class _LinkParser(html.parser.HTMLParser):
    """Extract all link-bearing attributes from HTML."""

    _ATTR_MAP: dict[str, str] = {
        "a": "href",
        "form": "action",
        "script": "src",
        "link": "href",
        "img": "src",
        "iframe": "src",
    }

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_name = self._ATTR_MAP.get(tag.lower())
        if not attr_name:
            return
        for name, value in attrs:
            if name.lower() == attr_name and value:
                self.links.append(value)


def _extract_links(base_url: str, html_bytes: bytes) -> list[str]:
    try:
        text = html_bytes.decode(errors="replace")
    except Exception:
        return []
    parser = _LinkParser()
    try:
        parser.feed(text)
    except Exception:
        pass
    resolved: list[str] = []
    for raw in parser.links:
        raw = raw.strip()
        if not raw or raw.startswith("#") or raw.startswith("javascript:"):
            continue
        try:
            full = urllib.parse.urljoin(base_url, raw)
            parsed = urllib.parse.urlparse(full)
            clean = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
            )
            resolved.append(clean)
        except Exception:
            pass
    return resolved


# ---------------------------------------------------------------------------
# Spider worker
# ---------------------------------------------------------------------------

class SpiderWorker(QThread):
    page_found = pyqtSignal(str, int, str, int)   # url, status, content_type, link_count
    finished = pyqtSignal()
    progress = pyqtSignal(int, int)               # crawled, queued

    def __init__(
        self,
        seed_url: str,
        max_depth: int,
        max_pages: int,
        scope_patterns: list[str],
        parent: Optional[QThread] = None,
    ) -> None:
        super().__init__(parent)
        self._seed = seed_url
        self._max_depth = max_depth
        self._max_pages = max_pages
        self._scope_patterns = scope_patterns
        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True

    def _in_scope(self, url: str) -> bool:
        if not self._scope_patterns:
            return True
        try:
            host = urllib.parse.urlparse(url).netloc
        except Exception:
            return False
        return any(pat in host for pat in self._scope_patterns)

    def _same_origin(self, url: str, seed_netloc: str) -> bool:
        try:
            return urllib.parse.urlparse(url).netloc == seed_netloc
        except Exception:
            return False

    def run(self) -> None:
        try:
            seed_parsed = urllib.parse.urlparse(self._seed)
            seed_netloc = seed_parsed.netloc
        except Exception:
            self.finished.emit()
            return

        queue: deque[tuple[str, int]] = deque()
        queue.append((self._seed, 0))
        visited: set[str] = set()
        crawled = 0

        opener = urllib.request.build_opener()
        opener.addheaders = [
            ("User-Agent", "Fracture-Spider/1.0"),
            ("Accept", "text/html,*/*"),
        ]

        while queue and not self._stop_requested and crawled < self._max_pages:
            url, depth = queue.popleft()

            if url in visited:
                continue
            visited.add(url)

            if not self._in_scope(url):
                continue
            if depth > self._max_depth:
                continue

            self.progress.emit(crawled, len(queue))

            try:
                with opener.open(url, timeout=8) as resp:
                    status = resp.status
                    content_type = resp.headers.get("Content-Type", "")
                    ct_short = content_type.split(";")[0].strip()
                    body = resp.read(512 * 1024)
            except urllib.error.HTTPError as exc:
                status = exc.code
                ct_short = ""
                body = b""
            except Exception:
                continue

            new_links: list[str] = []
            if "text/html" in ct_short:
                links = _extract_links(url, body)
                for link in links:
                    if link not in visited and self._same_origin(link, seed_netloc):
                        queue.append((link, depth + 1))
                        new_links.append(link)

            self.page_found.emit(url, status, ct_short, len(new_links))
            crawled += 1
            self.progress.emit(crawled, len(queue))

        self.finished.emit()


# ---------------------------------------------------------------------------
# SpiderTab
# ---------------------------------------------------------------------------

class SpiderTab(QWidget):
    entry_discovered = pyqtSignal(str, str)   # url, method

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._scope_patterns: list[str] = []
        self._worker: Optional[SpiderWorker] = None
        self._setup_ui()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_scope_patterns(self, patterns: list[str]) -> None:
        self._scope_patterns = list(patterns)

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(6)

        top = QHBoxLayout()
        top.setSpacing(6)

        top.addWidget(QLabel("Seed URL:"))
        self._url_edit = QLineEdit()
        self._url_edit.setPlaceholderText("https://example.com")
        self._url_edit.setStyleSheet(_LINEEDIT_SS)
        top.addWidget(self._url_edit, stretch=1)

        top.addWidget(QLabel("Max Depth:"))
        self._depth_spin = QSpinBox()
        self._depth_spin.setRange(1, 10)
        self._depth_spin.setValue(3)
        self._depth_spin.setStyleSheet(_SPINBOX_SS)
        self._depth_spin.setFixedWidth(60)
        top.addWidget(self._depth_spin)

        top.addWidget(QLabel("Max Pages:"))
        self._pages_spin = QSpinBox()
        self._pages_spin.setRange(10, 5000)
        self._pages_spin.setValue(200)
        self._pages_spin.setSingleStep(10)
        self._pages_spin.setStyleSheet(_SPINBOX_SS)
        self._pages_spin.setFixedWidth(80)
        top.addWidget(self._pages_spin)

        self._crawl_btn = QPushButton("Crawl")
        self._crawl_btn.setStyleSheet(_BTN_SS)
        self._crawl_btn.clicked.connect(self._start_crawl)
        top.addWidget(self._crawl_btn)

        self._stop_btn = QPushButton("Stop")
        self._stop_btn.setStyleSheet(_BTN_SS)
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_crawl)
        top.addWidget(self._stop_btn)

        self._clear_btn = QPushButton("Clear")
        self._clear_btn.setStyleSheet(_BTN_SS)
        self._clear_btn.clicked.connect(self._clear)
        top.addWidget(self._clear_btn)

        root.addLayout(top)

        self._progress_label = QLabel("0 pages crawled / 0 queued")
        self._progress_label.setStyleSheet("color: #a6adc8;")
        root.addWidget(self._progress_label)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["URL", "Status", "Content-Type", "Links Found"])
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

        self._status_label = QLabel("Ready.")
        self._status_label.setStyleSheet("color: #585b70; font-size: 10px;")
        root.addWidget(self._status_label)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _start_crawl(self) -> None:
        url = self._url_edit.text().strip()
        if not url:
            self._status_label.setText("Enter a seed URL first.")
            return

        self._table.setRowCount(0)
        self._status_label.setText("Crawling...")
        self._crawl_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)

        self._worker = SpiderWorker(
            seed_url=url,
            max_depth=self._depth_spin.value(),
            max_pages=self._pages_spin.value(),
            scope_patterns=self._scope_patterns,
        )
        self._worker.page_found.connect(self._on_page_found)
        self._worker.finished.connect(self._on_finished)
        self._worker.progress.connect(self._on_progress)
        self._worker.start()

    def _stop_crawl(self) -> None:
        if self._worker:
            self._worker.stop()
        self._stop_btn.setEnabled(False)
        self._status_label.setText("Stopping...")

    def _clear(self) -> None:
        self._table.setRowCount(0)
        self._progress_label.setText("0 pages crawled / 0 queued")
        self._status_label.setText("Cleared.")

    # ------------------------------------------------------------------
    # Worker callbacks
    # ------------------------------------------------------------------

    def _on_page_found(self, url: str, status: int, content_type: str, link_count: int) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)

        url_item = QTableWidgetItem(url)
        status_item = QTableWidgetItem(str(status))
        ct_item = QTableWidgetItem(content_type)
        links_item = QTableWidgetItem(str(link_count))

        status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        links_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        self._table.setItem(row, 0, url_item)
        self._table.setItem(row, 1, status_item)
        self._table.setItem(row, 2, ct_item)
        self._table.setItem(row, 3, links_item)

        self.entry_discovered.emit(url, "GET")

    def _on_progress(self, crawled: int, queued: int) -> None:
        self._progress_label.setText(f"{crawled} pages crawled / {queued} queued")

    def _on_finished(self) -> None:
        self._crawl_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        count = self._table.rowCount()
        self._status_label.setText(f"Done. {count} pages found.")
