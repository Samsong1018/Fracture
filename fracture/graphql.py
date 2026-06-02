"""
GraphQL Analyzer tab for Fracture.

Runs introspection queries against a GraphQL endpoint, displays the
schema tree, lets the user write and send queries, and supports batch
query attack mode.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Optional

from PyQt6.QtCore import QThread, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .proxy import HttpRequest

# ---------------------------------------------------------------------------
# Catppuccin Mocha theme
# ---------------------------------------------------------------------------

_BG = "#1e1e2e"
_SURFACE = "#181825"
_OVERLAY = "#313244"
_HIGHLIGHT = "#45475a"
_TEXT = "#cdd6f4"
_SUBTEXT = "#a6adc8"
_TEXTEDIT_SS = "QTextEdit { background: #181825; border: 1px solid #313244; color: #cdd6f4; }"
_LINEEDIT_SS = "QLineEdit { background: #181825; border: 1px solid #313244; padding: 4px; color: #cdd6f4; }"
_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
    "QPushButton:hover { background: #45475a; }"
    "QPushButton:disabled { color: #585b70; }"
)
_TREE_SS = (
    f"QTreeWidget {{ background: {_SURFACE}; border: 1px solid {_OVERLAY}; "
    f"color: {_TEXT}; font-family: monospace; font-size: 12px; }}"
    f"QTreeWidget::item:selected {{ background: {_HIGHLIGHT}; }}"
    f"QTreeWidget::item:hover {{ background: {_OVERLAY}; }}"
)
_LIST_SS = (
    f"QListWidget {{ background: {_SURFACE}; border: 1px solid {_OVERLAY}; "
    f"color: {_TEXT}; font-family: monospace; font-size: 12px; }}"
    f"QListWidget::item:selected {{ background: {_HIGHLIGHT}; }}"
)
_TABS_SS = (
    f"QTabWidget::pane {{ border: 1px solid {_OVERLAY}; background: {_BG}; }}"
    f"QTabBar::tab {{ background: {_SURFACE}; color: {_SUBTEXT}; padding: 4px 12px; "
    f"border: 1px solid {_OVERLAY}; border-bottom: none; margin-right: 2px; }}"
    f"QTabBar::tab:selected {{ background: {_OVERLAY}; color: {_TEXT}; }}"
    f"QTabBar::tab:hover {{ background: {_HIGHLIGHT}; color: {_TEXT}; }}"
)
_LABEL_SS = f"color: {_SUBTEXT}; font-size: 11px;"
_CHECKBOX_SS = f"QCheckBox {{ spacing: 6px; color: {_TEXT}; }}"

_INTROSPECTION_QUERY = (
    '{ __schema { types { name kind fields { name type { name kind } } } } }'
)


# ---------------------------------------------------------------------------
# Worker threads
# ---------------------------------------------------------------------------

class IntrospectionWorker(QThread):
    schema_loaded = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, url: str, parent: Optional[QThread] = None) -> None:
        super().__init__(parent)
        self._url = url

    def run(self) -> None:
        payload = json.dumps({"query": _INTROSPECTION_QUERY}).encode()
        req = urllib.request.Request(
            self._url,
            data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read()
        except urllib.error.URLError as exc:
            self.error.emit(f"Request failed: {exc}")
            return
        except Exception as exc:
            self.error.emit(f"Unexpected error: {exc}")
            return

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            self.error.emit(f"JSON parse error: {exc}\n\n{raw[:500].decode(errors='replace')}")
            return

        if "errors" in data:
            errs = data["errors"]
            msgs = "; ".join(e.get("message", str(e)) for e in errs)
            self.error.emit(f"GraphQL errors: {msgs}")
            return

        schema = data.get("data", {}).get("__schema")
        if schema is None:
            self.error.emit("Response did not contain __schema data.")
            return

        self.schema_loaded.emit(schema)


class QueryWorker(QThread):
    result = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, url: str, query: str, parent: Optional[QThread] = None) -> None:
        super().__init__(parent)
        self._url = url
        self._query = query

    def run(self) -> None:
        payload = json.dumps({"query": self._query}).encode()
        req = urllib.request.Request(
            self._url,
            data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read()
            self.result.emit(raw.decode(errors="replace"))
        except urllib.error.URLError as exc:
            self.error.emit(f"Request failed: {exc}")
        except Exception as exc:
            self.error.emit(f"Unexpected error: {exc}")


class BatchWorker(QThread):
    result = pyqtSignal(int, str, int)
    finished = pyqtSignal()

    def __init__(self, url: str, queries: list[str], parent: Optional[QThread] = None) -> None:
        super().__init__(parent)
        self._url = url
        self._queries = queries

    def run(self) -> None:
        for idx, query in enumerate(self._queries):
            query = query.strip()
            if not query:
                continue
            payload = json.dumps({"query": query}).encode()
            req = urllib.request.Request(
                self._url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    raw = resp.read()
                status_line = f"[{idx + 1}] HTTP 200"
                self.result.emit(idx, status_line, len(raw))
            except urllib.error.HTTPError as exc:
                self.result.emit(idx, f"[{idx + 1}] HTTP {exc.code}", 0)
            except Exception as exc:
                self.result.emit(idx, f"[{idx + 1}] ERROR: {exc}", 0)
        self.finished.emit()


# ---------------------------------------------------------------------------
# GraphQLTab
# ---------------------------------------------------------------------------

class GraphQLTab(QWidget):
    """GraphQL Analyzer — introspection, query builder, and batch attack."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._introspection_worker: Optional[IntrospectionWorker] = None
        self._query_worker: Optional[QueryWorker] = None
        self._batch_worker: Optional[BatchWorker] = None
        self._build_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        self.setStyleSheet(f"background: {_BG}; color: {_TEXT};")
        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(6)

        # ---- top bar ----
        top_bar = QHBoxLayout()
        top_bar.setSpacing(6)

        url_label = QLabel("Target URL:")
        url_label.setStyleSheet(_LABEL_SS)
        top_bar.addWidget(url_label)

        self._url_edit = QLineEdit()
        self._url_edit.setPlaceholderText("https://example.com/graphql")
        self._url_edit.setStyleSheet(_LINEEDIT_SS)
        top_bar.addWidget(self._url_edit, stretch=1)

        self._https_check = QCheckBox("HTTPS")
        self._https_check.setStyleSheet(_CHECKBOX_SS)
        top_bar.addWidget(self._https_check)

        self._introspect_btn = QPushButton("Run Introspection")
        self._introspect_btn.setStyleSheet(_BTN_SS)
        self._introspect_btn.clicked.connect(self._run_introspection)
        top_bar.addWidget(self._introspect_btn)

        self._clear_btn = QPushButton("Clear")
        self._clear_btn.setStyleSheet(_BTN_SS)
        self._clear_btn.clicked.connect(self._clear)
        top_bar.addWidget(self._clear_btn)

        root.addLayout(top_bar)

        # ---- main horizontal splitter ----
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        main_splitter.setStyleSheet(f"QSplitter::handle {{ background: {_OVERLAY}; }}")

        # ---- left: schema explorer ----
        left_panel = QWidget()
        left_panel.setStyleSheet(f"background: {_BG};")
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(4)

        schema_header = QLabel("Schema Explorer")
        schema_header.setStyleSheet(
            f"color: {_SUBTEXT}; font-size: 11px; font-family: monospace;"
            f" padding: 4px 8px; background: {_OVERLAY};"
        )
        left_layout.addWidget(schema_header)

        self._schema_lbl = QLabel("No schema loaded")
        self._schema_lbl.setStyleSheet(_LABEL_SS + " padding: 2px 4px;")
        left_layout.addWidget(self._schema_lbl)

        self._schema_tree = QTreeWidget()
        self._schema_tree.setHeaderHidden(True)
        self._schema_tree.setStyleSheet(_TREE_SS)
        left_layout.addWidget(self._schema_tree, stretch=1)

        main_splitter.addWidget(left_panel)

        # ---- right: tab widget ----
        right_tabs = QTabWidget()
        right_tabs.setStyleSheet(_TABS_SS)

        # --- Query Builder tab ---
        query_tab = QWidget()
        query_tab.setStyleSheet(f"background: {_BG};")
        query_layout = QVBoxLayout(query_tab)
        query_layout.setContentsMargins(4, 4, 4, 4)
        query_layout.setSpacing(4)

        query_splitter = QSplitter(Qt.Orientation.Vertical)
        query_splitter.setStyleSheet(f"QSplitter::handle {{ background: {_OVERLAY}; }}")

        query_top = QWidget()
        query_top.setStyleSheet(f"background: {_BG};")
        query_top_layout = QVBoxLayout(query_top)
        query_top_layout.setContentsMargins(0, 0, 0, 0)
        query_top_layout.setSpacing(4)

        query_lbl = QLabel("Query")
        query_lbl.setStyleSheet(_LABEL_SS)
        query_top_layout.addWidget(query_lbl)

        self._query_edit = QTextEdit()
        self._query_edit.setPlaceholderText("{ __typename }")
        self._query_edit.setStyleSheet(_TEXTEDIT_SS)
        query_top_layout.addWidget(self._query_edit, stretch=1)

        send_query_btn = QPushButton("Send Query")
        send_query_btn.setStyleSheet(_BTN_SS)
        send_query_btn.clicked.connect(self._send_query)
        query_top_layout.addWidget(send_query_btn, alignment=Qt.AlignmentFlag.AlignLeft)

        query_splitter.addWidget(query_top)

        query_bottom = QWidget()
        query_bottom.setStyleSheet(f"background: {_BG};")
        query_bottom_layout = QVBoxLayout(query_bottom)
        query_bottom_layout.setContentsMargins(0, 0, 0, 0)
        query_bottom_layout.setSpacing(4)

        response_lbl = QLabel("Response")
        response_lbl.setStyleSheet(_LABEL_SS)
        query_bottom_layout.addWidget(response_lbl)

        self._response_edit = QTextEdit()
        self._response_edit.setReadOnly(True)
        self._response_edit.setStyleSheet(_TEXTEDIT_SS)
        query_bottom_layout.addWidget(self._response_edit, stretch=1)

        query_splitter.addWidget(query_bottom)
        query_splitter.setSizes([300, 200])
        query_layout.addWidget(query_splitter)

        right_tabs.addTab(query_tab, "Query Builder")

        # --- Batch Attack tab ---
        batch_tab = QWidget()
        batch_tab.setStyleSheet(f"background: {_BG};")
        batch_layout = QVBoxLayout(batch_tab)
        batch_layout.setContentsMargins(4, 4, 4, 4)
        batch_layout.setSpacing(4)

        batch_lbl = QLabel("Queries (one per line)")
        batch_lbl.setStyleSheet(_LABEL_SS)
        batch_layout.addWidget(batch_lbl)

        self._batch_edit = QTextEdit()
        self._batch_edit.setPlaceholderText("{ __typename }\n{ users { id } }\n...")
        self._batch_edit.setStyleSheet(_TEXTEDIT_SS)
        batch_layout.addWidget(self._batch_edit, stretch=1)

        send_batch_btn = QPushButton("Send Batch")
        send_batch_btn.setStyleSheet(_BTN_SS)
        send_batch_btn.clicked.connect(self._send_batch)
        batch_layout.addWidget(send_batch_btn, alignment=Qt.AlignmentFlag.AlignLeft)

        batch_results_lbl = QLabel("Results")
        batch_results_lbl.setStyleSheet(_LABEL_SS)
        batch_layout.addWidget(batch_results_lbl)

        self._batch_results = QListWidget()
        self._batch_results.setStyleSheet(_LIST_SS)
        batch_layout.addWidget(self._batch_results, stretch=1)

        right_tabs.addTab(batch_tab, "Batch Attack")

        main_splitter.addWidget(right_tabs)
        main_splitter.setSizes([300, 700])
        root.addWidget(main_splitter, stretch=1)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_request(self, req: HttpRequest) -> None:
        scheme = "https" if req.is_https else "http"
        port_part = ""
        default_port = 443 if req.is_https else 80
        if req.port != default_port:
            port_part = f":{req.port}"
        url = f"{scheme}://{req.host}{port_part}{req.path}"
        self._url_edit.setText(url)
        self._https_check.setChecked(req.is_https)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _run_introspection(self) -> None:
        url = self._url_edit.text().strip()
        if not url:
            self._schema_lbl.setText("Error: target URL is empty")
            return

        self._introspect_btn.setEnabled(False)
        self._schema_lbl.setText("Running introspection…")
        self._schema_tree.clear()

        self._introspection_worker = IntrospectionWorker(url)
        self._introspection_worker.schema_loaded.connect(self._populate_schema)
        self._introspection_worker.error.connect(self._on_introspection_error)
        self._introspection_worker.finished.connect(
            lambda: self._introspect_btn.setEnabled(True)
        )
        self._introspection_worker.start()

    def _send_query(self) -> None:
        url = self._url_edit.text().strip()
        if not url:
            self._response_edit.setPlainText("[Error] Target URL is empty.")
            return
        query = self._query_edit.toPlainText().strip()
        if not query:
            self._response_edit.setPlainText("[Error] Query is empty.")
            return

        self._response_edit.setPlainText("Sending…")
        self._query_worker = QueryWorker(url, query)
        self._query_worker.result.connect(self._on_query_result)
        self._query_worker.error.connect(
            lambda msg: self._response_edit.setPlainText(f"[Error] {msg}")
        )
        self._query_worker.start()

    def _send_batch(self) -> None:
        url = self._url_edit.text().strip()
        if not url:
            return
        text = self._batch_edit.toPlainText()
        queries = [q for q in text.splitlines() if q.strip()]
        if not queries:
            return

        self._batch_results.clear()
        self._batch_worker = BatchWorker(url, queries)
        self._batch_worker.result.connect(self._on_batch_result)
        self._batch_worker.start()

    def _clear(self) -> None:
        self._schema_tree.clear()
        self._schema_lbl.setText("No schema loaded")
        self._query_edit.clear()
        self._response_edit.clear()
        self._batch_edit.clear()
        self._batch_results.clear()

    # ------------------------------------------------------------------
    # Worker callbacks
    # ------------------------------------------------------------------

    def _populate_schema(self, schema: dict) -> None:
        self._schema_tree.clear()
        types = schema.get("types", [])
        user_types = [t for t in types if not t["name"].startswith("__")]
        self._schema_lbl.setText(f"Schema loaded: {len(user_types)} types")
        for t in sorted(user_types, key=lambda x: x["name"]):
            parent = QTreeWidgetItem(self._schema_tree, [f"{t['name']} ({t['kind']})"])
            for field in t.get("fields") or []:
                field_type = field.get("type", {})
                type_name = field_type.get("name") or field_type.get("kind", "?")
                QTreeWidgetItem(parent, [f"{field['name']}: {type_name}"])

    def _on_introspection_error(self, msg: str) -> None:
        self._schema_lbl.setText(f"Error: {msg[:80]}")

    def _on_query_result(self, raw: str) -> None:
        try:
            parsed = json.loads(raw)
            pretty = json.dumps(parsed, indent=2)
            self._response_edit.setPlainText(pretty)
        except json.JSONDecodeError:
            self._response_edit.setPlainText(raw)

    def _on_batch_result(self, idx: int, status_line: str, length: int) -> None:
        item = QListWidgetItem(f"{status_line}  ({length} bytes)")
        self._batch_results.addItem(item)
