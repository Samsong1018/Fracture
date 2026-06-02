"""
Site Map tab for Fracture.

Displays a tree of all hosts and URL paths observed in proxy history,
built automatically as traffic flows through. Clicking a node shows
all requests to that endpoint.
"""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSplitter,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .proxy import HttpRequest, HttpResponse

# ---------------------------------------------------------------------------
# Catppuccin Mocha palette constants
# ---------------------------------------------------------------------------
_BG = "#1e1e2e"
_SURFACE = "#181825"
_OVERLAY = "#313244"
_HIGHLIGHT = "#45475a"
_TEXT = "#cdd6f4"
_SUBTEXT = "#a6adc8"
_ACCENT = "#89b4fa"

_TREE_STYLE = f"""
QTreeWidget {{
    background: {_SURFACE};
    border: 1px solid {_OVERLAY};
    color: {_TEXT};
    font-family: monospace;
    font-size: 13px;
}}
QTreeWidget::item:selected {{
    background: {_HIGHLIGHT};
}}
QTreeWidget::branch {{
    background: {_SURFACE};
}}
QTreeWidget::item:hover {{
    background: {_OVERLAY};
}}
QHeaderView::section {{
    background: {_OVERLAY};
    color: {_TEXT};
    border: none;
    padding: 4px;
}}
"""

_LIST_STYLE = f"""
QListWidget {{
    background: {_SURFACE};
    border: 1px solid {_OVERLAY};
    color: {_TEXT};
    font-family: monospace;
    font-size: 12px;
}}
QListWidget::item:selected {{
    background: {_HIGHLIGHT};
}}
QListWidget::item:hover {{
    background: {_OVERLAY};
}}
"""

_TEXTEDIT_STYLE = f"""
QTextEdit {{
    background: {_SURFACE};
    border: 1px solid {_OVERLAY};
    color: {_TEXT};
    font-family: monospace;
    font-size: 12px;
}}
"""

_LINE_STYLE = f"""
QLineEdit {{
    background: {_SURFACE};
    border: 1px solid {_OVERLAY};
    color: {_TEXT};
    font-family: monospace;
    font-size: 12px;
    padding: 4px 6px;
    border-radius: 3px;
}}
QLineEdit:focus {{
    border: 1px solid {_ACCENT};
}}
"""

_BTN_STYLE = f"""
QPushButton {{
    background: {_OVERLAY};
    color: {_TEXT};
    border: 1px solid {_HIGHLIGHT};
    padding: 4px 12px;
    border-radius: 3px;
    font-size: 12px;
}}
QPushButton:hover {{
    background: {_HIGHLIGHT};
}}
QPushButton:pressed {{
    background: {_BG};
}}
"""

_LABEL_STYLE = f"color: {_SUBTEXT}; font-size: 11px; font-family: monospace;"


# ---------------------------------------------------------------------------
# Helper – format a raw HTTP request/response pair for the detail panel
# ---------------------------------------------------------------------------

def _format_request(req: HttpRequest) -> str:
    scheme = "https" if req.is_https else "http"
    lines = [f"{req.method} {req.path} HTTP/{req.version}"]
    for k, v in req.headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if req.body:
        try:
            lines.append(req.body.decode("utf-8", errors="replace"))
        except Exception:
            lines.append(f"<binary {len(req.body)} bytes>")
    return "\n".join(lines)


def _format_response(resp: Optional[HttpResponse]) -> str:
    if resp is None:
        return "(no response captured)"
    lines = [f"HTTP/1.1 {resp.status_code} {resp.status_text}"]
    for k, v in resp.headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if resp.body:
        try:
            lines.append(resp.body.decode("utf-8", errors="replace"))
        except Exception:
            lines.append(f"<binary {len(resp.body)} bytes>")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# SiteMapTab
# ---------------------------------------------------------------------------

class SiteMapTab(QWidget):
    """
    Site Map tab.

    Internal data structure:
        _tree_data: dict[host, dict[path, list[tuple[HttpRequest, HttpResponse|None]]]]
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)

        # host -> path -> [(req, resp), ...]
        self._tree_data: dict[str, dict[str, list[tuple[HttpRequest, Optional[HttpResponse]]]]] = {}

        # QTreeWidgetItem cache: (host, path) -> QTreeWidgetItem
        self._item_map: dict[tuple[str, str], QTreeWidgetItem] = {}
        # host -> top-level QTreeWidgetItem
        self._host_items: dict[str, QTreeWidgetItem] = {}

        self._build_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        self.setStyleSheet(f"background: {_BG}; color: {_TEXT};")

        # ---- top toolbar ----
        toolbar = QWidget()
        toolbar.setStyleSheet(f"background: {_BG};")
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(8, 6, 8, 6)
        tb_layout.setSpacing(8)

        filter_label = QLabel("Filter:")
        filter_label.setStyleSheet(_LABEL_STYLE)
        tb_layout.addWidget(filter_label)

        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("Search hosts / paths…")
        self._filter_edit.setStyleSheet(_LINE_STYLE)
        self._filter_edit.textChanged.connect(self._apply_filter)
        tb_layout.addWidget(self._filter_edit, stretch=1)

        clear_btn = QPushButton("Clear")
        clear_btn.setStyleSheet(_BTN_STYLE)
        clear_btn.clicked.connect(self._clear)
        tb_layout.addWidget(clear_btn)

        root_layout.addWidget(toolbar)

        # ---- main horizontal splitter (tree | right panel) ----
        h_splitter = QSplitter(Qt.Orientation.Horizontal)
        h_splitter.setStyleSheet(f"QSplitter::handle {{ background: {_OVERLAY}; }}")
        root_layout.addWidget(h_splitter, stretch=1)

        # ---- left: tree ----
        self._tree = QTreeWidget()
        self._tree.setHeaderLabel("Site Map")
        self._tree.setStyleSheet(_TREE_STYLE)
        self._tree.itemSelectionChanged.connect(self._on_tree_selection)
        h_splitter.addWidget(self._tree)

        # ---- right: vertical splitter (list | detail) ----
        v_splitter = QSplitter(Qt.Orientation.Vertical)
        v_splitter.setStyleSheet(f"QSplitter::handle {{ background: {_OVERLAY}; }}")
        h_splitter.addWidget(v_splitter)

        # request list
        list_container = QWidget()
        list_container.setStyleSheet(f"background: {_BG};")
        lc_layout = QVBoxLayout(list_container)
        lc_layout.setContentsMargins(0, 0, 0, 0)
        lc_layout.setSpacing(0)

        list_label = QLabel("Requests")
        list_label.setStyleSheet(
            f"color: {_SUBTEXT}; font-size: 11px; font-family: monospace;"
            f" padding: 4px 8px; background: {_OVERLAY};"
        )
        lc_layout.addWidget(list_label)

        self._req_list = QListWidget()
        self._req_list.setStyleSheet(_LIST_STYLE)
        self._req_list.currentRowChanged.connect(self._on_list_selection)
        lc_layout.addWidget(self._req_list, stretch=1)
        v_splitter.addWidget(list_container)

        # detail panel
        detail_container = QWidget()
        detail_container.setStyleSheet(f"background: {_BG};")
        dc_layout = QVBoxLayout(detail_container)
        dc_layout.setContentsMargins(0, 0, 0, 0)
        dc_layout.setSpacing(0)

        detail_h = QSplitter(Qt.Orientation.Horizontal)
        detail_h.setStyleSheet(f"QSplitter::handle {{ background: {_OVERLAY}; }}")

        req_panel = QWidget()
        req_panel.setStyleSheet(f"background: {_BG};")
        rp_layout = QVBoxLayout(req_panel)
        rp_layout.setContentsMargins(0, 0, 0, 0)
        rp_layout.setSpacing(0)
        req_label = QLabel("Request")
        req_label.setStyleSheet(
            f"color: {_SUBTEXT}; font-size: 11px; font-family: monospace;"
            f" padding: 4px 8px; background: {_OVERLAY};"
        )
        rp_layout.addWidget(req_label)
        self._req_detail = QTextEdit()
        self._req_detail.setReadOnly(True)
        self._req_detail.setStyleSheet(_TEXTEDIT_STYLE)
        rp_layout.addWidget(self._req_detail, stretch=1)
        detail_h.addWidget(req_panel)

        resp_panel = QWidget()
        resp_panel.setStyleSheet(f"background: {_BG};")
        resp_layout = QVBoxLayout(resp_panel)
        resp_layout.setContentsMargins(0, 0, 0, 0)
        resp_layout.setSpacing(0)
        resp_label = QLabel("Response")
        resp_label.setStyleSheet(
            f"color: {_SUBTEXT}; font-size: 11px; font-family: monospace;"
            f" padding: 4px 8px; background: {_OVERLAY};"
        )
        resp_layout.addWidget(resp_label)
        self._resp_detail = QTextEdit()
        self._resp_detail.setReadOnly(True)
        self._resp_detail.setStyleSheet(_TEXTEDIT_STYLE)
        resp_layout.addWidget(self._resp_detail, stretch=1)
        detail_h.addWidget(resp_panel)

        dc_layout.addWidget(detail_h, stretch=1)
        v_splitter.addWidget(detail_container)

        # proportions
        h_splitter.setSizes([280, 720])
        v_splitter.setSizes([300, 200])

        # current selection state
        self._current_pairs: list[tuple[HttpRequest, Optional[HttpResponse]]] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_entry(self, req: HttpRequest, resp: Optional[HttpResponse]) -> None:
        """Called from gui.py after each proxy history entry."""
        host = req.host
        path = req.path or "/"

        # Update internal data model
        if host not in self._tree_data:
            self._tree_data[host] = {}
        if path not in self._tree_data[host]:
            self._tree_data[host][path] = []
        self._tree_data[host][path].append((req, resp))

        # Update the tree widget
        self._ensure_tree_node(host, path, req, resp)

    # ------------------------------------------------------------------
    # Tree node management
    # ------------------------------------------------------------------

    def _ensure_tree_node(
        self,
        host: str,
        path: str,
        req: HttpRequest,
        resp: Optional[HttpResponse],
    ) -> None:
        """Insert or update the tree node for (host, path)."""
        # Ensure host top-level item
        if host not in self._host_items:
            host_item = QTreeWidgetItem(self._tree, [host])
            host_item.setData(0, Qt.ItemDataRole.UserRole, (host, None))
            host_item.setForeground(0, self._color(_ACCENT))
            self._host_items[host] = host_item
            self._tree.addTopLevelItem(host_item)

        host_item = self._host_items[host]

        # Walk path segments and build intermediate nodes
        segments = [s for s in path.split("/") if s]  # strip empty strings
        # Always treat the empty path as "/"
        if not segments:
            segments = [""]

        parent_item = host_item
        accumulated = ""
        for i, seg in enumerate(segments):
            accumulated = accumulated + "/" + seg if seg else "/"
            node_key = (host, accumulated)

            if node_key not in self._item_map:
                node_item = QTreeWidgetItem(parent_item, [f"/{seg}" if seg else "/"])
                node_item.setData(0, Qt.ItemDataRole.UserRole, node_key)
                node_item.setForeground(0, self._color(_TEXT))
                self._item_map[node_key] = node_item
                parent_item.addChild(node_item)
                parent_item.setExpanded(True)
            else:
                node_item = self._item_map[node_key]

            parent_item = node_item

        # Update the leaf label with latest method + status
        leaf_key = (host, path)
        if leaf_key in self._item_map:
            leaf = self._item_map[leaf_key]
            status = resp.status_code if resp else "?"
            leaf.setText(0, f"{_last_segment(path)}  [{req.method} {status}]")
            leaf.setForeground(0, self._color(_TEXT))

        # Apply current filter to newly added items
        filter_text = self._filter_edit.text().strip().lower()
        if filter_text:
            self._apply_filter(filter_text)

    @staticmethod
    def _color(hex_color: str):
        from PyQt6.QtGui import QColor
        return QColor(hex_color)

    # ------------------------------------------------------------------
    # Filter
    # ------------------------------------------------------------------

    def _apply_filter(self, text: str) -> None:
        text = text.strip().lower()
        for i in range(self._tree.topLevelItemCount()):
            host_item = self._tree.topLevelItem(i)
            host_text = host_item.text(0).lower()
            host_visible = not text or text in host_text
            any_child_visible = self._filter_children(host_item, text)
            host_item.setHidden(not (host_visible or any_child_visible))

    def _filter_children(self, parent: QTreeWidgetItem, text: str) -> bool:
        any_visible = False
        for i in range(parent.childCount()):
            child = parent.child(i)
            child_text = child.text(0).lower()
            child_visible = not text or text in child_text
            sub_visible = self._filter_children(child, text)
            visible = child_visible or sub_visible
            child.setHidden(not visible)
            if visible:
                any_visible = True
        return any_visible

    # ------------------------------------------------------------------
    # Clear
    # ------------------------------------------------------------------

    def _clear(self) -> None:
        self._tree_data.clear()
        self._item_map.clear()
        self._host_items.clear()
        self._tree.clear()
        self._req_list.clear()
        self._req_detail.clear()
        self._resp_detail.clear()
        self._current_pairs = []

    # ------------------------------------------------------------------
    # Selection handlers
    # ------------------------------------------------------------------

    def _on_tree_selection(self) -> None:
        selected = self._tree.selectedItems()
        if not selected:
            return

        item = selected[0]
        user_data = item.data(0, Qt.ItemDataRole.UserRole)
        if user_data is None:
            return

        host, path = user_data  # path is None for host-level items

        if path is None:
            # Host node selected — aggregate all paths under this host
            pairs: list[tuple[HttpRequest, Optional[HttpResponse]]] = []
            for path_pairs in self._tree_data.get(host, {}).values():
                pairs.extend(path_pairs)
        else:
            pairs = list(self._tree_data.get(host, {}).get(path, []))

        self._current_pairs = pairs
        self._populate_list(pairs)

    def _populate_list(
        self, pairs: list[tuple[HttpRequest, Optional[HttpResponse]]]
    ) -> None:
        self._req_list.clear()
        self._req_detail.clear()
        self._resp_detail.clear()

        for req, resp in pairs:
            status = resp.status_code if resp else "?"
            ts = req.timestamp.strftime("%H:%M:%S") if req.timestamp else ""
            label = f"[{status}] {req.method} {req.path} — {ts}"
            self._req_list.addItem(label)

    def _on_list_selection(self, row: int) -> None:
        if row < 0 or row >= len(self._current_pairs):
            return
        req, resp = self._current_pairs[row]
        self._req_detail.setPlainText(_format_request(req))
        self._resp_detail.setPlainText(_format_response(resp))


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _last_segment(path: str) -> str:
    """Return the last non-empty path segment (for leaf display)."""
    parts = [p for p in path.split("/") if p]
    return f"/{parts[-1]}" if parts else "/"
