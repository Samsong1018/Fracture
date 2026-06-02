"""
Logger++ — sortable, filterable in-app log of every proxied request.

Stream entries via `add_entry(req, resp)`; the table supports per-column
filters, a row detail view, and "Send to …" right-click actions.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .proxy import HttpRequest, HttpResponse


_TEXTEDIT_SS = (
    "QTextEdit { background: #181825; border: 1px solid #313244; "
    "color: #cdd6f4; font-family: monospace; font-size: 12px; }"
)
_LINEEDIT_SS = (
    "QLineEdit { background: #181825; border: 1px solid #313244; "
    "padding: 4px; color: #cdd6f4; }"
)
_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
    "QPushButton:hover { background: #45475a; }"
)
_TABLE_SS = (
    "QTableWidget { background: #181825; gridline-color: #313244; color: #cdd6f4; }"
    "QTableWidget::item:selected { background: #45475a; }"
    "QHeaderView::section { background: #313244; color: #cdd6f4; border: 0; padding: 4px; }"
)


_COLUMNS = ["#", "Time", "Host", "Method", "Path", "Status", "MIME", "Length"]


class LoggerTab(QWidget):
    """Sortable, filterable log of proxied traffic."""

    send_to_repeater = pyqtSignal(object)
    send_to_intruder = pyqtSignal(object)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._entries: list[tuple[HttpRequest, Optional[HttpResponse]]] = []
        self._presets: dict[str, dict[str, str]] = {}

        root = QVBoxLayout(self)

        # Filter row
        filter_row = QHBoxLayout()
        self._filters: dict[str, QLineEdit] = {}
        for col in ("Host", "Method", "Path", "Status", "MIME"):
            filter_row.addWidget(QLabel(f"{col}:"))
            e = QLineEdit()
            e.setStyleSheet(_LINEEDIT_SS)
            e.setPlaceholderText(f"filter {col.lower()}")
            e.setFixedWidth(120)
            e.textChanged.connect(self._apply_filters)
            self._filters[col] = e
            filter_row.addWidget(e)

        filter_row.addStretch()

        # Preset save/load
        filter_row.addWidget(QLabel("Preset:"))
        self._preset_combo = QComboBox()
        self._preset_combo.setMinimumWidth(120)
        self._preset_combo.currentTextChanged.connect(self._load_preset)
        filter_row.addWidget(self._preset_combo)

        save_btn = QPushButton("Save")
        save_btn.setStyleSheet(_BTN_SS)
        save_btn.clicked.connect(self._save_preset)
        filter_row.addWidget(save_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.setStyleSheet(_BTN_SS)
        clear_btn.clicked.connect(self._clear_filters)
        filter_row.addWidget(clear_btn)

        root.addLayout(filter_row)

        # Splitter: table + detail
        splitter = QSplitter(Qt.Orientation.Vertical)

        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.setSortingEnabled(True)
        self._table.setStyleSheet(_TABLE_SS)
        self._table.setSelectionBehavior(self._table.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(self._table.EditTrigger.NoEditTriggers)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._context_menu)
        self._table.itemSelectionChanged.connect(self._on_selection)

        header = self._table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)  # Path

        splitter.addWidget(self._table)

        # Detail
        detail = QSplitter(Qt.Orientation.Horizontal)
        self._req_view = QTextEdit()
        self._req_view.setReadOnly(True)
        self._req_view.setStyleSheet(_TEXTEDIT_SS)
        self._resp_view = QTextEdit()
        self._resp_view.setReadOnly(True)
        self._resp_view.setStyleSheet(_TEXTEDIT_SS)
        detail.addWidget(self._req_view)
        detail.addWidget(self._resp_view)
        splitter.addWidget(detail)
        splitter.setSizes([400, 220])

        root.addWidget(splitter, 1)

    # ------------------------------------------------------------------
    def add_entry(self, req: HttpRequest, resp: Optional[HttpResponse]) -> None:
        self._entries.append((req, resp))
        self._append_row(req, resp)

    def _append_row(self, req: HttpRequest, resp: Optional[HttpResponse]) -> None:
        self._table.setSortingEnabled(False)
        row = self._table.rowCount()
        self._table.insertRow(row)

        status = resp.status_code if resp else 0
        length = len(resp.body) if (resp and resp.body) else 0
        mime = ""
        if resp:
            for k, v in resp.headers.items():
                if k.lower() == "content-type":
                    mime = v.split(";")[0].strip()
                    break

        values = [
            req.id,
            req.timestamp.strftime("%H:%M:%S"),
            req.host,
            req.method,
            req.path,
            status,
            mime,
            length,
        ]
        for col, val in enumerate(values):
            if isinstance(val, int):
                item = QTableWidgetItem()
                item.setData(Qt.ItemDataRole.DisplayRole, val)
            else:
                item = QTableWidgetItem(str(val))
            if col == 5 and isinstance(val, int):
                # color status
                if 200 <= val < 300:
                    item.setForeground(QColor("#a6e3a1"))
                elif 300 <= val < 400:
                    item.setForeground(QColor("#89dceb"))
                elif 400 <= val < 500:
                    item.setForeground(QColor("#f9e2af"))
                elif val >= 500:
                    item.setForeground(QColor("#f38ba8"))
            self._table.setItem(row, col, item)
        self._table.setSortingEnabled(True)
        self._apply_row_visibility(row)

    # ------------------------------------------------------------------
    # Filters
    # ------------------------------------------------------------------
    def _apply_filters(self) -> None:
        for row in range(self._table.rowCount()):
            self._apply_row_visibility(row)

    def _apply_row_visibility(self, row: int) -> None:
        col_map = {"Host": 2, "Method": 3, "Path": 4, "Status": 5, "MIME": 6}
        visible = True
        for col_name, edit in self._filters.items():
            needle = edit.text().strip().lower()
            if not needle:
                continue
            item = self._table.item(row, col_map[col_name])
            hay = (item.text() if item else "").lower()
            if needle not in hay:
                visible = False
                break
        self._table.setRowHidden(row, not visible)

    def _clear_filters(self) -> None:
        for e in self._filters.values():
            e.clear()

    def _save_preset(self) -> None:
        from PyQt6.QtWidgets import QInputDialog
        name, ok = QInputDialog.getText(self, "Save preset", "Preset name:")
        if not ok or not name.strip():
            return
        snapshot = {col: e.text() for col, e in self._filters.items()}
        self._presets[name.strip()] = snapshot
        if self._preset_combo.findText(name.strip()) < 0:
            self._preset_combo.addItem(name.strip())
        self._preset_combo.setCurrentText(name.strip())

    def _load_preset(self, name: str) -> None:
        snap = self._presets.get(name)
        if not snap:
            return
        for col, e in self._filters.items():
            e.setText(snap.get(col, ""))

    # ------------------------------------------------------------------
    # Detail + context menu
    # ------------------------------------------------------------------
    def _selected_entry(self) -> Optional[tuple[HttpRequest, Optional[HttpResponse]]]:
        row = self._table.currentRow()
        if row < 0:
            return None
        item = self._table.item(row, 0)
        if item is None:
            return None
        try:
            rid = int(item.text())
        except ValueError:
            return None
        for req, resp in self._entries:
            if req.id == rid:
                return req, resp
        return None

    def _on_selection(self) -> None:
        sel = self._selected_entry()
        if sel is None:
            return
        req, resp = sel
        self._req_view.setPlainText(self._fmt_request(req))
        self._resp_view.setPlainText(self._fmt_response(resp))

    def _context_menu(self, pos) -> None:
        sel = self._selected_entry()
        if sel is None:
            return
        req, _ = sel
        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu { background: #181825; color: #cdd6f4; border: 1px solid #313244; }"
            "QMenu::item:selected { background: #45475a; }"
        )
        menu.addAction("Send to Repeater", lambda: self.send_to_repeater.emit(req))
        menu.addAction("Send to Intruder", lambda: self.send_to_intruder.emit(req))
        menu.exec(self._table.mapToGlobal(pos))

    @staticmethod
    def _fmt_request(req: HttpRequest) -> str:
        lines = [f"{req.method} {req.path} HTTP/{req.version}"]
        for k, v in req.headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        if req.body:
            lines.append(req.body.decode("utf-8", errors="replace"))
        return "\n".join(lines)

    @staticmethod
    def _fmt_response(resp: Optional[HttpResponse]) -> str:
        if resp is None:
            return "(no response)"
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
