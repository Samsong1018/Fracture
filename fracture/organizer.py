"""
Organizer tab for Fracture.

A triage board for HTTP requests captured during testing.
Requests can be annotated with status (Untriaged / In Progress / Done)
and free-text notes to track testing progress.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .proxy import HttpRequest

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
_COMBO_SS = (
    "QComboBox { background: #181825; border: 1px solid #313244; "
    "padding: 4px; color: #cdd6f4; }"
    "QComboBox::drop-down { border: none; }"
    "QComboBox QAbstractItemView { background: #181825; color: #cdd6f4; "
    "selection-background-color: #45475a; }"
)

_STATUS_CYCLE = ["Untriaged", "In Progress", "Done"]
_STATUS_COLORS = {
    "Untriaged": "#f38ba8",
    "In Progress": "#fab387",
    "Done": "#a6e3a1",
}

_COL_STATUS = 0
_COL_METHOD = 1
_COL_HOST = 2
_COL_PATH = 3
_COL_NOTE = 4
_COL_ADDED = 5


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class OrganizerEntry:
    req: HttpRequest
    status: str = "Untriaged"
    note: str = ""
    added: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))


# ---------------------------------------------------------------------------
# OrganizerTab
# ---------------------------------------------------------------------------

class OrganizerTab(QWidget):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._entries: list[OrganizerEntry] = []
        self._setup_ui()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_request(self, req: HttpRequest) -> None:
        entry = OrganizerEntry(req=req)
        self._entries.append(entry)
        self._append_table_row(entry, len(self._entries) - 1)
        self._apply_filter()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(6)

        # Top bar
        top = QHBoxLayout()
        top.setSpacing(6)

        top.addWidget(QLabel("Status:"))
        self._status_combo = QComboBox()
        self._status_combo.setStyleSheet(_COMBO_SS)
        self._status_combo.addItems(["All", "Untriaged", "In Progress", "Done"])
        self._status_combo.currentTextChanged.connect(self._apply_filter)
        top.addWidget(self._status_combo)

        top.addWidget(QLabel("Search:"))
        self._search_edit = QLineEdit()
        self._search_edit.setStyleSheet(_LINEEDIT_SS)
        self._search_edit.setPlaceholderText("Filter by host/path/note...")
        self._search_edit.textChanged.connect(self._apply_filter)
        top.addWidget(self._search_edit, stretch=1)

        clear_done_btn = QPushButton("Clear Done")
        clear_done_btn.setStyleSheet(_BTN_SS)
        clear_done_btn.clicked.connect(self._clear_done)
        top.addWidget(clear_done_btn)

        root.addLayout(top)

        # Main table
        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels(["Status", "Method", "Host", "Path", "Note", "Added"])
        self._table.setStyleSheet(_TABLE_SS)
        self._table.setFont(QFont("Monospace", 9))
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self._table.verticalHeader().setVisible(False)
        self._table.cellDoubleClicked.connect(self._on_cell_double_clicked)
        self._table.currentCellChanged.connect(self._on_row_changed)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._context_menu)
        root.addWidget(self._table, stretch=1)

        # Notes area
        notes_row = QHBoxLayout()
        notes_row.addWidget(QLabel("Note:"))
        self._notes_edit = QTextEdit()
        self._notes_edit.setMaximumHeight(70)
        self._notes_edit.setStyleSheet(_TEXTEDIT_SS)
        notes_row.addWidget(self._notes_edit, stretch=1)
        save_note_btn = QPushButton("Save Note")
        save_note_btn.setStyleSheet(_BTN_SS)
        save_note_btn.clicked.connect(self._save_note)
        notes_row.addWidget(save_note_btn)
        root.addLayout(notes_row)

    # ------------------------------------------------------------------
    # Table helpers
    # ------------------------------------------------------------------

    def _append_table_row(self, entry: OrganizerEntry, entry_idx: int) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)
        self._populate_table_row(row, entry, entry_idx)

    def _populate_table_row(self, row: int, entry: OrganizerEntry, entry_idx: int) -> None:
        status_item = QTableWidgetItem(entry.status)
        color = _STATUS_COLORS.get(entry.status, _TEXT)
        status_item.setForeground(Qt.GlobalColor.white)
        status_item.setBackground(Qt.GlobalColor.transparent)
        status_item.setData(Qt.ItemDataRole.UserRole, entry_idx)

        from PyQt6.QtGui import QColor
        status_item.setForeground(QColor(color))

        self._table.setItem(row, _COL_STATUS, status_item)
        self._table.setItem(row, _COL_METHOD, QTableWidgetItem(entry.req.method))
        self._table.setItem(row, _COL_HOST, QTableWidgetItem(entry.req.host))
        self._table.setItem(row, _COL_PATH, QTableWidgetItem(entry.req.path))
        self._table.setItem(row, _COL_NOTE, QTableWidgetItem(entry.note))
        self._table.setItem(row, _COL_ADDED, QTableWidgetItem(entry.added))

    def _entry_idx_for_row(self, row: int) -> int:
        item = self._table.item(row, _COL_STATUS)
        if item is None:
            return -1
        return item.data(Qt.ItemDataRole.UserRole)

    def _rebuild_table(self) -> None:
        self._table.setRowCount(0)
        for idx, entry in enumerate(self._entries):
            self._append_table_row(entry, idx)
        self._apply_filter()

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    def _apply_filter(self) -> None:
        status_filter = self._status_combo.currentText()
        search_text = self._search_edit.text().lower()

        for row in range(self._table.rowCount()):
            entry_idx = self._entry_idx_for_row(row)
            if entry_idx < 0 or entry_idx >= len(self._entries):
                self._table.setRowHidden(row, True)
                continue

            entry = self._entries[entry_idx]
            status_match = status_filter == "All" or entry.status == status_filter
            search_str = f"{entry.req.host} {entry.req.path} {entry.note}".lower()
            text_match = not search_text or search_text in search_str
            self._table.setRowHidden(row, not (status_match and text_match))

    # ------------------------------------------------------------------
    # Interactions
    # ------------------------------------------------------------------

    def _on_cell_double_clicked(self, row: int, col: int) -> None:
        if col != _COL_STATUS:
            return
        entry_idx = self._entry_idx_for_row(row)
        if entry_idx < 0 or entry_idx >= len(self._entries):
            return
        entry = self._entries[entry_idx]
        current_idx = _STATUS_CYCLE.index(entry.status) if entry.status in _STATUS_CYCLE else 0
        next_status = _STATUS_CYCLE[(current_idx + 1) % len(_STATUS_CYCLE)]
        entry.status = next_status

        from PyQt6.QtGui import QColor
        item = self._table.item(row, _COL_STATUS)
        item.setText(next_status)
        item.setForeground(QColor(_STATUS_COLORS.get(next_status, _TEXT)))
        self._apply_filter()

    def _on_row_changed(self, current_row: int, _cc: int, _pr: int, _pc: int) -> None:
        if current_row < 0:
            self._notes_edit.clear()
            return
        entry_idx = self._entry_idx_for_row(current_row)
        if entry_idx < 0 or entry_idx >= len(self._entries):
            self._notes_edit.clear()
            return
        self._notes_edit.setPlainText(self._entries[entry_idx].note)

    def _save_note(self) -> None:
        row = self._table.currentRow()
        if row < 0:
            return
        entry_idx = self._entry_idx_for_row(row)
        if entry_idx < 0 or entry_idx >= len(self._entries):
            return
        note = self._notes_edit.toPlainText()
        self._entries[entry_idx].note = note
        self._table.item(row, _COL_NOTE).setText(note)

    def _clear_done(self) -> None:
        self._entries = [e for e in self._entries if e.status != "Done"]
        self._rebuild_table()

    # ------------------------------------------------------------------
    # Context menu
    # ------------------------------------------------------------------

    def _context_menu(self, pos) -> None:
        row = self._table.currentRow()
        if row < 0:
            return
        entry_idx = self._entry_idx_for_row(row)
        if entry_idx < 0 or entry_idx >= len(self._entries):
            return
        entry = self._entries[entry_idx]

        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu { background: #181825; color: #cdd6f4; border: 1px solid #313244; } "
            "QMenu::item:selected { background: #45475a; }"
        )
        menu.addAction("Copy as cURL", lambda: self._copy_as_curl(entry))
        menu.addAction("Remove", lambda: self._remove_entry(entry_idx))
        menu.exec(self._table.mapToGlobal(pos))

    def _copy_as_curl(self, entry: OrganizerEntry) -> None:
        req = entry.req
        scheme = "https" if req.is_https else "http"
        url = f"{scheme}://{req.host}{req.path}"
        parts = [f"curl -X {req.method}"]
        for k, v in req.headers.items():
            parts.append(f"-H {repr(k + ': ' + v)}")
        if req.body:
            try:
                body_str = req.body.decode(errors="replace")
                parts.append(f"--data {repr(body_str)}")
            except Exception:
                pass
        parts.append(repr(url))
        curl_cmd = " \\\n  ".join(parts)
        QApplication.clipboard().setText(curl_cmd)

    def _remove_entry(self, entry_idx: int) -> None:
        if entry_idx < 0 or entry_idx >= len(self._entries):
            return
        self._entries.pop(entry_idx)
        self._rebuild_table()
