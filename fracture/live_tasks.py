"""
Live tasks panel — central registry of running workers.

A "task" here is anything with a long-running QThread: intruder attacks,
turbo intruder, spider, content discovery, sequencer, scanner.  The panel
polls each registered source for its worker thread and shows running state
with cancel buttons.
"""

from __future__ import annotations

from typing import Callable, Optional

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 2px 8px; border-radius: 3px; color: #cdd6f4; }"
    "QPushButton:hover { background: #45475a; }"
    "QPushButton:disabled { color: #585b70; }"
)
_TABLE_SS = (
    "QTableWidget { background: #181825; gridline-color: #313244; color: #cdd6f4; }"
    "QHeaderView::section { background: #313244; color: #cdd6f4; border: 0; padding: 4px; }"
)


class TaskSource:
    """Adapter describing how to read worker state from an owning tab."""

    def __init__(self, name: str, get_worker: Callable[[], object], focus: Callable[[], None]):
        self.name = name
        self.get_worker = get_worker
        self.focus = focus


class LiveTasksTab(QWidget):
    """Polls registered TaskSources and shows their state."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._sources: list[TaskSource] = []

        root = QVBoxLayout(self)
        header = QHBoxLayout()
        title = QLabel("Live tasks")
        title.setStyleSheet("color: #89b4fa; font-weight: bold;")
        header.addWidget(title)
        header.addStretch()
        refresh = QPushButton("Refresh")
        refresh.setStyleSheet(_BTN_SS)
        refresh.clicked.connect(self._refresh)
        header.addWidget(refresh)
        root.addLayout(header)

        hint = QLabel(
            "Snapshot of every long-running worker. Cancel stops the worker "
            "(if it supports stop). Focus jumps to that tool's tab."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #a6adc8; font-size: 11px;")
        root.addWidget(hint)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Task", "State", "Focus", "Cancel"])
        self._table.setStyleSheet(_TABLE_SS)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.setEditTriggers(self._table.EditTrigger.NoEditTriggers)
        root.addWidget(self._table, 1)

        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._refresh)
        self._timer.start()

    def register(self, source: TaskSource) -> None:
        self._sources.append(source)
        self._refresh()

    def _refresh(self) -> None:
        self._table.setRowCount(0)
        for src in self._sources:
            try:
                worker = src.get_worker()
            except Exception:
                worker = None
            state = "—"
            running = False
            try:
                if worker is not None and hasattr(worker, "isRunning"):
                    running = bool(worker.isRunning())
                    state = "running" if running else "idle"
            except Exception:
                state = "?"

            row = self._table.rowCount()
            self._table.insertRow(row)
            name_item = QTableWidgetItem(src.name)
            state_item = QTableWidgetItem(state)
            state_item.setForeground(QColor("#a6e3a1" if running else "#a6adc8"))
            self._table.setItem(row, 0, name_item)
            self._table.setItem(row, 1, state_item)

            focus_btn = QPushButton("Focus")
            focus_btn.setStyleSheet(_BTN_SS)
            focus_btn.clicked.connect(lambda _, s=src: s.focus())
            self._table.setCellWidget(row, 2, focus_btn)

            cancel_btn = QPushButton("Cancel")
            cancel_btn.setStyleSheet(_BTN_SS)
            cancel_btn.setEnabled(running and hasattr(worker, "stop"))
            cancel_btn.clicked.connect(lambda _, w=worker: self._stop_worker(w))
            self._table.setCellWidget(row, 3, cancel_btn)

    @staticmethod
    def _stop_worker(worker) -> None:
        if worker is None:
            return
        try:
            stop = getattr(worker, "stop", None)
            if callable(stop):
                stop()
        except Exception:
            pass
