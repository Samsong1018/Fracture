"""
Project notes panel — free-form engagement notebook.

Stores plain text that round-trips through the .cough project file.
"""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)


_TEXT_SS = (
    "QPlainTextEdit { background: #181825; border: 1px solid #313244; "
    "color: #cdd6f4; font-family: monospace; font-size: 12px; }"
)


class NotesTab(QWidget):
    """Free-form notes editor; persists through ProjectManager."""

    modified = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)

        header = QHBoxLayout()
        title = QLabel("Engagement notes")
        title.setStyleSheet("color: #89b4fa; font-weight: bold;")
        header.addWidget(title)
        header.addStretch()
        self._char_label = QLabel("0 chars")
        self._char_label.setStyleSheet("color: #a6adc8; font-size: 11px;")
        header.addWidget(self._char_label)
        root.addLayout(header)

        hint = QLabel(
            "Free-form scratchpad — saved with the project. "
            "Use it for engagement context, target intel, TODOs, etc."
        )
        hint.setStyleSheet("color: #a6adc8; font-size: 11px;")
        hint.setWordWrap(True)
        root.addWidget(hint)

        self._edit = QPlainTextEdit()
        self._edit.setStyleSheet(_TEXT_SS)
        self._edit.setPlaceholderText(
            "## Target\n"
            "https://app.example.com\n\n"
            "## Credentials\n"
            "alice / hunter2 (test account)\n\n"
            "## Findings so far\n"
            "- ..."
        )
        self._edit.textChanged.connect(self._on_changed)
        root.addWidget(self._edit, 1)

    def _on_changed(self) -> None:
        self._char_label.setText(f"{len(self._edit.toPlainText())} chars")
        self.modified.emit()

    def get_text(self) -> str:
        return self._edit.toPlainText()

    def set_text(self, text: str) -> None:
        self._edit.blockSignals(True)
        self._edit.setPlainText(text or "")
        self._edit.blockSignals(False)
        self._char_label.setText(f"{len(text or '')} chars")
