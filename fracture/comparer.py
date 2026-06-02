"""
Fracture Comparer tab — visual byte/word-level diff between two texts.
Mirrors Burp Suite's Comparer functionality.
"""

import difflib
import json

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QButtonGroup,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

_MONO = QFont("Monospace", 9)

_STYLE = """
    QWidget {
        background: #1e1e2e;
        color: #cdd6f4;
    }
    QTextEdit {
        background: #181825;
        border: 1px solid #313244;
        color: #cdd6f4;
    }
    QPushButton {
        background: #313244;
        border: 1px solid #45475a;
        padding: 4px 10px;
        border-radius: 4px;
        color: #cdd6f4;
    }
    QPushButton:hover {
        background: #45475a;
    }
    QPushButton:checked {
        background: #45475a;
        border: 1px solid #89b4fa;
    }
    QLabel {
        color: #cdd6f4;
        background: transparent;
    }
"""

# Catppuccin Mocha diff colours
_COLOR_DELETED = QColor("#f38ba8")   # red  — only in left
_COLOR_INSERTED = QColor("#a6e3a1")  # green — only in right
_COLOR_TEXT_ON_DIFF = QColor("#1e1e2e")  # dark text on coloured backgrounds


def _fmt(bg: QColor | None = None) -> QTextCharFormat:
    """Return a QTextCharFormat with the given background (or none)."""
    fmt = QTextCharFormat()
    if bg is not None:
        fmt.setBackground(bg)
        fmt.setForeground(_COLOR_TEXT_ON_DIFF)
    return fmt


def _fmt_value(v) -> str:
    s = json.dumps(v, ensure_ascii=False)
    return s if len(s) <= 120 else s[:117] + "…"


def _walk_json(path: str, a, b, out: list[tuple[str, str, str]]) -> None:
    """Recursively diff two JSON-decoded values; append findings to *out*."""
    if type(a) is not type(b) and not (a is None or b is None):
        out.append(("type", path, f"{type(a).__name__} → {type(b).__name__}  "
                                  f"({_fmt_value(a)} vs {_fmt_value(b)})"))
        return
    if isinstance(a, dict) and isinstance(b, dict):
        keys_a = set(a.keys())
        keys_b = set(b.keys())
        for k in sorted(keys_a - keys_b):
            out.append(("removed", f"{path}.{k}", _fmt_value(a[k])))
        for k in sorted(keys_b - keys_a):
            out.append(("added", f"{path}.{k}", _fmt_value(b[k])))
        for k in sorted(keys_a & keys_b):
            _walk_json(f"{path}.{k}", a[k], b[k], out)
        return
    if isinstance(a, list) and isinstance(b, list):
        for i in range(min(len(a), len(b))):
            _walk_json(f"{path}[{i}]", a[i], b[i], out)
        for i in range(len(b), len(a)):
            out.append(("removed", f"{path}[{i}]", _fmt_value(a[i])))
        for i in range(len(a), len(b)):
            out.append(("added", f"{path}[{i}]", _fmt_value(b[i])))
        return
    if a != b:
        out.append(("changed", path, f"{_fmt_value(a)} → {_fmt_value(b)}"))


# ---------------------------------------------------------------------------
# ComparerTab widget
# ---------------------------------------------------------------------------


class ComparerTab(QWidget):
    """Side-by-side visual diff viewer (words or bytes/characters)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setStyleSheet(_STYLE)
        self._setup_ui()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_left(self, text: str) -> None:
        """Load *text* into the left input panel."""
        self._left.setPlainText(text)

    def load_right(self, text: str) -> None:
        """Load *text* into the right input panel."""
        self._right.setPlainText(text)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        # ---- Input panels (side by side) ----
        input_row = QHBoxLayout()
        input_row.setSpacing(8)

        left_col = QVBoxLayout()
        left_col.setSpacing(4)
        left_label = QLabel("Item 1")
        left_label.setStyleSheet("font-weight: bold; color: #89b4fa;")
        left_col.addWidget(left_label)
        self._left = QTextEdit()
        self._left.setFont(_MONO)
        self._left.setPlaceholderText("Paste or type the first item here…")
        left_col.addWidget(self._left)

        right_col = QVBoxLayout()
        right_col.setSpacing(4)
        right_label = QLabel("Item 2")
        right_label.setStyleSheet("font-weight: bold; color: #89b4fa;")
        right_col.addWidget(right_label)
        self._right = QTextEdit()
        self._right.setFont(_MONO)
        self._right.setPlaceholderText("Paste or type the second item here…")
        right_col.addWidget(self._right)

        input_row.addLayout(left_col)
        input_row.addLayout(right_col)
        root.addLayout(input_row, stretch=3)

        # ---- Control row ----
        ctrl_row = QHBoxLayout()
        ctrl_row.setSpacing(6)

        # Mode toggles (checkable, exclusive): Words / Lines / Bytes / JSON
        self._words_btn = QPushButton("Words")
        self._words_btn.setCheckable(True)
        self._words_btn.setChecked(True)

        self._lines_btn = QPushButton("Lines")
        self._lines_btn.setCheckable(True)

        self._bytes_btn = QPushButton("Bytes")
        self._bytes_btn.setCheckable(True)

        self._json_btn = QPushButton("JSON")
        self._json_btn.setCheckable(True)
        self._json_btn.setToolTip("Semantic JSON diff (key order ignored, type changes flagged)")

        self._mode_group = QButtonGroup(self)
        self._mode_group.setExclusive(True)
        for btn in (self._words_btn, self._lines_btn, self._bytes_btn, self._json_btn):
            self._mode_group.addButton(btn)
            ctrl_row.addWidget(btn)

        ctrl_row.addSpacing(10)

        compare_btn = QPushButton("Compare")
        compare_btn.setStyleSheet(
            "QPushButton { background: #89b4fa; color: #1e1e2e; font-weight: bold; }"
            "QPushButton:hover { background: #b4befe; }"
        )
        compare_btn.clicked.connect(self._run_compare)
        ctrl_row.addWidget(compare_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self._clear)
        ctrl_row.addWidget(clear_btn)

        ctrl_row.addSpacing(10)

        self._stats_label = QLabel("")
        self._stats_label.setStyleSheet("color: #a6adc8; font-size: 11px;")
        ctrl_row.addWidget(self._stats_label)

        ctrl_row.addStretch()
        root.addLayout(ctrl_row)

        # ---- Diff view ----
        diff_label = QLabel("Diff")
        diff_label.setStyleSheet("font-weight: bold; color: #89b4fa;")
        root.addWidget(diff_label)

        self._diff_view = QTextEdit()
        self._diff_view.setFont(_MONO)
        self._diff_view.setReadOnly(True)
        self._diff_view.setPlaceholderText(
            "Click Compare to see the diff here…"
        )
        root.addWidget(self._diff_view, stretch=4)

    # ------------------------------------------------------------------
    # Diff logic
    # ------------------------------------------------------------------

    def _tokenise(self, text: str) -> list[str]:
        """Split *text* into a sequence of tokens for diffing."""
        if self._lines_btn.isChecked():
            return text.splitlines(keepends=True)
        if self._words_btn.isChecked():
            tokens: list[str] = []
            current = ""
            for ch in text:
                if ch in " \t\n\r":
                    if current:
                        tokens.append(current)
                        current = ""
                    tokens.append(ch)
                else:
                    current += ch
            if current:
                tokens.append(current)
            return tokens
        # Bytes mode (also fallback)
        return list(text)

    def _run_compare(self) -> None:
        left_text = self._left.toPlainText()
        right_text = self._right.toPlainText()

        if self._json_btn.isChecked():
            self._run_json_compare(left_text, right_text)
            return

        seq_a = self._tokenise(left_text)
        seq_b = self._tokenise(right_text)

        matcher = difflib.SequenceMatcher(None, seq_a, seq_b, autojunk=False)
        opcodes = matcher.get_opcodes()

        # Render into the diff view
        self._diff_view.clear()
        cursor = self._diff_view.textCursor()

        fmt_equal = _fmt()                  # no highlight
        fmt_deleted = _fmt(_COLOR_DELETED)  # red
        fmt_inserted = _fmt(_COLOR_INSERTED)  # green

        for tag, i1, i2, j1, j2 in opcodes:
            if tag == "equal":
                cursor.insertText("".join(seq_a[i1:i2]), fmt_equal)
            elif tag == "delete":
                cursor.insertText("".join(seq_a[i1:i2]), fmt_deleted)
            elif tag == "insert":
                cursor.insertText("".join(seq_b[j1:j2]), fmt_inserted)
            elif tag == "replace":
                # Show deleted part first (red), then inserted part (green)
                cursor.insertText("".join(seq_a[i1:i2]), fmt_deleted)
                cursor.insertText("".join(seq_b[j1:j2]), fmt_inserted)

        # Scroll to top after rendering
        self._diff_view.moveCursor(QTextCursor.MoveOperation.Start)

        # Update stats
        self._update_stats(left_text, right_text, opcodes, seq_a, seq_b)

    def _update_stats(
        self,
        left_text: str,
        right_text: str,
        opcodes: list[tuple[str, int, int, int, int]],
        seq_a: list[str],
        seq_b: list[str],
    ) -> None:
        left_bytes = len(left_text.encode("utf-8"))
        right_bytes = len(right_text.encode("utf-8"))

        # Count changed characters (raw chars, not tokens)
        changed = 0
        for tag, i1, i2, j1, j2 in opcodes:
            if tag != "equal":
                changed += len("".join(seq_a[i1:i2]).encode("utf-8"))
                changed += len("".join(seq_b[j1:j2]).encode("utf-8"))

        self._stats_label.setText(
            f"{left_bytes} bytes in left   {right_bytes} bytes in right   "
            f"{changed} bytes different"
        )

    # ------------------------------------------------------------------
    # Clear
    # ------------------------------------------------------------------

    def _clear(self) -> None:
        """Reset all panels and stats."""
        self._left.clear()
        self._right.clear()
        self._diff_view.clear()
        self._stats_label.setText("")

    # ------------------------------------------------------------------
    # Semantic JSON diff
    # ------------------------------------------------------------------

    def _run_json_compare(self, left_text: str, right_text: str) -> None:
        try:
            a = json.loads(left_text) if left_text.strip() else None
            b = json.loads(right_text) if right_text.strip() else None
        except json.JSONDecodeError as e:
            self._diff_view.setPlainText(f"JSON parse error: {e}")
            self._stats_label.setText("")
            return

        diffs: list[tuple[str, str, str]] = []  # (kind, path, detail)
        _walk_json("$", a, b, diffs)

        self._diff_view.clear()
        cursor = self._diff_view.textCursor()
        fmt_del = _fmt(_COLOR_DELETED)
        fmt_ins = _fmt(_COLOR_INSERTED)
        fmt_change = _fmt(QColor("#f9e2af"))  # yellow for type/value changes
        fmt_equal = _fmt()

        if not diffs:
            cursor.insertText("(both documents are semantically equal)\n", fmt_equal)
            self._stats_label.setText("0 differences")
            return

        kind_count = {"removed": 0, "added": 0, "changed": 0, "type": 0}
        for kind, path, detail in diffs:
            if kind == "removed":
                cursor.insertText(f"− {path}: {detail}\n", fmt_del)
            elif kind == "added":
                cursor.insertText(f"+ {path}: {detail}\n", fmt_ins)
            elif kind == "type":
                cursor.insertText(f"≠ {path}: {detail}\n", fmt_change)
            else:
                cursor.insertText(f"~ {path}: {detail}\n", fmt_change)
            kind_count[kind if kind in kind_count else "changed"] += 1

        self._stats_label.setText(
            f"{kind_count['removed']} removed   "
            f"{kind_count['added']} added   "
            f"{kind_count['changed']} changed   "
            f"{kind_count['type']} type changes"
        )
