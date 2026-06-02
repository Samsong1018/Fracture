"""
Editor extensions used by Repeater: syntax highlighter, find/replace bar,
and a body auto-formatter for JSON / XML / HTML.
"""

from __future__ import annotations

import json
import re
import xml.dom.minidom
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtGui import (
    QColor,
    QKeySequence,
    QShortcut,
    QSyntaxHighlighter,
    QTextCharFormat,
    QTextCursor,
    QTextDocument,
    QFont,
)
from PyQt6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


# Catppuccin Mocha palette
_HEADER_NAME = "#89b4fa"   # blue
_HEADER_VAL  = "#cdd6f4"   # text
_METHOD      = "#f9e2af"   # yellow
_PATH        = "#a6e3a1"   # green
_STRING      = "#a6e3a1"   # green
_NUMBER      = "#fab387"   # peach
_KEYWORD     = "#cba6f7"   # mauve
_BRACKET     = "#f5c2e7"   # pink
_TAG         = "#89b4fa"   # blue
_ATTR        = "#fab387"   # peach
_COMMENT     = "#585b70"   # subtle


def _fmt(color: str, bold: bool = False) -> QTextCharFormat:
    f = QTextCharFormat()
    f.setForeground(QColor(color))
    if bold:
        f.setFontWeight(QFont.Weight.Bold)
    return f


class HttpSyntaxHighlighter(QSyntaxHighlighter):
    """Highlights HTTP request and JSON/XML/HTML bodies inline."""

    def __init__(self, document: QTextDocument) -> None:
        super().__init__(document)

        # Detection: lines before the first blank line are headers; after, body.
        self._header_re = re.compile(r"^([A-Za-z0-9\-]+):\s*(.*)$")
        self._request_line_re = re.compile(
            r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+(HTTP/\S+)$"
        )

        # Body patterns
        self._json_string_re = re.compile(r'"(?:[^"\\]|\\.)*"')
        self._json_number_re = re.compile(r'\b-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b')
        self._json_keyword_re = re.compile(r'\b(?:true|false|null)\b')
        self._json_punct_re = re.compile(r'[{}\[\]]')

        self._xml_tag_re = re.compile(r"</?([A-Za-z][\w:-]*)([^>]*?)/?>")
        self._xml_attr_re = re.compile(r'([\w:-]+)\s*=\s*(".*?"|\'.*?\')')
        self._xml_comment_re = re.compile(r"<!--.*?-->", re.DOTALL)

    # Use block state: 0 = headers, 1 = body
    def highlightBlock(self, text: str) -> None:
        prev_state = self.previousBlockState()
        if prev_state < 0:
            prev_state = 0

        if prev_state == 0:
            # Still in header region
            if text.strip() == "":
                # Blank line — body starts on the *next* block
                self.setCurrentBlockState(1)
                return
            self.setCurrentBlockState(0)
            self._highlight_header_line(text)
        else:
            self.setCurrentBlockState(1)
            self._highlight_body_line(text)

    def _highlight_header_line(self, text: str) -> None:
        m = self._request_line_re.match(text)
        if m:
            self.setFormat(m.start(1), m.end(1) - m.start(1), _fmt(_METHOD, bold=True))
            self.setFormat(m.start(2), m.end(2) - m.start(2), _fmt(_PATH))
            self.setFormat(m.start(3), m.end(3) - m.start(3), _fmt(_COMMENT))
            return
        m = self._header_re.match(text)
        if m:
            self.setFormat(m.start(1), m.end(1) - m.start(1), _fmt(_HEADER_NAME, bold=True))
            self.setFormat(m.start(2), m.end(2) - m.start(2), _fmt(_HEADER_VAL))

    def _highlight_body_line(self, text: str) -> None:
        # JSON-ish: highlight whether or not the doc is fully valid
        for m in self._json_string_re.finditer(text):
            self.setFormat(m.start(), m.end() - m.start(), _fmt(_STRING))
        for m in self._json_number_re.finditer(text):
            self.setFormat(m.start(), m.end() - m.start(), _fmt(_NUMBER))
        for m in self._json_keyword_re.finditer(text):
            self.setFormat(m.start(), m.end() - m.start(), _fmt(_KEYWORD))
        for m in self._json_punct_re.finditer(text):
            self.setFormat(m.start(), m.end() - m.start(), _fmt(_BRACKET))

        # XML/HTML tags: layer on top so they win for tag spans
        for m in self._xml_comment_re.finditer(text):
            self.setFormat(m.start(), m.end() - m.start(), _fmt(_COMMENT))
        for m in self._xml_tag_re.finditer(text):
            self.setFormat(m.start(), m.end() - m.start(), _fmt(_TAG))
            attrs = m.group(2) or ""
            base = m.start(2)
            for am in self._xml_attr_re.finditer(attrs):
                self.setFormat(base + am.start(1), am.end(1) - am.start(1), _fmt(_ATTR))
                self.setFormat(base + am.start(2), am.end(2) - am.start(2), _fmt(_STRING))


# ---------------------------------------------------------------------------
# Find / replace bar
# ---------------------------------------------------------------------------

_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 2px 8px; border-radius: 3px; color: #cdd6f4; }"
    "QPushButton:hover { background: #45475a; }"
)
_LINEEDIT_SS = (
    "QLineEdit { background: #181825; border: 1px solid #313244; "
    "padding: 2px 4px; color: #cdd6f4; }"
)


class FindReplaceBar(QWidget):
    """Slim Ctrl+F / Ctrl+H bar that attaches to a QTextEdit."""

    def __init__(self, editor: QTextEdit, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._editor = editor

        row1 = QHBoxLayout()
        row1.setContentsMargins(2, 2, 2, 2)
        row1.setSpacing(4)
        row1.addWidget(QLabel("Find:"))
        self.find_edit = QLineEdit()
        self.find_edit.setStyleSheet(_LINEEDIT_SS)
        self.find_edit.returnPressed.connect(self.find_next)
        row1.addWidget(self.find_edit, 1)

        next_btn = QPushButton("Next")
        next_btn.setStyleSheet(_BTN_SS)
        next_btn.clicked.connect(self.find_next)
        row1.addWidget(next_btn)

        prev_btn = QPushButton("Prev")
        prev_btn.setStyleSheet(_BTN_SS)
        prev_btn.clicked.connect(self.find_prev)
        row1.addWidget(prev_btn)

        self.case_check = QCheckBox("Aa")
        self.case_check.setStyleSheet("color: #cdd6f4;")
        self.case_check.setToolTip("Match case")
        row1.addWidget(self.case_check)

        self.regex_check = QCheckBox(".*")
        self.regex_check.setStyleSheet("color: #cdd6f4;")
        self.regex_check.setToolTip("Regex")
        row1.addWidget(self.regex_check)

        close_btn = QPushButton("✕")
        close_btn.setStyleSheet(_BTN_SS)
        close_btn.clicked.connect(self.hide)
        row1.addWidget(close_btn)

        row2 = QHBoxLayout()
        row2.setContentsMargins(2, 2, 2, 2)
        row2.setSpacing(4)
        row2.addWidget(QLabel("Replace:"))
        self.replace_edit = QLineEdit()
        self.replace_edit.setStyleSheet(_LINEEDIT_SS)
        row2.addWidget(self.replace_edit, 1)

        rep_btn = QPushButton("Replace")
        rep_btn.setStyleSheet(_BTN_SS)
        rep_btn.clicked.connect(self.replace_current)
        row2.addWidget(rep_btn)

        rep_all_btn = QPushButton("All")
        rep_all_btn.setStyleSheet(_BTN_SS)
        rep_all_btn.clicked.connect(self.replace_all)
        row2.addWidget(rep_all_btn)

        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        v.addLayout(row1)
        self._row2_widget = QWidget()
        self._row2_widget.setLayout(row2)
        v.addWidget(self._row2_widget)
        self.hide()

    def show_find(self) -> None:
        self._row2_widget.hide()
        self.show()
        self.find_edit.setFocus()
        self.find_edit.selectAll()

    def show_replace(self) -> None:
        self._row2_widget.show()
        self.show()
        self.find_edit.setFocus()
        self.find_edit.selectAll()

    def _flags(self, backward: bool = False) -> QTextDocument.FindFlag:
        flags = QTextDocument.FindFlag(0)
        if self.case_check.isChecked():
            flags |= QTextDocument.FindFlag.FindCaseSensitively
        if backward:
            flags |= QTextDocument.FindFlag.FindBackward
        return flags

    def find_next(self) -> None:
        self._do_find(False)

    def find_prev(self) -> None:
        self._do_find(True)

    def _do_find(self, backward: bool) -> None:
        needle = self.find_edit.text()
        if not needle:
            return
        if self.regex_check.isChecked():
            try:
                pat = re.compile(
                    needle,
                    0 if self.case_check.isChecked() else re.IGNORECASE,
                )
            except re.error:
                return
            text = self._editor.toPlainText()
            cursor = self._editor.textCursor()
            start = cursor.selectionEnd() if not backward else cursor.selectionStart()
            if backward:
                matches = list(pat.finditer(text[:start]))
                if matches:
                    m = matches[-1]
                else:
                    matches = list(pat.finditer(text))
                    if not matches:
                        return
                    m = matches[-1]
            else:
                m = pat.search(text, start)
                if not m:
                    m = pat.search(text)
                    if not m:
                        return
            new_cursor = QTextCursor(self._editor.document())
            new_cursor.setPosition(m.start())
            new_cursor.setPosition(m.end(), QTextCursor.MoveMode.KeepAnchor)
            self._editor.setTextCursor(new_cursor)
        else:
            found = self._editor.find(needle, self._flags(backward))
            if not found:
                # wrap
                cursor = self._editor.textCursor()
                cursor.movePosition(
                    QTextCursor.MoveOperation.End if backward else QTextCursor.MoveOperation.Start
                )
                self._editor.setTextCursor(cursor)
                self._editor.find(needle, self._flags(backward))

    def replace_current(self) -> None:
        cursor = self._editor.textCursor()
        if not cursor.hasSelection():
            self.find_next()
            return
        cursor.insertText(self.replace_edit.text())
        self.find_next()

    def replace_all(self) -> None:
        needle = self.find_edit.text()
        replacement = self.replace_edit.text()
        if not needle:
            return
        text = self._editor.toPlainText()
        if self.regex_check.isChecked():
            try:
                pat = re.compile(
                    needle,
                    0 if self.case_check.isChecked() else re.IGNORECASE,
                )
            except re.error:
                return
            new = pat.sub(replacement, text)
        else:
            if self.case_check.isChecked():
                new = text.replace(needle, replacement)
            else:
                pat = re.compile(re.escape(needle), re.IGNORECASE)
                new = pat.sub(replacement, text)
        if new != text:
            cur = self._editor.textCursor()
            pos = cur.position()
            self._editor.setPlainText(new)
            cur = self._editor.textCursor()
            cur.setPosition(min(pos, len(new)))
            self._editor.setTextCursor(cur)


def install_find_replace(editor: QTextEdit) -> FindReplaceBar:
    """Create a FindReplaceBar and bind Ctrl+F / Ctrl+H shortcuts to the editor."""
    bar = FindReplaceBar(editor, editor.parentWidget())
    sc_find = QShortcut(QKeySequence("Ctrl+F"), editor)
    sc_find.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
    sc_find.activated.connect(bar.show_find)
    sc_replace = QShortcut(QKeySequence("Ctrl+H"), editor)
    sc_replace.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
    sc_replace.activated.connect(bar.show_replace)
    return bar


# ---------------------------------------------------------------------------
# Auto-format helpers
# ---------------------------------------------------------------------------

def format_body(text: str) -> str:
    """Best-effort pretty-print of a JSON / XML / HTML body.

    Detects format heuristically and returns a formatted copy.  If nothing
    can be parsed, returns the original text unchanged.
    """
    s = text.strip()
    if not s:
        return text

    if s[0] in "{[":
        try:
            return json.dumps(json.loads(s), indent=2, ensure_ascii=False)
        except Exception:
            pass

    if s.startswith("<"):
        try:
            return xml.dom.minidom.parseString(s).toprettyxml(indent="  ")
        except Exception:
            pass

    return text


def format_http_message(raw: str) -> str:
    """Pretty-print the body of an HTTP request/response if its body parses."""
    if "\r\n\r\n" in raw:
        head, _, body = raw.partition("\r\n\r\n")
        sep = "\r\n\r\n"
    elif "\n\n" in raw:
        head, _, body = raw.partition("\n\n")
        sep = "\n\n"
    else:
        return raw
    formatted = format_body(body)
    return f"{head}{sep}{formatted}"
