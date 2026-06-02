"""
Reusable hex view / hex editor widget and a Text/Hex toggle wrapper.

Used by Repeater (and any other tool that wants byte-level editing of HTTP
messages or binary payloads). The visual style mirrors Catppuccin Mocha,
matching the rest of Fracture.

Public API:
    HexEditor(QWidget)
        set_bytes(data: bytes) -> None
        get_bytes() -> bytes
        set_read_only(ro: bool) -> None
        bytesChanged: pyqtSignal()
    HexTextToggle(QWidget)
        Wraps an existing QTextEdit + a HexEditor in a QStackedWidget with
        a two-button toolbar.  Toggling syncs content both ways.
"""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import QRect, QSize, Qt, pyqtSignal
from PyQt6.QtGui import (
    QColor,
    QFont,
    QFontMetrics,
    QKeyEvent,
    QMouseEvent,
    QPainter,
    QPaintEvent,
    QPen,
)
from PyQt6.QtWidgets import (
    QAbstractScrollArea,
    QHBoxLayout,
    QPushButton,
    QStackedWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


# ---------------------------------------------------------------------------
# Catppuccin Mocha palette
# ---------------------------------------------------------------------------
_BG          = "#1e1e2e"   # base background
_CELL        = "#181825"   # cell / gutter background
_TEXT        = "#cdd6f4"   # primary text
_GUTTER_FG   = "#a6adc8"   # offset gutter text
_ACCENT      = "#89b4fa"   # blue accent (header)
_SEL_BG      = "#45475a"   # selection background
_CURSOR_BG   = "#585b70"   # active-edit cell
_BORDER      = "#313244"

_BYTES_PER_LINE = 16
_MID_GAP = 8  # pixels of extra space between byte 7 and byte 8


_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 2px 10px; border-radius: 3px; color: #cdd6f4; }"
    "QPushButton:hover { background: #45475a; }"
    "QPushButton:checked { background: #45475a; border-color: #89b4fa; }"
)


def _is_printable(b: int) -> bool:
    # Restrict to 7-bit printable ASCII, exclude DEL.
    return 0x20 <= b < 0x7F


class HexEditor(QAbstractScrollArea):
    """
    Three-pane hex view:

        00000000 |  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a | GET / HTTP/1.1..

    Click any byte (hex or ASCII side) to select it.  Typing two hex digits
    on the hex side overwrites that byte.  Arrow keys navigate.  Invalid
    keystrokes are silently rejected.
    """

    bytesChanged = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)

        self._data = bytearray()
        self._read_only = False

        # selection / cursor state
        self._cursor = 0           # byte index
        self._nibble = 0           # 0 = high nibble, 1 = low nibble (hex edit)

        # font / metrics
        font = QFont("Monospace", 10)
        font.setStyleHint(QFont.StyleHint.TypeWriter)
        self.setFont(font)
        fm = QFontMetrics(font)
        self._char_w = fm.horizontalAdvance("0")
        self._line_h = fm.height() + 2
        self._ascent = fm.ascent()

        # Column geometry (in pixels, relative to left of viewport)
        pad = 8
        self._x_offset_gutter = pad
        # offset is 8 hex chars + 2 padding
        self._offset_w = self._char_w * 8 + pad * 2
        self._x_hex = self._x_offset_gutter + self._offset_w + pad
        # 16 bytes * 3 chars ("xx ") minus trailing space + mid gap
        self._hex_w = self._char_w * (_BYTES_PER_LINE * 3 - 1) + _MID_GAP
        self._x_ascii = self._x_hex + self._hex_w + pad * 2
        self._ascii_w = self._char_w * _BYTES_PER_LINE
        self._total_w = self._x_ascii + self._ascii_w + pad

        self.setMinimumSize(self._total_w, self._line_h * 6)
        self.viewport().setStyleSheet(f"background: {_BG};")
        self.setStyleSheet(f"QAbstractScrollArea {{ background: {_BG}; }}")

        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.viewport().setCursor(Qt.CursorShape.IBeamCursor)

        self._update_scrollbar()

    # ------------------------------------------------------------------ API

    def set_bytes(self, data: bytes) -> None:
        self._data = bytearray(data)
        if self._cursor > len(self._data):
            self._cursor = max(0, len(self._data) - 1)
        self._nibble = 0
        self._update_scrollbar()
        self.viewport().update()

    def get_bytes(self) -> bytes:
        return bytes(self._data)

    def set_read_only(self, ro: bool) -> None:
        self._read_only = bool(ro)

    def is_read_only(self) -> bool:
        return self._read_only

    # ---------------------------------------------------------- geometry --

    def _line_count(self) -> int:
        n = len(self._data)
        if n == 0:
            return 1
        return (n + _BYTES_PER_LINE - 1) // _BYTES_PER_LINE

    def _update_scrollbar(self) -> None:
        total_lines = self._line_count()
        visible_lines = max(1, self.viewport().height() // self._line_h)
        sb = self.verticalScrollBar()
        sb.setPageStep(visible_lines)
        sb.setRange(0, max(0, total_lines - visible_lines))
        self.horizontalScrollBar().setRange(0, max(0, self._total_w - self.viewport().width()))
        self.horizontalScrollBar().setPageStep(self.viewport().width())

    def resizeEvent(self, event) -> None:  # type: ignore[override]
        super().resizeEvent(event)
        self._update_scrollbar()

    def sizeHint(self) -> QSize:  # type: ignore[override]
        return QSize(self._total_w, self._line_h * 20)

    def _byte_rect_hex(self, index: int) -> QRect:
        """Return rect of the hex pair for byte `index` in viewport coords."""
        line = index // _BYTES_PER_LINE - self.verticalScrollBar().value()
        col = index % _BYTES_PER_LINE
        # 3 chars per byte ("xx "), with an extra gap after column 7
        x = self._x_hex + col * 3 * self._char_w
        if col >= 8:
            x += _MID_GAP
        x -= self.horizontalScrollBar().value()
        y = line * self._line_h
        return QRect(x - 1, y, self._char_w * 2 + 2, self._line_h)

    def _byte_rect_ascii(self, index: int) -> QRect:
        line = index // _BYTES_PER_LINE - self.verticalScrollBar().value()
        col = index % _BYTES_PER_LINE
        x = self._x_ascii + col * self._char_w - self.horizontalScrollBar().value()
        y = line * self._line_h
        return QRect(x, y, self._char_w, self._line_h)

    def _byte_at_pos(self, x: int, y: int) -> int:
        """Map a click in viewport coords to a byte index, or -1."""
        line = y // self._line_h + self.verticalScrollBar().value()
        if line < 0:
            return -1
        x += self.horizontalScrollBar().value()

        # Hex side?
        if self._x_hex <= x < self._x_hex + self._hex_w:
            rel = x - self._x_hex
            # Account for mid gap: shift right half left
            mid_x = 8 * 3 * self._char_w
            if rel >= mid_x + _MID_GAP:
                rel -= _MID_GAP
            elif rel >= mid_x:
                # in the gap — bias to last column of left half
                rel = mid_x - 1
            col = min(_BYTES_PER_LINE - 1, rel // (3 * self._char_w))
            idx = line * _BYTES_PER_LINE + col
            return idx if 0 <= idx < len(self._data) else -1

        # ASCII side?
        if self._x_ascii <= x < self._x_ascii + self._ascii_w:
            col = min(_BYTES_PER_LINE - 1, (x - self._x_ascii) // self._char_w)
            idx = line * _BYTES_PER_LINE + col
            return idx if 0 <= idx < len(self._data) else -1

        return -1

    # ----------------------------------------------------------- painting --

    def paintEvent(self, event: QPaintEvent) -> None:  # type: ignore[override]
        painter = QPainter(self.viewport())
        painter.setFont(self.font())
        try:
            self._paint(painter)
        finally:
            painter.end()

    def _paint(self, p: QPainter) -> None:
        vp = self.viewport().rect()
        p.fillRect(vp, QColor(_BG))

        sb_y = self.verticalScrollBar().value()
        sb_x = self.horizontalScrollBar().value()

        # Gutter / column backgrounds
        gutter_rect = QRect(
            self._x_offset_gutter - sb_x,
            0,
            self._offset_w,
            vp.height(),
        )
        p.fillRect(gutter_rect, QColor(_CELL))

        ascii_rect = QRect(
            self._x_ascii - sb_x - 4,
            0,
            self._ascii_w + 8,
            vp.height(),
        )
        p.fillRect(ascii_rect, QColor(_CELL))

        # Light separators
        sep_pen = QPen(QColor(_BORDER))
        p.setPen(sep_pen)
        p.drawLine(
            self._x_hex - sb_x - 4, 0,
            self._x_hex - sb_x - 4, vp.height(),
        )
        p.drawLine(
            self._x_ascii - sb_x - 8, 0,
            self._x_ascii - sb_x - 8, vp.height(),
        )

        total_lines = self._line_count()
        visible_lines = vp.height() // self._line_h + 1

        text_color = QColor(_TEXT)
        gutter_color = QColor(_GUTTER_FG)
        accent_color = QColor(_ACCENT)

        for vis in range(visible_lines):
            line = sb_y + vis
            if line >= total_lines:
                break
            y = vis * self._line_h
            baseline = y + self._ascent

            # Offset gutter
            line_off = line * _BYTES_PER_LINE
            offset_text = f"{line_off:08x}"
            p.setPen(gutter_color)
            p.drawText(
                self._x_offset_gutter + 8 - sb_x,
                baseline,
                offset_text,
            )

            # Hex pairs
            for col in range(_BYTES_PER_LINE):
                idx = line_off + col
                if idx >= len(self._data):
                    break
                rect = self._byte_rect_hex(idx)

                if idx == self._cursor:
                    p.fillRect(rect, QColor(_SEL_BG))

                # alternate column shade for the mid-line divider effect
                color = text_color if col % 2 == 0 else accent_color
                p.setPen(color)
                p.drawText(rect.x() + 1, baseline, f"{self._data[idx]:02x}")

            # ASCII gutter content
            for col in range(_BYTES_PER_LINE):
                idx = line_off + col
                if idx >= len(self._data):
                    break
                rect = self._byte_rect_ascii(idx)
                if idx == self._cursor:
                    p.fillRect(rect, QColor(_SEL_BG))
                b = self._data[idx]
                ch = chr(b) if _is_printable(b) else "."
                p.setPen(text_color if _is_printable(b) else gutter_color)
                p.drawText(rect.x(), baseline, ch)

    # ------------------------------------------------------------ input --

    def mousePressEvent(self, event: QMouseEvent) -> None:  # type: ignore[override]
        if event.button() != Qt.MouseButton.LeftButton:
            return
        pos = event.position().toPoint()
        idx = self._byte_at_pos(pos.x(), pos.y())
        if idx >= 0:
            self._cursor = idx
            self._nibble = 0
            self.viewport().update()
        self.setFocus()

    def keyPressEvent(self, event: QKeyEvent) -> None:  # type: ignore[override]
        if not self._data:
            return
        key = event.key()

        if key == Qt.Key.Key_Left:
            if self._cursor > 0:
                self._cursor -= 1
                self._nibble = 0
                self._ensure_visible(self._cursor)
                self.viewport().update()
            return
        if key == Qt.Key.Key_Right:
            if self._cursor < len(self._data) - 1:
                self._cursor += 1
                self._nibble = 0
                self._ensure_visible(self._cursor)
                self.viewport().update()
            return
        if key == Qt.Key.Key_Up:
            if self._cursor >= _BYTES_PER_LINE:
                self._cursor -= _BYTES_PER_LINE
                self._nibble = 0
                self._ensure_visible(self._cursor)
                self.viewport().update()
            return
        if key == Qt.Key.Key_Down:
            if self._cursor + _BYTES_PER_LINE < len(self._data):
                self._cursor += _BYTES_PER_LINE
                self._nibble = 0
                self._ensure_visible(self._cursor)
                self.viewport().update()
            return
        if key == Qt.Key.Key_Home:
            self._cursor -= self._cursor % _BYTES_PER_LINE
            self._nibble = 0
            self.viewport().update()
            return
        if key == Qt.Key.Key_End:
            row_end = (self._cursor // _BYTES_PER_LINE + 1) * _BYTES_PER_LINE - 1
            self._cursor = min(row_end, len(self._data) - 1)
            self._nibble = 0
            self.viewport().update()
            return

        if self._read_only:
            return

        text = event.text()
        if len(text) == 1 and text in "0123456789abcdefABCDEF":
            val = int(text, 16)
            if self._cursor >= len(self._data):
                return
            current = self._data[self._cursor]
            if self._nibble == 0:
                new = (val << 4) | (current & 0x0F)
                self._data[self._cursor] = new
                self._nibble = 1
            else:
                new = (current & 0xF0) | val
                self._data[self._cursor] = new
                self._nibble = 0
                if self._cursor < len(self._data) - 1:
                    self._cursor += 1
            self._ensure_visible(self._cursor)
            self.bytesChanged.emit()
            self.viewport().update()
            return
        # Silently reject everything else.

    def _ensure_visible(self, index: int) -> None:
        line = index // _BYTES_PER_LINE
        sb = self.verticalScrollBar()
        top = sb.value()
        visible = max(1, self.viewport().height() // self._line_h)
        if line < top:
            sb.setValue(line)
        elif line >= top + visible:
            sb.setValue(line - visible + 1)


# ---------------------------------------------------------------------------
# Text / Hex toggle
# ---------------------------------------------------------------------------


class HexTextToggle(QWidget):
    """
    Wraps an existing QTextEdit + a HexEditor in a QStackedWidget, with a
    two-button toolbar to flip between them.  Content is synced both ways:

        Text -> Hex:  text_edit.toPlainText().encode(errors='replace')
        Hex  -> Text: bytes decoded with errors='replace'
    """

    def __init__(
        self,
        text_edit: QTextEdit,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)

        self.text_edit = text_edit
        self.hex_editor = HexEditor()

        # Toolbar
        bar = QHBoxLayout()
        bar.setContentsMargins(0, 0, 0, 4)
        bar.setSpacing(4)

        self.text_btn = QPushButton("Text")
        self.text_btn.setCheckable(True)
        self.text_btn.setChecked(True)
        self.text_btn.setStyleSheet(_BTN_SS)
        self.text_btn.clicked.connect(self.show_text)

        self.hex_btn = QPushButton("Hex")
        self.hex_btn.setCheckable(True)
        self.hex_btn.setStyleSheet(_BTN_SS)
        self.hex_btn.clicked.connect(self.show_hex)

        bar.addWidget(self.text_btn)
        bar.addWidget(self.hex_btn)
        bar.addStretch(1)

        # Stack
        self.stack = QStackedWidget()
        self.stack.addWidget(self.text_edit)
        self.stack.addWidget(self.hex_editor)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(2)
        root.addLayout(bar)
        root.addWidget(self.stack, 1)

    # ---------------------------------------------------------------- API

    def show_text(self) -> None:
        # Hex -> Text sync (only if we're coming from hex view)
        if self.stack.currentIndex() == 1:
            data = self.hex_editor.get_bytes()
            self.text_edit.setPlainText(data.decode(errors="replace"))
        self.text_btn.setChecked(True)
        self.hex_btn.setChecked(False)
        self.stack.setCurrentIndex(0)

    def show_hex(self) -> None:
        # Text -> Hex sync
        if self.stack.currentIndex() == 0:
            data = self.text_edit.toPlainText().encode(errors="replace")
            self.hex_editor.set_bytes(data)
        self.text_btn.setChecked(False)
        self.hex_btn.setChecked(True)
        self.stack.setCurrentIndex(1)

    def current_mode(self) -> str:
        return "hex" if self.stack.currentIndex() == 1 else "text"

    def sync_to_text(self) -> None:
        """Force-flush whichever view is active back into text_edit."""
        if self.stack.currentIndex() == 1:
            data = self.hex_editor.get_bytes()
            self.text_edit.setPlainText(data.decode(errors="replace"))
