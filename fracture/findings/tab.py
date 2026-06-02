"""
PentestNotes — PyQt6 GUI application.
Entry point via PentestNotesApp.run().
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import (
    Qt,
    QSize,
    pyqtSignal,
    QMimeData,
)
from PyQt6.QtGui import (
    QAction,
    QColor,
    QDragEnterEvent,
    QDropEvent,
    QFont,
    QFontDatabase,
    QIcon,
    QPainter,
    QPen,
    QPixmap,
    QTextOption,
)
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from . import storage
from . import exporter
from .models import (
    Finding,
    Session,
    VULN_TYPES,
    SEVERITIES,
    PHASES,
    STATUSES,
    SEVERITY_COLORS,
    CVSS_RANGES,
    calculate_cvss,
    CVSS_METRICS,
    CVSS_DEFAULTS,
)

# ---------------------------------------------------------------------------
# Global stylesheet
# ---------------------------------------------------------------------------

APP_STYLESHEET = """
QMainWindow, QDialog {
    background-color: #1a1a2e;
    color: #e0e0e0;
}

QWidget {
    background-color: #1a1a2e;
    color: #e0e0e0;
    font-family: "Segoe UI", "Inter", "Helvetica Neue", sans-serif;
    font-size: 13px;
}

QSplitter {
    background-color: #1a1a2e;
}

QSplitter::handle {
    background-color: #2d2d44;
    width: 2px;
    height: 2px;
}

/* --- List Widget --- */
QListWidget {
    background-color: #16213e;
    border: 1px solid #2d2d44;
    border-radius: 4px;
    outline: none;
    padding: 4px;
}

QListWidget::item {
    background-color: #16213e;
    color: #e0e0e0;
    border-radius: 4px;
    padding: 6px 8px;
    margin: 2px 0;
}

QListWidget::item:selected {
    background-color: #252545;
    color: #e0e0e0;
    border-left: 3px solid #e94560;
}

QListWidget::item:hover {
    background-color: #1e2a4a;
}

/* --- Buttons --- */
QPushButton {
    background-color: #252545;
    color: #e0e0e0;
    border: 1px solid #2d2d44;
    border-radius: 5px;
    padding: 6px 14px;
    font-size: 13px;
}

QPushButton:hover {
    background-color: #2d2d55;
    border-color: #3d3d66;
}

QPushButton:pressed {
    background-color: #1e1e38;
}

QPushButton#accent {
    background-color: #e94560;
    color: #ffffff;
    border: none;
    font-weight: bold;
}

QPushButton#accent:hover {
    background-color: #ff5577;
}

QPushButton#accent:pressed {
    background-color: #cc3350;
}

QPushButton#danger {
    background-color: #5a1a24;
    color: #ffaaaa;
    border: 1px solid #7a2234;
}

QPushButton#danger:hover {
    background-color: #6a2030;
    border-color: #9a3044;
}

/* --- ComboBox --- */
QComboBox {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #2d2d44;
    border-radius: 5px;
    padding: 5px 10px;
    min-height: 28px;
}

QComboBox:hover {
    border-color: #3d3d66;
}

QComboBox:focus {
    border-color: #e94560;
}

QComboBox::drop-down {
    border: none;
    width: 20px;
}

QComboBox::down-arrow {
    width: 10px;
    height: 10px;
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 6px solid #7a7a9a;
}

QComboBox QAbstractItemView {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #2d2d44;
    selection-background-color: #252545;
    selection-color: #e0e0e0;
    outline: none;
}

/* --- LineEdit --- */
QLineEdit {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #2d2d44;
    border-radius: 5px;
    padding: 5px 10px;
    min-height: 28px;
}

QLineEdit:hover {
    border-color: #3d3d66;
}

QLineEdit:focus {
    border-color: #e94560;
}

/* --- PlainTextEdit --- */
QPlainTextEdit {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #2d2d44;
    border-radius: 5px;
    padding: 6px;
}

QPlainTextEdit:focus {
    border-color: #e94560;
}

/* --- ScrollBar --- */
QScrollBar:vertical {
    background-color: #16213e;
    width: 8px;
    border-radius: 4px;
}

QScrollBar::handle:vertical {
    background-color: #2d2d44;
    border-radius: 4px;
    min-height: 20px;
}

QScrollBar::handle:vertical:hover {
    background-color: #3d3d66;
}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    background-color: #16213e;
    height: 8px;
    border-radius: 4px;
}

QScrollBar::handle:horizontal {
    background-color: #2d2d44;
    border-radius: 4px;
    min-width: 20px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #3d3d66;
}

QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal {
    width: 0px;
}

/* --- Menu bar --- */
QMenuBar {
    background-color: #16213e;
    color: #e0e0e0;
    border-bottom: 1px solid #2d2d44;
    padding: 2px;
}

QMenuBar::item {
    background-color: transparent;
    color: #e0e0e0;
    padding: 4px 10px;
    border-radius: 4px;
}

QMenuBar::item:selected {
    background-color: #252545;
}

QMenu {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #2d2d44;
    padding: 4px;
}

QMenu::item {
    padding: 6px 20px;
    border-radius: 3px;
}

QMenu::item:selected {
    background-color: #252545;
    color: #e0e0e0;
}

QMenu::separator {
    height: 1px;
    background-color: #2d2d44;
    margin: 4px 0;
}

/* --- Toolbar --- */
QToolBar {
    background-color: #16213e;
    border-bottom: 1px solid #2d2d44;
    padding: 4px 8px;
    spacing: 6px;
}

QToolBar::separator {
    background-color: #2d2d44;
    width: 1px;
    margin: 4px 4px;
}

/* --- Status bar --- */
QStatusBar {
    background-color: #16213e;
    color: #7a7a9a;
    border-top: 1px solid #2d2d44;
    font-size: 11px;
}

/* --- Labels --- */
QLabel {
    background-color: transparent;
    color: #e0e0e0;
}

QLabel#dim {
    color: #7a7a9a;
    font-size: 11px;
}

QLabel#section-header {
    color: #7a7a9a;
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 1px;
    text-transform: uppercase;
}

/* --- Frames --- */
QFrame#surface {
    background-color: #16213e;
    border: 1px solid #2d2d44;
    border-radius: 6px;
}

QFrame#drop-area {
    background-color: #16213e;
    border: 2px dashed #2d2d44;
    border-radius: 6px;
}

QFrame#drop-area-active {
    background-color: #1a1f3a;
    border: 2px dashed #e94560;
    border-radius: 6px;
}

QScrollArea {
    background-color: #1a1a2e;
    border: none;
}
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("section-header")
    return lbl


def _make_monospace_font() -> QFont:
    for name in ("Fira Code", "JetBrains Mono", "Cascadia Code", "Courier New", "Monospace"):
        f = QFont(name, 12)
        fi = QFontDatabase.font(name, "", 12)
        if fi.family().lower().replace(" ", "") == name.lower().replace(" ", "") or name == "Courier New":
            f.setFixedPitch(True)
            return f
    fallback = QFont("Courier New", 12)
    fallback.setFixedPitch(True)
    return fallback


# ---------------------------------------------------------------------------
# ImageDropArea
# ---------------------------------------------------------------------------

class _ThumbnailWidget(QFrame):
    remove_requested = pyqtSignal(str)

    def __init__(self, image_path: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.image_path = image_path
        self.setFixedSize(72, 72)
        self.setObjectName("surface")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(0)

        # Thumbnail image label
        pix = QPixmap(image_path)
        if pix.isNull():
            pix = QPixmap(60, 60)
            pix.fill(QColor("#2d2d44"))
        pix = pix.scaled(60, 60, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
        img_label = QLabel()
        img_label.setPixmap(pix)
        img_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Remove button — small X
        remove_btn = QPushButton("✕")
        remove_btn.setFixedSize(16, 16)
        remove_btn.setStyleSheet(
            "QPushButton { background-color: #e94560; color: white; border: none; "
            "border-radius: 8px; font-size: 9px; padding: 0; }"
            "QPushButton:hover { background-color: #ff5577; }"
        )
        remove_btn.clicked.connect(lambda: self.remove_requested.emit(self.image_path))

        top_row = QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.addStretch()
        top_row.addWidget(remove_btn)

        layout.addLayout(top_row)
        layout.addWidget(img_label)


class ImageDropArea(QFrame):
    images_changed = pyqtSignal(list)

    ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("drop-area")
        self.setAcceptDrops(True)
        self._images: list[str] = []

        self._outer = QVBoxLayout(self)
        self._outer.setContentsMargins(8, 8, 8, 8)
        self._outer.setSpacing(6)

        # Thumbnails row
        self._thumb_row = QHBoxLayout()
        self._thumb_row.setSpacing(6)
        self._thumb_row.setAlignment(Qt.AlignmentFlag.AlignLeft)

        # Placeholder label (shown when no images)
        self._placeholder = QLabel("Drop images here or click Add Image")
        self._placeholder.setObjectName("dim")
        self._placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Add image button
        add_btn = QPushButton("Add Image")
        add_btn.setFixedWidth(100)
        add_btn.clicked.connect(self._open_file_dialog)

        btn_row = QHBoxLayout()
        btn_row.addWidget(add_btn)
        btn_row.addStretch()

        self._outer.addWidget(self._placeholder)
        self._outer.addLayout(self._thumb_row)
        self._outer.addLayout(btn_row)

        self._refresh_ui()

    # ------------------------------------------------------------------
    def get_images(self) -> list[str]:
        return list(self._images)

    def set_images(self, paths: list[str]):
        self._images = list(paths)
        self._refresh_ui()

    # ------------------------------------------------------------------
    def _refresh_ui(self):
        # Clear existing thumbnails from layout
        while self._thumb_row.count():
            item = self._thumb_row.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self._placeholder.setVisible(len(self._images) == 0)

        for path in self._images:
            thumb = _ThumbnailWidget(path)
            thumb.remove_requested.connect(self._remove_image)
            self._thumb_row.addWidget(thumb)

    def _add_image(self, path: str):
        path = str(Path(path).resolve())
        if path not in self._images:
            self._images.append(path)
            self._refresh_ui()
            self.images_changed.emit(list(self._images))

    def _remove_image(self, path: str):
        if path in self._images:
            self._images.remove(path)
            self._refresh_ui()
            self.images_changed.emit(list(self._images))

    def _open_file_dialog(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Images",
            str(Path.home()),
            "Images (*.png *.jpg *.jpeg *.gif *.bmp *.webp)",
        )
        for p in paths:
            self._add_image(p)

    # ------------------------------------------------------------------
    # Drag & drop
    # ------------------------------------------------------------------
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if any(Path(u.toLocalFile()).suffix.lower() in self.ALLOWED_EXTENSIONS for u in urls):
                self.setObjectName("drop-area-active")
                self.setStyleSheet("")  # force style refresh
                event.acceptProposedAction()
                return
        event.ignore()

    def dragLeaveEvent(self, event):
        self.setObjectName("drop-area")
        self.setStyleSheet("")
        super().dragLeaveEvent(event)

    def dropEvent(self, event: QDropEvent):
        self.setObjectName("drop-area")
        self.setStyleSheet("")
        for url in event.mimeData().urls():
            local = url.toLocalFile()
            if Path(local).suffix.lower() in self.ALLOWED_EXTENSIONS:
                self._add_image(local)
        event.acceptProposedAction()


# ---------------------------------------------------------------------------
# FindingListWidget
# ---------------------------------------------------------------------------

class FindingListWidget(QWidget):
    finding_selected = pyqtSignal(str)   # emits finding id
    new_finding_requested = pyqtSignal()
    delete_finding_requested = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        # Header label
        header = QLabel("FINDINGS")
        header.setObjectName("section-header")
        layout.addWidget(header)

        # --- Search bar ---
        search_row = QHBoxLayout()
        search_row.setSpacing(4)
        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("Search findings…")
        self._search_edit.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        search_row.addWidget(self._search_edit)

        clear_btn = QPushButton("✕")
        clear_btn.setFixedSize(24, 24)
        clear_btn.setToolTip("Clear search")
        clear_btn.setStyleSheet(
            "QPushButton { background-color: transparent; color: #7a7a9a; "
            "border: none; font-size: 11px; padding: 0; }"
            "QPushButton:hover { color: #e94560; }"
        )
        clear_btn.clicked.connect(self._search_edit.clear)
        search_row.addWidget(clear_btn)
        layout.addLayout(search_row)

        # --- Severity filter buttons ---
        self._filter_btns: dict[str, QPushButton] = {}
        filter_row = QHBoxLayout()
        filter_row.setSpacing(3)

        _sev_colors = {
            "All": "#e94560",
            "Critical": SEVERITY_COLORS.get("Critical", "#ff0000"),
            "High": SEVERITY_COLORS.get("High", "#ff6600"),
            "Medium": SEVERITY_COLORS.get("Medium", "#ffcc00"),
            "Low": SEVERITY_COLORS.get("Low", "#00aaff"),
            "Informational": SEVERITY_COLORS.get("Informational", "#aaaaaa"),
        }
        _btn_labels = {
            "All": "All",
            "Critical": "C",
            "High": "H",
            "Medium": "M",
            "Low": "L",
            "Informational": "I",
        }
        for sev_key, label in _btn_labels.items():
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.setFixedHeight(20)
            color = _sev_colors[sev_key]
            btn.setStyleSheet(
                f"QPushButton {{ background-color: #16213e; color: #9a9ab0; "
                f"border: 1px solid #2d2d44; border-radius: 3px; "
                f"padding: 1px 5px; font-size: 11px; font-weight: bold; }}"
                f"QPushButton:checked {{ color: {color}; border-left: 3px solid {color}; "
                f"background-color: #1e2040; }}"
                f"QPushButton:hover {{ background-color: #1e2040; }}"
            )
            btn.toggled.connect(lambda checked, k=sev_key: self._on_filter_toggled(k, checked))
            self._filter_btns[sev_key] = btn
            filter_row.addWidget(btn)

        filter_row.addStretch()
        layout.addLayout(filter_row)

        # Start with "All" checked
        self._filter_btns["All"].setChecked(True)

        self._list = QListWidget()
        self._list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._list.customContextMenuRequested.connect(self._show_context_menu)
        self._list.currentRowChanged.connect(self._on_row_changed)
        layout.addWidget(self._list)

        new_btn = QPushButton("+ New Finding")
        new_btn.setObjectName("accent")
        new_btn.clicked.connect(self.new_finding_requested.emit)
        layout.addWidget(new_btn)

        self._findings: list[Finding] = []
        self._active_severity_filter: str = "All"

        # Connect search signal
        self._search_edit.textChanged.connect(self._apply_filter)

    # ------------------------------------------------------------------
    def _on_filter_toggled(self, key: str, checked: bool):
        if checked:
            # Radio behaviour: uncheck all others
            self._active_severity_filter = key
            for k, btn in self._filter_btns.items():
                if k != key:
                    btn.blockSignals(True)
                    btn.setChecked(False)
                    btn.blockSignals(False)
        else:
            # Re-check if this was the active one (prevent un-checking all)
            if self._active_severity_filter == key:
                self._filter_btns[key].blockSignals(True)
                self._filter_btns[key].setChecked(True)
                self._filter_btns[key].blockSignals(False)
        self._apply_filter()

    def _apply_filter(self):
        if not hasattr(self, '_list'):
            return
        text = self._search_edit.text().lower()
        sev = self._active_severity_filter
        for i in range(self._list.count()):
            item = self._list.item(i)
            if item is None:
                continue
            fid = item.data(Qt.ItemDataRole.UserRole)
            if not fid:
                # placeholder item — always show when no filter applied
                item.setHidden(False)
                continue
            # Find the matching Finding object
            finding = next((f for f in self._findings if f.id == fid), None)
            if finding is None:
                item.setHidden(True)
                continue
            # Severity filter
            sev_match = (sev == "All") or (finding.severity == sev)
            # Text filter
            haystack = (
                (finding.vuln_type or "") + " " +
                (finding.target or "") + " " +
                (finding.notes or "")
            ).lower()
            text_match = (not text) or (text in haystack)
            item.setHidden(not (sev_match and text_match))

    # ------------------------------------------------------------------
    def load_findings(self, findings: list[Finding]):
        self._findings = findings
        self._list.blockSignals(True)
        self._list.clear()

        if not findings:
            placeholder = QListWidgetItem("No findings yet")
            placeholder.setForeground(QColor("#7a7a9a"))
            placeholder.setFlags(Qt.ItemFlag.NoItemFlags)
            self._list.addItem(placeholder)
        else:
            for f in findings:
                self._list.addItem(self._make_item(f))

        self._list.blockSignals(False)
        self._apply_filter()

    def _make_item(self, finding: Finding) -> QListWidgetItem:
        item = QListWidgetItem()
        color = SEVERITY_COLORS.get(finding.severity, "#8888ff")

        # Build display text
        vuln = finding.vuln_type
        target = finding.target[:32] if finding.target else "no target"

        item.setData(Qt.ItemDataRole.UserRole, finding.id)
        item.setData(Qt.ItemDataRole.UserRole + 1, color)

        # Use custom widget via setSizeHint + delegate approach is complex;
        # instead embed severity color as foreground and rely on two-line text
        item.setText(f"{vuln}\n{target}")
        item.setForeground(QColor("#e0e0e0"))

        # Store color for delegate
        font_top = QFont()
        font_top.setBold(True)
        item.setFont(font_top)

        # We'll paint the severity dot via a delegate (see FindingItemDelegate)
        # Store severity color in decoration role as a colored pixmap
        dot_pix = QPixmap(10, 36)
        dot_pix.fill(Qt.GlobalColor.transparent)
        painter = QPainter(dot_pix)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(QColor(color))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(2, 4, 6, 28, 3, 3)
        painter.end()
        item.setIcon(QIcon(dot_pix))

        item.setSizeHint(QSize(200, 52))
        return item

    def select_finding(self, finding_id: str):
        for i in range(self._list.count()):
            item = self._list.item(i)
            if item and item.data(Qt.ItemDataRole.UserRole) == finding_id:
                self._list.setCurrentRow(i)
                return

    def clear_selection(self):
        self._list.clearSelection()
        self._list.setCurrentRow(-1)

    # ------------------------------------------------------------------
    def _on_row_changed(self, row: int):
        if row < 0:
            return
        item = self._list.item(row)
        if item:
            fid = item.data(Qt.ItemDataRole.UserRole)
            if fid:
                self.finding_selected.emit(fid)

    def _show_context_menu(self, pos):
        item = self._list.itemAt(pos)
        if not item:
            return
        fid = item.data(Qt.ItemDataRole.UserRole)
        if not fid:
            return

        menu = QMenu(self)
        delete_action = QAction("Delete Finding", self)
        delete_action.triggered.connect(lambda: self.delete_finding_requested.emit(fid))
        menu.addAction(delete_action)
        menu.exec(self._list.mapToGlobal(pos))


# ---------------------------------------------------------------------------
# FindingEditor
# ---------------------------------------------------------------------------

class FindingEditor(QWidget):
    """Center panel — editable fields for a single finding."""

    changed = pyqtSignal()  # fires whenever any field is modified

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._block_signals = False

        # Outer scroll area wraps the whole editor
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setLayoutDirection(Qt.LayoutDirection.LeftToRight)

        inner = QWidget()
        self._layout = QVBoxLayout(inner)
        self._layout.setContentsMargins(16, 16, 16, 16)
        self._layout.setSpacing(14)

        self._build_ui()

        scroll.setWidget(inner)
        outer_layout.addWidget(scroll)

    # ------------------------------------------------------------------
    def _build_ui(self):
        lyt = self._layout

        # --- Row 1: Vuln Type + Target ---
        row1 = QHBoxLayout()
        row1.setSpacing(10)

        vuln_col = QVBoxLayout()
        vuln_col.addWidget(_section_label("VULNERABILITY TYPE"))
        self.vuln_combo = QComboBox()
        self.vuln_combo.addItems(VULN_TYPES)
        vuln_col.addWidget(self.vuln_combo)
        row1.addLayout(vuln_col, 2)

        target_col = QVBoxLayout()
        target_col.addWidget(_section_label("TARGET"))
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("e.g. 192.168.1.1 or https://example.com")
        self.target_edit.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        target_col.addWidget(self.target_edit)
        row1.addLayout(target_col, 3)

        lyt.addLayout(row1)

        # --- Row 2: Severity + Phase + Status ---
        row2 = QHBoxLayout()
        row2.setSpacing(10)

        for label_text, attr, choices in [
            ("SEVERITY", "severity_combo", SEVERITIES),
            ("PHASE", "phase_combo", PHASES),
            ("STATUS", "status_combo", STATUSES),
        ]:
            col = QVBoxLayout()
            col.addWidget(_section_label(label_text))
            combo = QComboBox()
            combo.addItems(choices)
            setattr(self, attr, combo)
            col.addWidget(combo)
            row2.addLayout(col)

        lyt.addLayout(row2)

        # --- Payload / Code Used ---
        lyt.addWidget(_section_label("PAYLOAD / CODE USED"))
        self.payload_edit = QPlainTextEdit()
        self.payload_edit.setPlaceholderText("Paste payload, exploit code, or request here...")
        mono = _make_monospace_font()
        self.payload_edit.setFont(mono)
        self.payload_edit.setStyleSheet(
            "QPlainTextEdit { background-color: #0d1117; color: #4ec9b0; "
            "border: 1px solid #2d2d44; border-radius: 5px; padding: 8px; }"
            "QPlainTextEdit:focus { border-color: #e94560; }"
        )
        self.payload_edit.setMinimumHeight(5 * 22)
        self.payload_edit.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        _ltr_opt = QTextOption()
        _ltr_opt.setTextDirection(Qt.LayoutDirection.LeftToRight)
        self.payload_edit.document().setDefaultTextOption(_ltr_opt)
        lyt.addWidget(self.payload_edit)

        # --- What Was Accessed / Impact ---
        lyt.addWidget(_section_label("WHAT WAS ACCESSED / IMPACT"))
        self.accessed_edit = QPlainTextEdit()
        self.accessed_edit.setPlaceholderText("Describe what data or systems were accessed, and the impact...")
        self.accessed_edit.setMinimumHeight(4 * 22)
        self.accessed_edit.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        _ltr_opt = QTextOption()
        _ltr_opt.setTextDirection(Qt.LayoutDirection.LeftToRight)
        self.accessed_edit.document().setDefaultTextOption(_ltr_opt)
        lyt.addWidget(self.accessed_edit)

        # --- Notes & Evidence ---
        lyt.addWidget(_section_label("NOTES & EVIDENCE"))
        self.notes_edit = QPlainTextEdit()
        self.notes_edit.setPlaceholderText("Steps to reproduce, references, additional context...")
        self.notes_edit.setMinimumHeight(4 * 22)
        self.notes_edit.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        _ltr_opt = QTextOption()
        _ltr_opt.setTextDirection(Qt.LayoutDirection.LeftToRight)
        self.notes_edit.document().setDefaultTextOption(_ltr_opt)
        lyt.addWidget(self.notes_edit)

        # --- HTTP Request / Response ---
        lyt.addWidget(_section_label("HTTP REQUEST / RESPONSE"))
        self._http_tabs = QTabWidget()
        self._http_tabs.setStyleSheet(
            "QTabWidget::pane { border: 1px solid #2d2d44; border-radius: 4px; }"
            "QTabBar::tab { background-color: #16213e; color: #9a9ab0; "
            "padding: 4px 12px; border: 1px solid #2d2d44; border-bottom: none; "
            "border-top-left-radius: 4px; border-top-right-radius: 4px; }"
            "QTabBar::tab:selected { background-color: #1e2040; color: #e0e0e0; "
            "border-color: #e94560; }"
        )

        _req_ltr_opt = QTextOption()
        _req_ltr_opt.setTextDirection(Qt.LayoutDirection.LeftToRight)

        self.request_edit = QPlainTextEdit()
        self.request_edit.setPlaceholderText("Paste raw HTTP request here…")
        self.request_edit.setFont(_make_monospace_font())
        self.request_edit.setStyleSheet(
            "QPlainTextEdit { background-color: #0d1117; color: #56b6c2; "
            "border: none; padding: 8px; }"
            "QPlainTextEdit:focus { border: none; }"
        )
        self.request_edit.setMinimumHeight(4 * 22)
        self.request_edit.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.request_edit.document().setDefaultTextOption(_req_ltr_opt)

        _resp_ltr_opt = QTextOption()
        _resp_ltr_opt.setTextDirection(Qt.LayoutDirection.LeftToRight)

        self.response_edit = QPlainTextEdit()
        self.response_edit.setPlaceholderText("Paste raw HTTP response here…")
        self.response_edit.setFont(_make_monospace_font())
        self.response_edit.setStyleSheet(
            "QPlainTextEdit { background-color: #0d1117; color: #98c379; "
            "border: none; padding: 8px; }"
            "QPlainTextEdit:focus { border: none; }"
        )
        self.response_edit.setMinimumHeight(4 * 22)
        self.response_edit.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.response_edit.document().setDefaultTextOption(_resp_ltr_opt)

        self._http_tabs.addTab(self.request_edit, "Request")
        self._http_tabs.addTab(self.response_edit, "Response")
        lyt.addWidget(self._http_tabs)

        # --- Screenshots ---
        lyt.addWidget(_section_label("SCREENSHOTS"))
        self.image_area = ImageDropArea()
        self.image_area.setMinimumHeight(90)
        lyt.addWidget(self.image_area)

        lyt.addStretch()

        # Connect signals
        self.vuln_combo.currentIndexChanged.connect(self._emit_changed)
        self.target_edit.textChanged.connect(self._emit_changed)
        self.severity_combo.currentIndexChanged.connect(self._emit_changed)
        self.phase_combo.currentIndexChanged.connect(self._emit_changed)
        self.status_combo.currentIndexChanged.connect(self._emit_changed)
        self.payload_edit.textChanged.connect(self._emit_changed)
        self.accessed_edit.textChanged.connect(self._emit_changed)
        self.notes_edit.textChanged.connect(self._emit_changed)
        self.request_edit.textChanged.connect(self._emit_changed)
        self.response_edit.textChanged.connect(self._emit_changed)
        self.image_area.images_changed.connect(self._emit_changed)

    # ------------------------------------------------------------------
    def _emit_changed(self, *_args):
        if not self._block_signals:
            self.changed.emit()

    # ------------------------------------------------------------------
    def load_finding(self, finding: Finding):
        self._block_signals = True
        try:
            self._set_combo(self.vuln_combo, finding.vuln_type)
            self.target_edit.setText(finding.target)
            self._set_combo(self.severity_combo, finding.severity)
            self._set_combo(self.phase_combo, finding.phase)
            self._set_combo(self.status_combo, finding.status)
            self.payload_edit.setPlainText(finding.payload)
            self.accessed_edit.setPlainText(finding.accessed)
            self.notes_edit.setPlainText(finding.notes)
            self.request_edit.setPlainText(finding.request_raw)
            self.response_edit.setPlainText(finding.response_raw)
            self.image_area.set_images(finding.images or [])
        finally:
            self._block_signals = False

    def clear(self):
        self._block_signals = True
        try:
            self.vuln_combo.setCurrentIndex(0)
            self.target_edit.clear()
            self.severity_combo.setCurrentIndex(0)
            self.phase_combo.setCurrentIndex(0)
            self.status_combo.setCurrentIndex(0)
            self.payload_edit.clear()
            self.accessed_edit.clear()
            self.notes_edit.clear()
            self.request_edit.clear()
            self.response_edit.clear()
            self.image_area.set_images([])
        finally:
            self._block_signals = False

    # ------------------------------------------------------------------
    def read_finding_into(self, finding: Finding):
        """Write current editor state into a Finding object (in-place)."""
        finding.vuln_type = self.vuln_combo.currentText()
        finding.target = self.target_edit.text().strip()
        finding.severity = self.severity_combo.currentText()
        finding.phase = self.phase_combo.currentText()
        finding.status = self.status_combo.currentText()
        finding.payload = self.payload_edit.toPlainText()
        finding.accessed = self.accessed_edit.toPlainText()
        finding.notes = self.notes_edit.toPlainText()
        finding.request_raw = self.request_edit.toPlainText()
        finding.response_raw = self.response_edit.toPlainText()
        finding.images = self.image_area.get_images()

    # ------------------------------------------------------------------
    @staticmethod
    def _set_combo(combo: QComboBox, value: str):
        idx = combo.findText(value)
        if idx >= 0:
            combo.setCurrentIndex(idx)


# ---------------------------------------------------------------------------
# QuickPanel
# ---------------------------------------------------------------------------

class QuickPanel(QWidget):
    export_finding_requested = pyqtSignal()
    export_session_requested = pyqtSignal()
    delete_finding_requested = pyqtSignal()
    vault_path_changed = pyqtSignal(str)
    cvss_calculated = pyqtSignal(float, str)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        header = QLabel("QUICK INFO")
        header.setObjectName("section-header")
        layout.addWidget(header)

        # Severity badge
        self._severity_badge = QLabel("—")
        self._severity_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._severity_badge.setStyleSheet(
            "QLabel { background-color: #2d2d44; color: #e0e0e0; border-radius: 12px; "
            "padding: 6px 12px; font-weight: bold; font-size: 14px; }"
        )
        layout.addWidget(self._severity_badge)

        # Info rows
        self._cvss_label = self._info_row(layout, "CVSS Range", "—")
        self._phase_label = self._info_row(layout, "Phase", "—")
        self._status_label = self._info_row(layout, "Status", "—")
        self._created_label = self._info_row(layout, "Created", "—")

        layout.addStretch()

        # --- CVSS Calculator button ---
        self._cvss_btn = QPushButton("Calculate CVSS…")
        self._cvss_btn.clicked.connect(self._open_cvss_calc)
        layout.addWidget(self._cvss_btn)

        # --- Export / delete buttons ---
        export_btn = QPushButton("Export Finding")
        export_btn.setObjectName("accent")
        export_btn.clicked.connect(self.export_finding_requested.emit)
        layout.addWidget(export_btn)

        export_session_btn = QPushButton("Export Session")
        export_session_btn.clicked.connect(self.export_session_requested.emit)
        layout.addWidget(export_session_btn)

        delete_btn = QPushButton("Delete Finding")
        delete_btn.setObjectName("danger")
        delete_btn.clicked.connect(self.delete_finding_requested.emit)
        layout.addWidget(delete_btn)

        # --- Vault path ---
        layout.addWidget(_section_label("VAULT PATH"))

        vault_row = QHBoxLayout()
        self._vault_label = QLabel("—")
        self._vault_label.setObjectName("dim")
        self._vault_label.setWordWrap(True)
        vault_row.addWidget(self._vault_label, 1)

        change_btn = QPushButton("Change")
        change_btn.setFixedWidth(60)
        change_btn.clicked.connect(self._change_vault)
        vault_row.addWidget(change_btn)
        layout.addLayout(vault_row)

    # ------------------------------------------------------------------
    def _open_cvss_calc(self):
        dlg = CvssCalculatorDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            score, vector = dlg.get_result()
            self.cvss_calculated.emit(score, vector)

    # ------------------------------------------------------------------
    def _info_row(self, parent_layout: QVBoxLayout, label_text: str, default: str) -> QLabel:
        row = QHBoxLayout()
        key = QLabel(label_text)
        key.setObjectName("dim")
        key.setFixedWidth(70)
        val = QLabel(default)
        row.addWidget(key)
        row.addWidget(val)
        row.addStretch()
        parent_layout.addLayout(row)
        return val

    # ------------------------------------------------------------------
    def update_finding(self, finding: Finding | None):
        if finding is None:
            self._severity_badge.setText("—")
            self._severity_badge.setStyleSheet(
                "QLabel { background-color: #2d2d44; color: #e0e0e0; border-radius: 12px; "
                "padding: 6px 12px; font-weight: bold; font-size: 14px; }"
            )
            self._cvss_label.setText("—")
            self._phase_label.setText("—")
            self._status_label.setText("—")
            self._created_label.setText("—")
            return

        sev = finding.severity
        color = SEVERITY_COLORS.get(sev, "#8888ff")
        self._severity_badge.setText(sev)
        self._severity_badge.setStyleSheet(
            f"QLabel {{ background-color: {color}; color: #000000; border-radius: 12px; "
            f"padding: 6px 12px; font-weight: bold; font-size: 14px; }}"
        )
        if finding.cvss_score > 0:
            self._cvss_label.setText(str(finding.cvss_score))
        else:
            self._cvss_label.setText(CVSS_RANGES.get(sev, "N/A"))
        self._phase_label.setText(finding.phase)
        self._status_label.setText(finding.status)

        # Parse created_at
        try:
            dt = datetime.fromisoformat(finding.created_at)
            self._created_label.setText(dt.strftime("%Y-%m-%d %H:%M"))
        except Exception:
            self._created_label.setText(finding.created_at[:16])

    def set_vault_path(self, path: str):
        truncated = path if len(path) <= 30 else "…" + path[-28:]
        self._vault_label.setText(truncated)
        self._vault_label.setToolTip(path)

    def _change_vault(self):
        chosen = QFileDialog.getExistingDirectory(
            self,
            "Select Vault Directory",
            self._vault_label.toolTip() or str(Path.home()),
        )
        if chosen:
            self.vault_path_changed.emit(chosen)


# ---------------------------------------------------------------------------
# Empty state widget
# ---------------------------------------------------------------------------

class EmptyState(QWidget):
    def __init__(self, title: str, subtitle: str, parent: QWidget | None = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        icon_lbl = QLabel("🔍")
        icon_lbl.setStyleSheet("font-size: 48px;")
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_lbl)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet("font-size: 16px; font-weight: bold; color: #e0e0e0;")
        title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_lbl)

        sub_lbl = QLabel(subtitle)
        sub_lbl.setObjectName("dim")
        sub_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(sub_lbl)


# ---------------------------------------------------------------------------
# NewSessionDialog
# ---------------------------------------------------------------------------

class NewSessionDialog(QDialog):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("New Session")
        self.setMinimumWidth(380)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        form = QFormLayout()
        form.setSpacing(10)

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("e.g. HackTheBox — Forest, Client Pentest Q3")
        self.name_edit.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        form.addRow("Session Name:", self.name_edit)

        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("e.g. 10.10.10.161 or example.com")
        self.host_edit.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        form.addRow("Target Host / IP:", self.host_edit)

        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_values(self) -> tuple[str, str]:
        return self.name_edit.text().strip(), self.host_edit.text().strip()


# ---------------------------------------------------------------------------
# CvssCalculatorDialog
# ---------------------------------------------------------------------------

class CvssCalculatorDialog(QDialog):
    """CVSS v3.1 Base Score Calculator dialog."""

    _METRIC_ORDER = [
        ("Attack Vector",       ["Network", "Adjacent", "Local", "Physical"]),
        ("Attack Complexity",   ["Low", "High"]),
        ("Privileges Required", ["None", "Low", "High"]),
        ("User Interaction",    ["None", "Required"]),
        ("Scope",               ["Unchanged", "Changed"]),
        ("Confidentiality Impact", ["None", "Low", "High"]),
        ("Integrity Impact",    ["None", "Low", "High"]),
        ("Availability Impact", ["None", "Low", "High"]),
    ]

    # Internal keys passed to calculate_cvss (strip " Impact" suffix for CIA)
    _CALC_KEYS = [
        "Attack Vector",
        "Attack Complexity",
        "Privileges Required",
        "User Interaction",
        "Scope",
        "Confidentiality",
        "Integrity",
        "Availability",
    ]

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("CVSS v3.1 Calculator")
        self.setMinimumWidth(440)
        self.setModal(True)

        self._score: float = 0.0
        self._vector: str = ""

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Title
        title_lbl = QLabel("CVSS v3.1 Base Score Calculator")
        title_lbl.setStyleSheet("font-size: 15px; font-weight: bold; color: #e0e0e0;")
        title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_lbl)

        # Score display
        self._score_lbl = QLabel("—")
        self._score_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._score_lbl.setStyleSheet(
            "QLabel { font-size: 28px; font-weight: bold; color: #e0e0e0; "
            "padding: 10px; border-radius: 8px; background-color: #2d2d44; }"
        )
        layout.addWidget(self._score_lbl)

        # Vector string display
        self._vector_lbl = QLabel("")
        self._vector_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._vector_lbl.setObjectName("dim")
        self._vector_lbl.setWordWrap(True)
        layout.addWidget(self._vector_lbl)

        # Form with combos
        form = QFormLayout()
        form.setSpacing(8)
        self._combos: dict[str, QComboBox] = {}

        for display_name, options in self._METRIC_ORDER:
            combo = QComboBox()
            combo.addItems(options)
            # Set default value
            # Map display name to CVSS_DEFAULTS key
            key = display_name.replace(" Impact", "")
            if key in CVSS_DEFAULTS:
                default_val = CVSS_DEFAULTS[key]
                idx = combo.findText(default_val)
                if idx >= 0:
                    combo.setCurrentIndex(idx)
            combo.currentIndexChanged.connect(self._recalculate)
            self._combos[display_name] = combo
            form.addRow(display_name + ":", combo)

        layout.addLayout(form)

        # Buttons
        btn_row = QHBoxLayout()
        self._save_btn = QPushButton("Save to Finding")
        self._save_btn.setObjectName("accent")
        self._save_btn.clicked.connect(self.accept)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)

        btn_row.addWidget(self._save_btn)
        btn_row.addWidget(cancel_btn)
        layout.addLayout(btn_row)

        # Initial calculation
        self._recalculate()

    def _recalculate(self):
        av  = self._combos["Attack Vector"].currentText()
        ac  = self._combos["Attack Complexity"].currentText()
        pr  = self._combos["Privileges Required"].currentText()
        ui  = self._combos["User Interaction"].currentText()
        sc  = self._combos["Scope"].currentText()
        c   = self._combos["Confidentiality Impact"].currentText()
        i   = self._combos["Integrity Impact"].currentText()
        a   = self._combos["Availability Impact"].currentText()

        score, severity, vector = calculate_cvss(av, ac, pr, ui, sc, c, i, a)
        self._score = score
        self._vector = vector

        color = SEVERITY_COLORS.get(severity, "#8888ff")
        self._score_lbl.setText(f"{score} — {severity}")
        self._score_lbl.setStyleSheet(
            f"QLabel {{ font-size: 28px; font-weight: bold; color: #000000; "
            f"padding: 10px; border-radius: 8px; background-color: {color}; }}"
        )
        self._vector_lbl.setText(vector)

    def get_result(self) -> tuple[float, str]:
        """Return (score, vector) from the last calculation."""
        return self._score, self._vector


# ---------------------------------------------------------------------------
# SessionNotesDialog
# ---------------------------------------------------------------------------

class SessionNotesDialog(QDialog):
    def __init__(
        self,
        exec_summary: str = "",
        recon_notes: str = "",
        important_notes: str = "",
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.setWindowTitle("Session Notes")
        self.setMinimumWidth(560)
        self.setMinimumHeight(500)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        _ltr = QTextOption()
        _ltr.setTextDirection(Qt.LayoutDirection.LeftToRight)

        # Executive Summary
        layout.addWidget(_section_label("EXECUTIVE SUMMARY"))
        self._exec_edit = QPlainTextEdit()
        self._exec_edit.setPlaceholderText("High-level summary of findings for the client or report...")
        self._exec_edit.setMinimumHeight(5 * 22)
        self._exec_edit.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self._exec_edit.document().setDefaultTextOption(_ltr)
        self._exec_edit.setPlainText(exec_summary)
        layout.addWidget(self._exec_edit)

        # Reconnaissance Notes
        layout.addWidget(_section_label("RECONNAISSANCE NOTES"))
        self._recon_edit = QPlainTextEdit()
        self._recon_edit.setPlaceholderText("Open ports, service versions, subdomains, tech stack, etc.")
        self._recon_edit.setMinimumHeight(5 * 22)
        self._recon_edit.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self._recon_edit.document().setDefaultTextOption(_ltr)
        self._recon_edit.setPlainText(recon_notes)
        layout.addWidget(self._recon_edit)

        # Important Notes
        layout.addWidget(_section_label("IMPORTANT NOTES"))
        self._important_edit = QPlainTextEdit()
        self._important_edit.setPlaceholderText("Scope restrictions, credentials, key observations, next steps...")
        self._important_edit.setMinimumHeight(5 * 22)
        self._important_edit.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self._important_edit.document().setDefaultTextOption(_ltr)
        self._important_edit.setPlainText(important_notes)
        layout.addWidget(self._important_edit)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_values(self) -> tuple[str, str, str]:
        return (
            self._exec_edit.toPlainText(),
            self._recon_edit.toPlainText(),
            self._important_edit.toPlainText(),
        )


# ---------------------------------------------------------------------------
# MainWindow
# ---------------------------------------------------------------------------

class FindingsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.sessions: list[Session] = []
        self.current_session: Session | None = None
        self.current_finding: Finding | None = None

        self._settings = storage.load_settings()
        self._vault_path: str = self._settings.get("vault_path", str(Path.home() / "AmosH"))

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        toolbar_widget = self._build_toolbar()
        root.addWidget(toolbar_widget)

        central = self._build_central()
        root.addWidget(central, 1)

        self._status_bar = QLabel("Ready")
        self._status_bar.setStyleSheet(
            "QLabel { background: #11111b; color: #6c7086; "
            "font-size: 11px; padding: 3px 8px; border-top: 1px solid #313244; }"
        )
        root.addWidget(self._status_bar)

        self.load_sessions()

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    def _build_toolbar(self) -> QWidget:
        bar = QWidget()
        bar.setStyleSheet("background: #11111b; border-bottom: 1px solid #313244;")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(6)

        session_lbl = QLabel("Session:")
        session_lbl.setStyleSheet("color: #a6adc8; font-size: 11px;")
        layout.addWidget(session_lbl)

        self._session_combo = QComboBox()
        self._session_combo.setMinimumWidth(200)
        self._session_combo.currentIndexChanged.connect(self.on_session_changed)
        layout.addWidget(self._session_combo)

        new_session_btn = QPushButton("New Session")
        new_session_btn.clicked.connect(self.new_session)
        layout.addWidget(new_session_btn)

        layout.addWidget(self._make_sep())

        new_finding_btn = QPushButton("+ Finding")
        new_finding_btn.clicked.connect(self.new_finding)
        layout.addWidget(new_finding_btn)

        layout.addWidget(self._make_sep())

        export_btn = QPushButton("Export Finding")
        export_btn.clicked.connect(self._export_finding)
        layout.addWidget(export_btn)

        session_notes_btn = QPushButton("Session Notes…")
        session_notes_btn.clicked.connect(self._open_session_notes)
        layout.addWidget(session_notes_btn)

        full_report_btn = QPushButton("Full Report")
        full_report_btn.clicked.connect(self._export_full_report)
        layout.addWidget(full_report_btn)

        layout.addStretch()
        return bar

    @staticmethod
    def _make_sep() -> QWidget:
        line = QWidget()
        line.setFixedSize(1, 20)
        line.setStyleSheet("background: #313244;")
        return line

    def _build_central(self) -> QWidget:
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        # Left panel
        left_container = QWidget()
        left_container.setMinimumWidth(200)
        left_layout = QVBoxLayout(left_container)
        left_layout.setContentsMargins(8, 8, 8, 8)

        self._finding_list = FindingListWidget()
        self._finding_list.finding_selected.connect(self.on_finding_selected)
        self._finding_list.new_finding_requested.connect(self.new_finding)
        self._finding_list.delete_finding_requested.connect(self.delete_finding)
        left_layout.addWidget(self._finding_list)

        # Center panel — stack: editor or empty state
        self._center_stack = QStackedWidget()

        self._empty_state = EmptyState(
            "Create your first session",
            "Use the toolbar to start a new session.",
        )
        self._center_stack.addWidget(self._empty_state)  # index 0

        self._editor = FindingEditor()
        self._editor.changed.connect(self._auto_save)
        self._center_stack.addWidget(self._editor)       # index 1

        # No-finding empty state (reuse class, different text)
        self._no_finding_state = EmptyState(
            "No finding selected",
            "Select a finding from the list or create a new one.",
        )
        self._center_stack.addWidget(self._no_finding_state)  # index 2

        self._center_stack.setCurrentIndex(0)

        # Right panel
        self._quick_panel = QuickPanel()
        self._quick_panel.setMinimumWidth(180)
        self._quick_panel.export_finding_requested.connect(self._export_finding)
        self._quick_panel.export_session_requested.connect(self._export_session)
        self._quick_panel.delete_finding_requested.connect(
            lambda: self.delete_finding(self.current_finding.id) if self.current_finding else None
        )
        self._quick_panel.vault_path_changed.connect(self._on_vault_path_changed)
        self._quick_panel.cvss_calculated.connect(self._on_cvss_calculated)
        self._quick_panel.set_vault_path(self._vault_path)

        splitter.addWidget(left_container)
        splitter.addWidget(self._center_stack)
        splitter.addWidget(self._quick_panel)

        splitter.setSizes([220, 660, 200])
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setStretchFactor(2, 0)

        return splitter

    def load_sessions(self):
        self.sessions = storage.load_sessions()
        self._session_combo.blockSignals(True)
        self._session_combo.clear()

        if not self.sessions:
            self.current_session = None
            self.current_finding = None
            self._finding_list.load_findings([])
            self._center_stack.setCurrentIndex(0)
        else:
            for s in self.sessions:
                self._session_combo.addItem(s.name, s.id)
            # Keep signals blocked through setCurrentIndex so it does NOT fire
            # on_session_changed automatically; call it exactly once below.
            self._session_combo.setCurrentIndex(0)
            self._session_combo.blockSignals(False)
            self.on_session_changed(0)
            return

        self._session_combo.blockSignals(False)

    def new_session(self):
        dlg = NewSessionDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        name, host = dlg.get_values()
        if not name:
            name = "New Engagement"
        session = Session(name=name, target_host=host)
        storage.save_session(session)
        self.load_sessions()

        # Select the new session (it will be first due to sort by created_at desc)
        for i in range(self._session_combo.count()):
            if self._session_combo.itemData(i) == session.id:
                self._session_combo.setCurrentIndex(i)
                break

        self._status_bar.setText(f"Session '{name}' created.")

    def on_session_changed(self, index: int):
        if index < 0 or index >= len(self.sessions):
            return
        sid = self._session_combo.itemData(index)
        for s in self.sessions:
            if s.id == sid:
                self.current_session = s
                break
        else:
            return

        self.current_finding = None
        self._finding_list.load_findings(self.current_session.findings)
        self._editor.clear()
        self._quick_panel.update_finding(None)

        if self.current_session.findings:
            self._center_stack.setCurrentIndex(2)  # no finding selected
        else:
            self._center_stack.setCurrentIndex(2)  # same — "no finding selected"

        self._status_bar.setText(f"Session: {self.current_session.name}  |  {len(self.current_session.findings)} finding(s)")

    # ------------------------------------------------------------------
    # Finding management
    # ------------------------------------------------------------------

    def new_finding(self):
        if self.current_session is None:
            QMessageBox.information(self, "No Session", "Please create a session first.")
            return
        finding = Finding()
        self.current_session.findings.append(finding)
        storage.save_session(self.current_session)
        self._finding_list.load_findings(self.current_session.findings)
        self._finding_list.select_finding(finding.id)
        self.current_finding = finding
        self._editor.load_finding(finding)
        self._quick_panel.update_finding(finding)
        self._center_stack.setCurrentIndex(1)
        self._status_bar.setText(f"New finding created — {finding.vuln_type}")

    def on_finding_selected(self, finding_id: str):
        if self.current_session is None:
            return
        for f in self.current_session.findings:
            if f.id == finding_id:
                self.current_finding = f
                self._editor.load_finding(f)
                self._quick_panel.update_finding(f)
                self._center_stack.setCurrentIndex(1)
                return

    def _auto_save(self):
        if self.current_finding is None or self.current_session is None:
            return
        self._editor.read_finding_into(self.current_finding)
        self.current_finding.updated_at = datetime.now().isoformat()
        storage.save_session(self.current_session)

        # Refresh list item text to reflect vuln_type/target changes.
        # Do NOT call select_finding here — that fires currentRowChanged which
        # calls on_finding_selected → load_finding, resetting the editor's
        # cursor and selection state on every keystroke.
        self._finding_list.load_findings(self.current_session.findings)

        # Update quick panel (severity/phase/status may have changed)
        self._quick_panel.update_finding(self.current_finding)

    def delete_finding(self, finding_id: str):
        if self.current_session is None:
            return
        was_selected = self.current_finding and self.current_finding.id == finding_id

        self.current_session.findings = [
            f for f in self.current_session.findings if f.id != finding_id
        ]
        storage.save_session(self.current_session)
        self._finding_list.load_findings(self.current_session.findings)

        if was_selected:
            self.current_finding = None
            self._editor.clear()
            self._quick_panel.update_finding(None)
            self._center_stack.setCurrentIndex(2)

        self._status_bar.setText("Finding deleted.")

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def _ensure_vault(self) -> bool:
        if not Path(self._vault_path).exists():
            QMessageBox.warning(
                self,
                "Vault Not Found",
                f"The vault path does not exist:\n{self._vault_path}\n\nPlease choose a valid directory.",
            )
            self._open_vault_settings()
            return False
        return True

    def _export_finding(self):
        if self.current_finding is None:
            QMessageBox.information(self, "No Finding", "Please select a finding to export.")
            return
        if self.current_session is None:
            return
        if not self._ensure_vault():
            return
        try:
            path = exporter.export_finding(self.current_finding, self.current_session, self._vault_path)
            QMessageBox.information(self, "Exported", f"Finding exported to:\n{path}")
            self._status_bar.setText(f"Exported: {path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))

    def _export_session(self):
        if self.current_session is None:
            QMessageBox.information(self, "No Session", "Please select a session first.")
            return
        if not self._ensure_vault():
            return
        try:
            path = exporter.export_session_summary(self.current_session, self._vault_path)
            QMessageBox.information(self, "Exported", f"Session summary exported to:\n{path}")
            self._status_bar.setText(f"Exported: {path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))

    def _on_cvss_calculated(self, score: float, vector: str):
        if self.current_finding is None or self.current_session is None:
            return
        self.current_finding.cvss_score = score
        self.current_finding.cvss_vector = vector
        # Derive severity from score
        if score >= 9.0:
            self.current_finding.severity = "Critical"
        elif score >= 7.0:
            self.current_finding.severity = "High"
        elif score >= 4.0:
            self.current_finding.severity = "Medium"
        elif score >= 0.1:
            self.current_finding.severity = "Low"
        else:
            self.current_finding.severity = "Informational"
        storage.save_session(self.current_session)
        self._editor.load_finding(self.current_finding)
        self._quick_panel.update_finding(self.current_finding)

    def _export_full_report(self):
        if not self._ensure_vault():
            return
        if self.current_session is None:
            QMessageBox.warning(self, "No Session", "Select or create a session first.")
            return
        path = exporter.generate_full_report(self.current_session, self._vault_path)
        QMessageBox.information(self, "Report Exported", f"Full report saved to:\n{path}")
        self._status_bar.setText(f"Report exported: {path}")

    # ------------------------------------------------------------------
    # Vault / settings
    # ------------------------------------------------------------------

    def _on_vault_path_changed(self, path: str):
        self._vault_path = path
        self._settings["vault_path"] = path
        storage.save_settings(self._settings)
        self._quick_panel.set_vault_path(path)
        self._status_bar.setText(f"Vault path updated: {path}")

    def _open_vault_settings(self):
        chosen = QFileDialog.getExistingDirectory(
            self,
            "Select Vault Directory",
            self._vault_path or str(Path.home()),
        )
        if chosen:
            self._on_vault_path_changed(chosen)

    # ------------------------------------------------------------------
    # Session Notes
    # ------------------------------------------------------------------

    def _open_session_notes(self):
        if self.current_session is None:
            QMessageBox.warning(self, "No Session", "Please create or select a session first.")
            return
        dlg = SessionNotesDialog(
            exec_summary=self.current_session.exec_summary,
            recon_notes=self.current_session.recon_notes,
            important_notes=self.current_session.important_notes,
            parent=self,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        exec_summary, recon_notes, important_notes = dlg.get_values()
        self.current_session.exec_summary = exec_summary
        self.current_session.recon_notes = recon_notes
        self.current_session.important_notes = important_notes
        storage.save_session(self.current_session)
        self._status_bar.setText("Session notes saved.")

    # ------------------------------------------------------------------
    # About
    # ------------------------------------------------------------------

    def _show_about(self):
        QMessageBox.information(
            self,
            "About PentestNotes",
            "PentestNotes\n\nA dark-themed pentesting note-taking tool.\n"
            "Exports findings as Obsidian-compatible Markdown.\n\n"
            "Built with PyQt6.",
        )


# ---------------------------------------------------------------------------
# PentestNotesApp — entry point
# ---------------------------------------------------------------------------

__all__ = ["FindingsTab"]
