"""
Fracture Dashboard tab — overview panel with live stats and quick-launch buttons.
"""

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 6px 16px; border-radius: 6px; color: #cdd6f4; font-size: 12px; }"
    "QPushButton:hover { background: #45475a; }"
)

_CARD_SS = (
    "QFrame {{ background: #313244; border: 1px solid #45475a; "
    "border-radius: 8px; padding: 8px; }}"
)

_LIST_SS = (
    "QListWidget { background: #181825; border: 1px solid #313244; color: #cdd6f4; }"
    "QListWidget::item:selected { background: #45475a; }"
)


def _stat_card(title: str, color: str) -> tuple[QFrame, QLabel]:
    """Return (card_frame, value_label) pair styled as a stat card."""
    card = QFrame()
    card.setStyleSheet(
        f"QFrame {{ background: #313244; border: 1px solid #45475a; border-radius: 8px; }}"
    )
    card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
    card.setMinimumHeight(80)

    layout = QVBoxLayout(card)
    layout.setContentsMargins(12, 8, 12, 8)
    layout.setSpacing(4)

    title_lbl = QLabel(title)
    title_lbl.setStyleSheet("color: #a6adc8; font-size: 11px; border: none;")
    title_lbl.setAlignment(Qt.AlignmentFlag.AlignLeft)
    layout.addWidget(title_lbl)

    value_lbl = QLabel("0")
    value_lbl.setFont(QFont("Monospace", 22, QFont.Weight.Bold))
    value_lbl.setStyleSheet(f"color: {color}; border: none;")
    value_lbl.setAlignment(Qt.AlignmentFlag.AlignLeft)
    layout.addWidget(value_lbl)

    return card, value_lbl


def _severity_card() -> tuple[QFrame, QLabel, QLabel, QLabel]:
    """Return (frame, high_lbl, med_lbl, low_lbl)."""
    card = QFrame()
    card.setStyleSheet(
        "QFrame { background: #313244; border: 1px solid #45475a; border-radius: 8px; }"
    )
    card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
    card.setMinimumHeight(80)

    layout = QVBoxLayout(card)
    layout.setContentsMargins(12, 8, 12, 8)
    layout.setSpacing(4)

    title_lbl = QLabel("Severity Breakdown")
    title_lbl.setStyleSheet("color: #a6adc8; font-size: 11px; border: none;")
    layout.addWidget(title_lbl)

    counts_row = QHBoxLayout()
    counts_row.setSpacing(12)

    def _badge(text: str, color: str) -> tuple[QLabel, QLabel]:
        wrap = QWidget()
        wrap.setStyleSheet("background: transparent;")
        wl = QHBoxLayout(wrap)
        wl.setContentsMargins(0, 0, 0, 0)
        wl.setSpacing(4)
        tag = QLabel(text)
        tag.setStyleSheet(
            f"color: {color}; font-size: 9px; font-weight: bold; border: none; "
            f"background: transparent;"
        )
        val = QLabel("0")
        val.setFont(QFont("Monospace", 16, QFont.Weight.Bold))
        val.setStyleSheet(f"color: {color}; border: none; background: transparent;")
        wl.addWidget(tag)
        wl.addWidget(val)
        return wrap, val

    h_wrap, high_lbl = _badge("HIGH", "#f38ba8")
    m_wrap, med_lbl = _badge("MED", "#fab387")
    l_wrap, low_lbl = _badge("LOW", "#f9e2af")

    counts_row.addWidget(h_wrap)
    counts_row.addWidget(m_wrap)
    counts_row.addWidget(l_wrap)
    counts_row.addStretch()
    layout.addLayout(counts_row)

    return card, high_lbl, med_lbl, low_lbl


class DashboardTab(QWidget):
    """Dashboard overview: live stats, recent requests, quick-launch buttons."""

    open_tab = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._recent_entries: list[tuple] = []
        self._setup_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(14)

        # ── Title ───────────────────────────────────────────────────────
        title = QLabel("Fracture Dashboard")
        title.setFont(QFont("Monospace", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #cba6f7;")
        root.addWidget(title)

        # ── Stats cards row ─────────────────────────────────────────────
        cards_row = QHBoxLayout()
        cards_row.setSpacing(10)

        req_card, self._req_count_lbl = _stat_card("Requests Proxied", "#89b4fa")
        findings_card, self._findings_count_lbl = _stat_card("Total Findings", "#cba6f7")
        sev_card, self._high_lbl, self._med_lbl, self._low_lbl = _severity_card()
        scan_card, self._scan_lbl = _stat_card("Active Scans", "#a6e3a1")

        cards_row.addWidget(req_card)
        cards_row.addWidget(findings_card)
        cards_row.addWidget(sev_card)
        cards_row.addWidget(scan_card)
        root.addLayout(cards_row)

        # ── Recent requests ─────────────────────────────────────────────
        recent_lbl = QLabel("Recent Requests")
        recent_lbl.setStyleSheet("color: #a6adc8; font-size: 11px; font-weight: bold;")
        root.addWidget(recent_lbl)

        self._recent_list = QListWidget()
        self._recent_list.setFont(QFont("Monospace", 9))
        self._recent_list.setStyleSheet(_LIST_SS)
        self._recent_list.setMaximumHeight(180)
        root.addWidget(self._recent_list)

        # ── Quick-launch buttons ────────────────────────────────────────
        ql_lbl = QLabel("Quick Launch")
        ql_lbl.setStyleSheet("color: #a6adc8; font-size: 11px; font-weight: bold;")
        root.addWidget(ql_lbl)

        ql_row = QHBoxLayout()
        ql_row.setSpacing(8)

        for label, tab_name in [
            ("New Repeater Tab", "Repeater"),
            ("Start Active Scanner", "Scanner"),
            ("Open Intruder", "Intruder"),
        ]:
            btn = QPushButton(label)
            btn.setStyleSheet(_BTN_SS)
            btn.clicked.connect(lambda _, t=tab_name: self.open_tab.emit(t))
            ql_row.addWidget(btn)

        ql_row.addStretch()
        root.addLayout(ql_row)
        root.addStretch()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update_stats(self, history_count: int, findings: list) -> None:
        """Refresh stat cards. Call whenever history or findings change."""
        self._req_count_lbl.setText(str(history_count))
        self._findings_count_lbl.setText(str(len(findings)))

        high = sum(1 for f in findings if getattr(f, "severity", "") == "HIGH")
        med = sum(1 for f in findings if getattr(f, "severity", "") == "MEDIUM")
        low = sum(1 for f in findings if getattr(f, "severity", "") == "LOW")
        self._high_lbl.setText(str(high))
        self._med_lbl.setText(str(med))
        self._low_lbl.setText(str(low))

    def add_history_entry(self, req, resp) -> None:
        """Push a new proxy entry into the recent requests list (keeps last 10)."""
        self._recent_entries.append((req, resp))
        if len(self._recent_entries) > 10:
            self._recent_entries.pop(0)
        self._rebuild_recent_list()

    def set_active_scans(self, count: int) -> None:
        self._scan_lbl.setText(str(count))

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _rebuild_recent_list(self) -> None:
        self._recent_list.clear()
        for req, resp in self._recent_entries:
            code = getattr(resp, "status_code", "---") if resp else "---"
            method = getattr(req, "method", "?")
            host = getattr(req, "host", "?")
            path = getattr(req, "path", "/")
            item = QListWidgetItem(f"[{code}] {method} {host}{path}")
            self._recent_list.addItem(item)
        self._recent_list.scrollToBottom()
