"""
Cookie Jar — central tracker, editor, and injector for HTTP cookies.

The :class:`CookieJar` is a pure data model that:

* Observes :class:`~fracture.proxy.HttpResponse` objects, harvesting their
  ``Set-Cookie`` headers and indexing them by ``(host, name)``.
* Applies stored cookies (or manual overrides) to outbound request headers,
  matching on exact host or ``.tld`` suffix domains.

The :class:`CookieJarTab` widget is a Catppuccin Mocha themed editor over a
shared :class:`CookieJar` instance.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .proxy import HttpRequest, HttpResponse

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Catppuccin Mocha constants
# ---------------------------------------------------------------------------

_BG = "#1e1e2e"
_SURFACE = "#181825"
_OVERLAY = "#313244"
_HIGHLIGHT = "#45475a"
_TEXT = "#cdd6f4"
_MUTED = "#585b70"
_ACCENT = "#89b4fa"

_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
    "QPushButton:hover { background: #45475a; }"
    "QPushButton:disabled { color: #585b70; }"
)
_TABLE_SS = (
    "QTableWidget { background: #181825; gridline-color: #313244; color: #cdd6f4; "
    "selection-background-color: #45475a; selection-color: #cdd6f4; }"
    "QHeaderView::section { background: #313244; color: #cdd6f4; border: 0; padding: 4px; }"
)
_CHECK_SS = "QCheckBox { color: #cdd6f4; padding: 2px 6px; }"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class CookieEntry:
    """A single observed (or overridden) cookie."""

    host: str
    name: str
    value: str
    path: str = "/"
    secure: bool = False
    httponly: bool = False
    samesite: str = ""
    expires: str = ""
    override_value: Optional[str] = None
    last_seen: datetime = field(default_factory=datetime.now)

    @property
    def effective_value(self) -> str:
        """Return the override value when present, otherwise the observed value."""
        return self.override_value if self.override_value is not None else self.value

    def to_dict(self) -> dict:
        d = asdict(self)
        d["last_seen"] = self.last_seen.isoformat(timespec="seconds")
        d["effective_value"] = self.effective_value
        return d


def _parse_set_cookie(raw_value: str, default_host: str) -> Optional[CookieEntry]:
    """Parse a single ``Set-Cookie`` header value into a :class:`CookieEntry`."""
    if not raw_value:
        return None
    parts = [p.strip() for p in raw_value.split(";") if p.strip()]
    if not parts:
        return None
    head = parts[0]
    if "=" not in head:
        return None
    name, _, value = head.partition("=")
    name = name.strip()
    value = value.strip()
    if not name:
        return None

    entry = CookieEntry(host=default_host, name=name, value=value)

    for attr in parts[1:]:
        if "=" in attr:
            k, _, v = attr.partition("=")
            k_l = k.strip().lower()
            v = v.strip()
            if k_l == "domain":
                entry.host = v.lstrip(".") or default_host
            elif k_l == "path":
                entry.path = v or "/"
            elif k_l == "expires":
                entry.expires = v
            elif k_l == "max-age":
                entry.expires = f"Max-Age={v}"
            elif k_l == "samesite":
                entry.samesite = v
        else:
            flag = attr.lower()
            if flag == "secure":
                entry.secure = True
            elif flag == "httponly":
                entry.httponly = True

    return entry


def _split_set_cookie_header(value: str) -> list[str]:
    """Split a (possibly comma-joined) Set-Cookie header into individual cookies.

    Naive comma-splitting breaks dates like ``Expires=Wed, 09 Jun 2021 ...``;
    we therefore only split on commas that appear to introduce a new name=val
    pair, i.e. ``, name=`` with no equals inside the preceding fragment.
    """
    if not value:
        return []
    pieces: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(value)
    while i < n:
        ch = value[i]
        if ch == "," and "=" in "".join(buf):
            # Lookahead: is this the start of a new "name=" segment?
            j = i + 1
            while j < n and value[j] == " ":
                j += 1
            k = j
            while k < n and value[k] not in ";=,":
                k += 1
            if k < n and value[k] == "=":
                pieces.append("".join(buf).strip())
                buf = []
                i = j
                continue
        buf.append(ch)
        i += 1
    if buf:
        pieces.append("".join(buf).strip())
    return [p for p in pieces if p]


def _host_matches(cookie_host: str, request_host: str) -> bool:
    """Return True if a cookie scoped to ``cookie_host`` should apply to ``request_host``."""
    if not cookie_host or not request_host:
        return False
    c = cookie_host.lower().lstrip(".")
    h = request_host.lower()
    if c == h:
        return True
    return h.endswith("." + c)


class CookieJar:
    """Central, in-memory cookie store.

    Cookies are keyed by ``(host, name)`` so the jar can hold the same name
    for multiple hosts (e.g. ``session`` on two different APIs) without
    collision.
    """

    def __init__(self) -> None:
        self._cookies: dict[tuple[str, str], CookieEntry] = {}
        self.inject_enabled: bool = True

    # ------------------------------------------------------------------
    # Observation
    # ------------------------------------------------------------------

    def observe(self, req: HttpRequest, resp: HttpResponse) -> None:
        """Harvest ``Set-Cookie`` headers from ``resp`` into the jar."""
        if resp is None or not resp.headers:
            return
        host = (req.host or "").lower()

        for k, v in resp.headers.items():
            if k.lower() != "set-cookie":
                continue
            for raw in _split_set_cookie_header(v):
                entry = _parse_set_cookie(raw, default_host=host)
                if entry is None:
                    continue
                key = (entry.host.lower(), entry.name)
                existing = self._cookies.get(key)
                if existing is not None:
                    # Preserve any manual override across re-observation.
                    entry = replace(
                        entry,
                        override_value=existing.override_value,
                    )
                self._cookies[key] = entry

    # ------------------------------------------------------------------
    # Injection
    # ------------------------------------------------------------------

    def apply_to_outbound(
        self, host: str, headers: dict[str, str]
    ) -> dict[str, str]:
        """Return a *new* headers dict with jar cookies merged into ``Cookie``.

        Existing cookies in the request take precedence unless a manual
        override has been set for that ``(host, name)`` via
        :meth:`set_override`.
        """
        new_headers = dict(headers)
        if not self.inject_enabled or not host:
            return new_headers

        # Locate the existing Cookie header (case-insensitive) so we can
        # preserve its original casing.
        cookie_key = "Cookie"
        existing_value = ""
        for k, v in new_headers.items():
            if k.lower() == "cookie":
                cookie_key = k
                existing_value = v
                break

        existing_pairs: dict[str, str] = {}
        order: list[str] = []
        for part in existing_value.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            name, _, value = part.partition("=")
            name = name.strip()
            if not name:
                continue
            if name not in existing_pairs:
                order.append(name)
            existing_pairs[name] = value.strip()

        # Merge applicable jar cookies.
        for (chost, cname), entry in self._cookies.items():
            if not _host_matches(chost, host):
                continue
            has_override = entry.override_value is not None
            if cname in existing_pairs and not has_override:
                # Request-supplied value wins unless overridden.
                continue
            if cname not in existing_pairs:
                order.append(cname)
            existing_pairs[cname] = entry.effective_value

        if existing_pairs:
            merged = "; ".join(f"{n}={existing_pairs[n]}" for n in order)
            new_headers[cookie_key] = merged

        return new_headers

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def entries(self) -> list[dict]:
        """Return a snapshot list of all cookies for UI display."""
        return [e.to_dict() for e in self._cookies.values()]

    def set_override(self, host: str, name: str, value: str) -> None:
        """Force ``value`` as the effective value for ``(host, name)``.

        If no entry exists yet, one is created so the override has somewhere
        to live.
        """
        key = (host.lower(), name)
        entry = self._cookies.get(key)
        if entry is None:
            entry = CookieEntry(host=host.lower(), name=name, value=value)
        entry.override_value = value
        self._cookies[key] = entry

    def delete(self, host: str, name: str) -> bool:
        """Remove a cookie from the jar. Returns True if anything was deleted."""
        key = (host.lower(), name)
        return self._cookies.pop(key, None) is not None

    def clear(self) -> None:
        """Wipe every cookie."""
        self._cookies.clear()


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

_COLUMNS = ("Host", "Name", "Value", "Secure", "HttpOnly", "SameSite", "Expires")


class CookieJarTab(QWidget):
    """Editor widget over a shared :class:`CookieJar`."""

    def __init__(
        self,
        jar: CookieJar,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._jar = jar
        self._loading = False
        self._setup_ui()
        self.refresh()

    # ------------------------------------------------------------------
    # Public hooks
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """Rebuild the table from the underlying jar."""
        self._loading = True
        try:
            entries = self._jar.entries()
            self._table.setRowCount(len(entries))
            for row, e in enumerate(entries):
                items = [
                    QTableWidgetItem(e["host"]),
                    QTableWidgetItem(e["name"]),
                    QTableWidgetItem(e["effective_value"]),
                    QTableWidgetItem("yes" if e["secure"] else ""),
                    QTableWidgetItem("yes" if e["httponly"] else ""),
                    QTableWidgetItem(e["samesite"]),
                    QTableWidgetItem(e["expires"]),
                ]
                for col, item in enumerate(items):
                    if col != 2:  # only Value is editable
                        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    if col == 2 and e.get("override_value") is not None:
                        item.setForeground(Qt.GlobalColor.yellow)
                    self._table.setItem(row, col, item)
        finally:
            self._loading = False

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(6)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setStyleSheet(_BTN_SS)
        refresh_btn.clicked.connect(self.refresh)
        toolbar.addWidget(refresh_btn)

        del_btn = QPushButton("Delete Selected")
        del_btn.setStyleSheet(_BTN_SS)
        del_btn.clicked.connect(self._delete_selected)
        toolbar.addWidget(del_btn)

        clear_btn = QPushButton("Clear All")
        clear_btn.setStyleSheet(_BTN_SS)
        clear_btn.clicked.connect(self._clear_all)
        toolbar.addWidget(clear_btn)

        self._inject_check = QCheckBox("Inject on outbound")
        self._inject_check.setChecked(self._jar.inject_enabled)
        self._inject_check.setStyleSheet(_CHECK_SS)
        self._inject_check.stateChanged.connect(self._on_inject_toggled)
        toolbar.addWidget(self._inject_check)

        toolbar.addStretch(1)
        root.addLayout(toolbar)

        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(list(_COLUMNS))
        self._table.setStyleSheet(_TABLE_SS)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(False)
        self._table.verticalHeader().setVisible(False)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._table.itemChanged.connect(self._on_item_changed)
        root.addWidget(self._table, 1)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_inject_toggled(self, _state: int) -> None:
        self._jar.inject_enabled = self._inject_check.isChecked()

    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        if self._loading or item.column() != 2:
            return
        row = item.row()
        host_item = self._table.item(row, 0)
        name_item = self._table.item(row, 1)
        if host_item is None or name_item is None:
            return
        self._jar.set_override(host_item.text(), name_item.text(), item.text())

    def _delete_selected(self) -> None:
        rows = sorted({i.row() for i in self._table.selectedItems()}, reverse=True)
        if not rows:
            return
        for row in rows:
            host_item = self._table.item(row, 0)
            name_item = self._table.item(row, 1)
            if host_item is None or name_item is None:
                continue
            self._jar.delete(host_item.text(), name_item.text())
        self.refresh()

    def _clear_all(self) -> None:
        self._jar.clear()
        self.refresh()
