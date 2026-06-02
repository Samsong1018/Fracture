"""
InspectorWidget — structured HTTP message inspector.

Shows parsed HTTP fields in four tabs: Query Params, Headers, Cookies, Body.
Each tab is an editable QTableWidget. Edits reconstruct and emit the modified
raw HTTP message via the `content_modified(bytes)` signal.
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

# ---------------------------------------------------------------------------
# Stylesheet (Catppuccin Mocha)
# ---------------------------------------------------------------------------

_TABLE_STYLE = (
    "QTableWidget { background: #181825; border: 1px solid #313244; "
    "gridline-color: #313244; } "
    "QTableWidget::item:selected { background: #45475a; } "
    "QHeaderView::section { background: #313244; color: #cdd6f4; "
    "padding: 4px; border: none; }"
)

_TAB_STYLE = (
    "QTabWidget::pane { border: 1px solid #313244; background: #1e1e2e; }"
    "QTabBar::tab { background: #181825; color: #a6adc8; padding: 4px 12px; "
    "border: 1px solid #313244; border-bottom: none; margin-right: 2px; }"
    "QTabBar::tab:selected { background: #313244; color: #cdd6f4; }"
    "QTabBar::tab:hover { background: #45475a; color: #cdd6f4; }"
)

_LABEL_STYLE = "color: #585b70; font-size: 10px;"


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _parse_http_message(raw: bytes) -> dict:
    """
    Parse a raw HTTP message into its components.

    Returns a dict with keys:
        request_line  : str   (e.g. "GET /path?foo=bar HTTP/1.1")
        headers_raw   : list[tuple[str, str]]  (ordered, preserving case)
        body          : bytes
    """
    # Normalise line endings
    text = raw.replace(b"\r\n", b"\n")
    if b"\n\n" in text:
        head_part, body = text.split(b"\n\n", 1)
    else:
        head_part = text
        body = b""

    lines = head_part.decode(errors="replace").splitlines()
    if not lines:
        return {
            "request_line": "",
            "headers_raw": [],
            "body": body,
        }

    request_line = lines[0]
    headers_raw: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" in line:
            name, _, value = line.partition(":")
            headers_raw.append((name.strip(), value.strip()))

    return {
        "request_line": request_line,
        "headers_raw": headers_raw,
        "body": body,
    }


def _extract_query_params(request_line: str) -> list[tuple[str, str]]:
    """Extract query parameters from the request-line URL."""
    parts = request_line.split(" ", 2)
    if len(parts) < 2:
        return []
    url_part = parts[1]
    parsed = urlparse(url_part)
    return parse_qsl(parsed.query, keep_blank_values=True)


def _extract_cookies(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Parse all Cookie header values into key=value pairs."""
    cookies: list[tuple[str, str]] = []
    for name, value in headers:
        if name.lower() == "cookie":
            for pair in value.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    cookies.append((k.strip(), v.strip()))
                elif pair:
                    cookies.append((pair, ""))
    return cookies


def _get_content_type(headers: list[tuple[str, str]]) -> str:
    for name, value in headers:
        if name.lower() == "content-type":
            return value.lower()
    return ""


def _parse_body(body: bytes, content_type: str) -> list[tuple[str, str]]:
    """Parse the body into (name, value) rows."""
    if "application/x-www-form-urlencoded" in content_type:
        try:
            text = body.decode(errors="replace")
            return parse_qsl(text, keep_blank_values=True)
        except Exception:
            pass
    # Raw body — single row with empty key
    return [("", body.decode(errors="replace"))]


# ---------------------------------------------------------------------------
# Reconstruction helpers
# ---------------------------------------------------------------------------

def _rebuild_request_line_with_params(
    request_line: str, params: list[tuple[str, str]]
) -> str:
    """Rebuild the request line URL with updated query parameters."""
    parts = request_line.split(" ", 2)
    if len(parts) < 2:
        return request_line
    method = parts[0]
    url_part = parts[1]
    version = parts[2] if len(parts) > 2 else "HTTP/1.1"

    parsed = urlparse(url_part)
    new_query = urlencode(params)
    new_parsed = parsed._replace(query=new_query)
    new_url = urlunparse(new_parsed)
    return f"{method} {new_url} {version}"


def _rebuild_raw(
    request_line: str,
    headers: list[tuple[str, str]],
    body: bytes,
) -> bytes:
    """Reconstruct a raw HTTP message from parsed components."""
    lines = [request_line]
    for name, value in headers:
        lines.append(f"{name}: {value}")
    head = "\r\n".join(lines) + "\r\n\r\n"
    return head.encode() + body


def _rebuild_cookies_header(cookies: list[tuple[str, str]]) -> str:
    """Rebuild Cookie header value from parsed pairs."""
    parts = []
    for k, v in cookies:
        if k:
            parts.append(f"{k}={v}" if v else k)
        elif v:
            parts.append(v)
    return "; ".join(parts)


def _rebuild_body_from_rows(
    rows: list[tuple[str, str]], content_type: str
) -> bytes:
    """Reconstruct body bytes from edited table rows."""
    if "application/x-www-form-urlencoded" in content_type:
        params = [(k, v) for k, v in rows if k]
        return urlencode(params).encode()
    # Raw body: join all values (usually just one row with key="")
    return "".join(v for _, v in rows).encode()


# ---------------------------------------------------------------------------
# _ParamTable — an editable two-column table
# ---------------------------------------------------------------------------

class _ParamTable(QTableWidget):
    """A two-column (Name / Value) editable table widget."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(0, 2, parent)
        self.setHorizontalHeaderLabels(["Name", "Value"])
        self.horizontalHeader().setStretchLastSection(True)
        self.setFont(QFont("Monospace", 9))
        self.setStyleSheet(_TABLE_STYLE)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setAlternatingRowColors(False)

    def load_rows(self, rows: list[tuple[str, str]]) -> None:
        """Populate the table with (name, value) rows."""
        self.blockSignals(True)
        self.setRowCount(0)
        for name, value in rows:
            row = self.rowCount()
            self.insertRow(row)
            name_item = QTableWidgetItem(name)
            value_item = QTableWidgetItem(value)
            name_item.setFlags(
                Qt.ItemFlag.ItemIsEnabled
                | Qt.ItemFlag.ItemIsSelectable
                | Qt.ItemFlag.ItemIsEditable
            )
            value_item.setFlags(
                Qt.ItemFlag.ItemIsEnabled
                | Qt.ItemFlag.ItemIsSelectable
                | Qt.ItemFlag.ItemIsEditable
            )
            self.setItem(row, 0, name_item)
            self.setItem(row, 1, value_item)
        self.blockSignals(False)

    def get_rows(self) -> list[tuple[str, str]]:
        """Return current table contents as (name, value) pairs."""
        rows: list[tuple[str, str]] = []
        for r in range(self.rowCount()):
            name_item = self.item(r, 0)
            value_item = self.item(r, 1)
            name = name_item.text() if name_item else ""
            value = value_item.text() if value_item else ""
            rows.append((name, value))
        return rows


# ---------------------------------------------------------------------------
# InspectorWidget
# ---------------------------------------------------------------------------

class InspectorWidget(QWidget):
    """
    Structured HTTP message inspector with four editable tabs.

    Signals:
        content_modified(bytes): emitted when any cell is edited, carries the
                                 reconstructed raw HTTP message.
    """

    content_modified = pyqtSignal(bytes)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)

        # Internal state
        self._request_line: str = ""
        self._headers: list[tuple[str, str]] = []
        self._body: bytes = b""
        self._content_type: str = ""
        self._is_request: bool = True
        self._updating: bool = False  # re-entrancy guard

        self._setup_ui()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        header_bar = QHBoxLayout()
        header_bar.setContentsMargins(4, 2, 4, 2)
        lbl = QLabel("Inspector")
        lbl.setStyleSheet(_LABEL_STYLE)
        header_bar.addWidget(lbl)
        header_bar.addStretch()
        root.addLayout(header_bar)

        self._tabs = QTabWidget()
        self._tabs.setStyleSheet(_TAB_STYLE)
        root.addWidget(self._tabs)

        self._query_table = _ParamTable()
        self._headers_table = _ParamTable()
        self._cookies_table = _ParamTable()
        self._body_table = _ParamTable()

        self._tabs.addTab(self._query_table, "Query Params")
        self._tabs.addTab(self._headers_table, "Headers")
        self._tabs.addTab(self._cookies_table, "Cookies")
        self._tabs.addTab(self._body_table, "Body")

        # Connect cell edits to the reconstruction handler
        self._query_table.cellChanged.connect(self._on_query_changed)
        self._headers_table.cellChanged.connect(self._on_headers_changed)
        self._cookies_table.cellChanged.connect(self._on_cookies_changed)
        self._body_table.cellChanged.connect(self._on_body_changed)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self, raw_bytes: bytes, is_request: bool = True) -> None:
        """Parse *raw_bytes* and populate all four tabs."""
        self._is_request = is_request
        self._updating = True
        try:
            parsed = _parse_http_message(raw_bytes)
            self._request_line = parsed["request_line"]
            self._headers = list(parsed["headers_raw"])
            self._body = parsed["body"]
            self._content_type = _get_content_type(self._headers)

            # Query params (requests only)
            if is_request:
                query_rows = _extract_query_params(self._request_line)
            else:
                query_rows = []
            self._query_table.load_rows(query_rows)

            # Headers
            self._headers_table.load_rows(self._headers)

            # Cookies
            cookie_rows = _extract_cookies(self._headers)
            self._cookies_table.load_rows(cookie_rows)

            # Body
            body_rows = _parse_body(self._body, self._content_type)
            self._body_table.load_rows(body_rows)
        finally:
            self._updating = False

    def clear(self) -> None:
        """Clear all tabs and internal state."""
        self._updating = True
        try:
            self._request_line = ""
            self._headers = []
            self._body = b""
            self._content_type = ""
            self._query_table.load_rows([])
            self._headers_table.load_rows([])
            self._cookies_table.load_rows([])
            self._body_table.load_rows([])
        finally:
            self._updating = False

    # ------------------------------------------------------------------
    # Cell-change handlers — each reconstructs and emits the raw message
    # ------------------------------------------------------------------

    def _on_query_changed(self, row: int, col: int) -> None:
        if self._updating:
            return
        params = self._query_table.get_rows()
        self._request_line = _rebuild_request_line_with_params(
            self._request_line, params
        )
        self._emit_reconstructed()

    def _on_headers_changed(self, row: int, col: int) -> None:
        if self._updating:
            return
        self._headers = self._headers_table.get_rows()
        self._content_type = _get_content_type(self._headers)
        # Keep cookies tab in sync: re-derive from updated headers
        self._updating = True
        try:
            self._cookies_table.load_rows(_extract_cookies(self._headers))
        finally:
            self._updating = False
        self._emit_reconstructed()

    def _on_cookies_changed(self, row: int, col: int) -> None:
        if self._updating:
            return
        new_cookie_value = _rebuild_cookies_header(self._cookies_table.get_rows())
        # Update the Cookie header in self._headers in-place
        updated = False
        new_headers: list[tuple[str, str]] = []
        for name, value in self._headers:
            if name.lower() == "cookie":
                if new_cookie_value:
                    new_headers.append((name, new_cookie_value))
                updated = True
            else:
                new_headers.append((name, value))
        if not updated and new_cookie_value:
            new_headers.append(("Cookie", new_cookie_value))
        self._headers = new_headers
        # Keep headers table in sync
        self._updating = True
        try:
            self._headers_table.load_rows(self._headers)
        finally:
            self._updating = False
        self._emit_reconstructed()

    def _on_body_changed(self, row: int, col: int) -> None:
        if self._updating:
            return
        rows = self._body_table.get_rows()
        self._body = _rebuild_body_from_rows(rows, self._content_type)
        # Update Content-Length header if present
        new_length = str(len(self._body))
        new_headers: list[tuple[str, str]] = []
        for name, value in self._headers:
            if name.lower() == "content-length":
                new_headers.append((name, new_length))
            else:
                new_headers.append((name, value))
        self._headers = new_headers
        self._updating = True
        try:
            self._headers_table.load_rows(self._headers)
        finally:
            self._updating = False
        self._emit_reconstructed()

    # ------------------------------------------------------------------
    # Reconstruction
    # ------------------------------------------------------------------

    def _emit_reconstructed(self) -> None:
        raw = _rebuild_raw(self._request_line, self._headers, self._body)
        self.content_modified.emit(raw)
