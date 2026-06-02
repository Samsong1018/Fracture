"""
multipart_editor — parse, edit, and re-serialize ``multipart/form-data`` bodies.

Exposes:
  * :func:`parse_multipart`  — robust parser tolerant of missing trailing CRLF,
    mixed line endings, absent filename, and missing per-part Content-Type.
  * :func:`serialize_multipart` — rebuild a raw multipart body from parsed parts.
  * :class:`MultipartEditorDialog` — PyQt6 dialog for inspecting and editing
    individual parts. After ``accept()``, callers read the new body via
    :py:meth:`MultipartEditorDialog.serialized` and the boundary via
    :py:meth:`MultipartEditorDialog.boundary`.

Each part is represented as a ``dict`` with keys:
    ``name``          : str   — form field name (from Content-Disposition)
    ``filename``      : str   — filename (empty string if not a file part)
    ``content_type``  : str   — per-part Content-Type (empty if absent)
    ``headers``       : dict[str, str] — any *additional* part headers
    ``body``          : bytes — the raw part body (no trailing CRLF)
"""

from __future__ import annotations

import re
import secrets
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


# ---------------------------------------------------------------------------
# Stylesheet (Catppuccin Mocha) — mirrors the rest of the suite
# ---------------------------------------------------------------------------

_DIALOG_SS = "QDialog { background: #1e1e2e; color: #cdd6f4; }"
_LABEL_SS = "color: #585b70; font-size: 10px;"
_TEXTEDIT_SS = (
    "QTextEdit { background: #181825; border: 1px solid #313244; "
    "color: #cdd6f4; }"
)
_TABLE_SS = (
    "QTableWidget { background: #181825; border: 1px solid #313244; "
    "gridline-color: #313244; color: #cdd6f4; } "
    "QTableWidget::item:selected { background: #45475a; } "
    "QHeaderView::section { background: #313244; color: #cdd6f4; "
    "padding: 4px; border: none; }"
)
_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
    "QPushButton:hover { background: #45475a; }"
    "QPushButton:disabled { color: #585b70; }"
    "QPushButton:checked { background: #45475a; border: 1px solid #89b4fa; }"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BOUNDARY_RE = re.compile(rb'boundary=("([^"]+)"|([^;,\s]+))', re.IGNORECASE)
_DISP_PARAM_RE = re.compile(
    r'(?P<key>[a-zA-Z0-9_-]+)\s*=\s*("(?P<qval>[^"]*)"|(?P<val>[^;]+))'
)


def _extract_boundary(content_type: str) -> str:
    """
    Pull the boundary token out of a Content-Type header value.

    Returns an empty string if no boundary is present.
    """
    if not content_type:
        return ""
    match = _BOUNDARY_RE.search(content_type.encode("latin-1", "replace"))
    if not match:
        return ""
    if match.group(2) is not None:
        return match.group(2).decode("latin-1", "replace")
    if match.group(3) is not None:
        return match.group(3).decode("latin-1", "replace")
    return ""


def _normalise_eol(body: bytes) -> bytes:
    """
    Normalise lone ``\\n`` and lone ``\\r`` line endings to ``\\r\\n`` so the
    boundary scanner and header parser behave consistently regardless of how
    the original request was encoded.
    """
    if not body:
        return body
    # First, convert CRLF -> LF, then any remaining CR -> LF, then LF -> CRLF.
    # This is robust against mixed encodings without double-conversion.
    tmp = body.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return tmp.replace(b"\n", b"\r\n")


def _parse_disposition_params(value: str) -> dict[str, str]:
    """Extract ``name`` and ``filename`` (and any others) from a Content-Disposition value."""
    params: dict[str, str] = {}
    for match in _DISP_PARAM_RE.finditer(value):
        key = match.group("key").lower()
        val = match.group("qval")
        if val is None:
            val = (match.group("val") or "").strip()
        params[key] = val
    return params


def _parse_part_headers(raw_headers: bytes) -> tuple[dict[str, str], str, str, str]:
    """
    Parse a part's header block.

    Returns: (extra_headers, name, filename, content_type)
    ``extra_headers`` excludes the canonical Content-Disposition and
    Content-Type entries since those are stored in dedicated keys.
    """
    text = raw_headers.decode("latin-1", "replace")
    name = ""
    filename = ""
    content_type = ""
    extras: dict[str, str] = {}

    for line in text.split("\r\n"):
        if not line or ":" not in line:
            continue
        header_name, _, header_value = line.partition(":")
        header_name = header_name.strip()
        header_value = header_value.strip()
        lower = header_name.lower()
        if lower == "content-disposition":
            params = _parse_disposition_params(header_value)
            name = params.get("name", "")
            filename = params.get("filename", "")
        elif lower == "content-type":
            content_type = header_value
        else:
            extras[header_name] = header_value
    return extras, name, filename, content_type


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_multipart(body: bytes, content_type: str) -> list[dict]:
    """
    Parse a ``multipart/form-data`` body into a list of part dicts.

    Robust to:
      * missing final CRLF before the closing boundary
      * lone-LF or lone-CR line endings
      * parts with no ``filename`` and/or no ``Content-Type``
      * preamble or epilogue bytes outside the boundary markers
    """
    boundary = _extract_boundary(content_type)
    if not boundary or not body:
        return []

    delimiter = b"--" + boundary.encode("latin-1", "replace")
    normalised = _normalise_eol(body)

    # Split on the delimiter. The first segment is the preamble; everything
    # afterwards is either a part or the closing marker.
    chunks = normalised.split(delimiter)
    if len(chunks) < 2:
        return []

    parts: list[dict] = []
    # Skip the preamble (chunks[0]). Walk subsequent chunks until we either
    # see the closing "--" marker or run out.
    for chunk in chunks[1:]:
        if chunk.startswith(b"--"):
            # closing delimiter
            break
        # A well-formed chunk begins with CRLF (line after boundary) and
        # ends with CRLF (line before next boundary). Strip those if present.
        if chunk.startswith(b"\r\n"):
            chunk = chunk[2:]
        if chunk.endswith(b"\r\n"):
            chunk = chunk[:-2]

        # Split header block / body
        if b"\r\n\r\n" in chunk:
            header_block, _, part_body = chunk.partition(b"\r\n\r\n")
        else:
            # Malformed part with no header terminator — treat the whole chunk
            # as headers and the body as empty.
            header_block, part_body = chunk, b""

        extras, name, filename, part_ct = _parse_part_headers(header_block)
        parts.append(
            {
                "name": name,
                "filename": filename,
                "content_type": part_ct,
                "headers": extras,
                "body": part_body,
            }
        )
    return parts


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def serialize_multipart(parts: list[dict], boundary: str) -> bytes:
    """
    Reconstruct a raw ``multipart/form-data`` body.

    The output ends with the closing ``--boundary--\\r\\n`` marker so it can
    be reparsed identically by :func:`parse_multipart`.
    """
    if not boundary:
        raise ValueError("boundary must be non-empty")
    delim = b"--" + boundary.encode("latin-1", "replace")
    out = bytearray()
    for part in parts:
        out += delim + b"\r\n"

        # Build Content-Disposition
        name = part.get("name", "") or ""
        filename = part.get("filename", "") or ""
        disp = f'form-data; name="{name}"'
        if filename:
            disp += f'; filename="{filename}"'
        out += b"Content-Disposition: " + disp.encode("latin-1", "replace") + b"\r\n"

        # Per-part Content-Type (optional)
        ct = part.get("content_type", "") or ""
        if ct:
            out += b"Content-Type: " + ct.encode("latin-1", "replace") + b"\r\n"

        # Any extra headers
        for hname, hvalue in (part.get("headers") or {}).items():
            out += (
                hname.encode("latin-1", "replace")
                + b": "
                + str(hvalue).encode("latin-1", "replace")
                + b"\r\n"
            )

        out += b"\r\n"
        body = part.get("body", b"") or b""
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        out += body
        out += b"\r\n"

    out += delim + b"--\r\n"
    return bytes(out)


def generate_boundary() -> str:
    """Generate an RFC-2046 compatible boundary token."""
    return "----FractureBoundary" + secrets.token_hex(12)


# ---------------------------------------------------------------------------
# Dialog
# ---------------------------------------------------------------------------

class MultipartEditorDialog(QDialog):
    """
    Modal dialog for inspecting and editing a multipart/form-data body.

    Usage::

        dlg = MultipartEditorDialog(body_bytes, content_type, parent=self)
        if dlg.exec():
            new_body = dlg.serialized()
            new_boundary = dlg.boundary()
    """

    _COL_NAME = 0
    _COL_FILENAME = 1
    _COL_CT = 2
    _COL_SIZE = 3

    def __init__(
        self,
        body: bytes,
        content_type: str,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Multipart Body Editor")
        self.setStyleSheet(_DIALOG_SS)
        self.resize(820, 540)

        self._boundary: str = _extract_boundary(content_type) or generate_boundary()
        self._parts: list[dict] = parse_multipart(body, content_type)
        self._current_row: int = -1
        self._updating: bool = False

        self._setup_ui()
        self._reload_table()
        if self._parts:
            self._table.selectRow(0)

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        # Boundary info row
        boundary_row = QHBoxLayout()
        boundary_label = QLabel(f"Boundary: {self._boundary}")
        boundary_label.setStyleSheet(_LABEL_SS)
        self._boundary_label = boundary_label
        boundary_row.addWidget(boundary_label)
        boundary_row.addStretch()
        root.addLayout(boundary_row)

        # Parts table
        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(
            ["Name", "Filename", "Content-Type", "Size"]
        )
        self._table.setStyleSheet(_TABLE_SS)
        self._table.setFont(QFont("Monospace", 9))
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(self._COL_NAME, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(
            self._COL_FILENAME, QHeaderView.ResizeMode.Stretch
        )
        header.setSectionResizeMode(
            self._COL_CT, QHeaderView.ResizeMode.Stretch
        )
        header.setSectionResizeMode(
            self._COL_SIZE, QHeaderView.ResizeMode.ResizeToContents
        )
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        self._table.itemChanged.connect(self._on_table_edited)
        root.addWidget(self._table, 1)

        # Add / Remove buttons
        btn_row = QHBoxLayout()
        self._add_btn = QPushButton("Add Part")
        self._add_btn.setStyleSheet(_BTN_SS)
        self._add_btn.clicked.connect(self._on_add_part)
        self._remove_btn = QPushButton("Remove Part")
        self._remove_btn.setStyleSheet(_BTN_SS)
        self._remove_btn.clicked.connect(self._on_remove_part)
        btn_row.addWidget(self._add_btn)
        btn_row.addWidget(self._remove_btn)
        btn_row.addStretch()
        root.addLayout(btn_row)

        # Part body editor
        body_label = QLabel("Part body")
        body_label.setStyleSheet(_LABEL_SS)
        root.addWidget(body_label)

        self._body_edit = QTextEdit()
        self._body_edit.setStyleSheet(_TEXTEDIT_SS)
        self._body_edit.setFont(QFont("Monospace", 9))
        self._body_edit.textChanged.connect(self._on_body_edited)
        root.addWidget(self._body_edit, 2)

        # OK / Cancel
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        for btn in buttons.buttons():
            btn.setStyleSheet(_BTN_SS)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    # ------------------------------------------------------------------
    # Table management
    # ------------------------------------------------------------------

    def _reload_table(self) -> None:
        self._updating = True
        try:
            self._table.setRowCount(0)
            for part in self._parts:
                row = self._table.rowCount()
                self._table.insertRow(row)
                self._set_row(row, part)
        finally:
            self._updating = False
        self._update_remove_state()

    def _set_row(self, row: int, part: dict) -> None:
        name_item = QTableWidgetItem(part.get("name", ""))
        filename_item = QTableWidgetItem(part.get("filename", ""))
        ct_item = QTableWidgetItem(part.get("content_type", ""))
        size_item = QTableWidgetItem(str(len(part.get("body", b"") or b"")))
        size_item.setFlags(
            Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        )
        for item in (name_item, filename_item, ct_item):
            item.setFlags(
                Qt.ItemFlag.ItemIsEnabled
                | Qt.ItemFlag.ItemIsSelectable
                | Qt.ItemFlag.ItemIsEditable
            )
        self._table.setItem(row, self._COL_NAME, name_item)
        self._table.setItem(row, self._COL_FILENAME, filename_item)
        self._table.setItem(row, self._COL_CT, ct_item)
        self._table.setItem(row, self._COL_SIZE, size_item)

    def _refresh_size_cell(self, row: int) -> None:
        if 0 <= row < len(self._parts):
            size_item = self._table.item(row, self._COL_SIZE)
            if size_item is not None:
                self._updating = True
                try:
                    size_item.setText(
                        str(len(self._parts[row].get("body", b"") or b""))
                    )
                finally:
                    self._updating = False

    def _update_remove_state(self) -> None:
        self._remove_btn.setEnabled(self._current_row >= 0)

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _on_selection_changed(self) -> None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            self._current_row = -1
            self._updating = True
            try:
                self._body_edit.clear()
            finally:
                self._updating = False
            self._update_remove_state()
            return
        row = rows[0].row()
        self._current_row = row
        part = self._parts[row]
        body = part.get("body", b"") or b""
        if isinstance(body, bytes):
            try:
                text = body.decode("utf-8")
            except UnicodeDecodeError:
                text = body.decode("latin-1", "replace")
        else:
            text = str(body)
        self._updating = True
        try:
            self._body_edit.setPlainText(text)
        finally:
            self._updating = False
        self._update_remove_state()

    def _on_table_edited(self, item: QTableWidgetItem) -> None:
        if self._updating:
            return
        row = item.row()
        col = item.column()
        if not (0 <= row < len(self._parts)):
            return
        text = item.text()
        if col == self._COL_NAME:
            self._parts[row]["name"] = text
        elif col == self._COL_FILENAME:
            self._parts[row]["filename"] = text
        elif col == self._COL_CT:
            self._parts[row]["content_type"] = text

    def _on_body_edited(self) -> None:
        if self._updating:
            return
        if not (0 <= self._current_row < len(self._parts)):
            return
        text = self._body_edit.toPlainText()
        # Encode as UTF-8 — multipart bodies are bytes; user typed text.
        self._parts[self._current_row]["body"] = text.encode("utf-8", "replace")
        self._refresh_size_cell(self._current_row)

    def _on_add_part(self) -> None:
        new_part = {
            "name": "field",
            "filename": "",
            "content_type": "",
            "headers": {},
            "body": b"",
        }
        self._parts.append(new_part)
        row = self._table.rowCount()
        self._updating = True
        try:
            self._table.insertRow(row)
            self._set_row(row, new_part)
        finally:
            self._updating = False
        self._table.selectRow(row)

    def _on_remove_part(self) -> None:
        if self._current_row < 0 or self._current_row >= len(self._parts):
            return
        row = self._current_row
        del self._parts[row]
        self._updating = True
        try:
            self._table.removeRow(row)
        finally:
            self._updating = False
        # Adjust selection
        new_count = self._table.rowCount()
        if new_count == 0:
            self._current_row = -1
            self._body_edit.clear()
        else:
            new_row = min(row, new_count - 1)
            self._table.selectRow(new_row)
        self._update_remove_state()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def serialized(self) -> bytes:
        """Return the current parts list re-serialised as raw bytes."""
        return serialize_multipart(self._parts, self._boundary)

    def boundary(self) -> str:
        """Return the boundary token used for serialisation."""
        return self._boundary

    def parts(self) -> list[dict]:
        """Return a shallow copy of the current parts list."""
        return [dict(p) for p in self._parts]
