"""Pre-authentication helpers for Fracture Repeater / Proxy.

Provides:
- ``Credentials`` dataclass and ``CredentialStore`` (persisted to
  ``~/.fracture/preauth.json``).
- ``apply_basic`` / ``apply_bearer`` / ``apply_digest`` header builders.
- ``PreAuthDialog`` table editor for managing credentials.
- ``apply_preauth`` — top-level entry point that rewrites a raw HTTP/1.1
  request to include the right ``Authorization`` header for the target host.

stdlib-only HTTP probing is used for Digest (no ``requests`` dependency)
so it can be imported safely from worker threads.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import socket
import ssl
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Catppuccin Mocha theme
# ---------------------------------------------------------------------------

_BG = "#1e1e2e"
_SURFACE = "#181825"
_OVERLAY = "#313244"
_HIGHLIGHT = "#45475a"
_TEXT = "#cdd6f4"
_SUBTEXT = "#a6adc8"

_LINEEDIT_SS = (
    f"QLineEdit {{ background: {_SURFACE}; border: 1px solid {_OVERLAY}; "
    f"padding: 4px; color: {_TEXT}; }}"
)
_COMBO_SS = (
    f"QComboBox {{ background: {_SURFACE}; border: 1px solid {_OVERLAY}; "
    f"padding: 4px; color: {_TEXT}; }}"
    f"QComboBox QAbstractItemView {{ background: {_SURFACE}; color: {_TEXT}; "
    f"selection-background-color: {_HIGHLIGHT}; }}"
)
_BTN_SS = (
    f"QPushButton {{ background: {_OVERLAY}; border: 1px solid {_HIGHLIGHT}; "
    f"padding: 4px 10px; border-radius: 4px; color: {_TEXT}; }}"
    f"QPushButton:hover {{ background: {_HIGHLIGHT}; }}"
    f"QPushButton:disabled {{ color: #585b70; }}"
)
_TABLE_SS = (
    f"QTableWidget {{ background: {_SURFACE}; color: {_TEXT}; "
    f"gridline-color: {_OVERLAY}; border: 1px solid {_OVERLAY}; }}"
    f"QHeaderView::section {{ background: {_OVERLAY}; color: {_TEXT}; "
    f"padding: 4px; border: none; }}"
    f"QTableWidget::item:selected {{ background: {_HIGHLIGHT}; color: {_TEXT}; }}"
)
_LABEL_SS = f"color: {_SUBTEXT}; font-size: 11px;"


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

_CONFIG_DIR = Path(os.path.expanduser("~/.fracture"))
_CONFIG_PATH = _CONFIG_DIR / "preauth.json"

_VALID_SCHEMES = ("basic", "digest", "bearer")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Credentials:
    """A configured credential entry keyed by host substring pattern."""

    host_pattern: str
    scheme: str  # "basic" | "digest" | "bearer"
    username: str = ""
    password: str = ""
    token: str = ""


@dataclass
class CredentialStore:
    """In-memory list of credentials, persisted to JSON."""

    creds: List[Credentials] = field(default_factory=list)
    path: Path = field(default_factory=lambda: _CONFIG_PATH)

    # --- matching ----------------------------------------------------------

    def match(self, host: str) -> Optional[Credentials]:
        """Return the first credential whose ``host_pattern`` matches host."""
        if not host:
            return None
        h = host.lower()
        for cred in self.creds:
            pat = (cred.host_pattern or "").strip().lower()
            if pat and pat in h:
                return cred
        return None

    # --- persistence -------------------------------------------------------

    def load(self) -> None:
        try:
            if not self.path.exists():
                return
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                return
            self.creds = [
                Credentials(
                    host_pattern=str(item.get("host_pattern", "")),
                    scheme=str(item.get("scheme", "basic")).lower(),
                    username=str(item.get("username", "")),
                    password=str(item.get("password", "")),
                    token=str(item.get("token", "")),
                )
                for item in data
                if isinstance(item, dict)
            ]
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            logger.warning("preauth: failed to load %s: %s", self.path, exc)

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = [asdict(c) for c in self.creds]
            self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        except OSError as exc:
            logger.warning("preauth: failed to save %s: %s", self.path, exc)


# ---------------------------------------------------------------------------
# Header builders
# ---------------------------------------------------------------------------

def apply_basic(headers: Dict[str, str], username: str, password: str) -> Dict[str, str]:
    """Return a copy of ``headers`` with HTTP Basic Authorization added."""
    new = dict(headers)
    raw = f"{username}:{password}".encode("utf-8")
    new["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    return new


def apply_bearer(headers: Dict[str, str], token: str) -> Dict[str, str]:
    """Return a copy of ``headers`` with a Bearer Authorization added."""
    new = dict(headers)
    new["Authorization"] = f"Bearer {token}"
    return new


# ---------------------------------------------------------------------------
# Digest auth
# ---------------------------------------------------------------------------

def _md5_hex(data: str) -> str:
    # MD5 is required by RFC 7616 Digest auth — security comes from the
    # nonce/realm/server-challenge, not the hash. Mark as not-for-security
    # so bandit/usedforsecurity-aware linters don't complain.
    return hashlib.md5(data.encode("utf-8"), usedforsecurity=False).hexdigest()


def _parse_challenge(header_value: str) -> Dict[str, str]:
    """Parse a ``WWW-Authenticate: Digest …`` header into a dict.

    Tolerates quoted and unquoted values and comma separators inside
    ``qop`` lists. Returns an empty dict on parse failure.
    """
    if not header_value:
        return {}
    value = header_value.strip()
    if value.lower().startswith("digest"):
        value = value[len("digest"):].strip()
    result: Dict[str, str] = {}
    i = 0
    n = len(value)
    while i < n:
        # Skip whitespace and commas
        while i < n and value[i] in " ,\t":
            i += 1
        # Read key
        key_start = i
        while i < n and value[i] != "=":
            i += 1
        if i >= n:
            break
        key = value[key_start:i].strip().lower()
        i += 1  # consume '='
        # Read value
        if i < n and value[i] == '"':
            i += 1
            v_start = i
            while i < n and value[i] != '"':
                if value[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                i += 1
            val = value[v_start:i]
            if i < n:
                i += 1  # consume closing quote
        else:
            v_start = i
            while i < n and value[i] != ",":
                i += 1
            val = value[v_start:i].strip()
        if key:
            result[key] = val
    return result


def _probe_challenge(host: str, port: int, is_https: bool,
                     path: str) -> Optional[str]:
    """Send a minimal GET and return the raw ``WWW-Authenticate`` value, if any.

    Returns ``None`` if no challenge is offered or the probe fails.
    Uses stdlib socket + ssl only.
    """
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"User-Agent: Fracture-PreAuth/1.0\r\n"
        f"Accept: */*\r\n\r\n"
    ).encode("ascii", errors="replace")

    sock: Optional[socket.socket] = None
    try:
        sock = socket.create_connection((host, port), timeout=10)
        if is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(request)

        buf = b""
        sock.settimeout(10)
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(8192)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 65536:
                break

        head = buf.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", errors="replace")
        for line in head.splitlines()[1:]:
            if line.lower().startswith("www-authenticate:"):
                val = line.split(":", 1)[1].strip()
                if val.lower().startswith("digest"):
                    return val
        return None
    except (OSError, ssl.SSLError) as exc:
        logger.warning("preauth: digest probe failed for %s:%s: %s",
                       host, port, exc)
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def apply_digest(host: str, port: int, is_https: bool, method: str,
                 path: str, headers: Dict[str, str],
                 username: str, password: str) -> Dict[str, str]:
    """Probe the server for a Digest challenge and return updated headers.

    Supports MD5 / MD5-sess and qop=auth (RFC 2617 / 7616 subset). If the
    probe fails or no challenge is offered, returns ``headers`` unchanged.
    """
    challenge_value = _probe_challenge(host, port, is_https, path)
    if not challenge_value:
        return dict(headers)

    params = _parse_challenge(challenge_value)
    realm = params.get("realm", "")
    nonce = params.get("nonce", "")
    if not realm or not nonce:
        return dict(headers)

    algorithm = (params.get("algorithm") or "MD5").upper()
    qop_raw = params.get("qop", "")
    qop_options = [q.strip().lower() for q in qop_raw.split(",") if q.strip()]
    qop = "auth" if "auth" in qop_options else ""
    opaque = params.get("opaque", "")

    ha1 = _md5_hex(f"{username}:{realm}:{password}")
    if algorithm == "MD5-SESS":
        cnonce_for_ha1 = secrets.token_hex(8)
        ha1 = _md5_hex(f"{ha1}:{nonce}:{cnonce_for_ha1}")
        cnonce = cnonce_for_ha1
    else:
        cnonce = secrets.token_hex(8)

    ha2 = _md5_hex(f"{method}:{path}")

    if qop == "auth":
        nc = "00000001"
        response = _md5_hex(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
    else:
        nc = ""
        response = _md5_hex(f"{ha1}:{nonce}:{ha2}")

    parts = [
        f'username="{username}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{path}"',
        f'response="{response}"',
        f'algorithm={algorithm}',
    ]
    if qop:
        parts.append(f'qop={qop}')
        parts.append(f'nc={nc}')
        parts.append(f'cnonce="{cnonce}"')
    if opaque:
        parts.append(f'opaque="{opaque}"')

    new_headers = dict(headers)
    new_headers["Authorization"] = "Digest " + ", ".join(parts)
    return new_headers


# ---------------------------------------------------------------------------
# Raw-request rewriting
# ---------------------------------------------------------------------------

def _split_raw_request(req_raw: str) -> Tuple[str, List[str], str]:
    """Return ``(request_line, header_lines, body)``."""
    if "\r\n\r\n" in req_raw:
        head, body = req_raw.split("\r\n\r\n", 1)
        sep = "\r\n"
    elif "\n\n" in req_raw:
        head, body = req_raw.split("\n\n", 1)
        sep = "\n"
    else:
        head, body, sep = req_raw, "", "\r\n"

    lines = head.split(sep)
    if not lines:
        return "", [], body
    return lines[0], lines[1:], body


def _has_authorization(header_lines: List[str]) -> Optional[str]:
    """Return the existing Authorization scheme name in lower case, or None."""
    for line in header_lines:
        if line.lower().startswith("authorization:"):
            val = line.split(":", 1)[1].strip()
            return val.split(" ", 1)[0].lower() if val else ""
    return None


def _headers_dict(header_lines: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in header_lines:
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def _rebuild(request_line: str, headers: Dict[str, str], body: str) -> str:
    head_parts = [request_line]
    for k, v in headers.items():
        head_parts.append(f"{k}: {v}")
    return "\r\n".join(head_parts) + "\r\n\r\n" + body


def _request_method_and_path(request_line: str) -> Tuple[str, str]:
    parts = request_line.split(" ")
    if len(parts) < 2:
        return "GET", "/"
    return parts[0].upper(), parts[1]


def apply_preauth(req_raw: str, host: str, port: int, is_https: bool,
                  store: CredentialStore) -> str:
    """Apply a matching credential's Authorization header to a raw request.

    - If no credential matches ``host``, the request is returned unchanged.
    - If the request already has an Authorization header for a *different*
      scheme, the existing header is preserved (caller wants to override
      manually).
    - If it has an Authorization header matching the scheme, it is replaced.
    """
    if not store or not req_raw:
        return req_raw

    cred = store.match(host)
    if cred is None:
        return req_raw
    scheme = (cred.scheme or "").lower()
    if scheme not in _VALID_SCHEMES:
        return req_raw

    request_line, header_lines, body = _split_raw_request(req_raw)
    existing = _has_authorization(header_lines)
    if existing is not None and existing != scheme:
        # Don't clobber an explicit different-scheme header.
        return req_raw

    # Drop any existing Authorization header before applying the new one.
    filtered = [ln for ln in header_lines
                if not ln.lower().startswith("authorization:")]
    headers = _headers_dict(filtered)

    if scheme == "basic":
        headers = apply_basic(headers, cred.username, cred.password)
    elif scheme == "bearer":
        headers = apply_bearer(headers, cred.token)
    elif scheme == "digest":
        method, path = _request_method_and_path(request_line)
        headers = apply_digest(host, port, is_https, method, path, headers,
                               cred.username, cred.password)
    else:
        return req_raw

    return _rebuild(request_line, headers, body)


# ---------------------------------------------------------------------------
# Add/Edit dialog
# ---------------------------------------------------------------------------

class _CredEditDialog(QDialog):
    """Modal form for one ``Credentials`` row."""

    def __init__(self, parent: Optional[QWidget] = None,
                 cred: Optional[Credentials] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Pre-Auth Credential")
        self.setStyleSheet(f"background: {_BG}; color: {_TEXT};")
        self.resize(520, 260)

        self._host = QLineEdit(cred.host_pattern if cred else "")
        self._host.setStyleSheet(_LINEEDIT_SS)
        self._host.setPlaceholderText("substring, e.g. api.example.com")

        self._scheme = QComboBox()
        self._scheme.setStyleSheet(_COMBO_SS)
        self._scheme.addItems(["basic", "digest", "bearer"])
        if cred and cred.scheme in _VALID_SCHEMES:
            self._scheme.setCurrentText(cred.scheme)
        self._scheme.currentTextChanged.connect(self._update_visibility)

        self._username = QLineEdit(cred.username if cred else "")
        self._username.setStyleSheet(_LINEEDIT_SS)

        self._password = QLineEdit(cred.password if cred else "")
        self._password.setStyleSheet(_LINEEDIT_SS)
        self._password.setEchoMode(QLineEdit.EchoMode.Password)

        self._token = QLineEdit(cred.token if cred else "")
        self._token.setStyleSheet(_LINEEDIT_SS)
        self._token.setEchoMode(QLineEdit.EchoMode.Password)

        self._form = QFormLayout()
        host_lbl = QLabel("Host pattern:")
        host_lbl.setStyleSheet(_LABEL_SS)
        self._form.addRow(host_lbl, self._host)

        scheme_lbl = QLabel("Scheme:")
        scheme_lbl.setStyleSheet(_LABEL_SS)
        self._form.addRow(scheme_lbl, self._scheme)

        self._user_lbl = QLabel("Username:")
        self._user_lbl.setStyleSheet(_LABEL_SS)
        self._form.addRow(self._user_lbl, self._username)

        self._pw_lbl = QLabel("Password:")
        self._pw_lbl.setStyleSheet(_LABEL_SS)
        self._form.addRow(self._pw_lbl, self._password)

        self._tok_lbl = QLabel("Token:")
        self._tok_lbl.setStyleSheet(_LABEL_SS)
        self._form.addRow(self._tok_lbl, self._token)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        for btn in buttons.buttons():
            btn.setStyleSheet(_BTN_SS)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(self._form)
        layout.addWidget(buttons)

        self._update_visibility(self._scheme.currentText())

    def _update_visibility(self, scheme: str) -> None:
        is_bearer = scheme == "bearer"
        self._username.setVisible(not is_bearer)
        self._user_lbl.setVisible(not is_bearer)
        self._password.setVisible(not is_bearer)
        self._pw_lbl.setVisible(not is_bearer)
        self._token.setVisible(is_bearer)
        self._tok_lbl.setVisible(is_bearer)

    def _on_accept(self) -> None:
        if not self._host.text().strip():
            QMessageBox.warning(self, "Missing host", "Host pattern is required.")
            return
        scheme = self._scheme.currentText()
        if scheme == "bearer" and not self._token.text():
            QMessageBox.warning(self, "Missing token", "Token is required for bearer.")
            return
        if scheme in ("basic", "digest") and not self._username.text():
            QMessageBox.warning(self, "Missing username",
                                "Username is required for basic/digest.")
            return
        self.accept()

    def value(self) -> Credentials:
        return Credentials(
            host_pattern=self._host.text().strip(),
            scheme=self._scheme.currentText(),
            username=self._username.text(),
            password=self._password.text(),
            token=self._token.text(),
        )


# ---------------------------------------------------------------------------
# Main dialog
# ---------------------------------------------------------------------------

class PreAuthDialog(QDialog):
    """Table editor for ``CredentialStore``."""

    HEADERS = ("Host pattern", "Scheme", "Username", "Secret")

    def __init__(self, store: CredentialStore,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Pre-Auth Credentials")
        self.setStyleSheet(f"background: {_BG}; color: {_TEXT};")
        self.resize(720, 360)

        self._store = store

        intro = QLabel(
            "Configure pre-authentication credentials per host substring. "
            "Settings are saved to ~/.fracture/preauth.json."
        )
        intro.setStyleSheet(_LABEL_SS)
        intro.setWordWrap(True)

        self._table = QTableWidget(0, len(self.HEADERS))
        self._table.setHorizontalHeaderLabels(self.HEADERS)
        self._table.setStyleSheet(_TABLE_SS)
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._table.doubleClicked.connect(lambda _idx: self._edit())

        add_btn = QPushButton("Add…")
        add_btn.setStyleSheet(_BTN_SS)
        add_btn.clicked.connect(self._add)

        edit_btn = QPushButton("Edit…")
        edit_btn.setStyleSheet(_BTN_SS)
        edit_btn.clicked.connect(self._edit)

        remove_btn = QPushButton("Remove")
        remove_btn.setStyleSheet(_BTN_SS)
        remove_btn.clicked.connect(self._remove)

        btn_row = QHBoxLayout()
        btn_row.addWidget(add_btn)
        btn_row.addWidget(edit_btn)
        btn_row.addWidget(remove_btn)
        btn_row.addStretch(1)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        for btn in buttons.buttons():
            btn.setStyleSheet(_BTN_SS)
        buttons.accepted.connect(self._on_save)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addWidget(self._table, 1)
        layout.addLayout(btn_row)
        layout.addWidget(buttons)

        self._refresh()

    def _refresh(self) -> None:
        self._table.setRowCount(0)
        for cred in self._store.creds:
            self._append_row(cred)

    def _append_row(self, cred: Credentials) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)
        if cred.scheme == "bearer":
            secret_display = "•" * min(len(cred.token), 16) if cred.token else ""
            user_display = ""
        else:
            secret_display = "•" * min(len(cred.password), 16) if cred.password else ""
            user_display = cred.username
        values = (cred.host_pattern, cred.scheme, user_display, secret_display)
        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self._table.setItem(row, col, item)

    def _current_row(self) -> int:
        rows = self._table.selectionModel().selectedRows()
        return rows[0].row() if rows else -1

    def _add(self) -> None:
        dlg = _CredEditDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._store.creds.append(dlg.value())
            self._refresh()

    def _edit(self) -> None:
        row = self._current_row()
        if row < 0:
            return
        dlg = _CredEditDialog(self, self._store.creds[row])
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._store.creds[row] = dlg.value()
            self._refresh()
            self._table.selectRow(row)

    def _remove(self) -> None:
        row = self._current_row()
        if row < 0:
            return
        del self._store.creds[row]
        self._refresh()

    def _on_save(self) -> None:
        self._store.save()
        self.accept()
