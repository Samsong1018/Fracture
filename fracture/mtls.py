"""Client certificate (mTLS) support for Fracture.

Provides:
- ``ClientCert`` dataclass and ``ClientCertStore`` for matching certificates
  against target hosts via substring pattern.
- ``apply_to_ssl_context`` / ``make_ssl_context`` helpers used by the
  Repeater and Proxy to obtain a TLS context with the correct client cert
  loaded for outbound connections.
- ``ClientCertDialog`` PyQt6 editor backed by
  ``~/.fracture/mtls.json``.

This module is self-contained and does not import from the Repeater or
Proxy modules to avoid circular dependencies — wiring is performed by
``gui.py``/``repeater.py``/``proxy.py``.
"""

from __future__ import annotations

import json
import logging
import os
import ssl
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
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
_ACCENT = "#89b4fa"

_LINEEDIT_SS = (
    f"QLineEdit {{ background: {_SURFACE}; border: 1px solid {_OVERLAY}; "
    f"padding: 4px; color: {_TEXT}; }}"
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
# Persistence path
# ---------------------------------------------------------------------------

_CONFIG_DIR = Path(os.path.expanduser("~/.fracture"))
_CONFIG_PATH = _CONFIG_DIR / "mtls.json"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ClientCert:
    """A configured client certificate keyed by host substring pattern."""

    host_pattern: str
    cert_path: str
    key_path: str
    password: str = ""


@dataclass
class ClientCertStore:
    """In-memory collection of ``ClientCert`` entries, persisted to JSON."""

    certs: List[ClientCert] = field(default_factory=list)
    path: Path = field(default_factory=lambda: _CONFIG_PATH)

    # --- matching ----------------------------------------------------------

    def match(self, host: str) -> Optional[ClientCert]:
        """Return the first cert whose ``host_pattern`` is a substring of host.

        Empty patterns never match. Matching is case-insensitive.
        """
        if not host:
            return None
        h = host.lower()
        for cert in self.certs:
            pat = (cert.host_pattern or "").strip().lower()
            if pat and pat in h:
                return cert
        return None

    # --- persistence -------------------------------------------------------

    def load(self) -> None:
        """Load certs from ``self.path``; silently no-ops if missing/invalid."""
        try:
            if not self.path.exists():
                return
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                return
            self.certs = [
                ClientCert(
                    host_pattern=str(item.get("host_pattern", "")),
                    cert_path=str(item.get("cert_path", "")),
                    key_path=str(item.get("key_path", "")),
                    password=str(item.get("password", "")),
                )
                for item in data
                if isinstance(item, dict)
            ]
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            logger.warning("mtls: failed to load %s: %s", self.path, exc)

    def save(self) -> None:
        """Persist certs to ``self.path``. Creates the parent directory."""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = [asdict(c) for c in self.certs]
            self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        except OSError as exc:
            logger.warning("mtls: failed to save %s: %s", self.path, exc)


# ---------------------------------------------------------------------------
# SSL context helpers
# ---------------------------------------------------------------------------

def apply_to_ssl_context(ctx: ssl.SSLContext, cert: ClientCert) -> None:
    """Load ``cert`` (cert + key + optional password) into ``ctx``.

    Raises ``ssl.SSLError`` / ``OSError`` on bad files; callers should log
    and continue without the cert if appropriate.
    """
    if not cert or not cert.cert_path:
        return
    password = cert.password or None
    key_path = cert.key_path or None
    ctx.load_cert_chain(cert.cert_path, key_path, password=password)


def make_ssl_context(host: str, store: Optional[ClientCertStore]) -> ssl.SSLContext:
    """Return a default permissive TLS context with optional client cert.

    The returned context disables hostname/cert verification (matches the
    rest of Fracture's intercepting behavior). If ``store`` has a matching
    entry for ``host``, the cert chain is loaded; load failures are logged
    and the context is returned without the cert.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    if store is None:
        return ctx

    cert = store.match(host)
    if cert is None:
        return ctx

    try:
        apply_to_ssl_context(ctx, cert)
    except (ssl.SSLError, OSError, ValueError) as exc:
        logger.warning(
            "mtls: failed to load client cert for %s (%s): %s",
            host, cert.cert_path, exc,
        )
    return ctx


# ---------------------------------------------------------------------------
# Add/Edit dialog
# ---------------------------------------------------------------------------

class _CertEditDialog(QDialog):
    """Small modal form for adding/editing a single ``ClientCert``."""

    def __init__(self, parent: Optional[QWidget] = None,
                 cert: Optional[ClientCert] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Client Certificate")
        self.setStyleSheet(f"background: {_BG}; color: {_TEXT};")
        self.resize(560, 220)

        self._host = QLineEdit(cert.host_pattern if cert else "")
        self._host.setStyleSheet(_LINEEDIT_SS)
        self._host.setPlaceholderText("substring, e.g. api.example.com")

        self._cert = QLineEdit(cert.cert_path if cert else "")
        self._cert.setStyleSheet(_LINEEDIT_SS)
        cert_browse = QPushButton("Browse…")
        cert_browse.setStyleSheet(_BTN_SS)
        cert_browse.clicked.connect(self._pick_cert)

        self._key = QLineEdit(cert.key_path if cert else "")
        self._key.setStyleSheet(_LINEEDIT_SS)
        key_browse = QPushButton("Browse…")
        key_browse.setStyleSheet(_BTN_SS)
        key_browse.clicked.connect(self._pick_key)

        self._password = QLineEdit(cert.password if cert else "")
        self._password.setStyleSheet(_LINEEDIT_SS)
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        self._password.setPlaceholderText("(leave empty if key is unencrypted)")

        form = QFormLayout()
        host_lbl = QLabel("Host pattern:")
        host_lbl.setStyleSheet(_LABEL_SS)
        form.addRow(host_lbl, self._host)

        cert_row = QHBoxLayout()
        cert_row.addWidget(self._cert, 1)
        cert_row.addWidget(cert_browse)
        cert_wrap = QWidget()
        cert_wrap.setLayout(cert_row)
        cert_lbl = QLabel("Certificate file (PEM):")
        cert_lbl.setStyleSheet(_LABEL_SS)
        form.addRow(cert_lbl, cert_wrap)

        key_row = QHBoxLayout()
        key_row.addWidget(self._key, 1)
        key_row.addWidget(key_browse)
        key_wrap = QWidget()
        key_wrap.setLayout(key_row)
        key_lbl = QLabel("Key file (PEM):")
        key_lbl.setStyleSheet(_LABEL_SS)
        form.addRow(key_lbl, key_wrap)

        pw_lbl = QLabel("Key password:")
        pw_lbl.setStyleSheet(_LABEL_SS)
        form.addRow(pw_lbl, self._password)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        for btn in buttons.buttons():
            btn.setStyleSheet(_BTN_SS)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    # --- file pickers ------------------------------------------------------

    def _pick_cert(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select certificate", "", "PEM (*.pem *.crt *.cer);;All files (*)"
        )
        if path:
            self._cert.setText(path)

    def _pick_key(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select private key", "", "PEM (*.pem *.key);;All files (*)"
        )
        if path:
            self._key.setText(path)

    # --- accept / value ----------------------------------------------------

    def _on_accept(self) -> None:
        if not self._host.text().strip():
            QMessageBox.warning(self, "Missing host", "Host pattern is required.")
            return
        if not self._cert.text().strip():
            QMessageBox.warning(self, "Missing cert", "Certificate file is required.")
            return
        self.accept()

    def value(self) -> ClientCert:
        return ClientCert(
            host_pattern=self._host.text().strip(),
            cert_path=self._cert.text().strip(),
            key_path=self._key.text().strip(),
            password=self._password.text(),
        )


# ---------------------------------------------------------------------------
# Main dialog
# ---------------------------------------------------------------------------

class ClientCertDialog(QDialog):
    """Table editor for ``ClientCertStore`` with Add/Edit/Remove."""

    HEADERS = ("Host pattern", "Certificate", "Key", "Password")

    def __init__(self, store: ClientCertStore,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Client Certificates (mTLS)")
        self.setStyleSheet(f"background: {_BG}; color: {_TEXT};")
        self.resize(720, 360)

        self._store = store

        intro = QLabel(
            "Configure client certificates per host substring. "
            "Settings are saved to ~/.fracture/mtls.json."
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
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
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

    # --- table helpers -----------------------------------------------------

    def _refresh(self) -> None:
        self._table.setRowCount(0)
        for cert in self._store.certs:
            self._append_row(cert)

    def _append_row(self, cert: ClientCert) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)
        masked_pw = "•" * len(cert.password) if cert.password else ""
        values = (cert.host_pattern, cert.cert_path, cert.key_path, masked_pw)
        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self._table.setItem(row, col, item)

    def _current_row(self) -> int:
        rows = self._table.selectionModel().selectedRows()
        return rows[0].row() if rows else -1

    # --- actions -----------------------------------------------------------

    def _add(self) -> None:
        dlg = _CertEditDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._store.certs.append(dlg.value())
            self._refresh()

    def _edit(self) -> None:
        row = self._current_row()
        if row < 0:
            return
        existing = self._store.certs[row]
        dlg = _CertEditDialog(self, existing)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._store.certs[row] = dlg.value()
            self._refresh()
            self._table.selectRow(row)

    def _remove(self) -> None:
        row = self._current_row()
        if row < 0:
            return
        del self._store.certs[row]
        self._refresh()

    def _on_save(self) -> None:
        self._store.save()
        self.accept()
