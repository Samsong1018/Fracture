"""
Audit configuration profiles — named bundles of active-scanner probe toggles.

Stored as JSON under ~/.fracture/audit_profiles/<name>.json.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


# The full list of probe-toggle attribute names on ActiveScannerTab
PROBE_FIELDS = [
    "sqli_check",
    "xss_check",
    "path_traversal_check",
    "ssrf_check",
    "blind_sqli_time_check",
    "blind_sqli_bool_check",
    "xxe_check",
    "jwt_check",
    "ssti_check",
    "cmdi_check",
    "crlf_check",
    "host_header_check",
    "smuggling_check",
    "open_redirect_check",
    "nosql_check",
    "ldap_check",
    "proto_pollution_check",
    "backslash_check",
]


# Built-in defaults
QUICK_PROFILE = {
    "sqli_check": True,
    "xss_check": True,
    "path_traversal_check": True,
    "open_redirect_check": True,
    # everything else off for speed
}

THOROUGH_PROFILE = {f: True for f in PROBE_FIELDS}


def _profiles_dir() -> Path:
    p = Path(os.path.expanduser("~/.fracture/audit_profiles"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def list_profiles() -> list[str]:
    builtins = ["(Quick)", "(Thorough)"]
    return builtins + sorted(p.stem for p in _profiles_dir().glob("*.json"))


def capture(scanner_tab) -> dict[str, bool]:
    """Read the current probe toggles off ActiveScannerTab into a dict."""
    out: dict[str, bool] = {}
    for f in PROBE_FIELDS:
        cb = getattr(scanner_tab, f, None)
        if cb is not None:
            out[f] = bool(cb.isChecked())
    return out


def apply(scanner_tab, profile: dict[str, bool]) -> None:
    """Set the probe toggles on the scanner tab to match the profile dict.

    Missing keys default to False.
    """
    for f in PROBE_FIELDS:
        cb = getattr(scanner_tab, f, None)
        if cb is not None:
            cb.setChecked(bool(profile.get(f, False)))


def save_profile(name: str, profile: dict[str, bool]) -> Path:
    safe = "".join(c for c in name if c.isalnum() or c in "-_") or "default"
    path = _profiles_dir() / f"{safe}.json"
    path.write_text(json.dumps(profile, indent=2), encoding="utf-8")
    return path


def load_profile(name: str) -> Optional[dict[str, bool]]:
    if name == "(Quick)":
        return dict(QUICK_PROFILE)
    if name == "(Thorough)":
        return dict(THOROUGH_PROFILE)
    safe = "".join(c for c in name if c.isalnum() or c in "-_") or "default"
    path = _profiles_dir() / f"{safe}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def delete_profile(name: str) -> bool:
    if name in ("(Quick)", "(Thorough)"):
        return False
    safe = "".join(c for c in name if c.isalnum() or c in "-_") or "default"
    path = _profiles_dir() / f"{safe}.json"
    if path.exists():
        path.unlink()
        return True
    return False


_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
    "QPushButton:hover { background: #45475a; }"
)


class AuditProfileDialog(QDialog):
    """Pick / save / delete audit profiles."""

    def __init__(self, scanner_tab, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._scanner = scanner_tab
        self.setWindowTitle("Audit profiles")
        self.resize(440, 360)
        self.setStyleSheet(
            "QDialog { background: #1e1e2e; color: #cdd6f4; }"
            "QListWidget { background: #181825; border: 1px solid #313244; color: #cdd6f4; }"
            "QListWidget::item:selected { background: #45475a; }"
            "QLabel { color: #cdd6f4; }"
        )

        root = QVBoxLayout(self)
        root.addWidget(QLabel("Saved profiles:"))
        self._list = QListWidget()
        root.addWidget(self._list, 1)
        for n in list_profiles():
            self._list.addItem(n)

        btns = QHBoxLayout()
        for label, fn in (
            ("Apply", self._apply),
            ("Save current as…", self._save_current),
            ("Delete", self._delete),
        ):
            b = QPushButton(label)
            b.setStyleSheet(_BTN_SS)
            b.clicked.connect(fn)
            btns.addWidget(b)
        btns.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet(_BTN_SS)
        close_btn.clicked.connect(self.accept)
        btns.addWidget(close_btn)
        root.addLayout(btns)

    def _refresh(self):
        self._list.clear()
        for n in list_profiles():
            self._list.addItem(n)

    def _selected_name(self) -> Optional[str]:
        item = self._list.currentItem()
        return item.text() if item else None

    def _apply(self):
        name = self._selected_name()
        if not name:
            return
        profile = load_profile(name)
        if profile is None:
            return
        apply(self._scanner, profile)

    def _save_current(self):
        name, ok = QInputDialog.getText(self, "Save profile", "Profile name:")
        if not ok or not name.strip():
            return
        save_profile(name.strip(), capture(self._scanner))
        self._refresh()

    def _delete(self):
        name = self._selected_name()
        if not name:
            return
        delete_profile(name)
        self._refresh()
