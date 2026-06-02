"""
Flask Tools tab — Flask cookie decode/encode/tamper/verify/crack + Werkzeug PIN calculator.
Ported from AMPentools (tkinter) to PyQt6.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
    QComboBox,
    QProgressBar,
)

try:
    from .flask_cookie_logic import (
        decode_cookie,
        encode_cookie,
        verify_signature,
        crack_secret,
    )
    HAS_FLASK_LOGIC = True
except ImportError:
    HAS_FLASK_LOGIC = False

try:
    from .werkzeug_pin_logic import calculate_pin, mac_to_int, build_machine_id
    HAS_PIN_LOGIC = True
except ImportError:
    HAS_PIN_LOGIC = False

# ── Stylesheet constants ────────────────────────────────────────────────────

_SS_OUTPUT = (
    "QPlainTextEdit { background: #0d1117; color: #4ec9b0; "
    "font-family: 'Fira Code', 'JetBrains Mono', monospace; font-size: 12px; "
    "border: 1px solid #313244; border-radius: 4px; padding: 6px; }"
)
_SS_INPUT = (
    "QLineEdit { background: #181825; color: #cdd6f4; border: 1px solid #313244; "
    "border-radius: 4px; padding: 5px 8px; }"
    "QLineEdit:focus { border-color: #89b4fa; }"
)
_SS_LABEL = "color: #a6adc8; font-size: 11px; font-weight: bold;"
_SS_BTN = (
    "QPushButton { background: #313244; color: #cdd6f4; border: none; "
    "border-radius: 4px; padding: 5px 14px; }"
    "QPushButton:hover { background: #45475a; }"
    "QPushButton:pressed { background: #89b4fa; color: #1e1e2e; }"
)
_SS_BTN_ACCENT = (
    "QPushButton { background: #89b4fa; color: #1e1e2e; font-weight: bold; "
    "border: none; border-radius: 4px; padding: 5px 14px; }"
    "QPushButton:hover { background: #b4befe; }"
)


def _lbl(text: str) -> QLabel:
    l = QLabel(text)
    l.setStyleSheet(_SS_LABEL)
    return l


def _multiline(placeholder: str = "", height: int = 80) -> QPlainTextEdit:
    w = QPlainTextEdit()
    w.setPlaceholderText(placeholder)
    w.setStyleSheet(_SS_OUTPUT)
    w.setFixedHeight(height)
    return w


def _input(placeholder: str = "") -> QLineEdit:
    w = QLineEdit()
    w.setPlaceholderText(placeholder)
    w.setStyleSheet(_SS_INPUT)
    return w


def _btn(text: str, accent: bool = False) -> QPushButton:
    b = QPushButton(text)
    b.setStyleSheet(_SS_BTN_ACCENT if accent else _SS_BTN)
    return b


def _copy_btn(target: QPlainTextEdit) -> QPushButton:
    b = _btn("Copy")
    b.clicked.connect(lambda: (
        target.selectAll(),
        target.copy(),
        target.moveCursor(target.textCursor().MoveOperation.End),
    ))
    return b


# ── Cookie: Decode ──────────────────────────────────────────────────────────

class _DecodePanel(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(8)

        lay.addWidget(_lbl("Cookie"))
        self._cookie = _input(".eJyrVi...sig — paste cookie here")
        lay.addWidget(self._cookie)

        row = QHBoxLayout()
        go = _btn("Decode", accent=True)
        go.clicked.connect(self._run)
        row.addWidget(go)
        self._out = _multiline(height=200)
        row.addWidget(_copy_btn(self._out))
        row.addStretch()
        lay.addLayout(row)
        lay.addWidget(self._out)
        lay.addStretch()

    def _run(self):
        c = self._cookie.text().strip()
        if not c:
            self._out.setPlainText("[!] Paste a cookie first.")
            return
        if not HAS_FLASK_LOGIC:
            self._out.setPlainText("[!] itsdangerous not installed — pip install itsdangerous")
            return
        try:
            r = decode_cookie(c)
            self._out.setPlainText("\n".join([
                f"compressed  : {r['compressed']}",
                f"issued at   : {r['timestamp_human']}",
                f"signature   : {r['signature']}",
                "",
                "── payload ──────────────────────────",
                json.dumps(r["payload"], indent=2),
            ]))
        except Exception as e:
            self._out.setPlainText(f"[!] {e}")


# ── Cookie: Encode ──────────────────────────────────────────────────────────

class _EncodePanel(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(8)

        lay.addWidget(_lbl("Payload JSON"))
        self._payload = _multiline('{"role": "admin", "user": "test"}', height=80)
        self._payload.setReadOnly(False)
        self._payload.setStyleSheet(
            "QPlainTextEdit { background: #181825; color: #cdd6f4; "
            "font-family: monospace; font-size: 12px; border: 1px solid #313244; "
            "border-radius: 4px; padding: 6px; }"
        )
        lay.addWidget(self._payload)

        lay.addWidget(_lbl("Secret Key"))
        self._secret = _input("Your Flask SECRET_KEY")
        lay.addWidget(self._secret)

        row = QHBoxLayout()
        go = _btn("Encode & Sign", accent=True)
        go.clicked.connect(self._run)
        row.addWidget(go)
        self._out = _multiline(height=60)
        row.addWidget(_copy_btn(self._out))
        row.addStretch()
        lay.addLayout(row)
        lay.addWidget(self._out)
        lay.addStretch()

    def _run(self):
        if not HAS_FLASK_LOGIC:
            self._out.setPlainText("[!] pip install itsdangerous")
            return
        raw = self._payload.toPlainText().strip()
        secret = self._secret.text().strip()
        if not raw or not secret:
            self._out.setPlainText("[!] Fill in payload and secret key.")
            return
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as e:
            self._out.setPlainText(f"[!] Bad JSON: {e}")
            return
        try:
            self._out.setPlainText(encode_cookie(payload, secret))
        except Exception as e:
            self._out.setPlainText(f"[!] {e}")


# ── Cookie: Tamper ──────────────────────────────────────────────────────────

class _TamperPanel(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(8)

        lay.addWidget(_lbl("Original Cookie"))
        self._cookie = _input("Paste the cookie to decode and tamper with")
        lay.addWidget(self._cookie)

        decode_btn = _btn("Decode for Editing")
        decode_btn.clicked.connect(self._decode)
        lay.addWidget(decode_btn)

        lay.addWidget(_lbl("Edit Payload JSON"))
        self._payload = _multiline(height=100)
        self._payload.setReadOnly(False)
        self._payload.setStyleSheet(
            "QPlainTextEdit { background: #181825; color: #cdd6f4; "
            "font-family: monospace; font-size: 12px; border: 1px solid #313244; "
            "border-radius: 4px; padding: 6px; }"
        )
        lay.addWidget(self._payload)

        lay.addWidget(_lbl("New Secret Key (to re-sign with)"))
        self._secret = _input("New or recovered SECRET_KEY")
        lay.addWidget(self._secret)

        row = QHBoxLayout()
        go = _btn("Re-sign Cookie", accent=True)
        go.clicked.connect(self._resign)
        row.addWidget(go)
        self._out = _multiline(height=60)
        row.addWidget(_copy_btn(self._out))
        row.addStretch()
        lay.addLayout(row)
        lay.addWidget(self._out)
        lay.addStretch()

    def _decode(self):
        c = self._cookie.text().strip()
        if not c:
            return
        try:
            r = decode_cookie(c)
            self._payload.setPlainText(json.dumps(r["payload"], indent=2))
        except Exception as e:
            self._payload.setPlainText(f"[!] {e}")

    def _resign(self):
        if not HAS_FLASK_LOGIC:
            self._out.setPlainText("[!] pip install itsdangerous")
            return
        raw = self._payload.toPlainText().strip()
        secret = self._secret.text().strip()
        if not raw or not secret:
            self._out.setPlainText("[!] Decode a cookie and enter a secret.")
            return
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as e:
            self._out.setPlainText(f"[!] Bad JSON: {e}")
            return
        try:
            self._out.setPlainText(encode_cookie(payload, secret))
        except Exception as e:
            self._out.setPlainText(f"[!] {e}")


# ── Cookie: Verify ──────────────────────────────────────────────────────────

class _VerifyPanel(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(8)

        lay.addWidget(_lbl("Cookie"))
        self._cookie = _input("Paste cookie")
        lay.addWidget(self._cookie)

        lay.addWidget(_lbl("Secret Key"))
        self._secret = _input("SECRET_KEY to test against")
        lay.addWidget(self._secret)

        row = QHBoxLayout()
        go = _btn("Verify", accent=True)
        go.clicked.connect(self._run)
        row.addWidget(go)
        row.addStretch()
        lay.addLayout(row)

        self._out = _multiline(height=200)
        lay.addWidget(self._out)
        lay.addStretch()

    def _run(self):
        if not HAS_FLASK_LOGIC:
            self._out.setPlainText("[!] pip install itsdangerous")
            return
        cookie = self._cookie.text().strip()
        secret = self._secret.text().strip()
        if not cookie or not secret:
            self._out.setPlainText("[!] Provide cookie and secret.")
            return
        valid = verify_signature(cookie, secret)
        verdict = "✓  VALID SIGNATURE" if valid else "✗  INVALID SIGNATURE"
        lines = [verdict, ""]
        try:
            r = decode_cookie(cookie)
            lines += [
                f"issued at  : {r['timestamp_human']}",
                f"compressed : {r['compressed']}",
                "",
                "── payload ──────────────────────────",
                json.dumps(r["payload"], indent=2),
            ]
        except Exception as e:
            lines.append(f"[!] Could not decode payload: {e}")
        self._out.setPlainText("\n".join(lines))


# ── Cookie: Crack ───────────────────────────────────────────────────────────

class _CrackWorker(QThread):
    progress = pyqtSignal(int, str)
    found = pyqtSignal(str)
    done = pyqtSignal(int)

    def __init__(self, cookie: str, wordlist: str):
        super().__init__()
        self._cookie = cookie
        self._wordlist = wordlist
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        tried = 0
        try:
            with open(self._wordlist, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if self._stop:
                        break
                    secret = line.rstrip("\n\r")
                    if not secret:
                        continue
                    tried += 1
                    if tried % 500 == 0:
                        self.progress.emit(tried, secret[:40])
                    if verify_signature(self._cookie, secret):
                        self.found.emit(secret)
                        self.done.emit(tried)
                        return
        except FileNotFoundError:
            self.found.emit("")
        self.done.emit(tried)


class _CrackPanel(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._worker: Optional[_CrackWorker] = None

        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(8)

        lay.addWidget(_lbl("Cookie"))
        self._cookie = _input("Paste target cookie")
        lay.addWidget(self._cookie)

        lay.addWidget(_lbl("Wordlist Path"))
        wl_row = QHBoxLayout()
        import sys
        default_wl = (
            r"C:\Tools\rockyou.txt" if sys.platform == "win32"
            else "/usr/share/wordlists/rockyou.txt"
        )
        self._wordlist = _input(default_wl)
        browse = _btn("Browse")
        browse.clicked.connect(self._browse)
        wl_row.addWidget(self._wordlist, 1)
        wl_row.addWidget(browse)
        lay.addLayout(wl_row)

        btn_row = QHBoxLayout()
        self._start_btn = _btn("Start Crack", accent=True)
        self._start_btn.clicked.connect(self._start)
        self._stop_btn = _btn("Stop")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop)
        btn_row.addWidget(self._start_btn)
        btn_row.addWidget(self._stop_btn)
        btn_row.addStretch()
        lay.addLayout(btn_row)

        self._progress = QProgressBar()
        self._progress.setTextVisible(False)
        self._progress.setRange(0, 0)
        self._progress.setVisible(False)
        self._progress.setStyleSheet(
            "QProgressBar { background: #181825; border: 1px solid #313244; "
            "border-radius: 3px; height: 6px; }"
            "QProgressBar::chunk { background: #89b4fa; border-radius: 3px; }"
        )
        lay.addWidget(self._progress)

        self._out = _multiline(height=200)
        lay.addWidget(self._out)
        lay.addStretch()

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist")
        if path:
            self._wordlist.setText(path)

    def _start(self):
        if not HAS_FLASK_LOGIC:
            self._out.setPlainText("[!] pip install itsdangerous")
            return
        cookie = self._cookie.text().strip()
        wl = self._wordlist.text().strip()
        if not cookie or not wl:
            self._out.setPlainText("[!] Provide cookie and wordlist path.")
            return
        if not Path(wl).exists():
            self._out.setPlainText(f"[!] Wordlist not found: {wl}")
            return

        self._out.setPlainText(f"[*] Cracking… wordlist: {wl}\n")
        self._progress.setVisible(True)
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)

        self._worker = _CrackWorker(cookie, wl)
        self._worker.progress.connect(self._on_progress)
        self._worker.found.connect(self._on_found)
        self._worker.done.connect(self._on_done)
        self._worker.start()

    def _stop(self):
        if self._worker:
            self._worker.stop()

    def _on_progress(self, tried: int, current: str):
        self._out.setPlainText(f"[*] Tried {tried:,} candidates…\n[*] Current: {current}")

    def _on_found(self, secret: str):
        if secret:
            self._out.setPlainText(f"[+] FOUND SECRET KEY: {secret}")
        else:
            self._out.setPlainText("[-] Wordlist exhausted — no match found.")

    def _on_done(self, tried: int):
        self._progress.setVisible(False)
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        current = self._out.toPlainText()
        self._out.setPlainText(current + f"\n[*] Total candidates tried: {tried:,}")


# ── Cookie tab group ────────────────────────────────────────────────────────

class _CookieTab(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 4, 0, 0)

        inner = QTabWidget()
        inner.setStyleSheet(
            "QTabBar::tab { padding: 4px 14px; }"
            "QTabBar::tab:selected { color: #89b4fa; border-bottom: 2px solid #89b4fa; }"
        )
        inner.addTab(_DecodePanel(), "Decode")
        inner.addTab(_EncodePanel(), "Encode")
        inner.addTab(_TamperPanel(), "Tamper")
        inner.addTab(_VerifyPanel(), "Verify")
        inner.addTab(_CrackPanel(), "Crack")
        lay.addWidget(inner)


# ── Werkzeug PIN tab ────────────────────────────────────────────────────────

class _PinTab(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(8)

        intro = QLabel(
            "Calculate the Werkzeug debugger PIN from values read off the target via LFI."
        )
        intro.setStyleSheet("color: #a6adc8; font-size: 11px;")
        intro.setWordWrap(True)
        lay.addWidget(intro)

        fields = [
            ("Username", "username", "/proc/self/status → Uid, then /etc/passwd"),
            ("Flask mod path", "mod_path", "/proc/self/maps (grep flask), e.g. /app/venv/lib/.../flask/__init__.py"),
            ("MAC address", "mac", "/sys/class/net/eth0/address — as-is (xx:xx:xx:xx:xx:xx)"),
            ("Machine ID", "machine_id", "/etc/machine-id — 32 hex chars"),
            ("Cgroup (optional)", "cgroup", "/proc/self/cgroup first line — needed for containers"),
        ]
        self._inputs: dict[str, QLineEdit] = {}
        for label, key, hint in fields:
            lay.addWidget(_lbl(label))
            inp = _input(hint)
            self._inputs[key] = inp
            lay.addWidget(inp)

        row = QHBoxLayout()
        go = _btn("Calculate PIN", accent=True)
        go.clicked.connect(self._run)
        row.addWidget(go)
        row.addStretch()
        lay.addLayout(row)

        self._out = _multiline(height=160)
        lay.addWidget(self._out)
        lay.addStretch()

    def _run(self):
        if not HAS_PIN_LOGIC:
            self._out.setPlainText("[!] werkzeug_pin_logic import failed.")
            return

        username = self._inputs["username"].text().strip()
        mod_path = self._inputs["mod_path"].text().strip()
        mac_raw = self._inputs["mac"].text().strip()
        machine_id = self._inputs["machine_id"].text().strip()
        cgroup = self._inputs["cgroup"].text().strip()

        if not all([username, mod_path, mac_raw, machine_id]):
            self._out.setPlainText("[!] Fill in username, mod path, MAC, and machine ID.")
            return

        try:
            mac_int = mac_to_int(mac_raw)
            mid_bytes = build_machine_id(machine_id, cgroup)
            pin = calculate_pin(username, mod_path, mac_int, mid_bytes)
            self._out.setPlainText(
                f"  PIN: {pin}\n\n"
                f"  username   : {username}\n"
                f"  mod_path   : {mod_path}\n"
                f"  MAC (int)  : {mac_int}\n"
                f"  machine_id : {mid_bytes.decode(errors='replace')}"
            )
        except Exception as e:
            self._out.setPlainText(f"[!] {e}")


# ── Top-level FlaskToolsTab ─────────────────────────────────────────────────

class FlaskToolsTab(QWidget):
    """Tab added to the Tools group in the main window."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)

        tabs = QTabWidget()
        tabs.setStyleSheet(
            "QTabBar::tab { padding: 5px 16px; }"
            "QTabBar::tab:selected { color: #89b4fa; font-weight: bold; "
            "border-bottom: 2px solid #89b4fa; }"
        )
        tabs.addTab(_CookieTab(), "Flask Cookie")
        tabs.addTab(_PinTab(), "Werkzeug PIN")
        lay.addWidget(tabs)
