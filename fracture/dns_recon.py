"""
DNS / Recon tab — quick DNS lookups and WHOIS via subprocess.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
from typing import Optional

from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

# ── Styles ──────────────────────────────────────────────────────────────────

_SS_LABEL = "color: #a6adc8; font-size: 11px; font-weight: bold;"
_SS_INPUT = (
    "QLineEdit { background: #181825; color: #cdd6f4; border: 1px solid #313244; "
    "border-radius: 4px; padding: 5px 8px; }"
    "QLineEdit:focus { border-color: #89b4fa; }"
)
_SS_OUTPUT = (
    "QPlainTextEdit { background: #0d1117; color: #a6e3a1; "
    "font-family: 'Fira Code', 'JetBrains Mono', monospace; font-size: 12px; "
    "border: 1px solid #313244; border-radius: 4px; padding: 8px; }"
)
_SS_BTN = (
    "QPushButton { background: #313244; color: #cdd6f4; border: none; "
    "border-radius: 4px; padding: 5px 14px; }"
    "QPushButton:hover { background: #45475a; }"
)
_SS_BTN_ACCENT = (
    "QPushButton { background: #89b4fa; color: #1e1e2e; font-weight: bold; "
    "border: none; border-radius: 4px; padding: 5px 14px; }"
    "QPushButton:hover { background: #b4befe; }"
)
_SS_COMBO = (
    "QComboBox { background: #181825; color: #cdd6f4; border: 1px solid #313244; "
    "border-radius: 4px; padding: 4px 8px; } "
    "QComboBox QAbstractItemView { background: #181825; color: #cdd6f4; "
    "selection-background-color: #313244; }"
)


def _lbl(text: str) -> QLabel:
    l = QLabel(text)
    l.setStyleSheet(_SS_LABEL)
    return l


# ── Worker threads ───────────────────────────────────────────────────────────

class _DnsWorker(QThread):
    result = pyqtSignal(str)

    def __init__(self, target: str, record_type: str, use_dig: bool):
        super().__init__()
        self._target = target
        self._type = record_type
        self._use_dig = use_dig

    def run(self):
        target = self._target.strip()
        if not target:
            self.result.emit("[!] No target specified.")
            return

        if self._use_dig and shutil.which("dig"):
            self._dig_lookup(target)
        else:
            self._socket_lookup(target)

    def _dig_lookup(self, target: str):
        lines = [f"[*] dig {self._type} {target}\n"]
        try:
            out = subprocess.check_output(
                ["dig", self._type, target, "+noall", "+answer", "+authority"],
                timeout=10,
                text=True,
                stderr=subprocess.STDOUT,
            )
            lines.append(out if out.strip() else "(no answer)")

            if self._type == "ANY":
                for rt in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
                    extra = subprocess.check_output(
                        ["dig", rt, target, "+short"],
                        timeout=10, text=True, stderr=subprocess.STDOUT,
                    )
                    if extra.strip():
                        lines.append(f"[{rt}]")
                        lines.append(extra)
        except subprocess.TimeoutExpired:
            lines.append("[!] Timed out.")
        except subprocess.CalledProcessError as e:
            lines.append(e.output or str(e))
        except Exception as e:
            lines.append(f"[!] {e}")
        self.result.emit("\n".join(lines))

    def _socket_lookup(self, target: str):
        lines = [f"[*] Python socket lookup — {self._type} {target}\n"]
        try:
            if self._type in ("A", "ANY"):
                info = socket.getaddrinfo(target, None, socket.AF_INET)
                lines.append("[A] IPv4 addresses:")
                for r in info:
                    lines.append(f"  {r[4][0]}")
            if self._type in ("AAAA", "ANY"):
                try:
                    info6 = socket.getaddrinfo(target, None, socket.AF_INET6)
                    lines.append("[AAAA] IPv6 addresses:")
                    for r in info6:
                        lines.append(f"  {r[4][0]}")
                except socket.gaierror:
                    pass
            if self._type in ("PTR",):
                rev = socket.gethostbyaddr(target)
                lines.append(f"[PTR] {rev[0]}")
        except socket.gaierror as e:
            lines.append(f"[!] DNS error: {e}")
        except Exception as e:
            lines.append(f"[!] {e}")
        self.result.emit("\n".join(lines))


class _WhoisWorker(QThread):
    result = pyqtSignal(str)

    def __init__(self, target: str):
        super().__init__()
        self._target = target

    def run(self):
        target = self._target.strip()
        if not target:
            self.result.emit("[!] No target specified.")
            return
        if not shutil.which("whois"):
            self.result.emit("[!] 'whois' not found in PATH.\nInstall: sudo apt install whois")
            return
        try:
            out = subprocess.check_output(
                ["whois", target],
                timeout=15,
                text=True,
                stderr=subprocess.STDOUT,
            )
            self.result.emit(out)
        except subprocess.TimeoutExpired:
            self.result.emit("[!] WHOIS timed out.")
        except Exception as e:
            self.result.emit(f"[!] {e}")


class _RevDnsWorker(QThread):
    result = pyqtSignal(str)

    def __init__(self, ip: str):
        super().__init__()
        self._ip = ip

    def run(self):
        ip = self._ip.strip()
        try:
            host, aliases, _ = socket.gethostbyaddr(ip)
            lines = [f"[+] PTR record for {ip}:", f"  Hostname : {host}"]
            if aliases:
                lines.append(f"  Aliases  : {', '.join(aliases)}")
            self.result.emit("\n".join(lines))
        except socket.herror as e:
            self.result.emit(f"[!] Reverse DNS failed: {e}")
        except Exception as e:
            self.result.emit(f"[!] {e}")


# ── Sub-panels ───────────────────────────────────────────────────────────────

class _DnsPanel(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._worker: Optional[_DnsWorker] = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(8)

        row = QHBoxLayout()
        row.setSpacing(8)

        target_col = QVBoxLayout()
        target_col.addWidget(_lbl("TARGET (domain or IP)"))
        self._target = QLineEdit()
        self._target.setStyleSheet(_SS_INPUT)
        self._target.setPlaceholderText("example.com")
        self._target.returnPressed.connect(self._run)
        target_col.addWidget(self._target)
        row.addLayout(target_col, 3)

        type_col = QVBoxLayout()
        type_col.addWidget(_lbl("RECORD TYPE"))
        self._rtype = QComboBox()
        self._rtype.setStyleSheet(_SS_COMBO)
        self._rtype.addItems(["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "ANY"])
        type_col.addWidget(self._rtype)
        row.addLayout(type_col, 1)

        lay.addLayout(row)

        opts_row = QHBoxLayout()
        self._use_dig = QCheckBox("Use dig (recommended)")
        self._use_dig.setStyleSheet("color: #cdd6f4;")
        self._use_dig.setChecked(bool(shutil.which("dig")))
        opts_row.addWidget(self._use_dig)
        opts_row.addStretch()
        lay.addLayout(opts_row)

        btn_row = QHBoxLayout()
        go = QPushButton("Lookup")
        go.setStyleSheet(_SS_BTN_ACCENT)
        go.clicked.connect(self._run)
        copy = QPushButton("Copy")
        copy.setStyleSheet(_SS_BTN)
        copy.clicked.connect(lambda: QApplication.clipboard() and QApplication.clipboard().setText(self._out.toPlainText()))
        btn_row.addWidget(go)
        btn_row.addWidget(copy)
        btn_row.addStretch()
        lay.addLayout(btn_row)

        self._out = QPlainTextEdit()
        self._out.setReadOnly(True)
        self._out.setStyleSheet(_SS_OUTPUT)
        lay.addWidget(self._out)

    def _run(self):
        target = self._target.text().strip()
        if not target:
            return
        self._out.setPlainText(f"[*] Looking up {self._rtype.currentText()} for {target}…")
        self._worker = _DnsWorker(target, self._rtype.currentText(), self._use_dig.isChecked())
        self._worker.result.connect(self._out.setPlainText)
        self._worker.start()


class _WhoisPanel(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._worker: Optional[_WhoisWorker] = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(8)

        lay.addWidget(_lbl("DOMAIN OR IP"))
        self._target = QLineEdit()
        self._target.setStyleSheet(_SS_INPUT)
        self._target.setPlaceholderText("example.com or 93.184.216.34")
        self._target.returnPressed.connect(self._run)
        lay.addWidget(self._target)

        btn_row = QHBoxLayout()
        go = QPushButton("WHOIS Lookup")
        go.setStyleSheet(_SS_BTN_ACCENT)
        go.clicked.connect(self._run)
        copy = QPushButton("Copy")
        copy.setStyleSheet(_SS_BTN)
        copy.clicked.connect(lambda: QApplication.clipboard() and QApplication.clipboard().setText(self._out.toPlainText()))
        btn_row.addWidget(go)
        btn_row.addWidget(copy)
        btn_row.addStretch()
        lay.addLayout(btn_row)

        self._out = QPlainTextEdit()
        self._out.setReadOnly(True)
        self._out.setStyleSheet(_SS_OUTPUT)
        lay.addWidget(self._out)

    def _run(self):
        target = self._target.text().strip()
        if not target:
            return
        self._out.setPlainText(f"[*] WHOIS {target}…")
        self._worker = _WhoisWorker(target)
        self._worker.result.connect(self._out.setPlainText)
        self._worker.start()


class _RevDnsPanel(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._worker: Optional[_RevDnsWorker] = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(8)

        lay.addWidget(_lbl("IP ADDRESS"))
        self._ip = QLineEdit()
        self._ip.setStyleSheet(_SS_INPUT)
        self._ip.setPlaceholderText("93.184.216.34")
        self._ip.returnPressed.connect(self._run)
        lay.addWidget(self._ip)

        btn_row = QHBoxLayout()
        go = QPushButton("Reverse Lookup")
        go.setStyleSheet(_SS_BTN_ACCENT)
        go.clicked.connect(self._run)
        btn_row.addWidget(go)
        btn_row.addStretch()
        lay.addLayout(btn_row)

        self._out = QPlainTextEdit()
        self._out.setReadOnly(True)
        self._out.setStyleSheet(_SS_OUTPUT)
        self._out.setMaximumHeight(120)
        lay.addWidget(self._out)
        lay.addStretch()

    def _run(self):
        ip = self._ip.text().strip()
        if not ip:
            return
        self._out.setPlainText(f"[*] Reverse DNS for {ip}…")
        self._worker = _RevDnsWorker(ip)
        self._worker.result.connect(self._out.setPlainText)
        self._worker.start()


# ── Top-level tab ────────────────────────────────────────────────────────────

class DnsReconTab(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 4, 0, 0)

        inner = QTabWidget()
        inner.setStyleSheet(
            "QTabBar::tab { padding: 4px 14px; }"
            "QTabBar::tab:selected { color: #89b4fa; border-bottom: 2px solid #89b4fa; }"
        )
        inner.addTab(_DnsPanel(), "DNS Lookup")
        inner.addTab(_WhoisPanel(), "WHOIS")
        inner.addTab(_RevDnsPanel(), "Reverse DNS")
        lay.addWidget(inner)
