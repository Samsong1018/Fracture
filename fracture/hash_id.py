"""
Hash Identifier + calculator tab.
"""

from __future__ import annotations

import hashlib
import re
from typing import Optional

from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
    QFrame,
    QSplitter,
)
from PyQt6.QtCore import Qt

# ── Hash signatures ─────────────────────────────────────────────────────────
# Each entry: (regex, name, hashcat_mode, john_format, notes)

_HASH_SIGS: list[tuple[str, str, str, str, str]] = [
    (r"^[a-f0-9]{32}$",              "MD5",             "0",    "raw-md5",       ""),
    (r"^[a-f0-9]{32}$",              "MD4",             "900",  "raw-md4",       "same length as MD5"),
    (r"^[a-f0-9]{32}$",              "LM",              "3000", "lm",            "Windows LAN Manager"),
    (r"^[a-f0-9]{32}$",              "NTLM",            "1000", "nt",            "Windows NTLM (same len as MD5)"),
    (r"^\$1\$[^$]+\$.{22}$",         "MD5crypt",        "500",  "md5crypt-long", "Linux $1$ shadow"),
    (r"^\$apr1\$[^$]+\$.{22}$",      "MD5crypt (apr1)", "1600", "md5crypt-long", "Apache htpasswd"),
    (r"^[a-f0-9]{40}$",              "SHA-1",           "100",  "raw-sha1",      ""),
    (r"^[a-f0-9]{40}$",              "MySQL 4.1+",      "300",  "mysql-sha1",    "same length as SHA-1"),
    (r"^[a-f0-9]{56}$",              "SHA-224",         "1300", "raw-sha224",    ""),
    (r"^[a-f0-9]{64}$",              "SHA-256",         "1400", "raw-sha256",    ""),
    (r"^[a-f0-9]{96}$",              "SHA-384",         "10800","raw-sha384",    ""),
    (r"^[a-f0-9]{128}$",             "SHA-512",         "1700", "raw-sha512",    ""),
    (r"^\$2[aby]\$[0-9]{2}\$.{53}$", "bcrypt",          "3200", "bcrypt",        ""),
    (r"^\$5\$[^$]+\$.+$",            "SHA-256crypt",    "7400", "sha256crypt",   "Linux $5$ shadow"),
    (r"^\$6\$[^$]+\$.+$",            "SHA-512crypt",    "1800", "sha512crypt",   "Linux $6$ shadow"),
    (r"^[a-f0-9]{16}$",              "MySQL 3",         "200",  "mysql",         "OLD_PASSWORD()"),
    (r"^\*[A-F0-9]{40}$",            "MySQL 4.1+",      "300",  "mysql-sha1",    "leading * prefix"),
    (r"^[a-f0-9]{48}$",              "SHA-1 x1.5",      "4500", "raw-sha1",      "uncommon"),
    (r"^[a-zA-Z0-9+/]{24}={0,2}$",  "Base64 (16 byte)","",     "",              "possibly MD5 base64"),
    (r"^[a-zA-Z0-9+/]{28}={0,2}$",  "Base64 (20 byte)","",     "",              "possibly SHA-1 base64"),
    (r"^[a-zA-Z0-9+/]{44}={0,2}$",  "Base64 (32 byte)","",     "",              "possibly SHA-256 base64"),
    (r"^\$P\$[a-zA-Z0-9./]{31}$",   "phpass",          "400",  "phpass",        "WordPress/phpBB"),
    (r"^\$S\$[a-zA-Z0-9./]{52}$",   "Drupal 7+",       "7900", "drupal7",       "SHA-512 + salt"),
    (r"^[a-f0-9]{32}:[a-f0-9]+$",   "MD5 + salt",      "20",   "md5",           "salt appended after :"),
    (r"^sha1\$[^$]+\$.+$",          "Django SHA-1",    "124",  "",              ""),
    (r"^pbkdf2_sha256\$.+$",         "Django PBKDF2",   "10000","",              ""),
    (r"^\{SHA\}[a-zA-Z0-9+/=]+$",   "LDAP SHA",        "101",  "nsldap",        ""),
    (r"^\{SSHA\}[a-zA-Z0-9+/=]+$",  "LDAP SSHA",       "111",  "nsldaps",       ""),
    (r"^[a-f0-9]{13}$",             "DES (crypt)",     "1500", "descrypt",      "13-char Unix crypt"),
    (r"^[./0-9A-Za-z]{13}$",        "DES (crypt)",     "1500", "descrypt",      "Unix crypt salted DES"),
    (r"^[a-f0-9]{8}$",              "CRC32",           "11500","",              "or Adler32"),
    (r"^[a-f0-9]{56}$",             "SHA3-224",        "17300","",              ""),
    (r"^[a-f0-9]{64}$",             "SHA3-256",        "17400","raw-sha256",    "same len as SHA-256"),
    (r"^[a-f0-9]{96}$",             "SHA3-384",        "17500","",              ""),
    (r"^[a-f0-9]{128}$",            "SHA3-512",        "17600","",              "same len as SHA-512"),
    (r"^[a-f0-9]{32}$",             "MD5(MD5)",        "2600", "",              "double MD5"),
    (r"^[a-f0-9]{40}$",             "RIPEMD-160",      "6000", "ripemd-160",    ""),
    (r"^[a-f0-9]{64}$",             "Blake2b-256",     "600",  "",              ""),
    (r"^[a-f0-9]{128}$",            "Blake2b-512",     "600",  "",              ""),
    (r"^\$y\$[^$]+\$.+$",           "yescrypt",        "20600","",              "modern Linux shadow"),
    (r"^[a-f0-9]{40}$",             "Whirlpool-0",     "6100", "whirlpool",     ""),
    (r"^[a-f0-9]{128}$",            "Whirlpool",       "6100", "whirlpool",     ""),
]

# ── Styles ──────────────────────────────────────────────────────────────────

_SS_LABEL  = "color: #a6adc8; font-size: 11px; font-weight: bold;"
_SS_INPUT  = (
    "QLineEdit { background: #181825; color: #cdd6f4; border: 1px solid #313244; "
    "border-radius: 4px; padding: 5px 8px; font-family: monospace; }"
    "QLineEdit:focus { border-color: #89b4fa; }"
)
_SS_OUTPUT = (
    "QPlainTextEdit { background: #0d1117; color: #cdd6f4; "
    "font-family: 'Fira Code', 'JetBrains Mono', monospace; font-size: 12px; "
    "border: 1px solid #313244; border-radius: 4px; padding: 8px; }"
)
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


def identify(h: str) -> list[dict]:
    h = h.strip()
    matches = []
    seen: set[str] = set()
    for pattern, name, hc, jf, note in _HASH_SIGS:
        if re.fullmatch(pattern, h, re.IGNORECASE):
            key = f"{name}|{hc}"
            if key not in seen:
                seen.add(key)
                matches.append({
                    "name": name,
                    "hashcat": hc,
                    "john": jf,
                    "note": note,
                    "length": len(h),
                })
    return matches


def _format_results(h: str, matches: list[dict]) -> str:
    if not matches:
        return f"[?] No match found for hash of length {len(h)}\n\nIs it hex? Try removing 0x prefix or spaces."
    lines = [f"[+] Hash: {h}", f"[+] Length: {len(h)} chars\n"]
    for i, m in enumerate(matches, 1):
        lines.append(f"  {i}. {m['name']}")
        if m["hashcat"]:
            lines.append(f"     Hashcat mode : -m {m['hashcat']}")
        if m["john"]:
            lines.append(f"     John format  : --format={m['john']}")
        if m["note"]:
            lines.append(f"     Note         : {m['note']}")
        lines.append("")
    if matches:
        first = matches[0]
        lines.append("── Quick commands ──────────────────────")
        if first["hashcat"]:
            lines.append(f"hashcat -m {first['hashcat']} hash.txt wordlist.txt")
        if first["john"]:
            lines.append(f"john --format={first['john']} --wordlist=rockyou.txt hash.txt")
    return "\n".join(lines)


# ── Widget ───────────────────────────────────────────────────────────────────

class HashIdTab(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 12)
        root.setSpacing(10)

        # ── Identifier ────────────────────────────────────────────────
        root.addWidget(_lbl("PASTE HASH TO IDENTIFY"))
        self._hash_in = QLineEdit()
        self._hash_in.setStyleSheet(_SS_INPUT)
        self._hash_in.setPlaceholderText("5f4dcc3b5aa765d61d8327deb882cf99")
        self._hash_in.textChanged.connect(self._auto_identify)
        root.addWidget(self._hash_in)

        id_row = QHBoxLayout()
        id_btn = QPushButton("Identify")
        id_btn.setStyleSheet(_SS_BTN_ACCENT)
        id_btn.clicked.connect(self._identify)
        id_row.addWidget(id_btn)
        clear_btn = QPushButton("Clear")
        clear_btn.setStyleSheet(_SS_BTN)
        clear_btn.clicked.connect(lambda: (self._hash_in.clear(), self._id_out.clear()))
        id_row.addWidget(clear_btn)
        id_row.addStretch()
        root.addLayout(id_row)

        self._id_out = QPlainTextEdit()
        self._id_out.setReadOnly(True)
        self._id_out.setStyleSheet(_SS_OUTPUT)
        self._id_out.setMinimumHeight(180)
        root.addWidget(self._id_out)

        # ── Divider ────────────────────────────────────────────────────
        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setFixedHeight(1)
        div.setStyleSheet("background: #313244;")
        root.addWidget(div)

        # ── Calculator ─────────────────────────────────────────────────
        root.addWidget(_lbl("COMPUTE HASH FROM TEXT"))
        calc_row = QHBoxLayout()
        calc_row.setSpacing(8)

        self._calc_in = QLineEdit()
        self._calc_in.setStyleSheet(_SS_INPUT)
        self._calc_in.setPlaceholderText("Input text to hash")
        calc_row.addWidget(self._calc_in, 3)

        self._algo = QComboBox()
        self._algo.setStyleSheet(
            "QComboBox { background: #181825; color: #cdd6f4; border: 1px solid #313244; "
            "border-radius: 4px; padding: 4px 8px; } "
            "QComboBox QAbstractItemView { background: #181825; color: #cdd6f4; "
            "selection-background-color: #313244; }"
        )
        self._algo.addItems(["md5", "sha1", "sha224", "sha256", "sha384", "sha512",
                              "sha3_256", "sha3_512", "blake2b", "blake2s"])
        calc_row.addWidget(self._algo, 1)

        calc_btn = QPushButton("Hash it")
        calc_btn.setStyleSheet(_SS_BTN_ACCENT)
        calc_btn.clicked.connect(self._calc_hash)
        calc_row.addWidget(calc_btn)

        root.addLayout(calc_row)

        self._calc_out = QLineEdit()
        self._calc_out.setReadOnly(True)
        self._calc_out.setStyleSheet(_SS_INPUT)
        self._calc_out.setPlaceholderText("Result will appear here")
        root.addWidget(self._calc_out)

        copy_btn = QPushButton("Copy Hash")
        copy_btn.setStyleSheet(_SS_BTN)
        copy_btn.clicked.connect(self._copy_calc)
        root.addWidget(copy_btn, alignment=Qt.AlignmentFlag.AlignLeft)

        root.addStretch()

    def _auto_identify(self, text: str):
        text = text.strip()
        if not text:
            self._id_out.clear()
            return
        if len(text) >= 8:
            self._identify()

    def _identify(self):
        h = self._hash_in.text().strip()
        if not h:
            return
        matches = identify(h)
        self._id_out.setPlainText(_format_results(h, matches))

    def _calc_hash(self):
        text = self._calc_in.text()
        algo = self._algo.currentText()
        try:
            h = hashlib.new(algo, text.encode()).hexdigest()
            self._calc_out.setText(h)
        except Exception as e:
            self._calc_out.setText(f"Error: {e}")

    def _copy_calc(self):
        cb = QApplication.clipboard()
        if cb:
            cb.setText(self._calc_out.text())
