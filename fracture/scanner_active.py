"""
Active Scanner tab — sends crafted probe requests to detect vulnerabilities.

Probe types:
  - SQL Injection (error-based detection)
  - Reflected XSS
  - Path Traversal
  - SSRF Probes

All probing runs in a QThread so the UI stays responsive.
"""

import base64
import hashlib
import hmac
import json
import socket
import ssl
import time
import urllib.parse
from typing import Optional

from PyQt6.QtCore import QThread, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .proxy import HttpRequest

BUFFER = 65536

# ---------------------------------------------------------------------------
# Catppuccin Mocha stylesheet constants
# ---------------------------------------------------------------------------

_BG = "#1e1e2e"
_SURFACE = "#181825"
_OVERLAY = "#313244"
_HIGHLIGHT = "#45475a"
_TEXT = "#cdd6f4"

_TEXTEDIT_SS = "QTextEdit { background: #181825; border: 1px solid #313244; color: #cdd6f4; }"
_LINEEDIT_SS = "QLineEdit { background: #181825; border: 1px solid #313244; padding: 4px; color: #cdd6f4; }"
_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
    "QPushButton:hover { background: #45475a; }"
    "QPushButton:disabled { color: #585b70; }"
)
_CHECKBOX_SS = "QCheckBox { spacing: 6px; color: #cdd6f4; }"
_LABEL_SS = "color: #a6adc8; font-size: 10px;"
_TABLE_SS = (
    "QTableWidget { background: #181825; border: 1px solid #313244; "
    "gridline-color: #313244; color: #cdd6f4; }"
    "QHeaderView::section { background: #313244; color: #cdd6f4; padding: 4px; "
    "border: none; border-right: 1px solid #45475a; }"
    "QTableWidget::item:selected { background: #45475a; }"
)

# ---------------------------------------------------------------------------
# Probe definitions
# ---------------------------------------------------------------------------

SQLI_PAYLOADS = [
    "'",
    '"',
    "'; --",
    '" OR "1"="1',
    "' OR '1'='1",
    "1 AND 1=2--",
]

SQLI_ERROR_STRINGS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error",
    "pg_query()",
    "sqlite_",
    "ora-",
    "db2 sql error",
    "odbc sql server driver",
]

XSS_PROBE = "<coughxss1234>"

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

PATH_TRAVERSAL_INDICATORS = [
    "root:x:0:0",
    "[boot loader]",
    "root:*:",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost/",
]

SSRF_BODY_INDICATORS = [
    "ami-id",
    "instance-id",
    "local-hostname",
]

# Blind SQLi — time-based payloads
BLIND_SQLI_TIME_PAYLOADS = [
    "'; WAITFOR DELAY '0:0:5'--",
    "'; SELECT SLEEP(5)--",
    "1 AND SLEEP(5)--",
    "'; SELECT pg_sleep(5)--",
    "1; WAITFOR DELAY '0:0:5'--",
]

# Blind SQLi — boolean-blind payload pairs (true, false)
BLIND_SQLI_BOOL_PAIRS = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("1 OR 1=1", "1 OR 1=2"),
]

# XXE payloads
XXE_PAYLOADS = [
    b"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
    b"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
    b"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>",
]

XXE_INDICATORS = ["root:", "bin:", "[extensions]", "for 16-bit app support"]

# JWT regex
import re as _re
_JWT_RE = _re.compile(r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*")

JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "jwt_secret", "changeme",
    "key", "token", "api_key", "letmein", "admin",
]

# SSTI payloads
SSTI_PAYLOADS = [
    "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "${{7*7}}", "{7*7}", "[[7*7]]",
]

# Command injection
CMDI_PAYLOADS = [
    ";id", "`id`", "$(id)", "&whoami", "|whoami", "; whoami #", "$(whoami)",
]
CMDI_INDICATORS = ["uid=", "gid=", "root", "daemon", "www-data"]

# CRLF injection
CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:crlf=injected",
    "\r\nSet-Cookie:crlf=injected",
    "%0aSet-Cookie:crlf=injected",
    "%0d%0aX-Injected:crlf",
]

# Host header injection
HOST_HEADER_VALUES = ["evil.com", "attacker.com", "burpcollaborator.net"]

# Open redirect
OPEN_REDIRECT_PAYLOADS = [
    "//evil.com", "https://evil.com", "//evil.com/path", "http://evil.com",
]
OPEN_REDIRECT_DOMAIN = "evil.com"
OPEN_REDIRECT_PARAM_NAMES = {
    "url", "redirect", "next", "return", "goto", "dest", "destination",
    "target", "redir", "forward", "location", "continue", "page",
}

# NoSQL injection
NOSQL_QUERY_PAYLOADS = ["[$gt]=", "[$ne]=", "[$regex]=.*"]
NOSQL_JSON_PAYLOADS = ['{"$gt": ""}', '{"$ne": null}', '{"$where": "1==1"}']
NOSQL_SUCCESS_INDICATORS = [
    '"success"', '"token"', '"welcome"', "welcome", "dashboard", "logged in",
]

# LDAP injection
LDAP_PAYLOADS = [
    ")(cn=*)", "*)(uid=*))(|(uid=*", ")(|(password=*))", "admin)(&(password=*", "*",
]
LDAP_ERROR_INDICATORS = [
    "ldap", "javax.naming", "ldap_search", "invaliddnsyntax", "ldapexception",
    "namingexception", "[ldap:", "ldap error",
]

# Prototype pollution
PROTO_QUERY_PAYLOADS = [
    "__proto__[polluted]=yes",
    "constructor[prototype][polluted]=yes",
]

# Backslash / trigger-character probe set
BACKSLASH_TRIGGER_CHARS = ["'", '"', "\\", "<", ">", "${", "{{", "`", ";", "|"]
BACKSLASH_DELTA_THRESHOLD = 64

# ---------------------------------------------------------------------------
# Network helper
# ---------------------------------------------------------------------------

def _send_raw(
    host: str, port: int, is_https: bool, raw_request: bytes
) -> tuple[bytes, float]:
    """Send raw HTTP request bytes. Returns (response_bytes, elapsed_seconds)."""
    start = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=10)
        if is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(raw_request)
        response_data = b""
        sock.settimeout(5)
        while True:
            try:
                chunk = sock.recv(BUFFER)
                if not chunk:
                    break
                response_data += chunk
            except socket.timeout:
                break
        sock.close()
    except Exception as exc:
        print(f"[active-scanner] send error: {exc}")
        response_data = b""
    elapsed = time.monotonic() - start
    return response_data, elapsed


def _get_status_code(response: bytes) -> int:
    try:
        first_line = response.split(b"\r\n", 1)[0]
        parts = first_line.split(b" ", 2)
        return int(parts[1])
    except Exception:
        return 0


def _get_body(response: bytes) -> bytes:
    sep = response.find(b"\r\n\r\n")
    if sep == -1:
        return b""
    return response[sep + 4:]


def _get_headers_section(response: bytes) -> str:
    return response.split(b"\r\n\r\n", 1)[0].decode(errors="replace")


def _get_location_header(response: bytes) -> str:
    for line in _get_headers_section(response).splitlines():
        if line.lower().startswith("location:"):
            return line.split(":", 1)[1].strip()
    return ""


# ---------------------------------------------------------------------------
# Parameter extraction
# ---------------------------------------------------------------------------

def _extract_params_from_query(path: str) -> list[tuple[str, str]]:
    """Return list of (name, value) from the query string of path."""
    if "?" not in path:
        return []
    qs = path.split("?", 1)[1]
    params = []
    for part in qs.split("&"):
        if "=" in part:
            k, _, v = part.partition("=")
            params.append((urllib.parse.unquote_plus(k), urllib.parse.unquote_plus(v)))
        elif part:
            params.append((urllib.parse.unquote_plus(part), ""))
    return params


def _extract_params_from_form_body(body: bytes) -> list[tuple[str, str]]:
    """Return list of (name, value) from an application/x-www-form-urlencoded body."""
    try:
        text = body.decode(errors="replace")
        params = []
        for part in text.split("&"):
            if "=" in part:
                k, _, v = part.partition("=")
                params.append((urllib.parse.unquote_plus(k), urllib.parse.unquote_plus(v)))
            elif part:
                params.append((urllib.parse.unquote_plus(part), ""))
        return params
    except Exception:
        return []


def _extract_params_from_json_body(body: bytes) -> list[tuple[str, str]]:
    """Return list of (name, str_value) for top-level string values in a JSON body."""
    try:
        obj = json.loads(body.decode(errors="replace"))
        if not isinstance(obj, dict):
            return []
        return [(k, v) for k, v in obj.items() if isinstance(v, str)]
    except Exception:
        return []


def _get_content_type(headers: dict[str, str]) -> str:
    for k, v in headers.items():
        if k.lower() == "content-type":
            return v.lower()
    return ""


# ---------------------------------------------------------------------------
# Request rebuilding helpers
# ---------------------------------------------------------------------------

def _rebuild_raw(method: str, path: str, version: str, headers: dict[str, str], body: bytes) -> bytes:
    lines = [f"{method} {path} HTTP/{version}"]
    # Rebuild Content-Length if body changed
    updated_headers = dict(headers)
    if body is not None:
        updated_headers["content-length"] = str(len(body))
    for k, v in updated_headers.items():
        lines.append(f"{k}: {v}")
    header_text = "\r\n".join(lines) + "\r\n\r\n"
    return header_text.encode(errors="replace") + body


def _inject_query_param(path: str, param_name: str, payload: str) -> str:
    """Return path with param_name's value replaced by payload."""
    if "?" not in path:
        return path
    base, qs = path.split("?", 1)
    parts = []
    for part in qs.split("&"):
        if "=" in part:
            k, _, v = part.partition("=")
            decoded_k = urllib.parse.unquote_plus(k)
            if decoded_k == param_name:
                parts.append(f"{k}={urllib.parse.quote_plus(payload)}")
            else:
                parts.append(part)
        else:
            parts.append(part)
    return base + "?" + "&".join(parts)


def _inject_form_param(body: bytes, param_name: str, payload: str) -> bytes:
    """Return form body bytes with param_name's value replaced by payload."""
    try:
        text = body.decode(errors="replace")
        parts = []
        for part in text.split("&"):
            if "=" in part:
                k, _, v = part.partition("=")
                decoded_k = urllib.parse.unquote_plus(k)
                if decoded_k == param_name:
                    parts.append(f"{k}={urllib.parse.quote_plus(payload)}")
                else:
                    parts.append(part)
            else:
                parts.append(part)
        return "&".join(parts).encode(errors="replace")
    except Exception:
        return body


def _inject_json_param(body: bytes, param_name: str, payload: str) -> bytes:
    """Return JSON body bytes with param_name's string value replaced by payload."""
    try:
        obj = json.loads(body.decode(errors="replace"))
        if isinstance(obj, dict) and param_name in obj:
            obj[param_name] = payload
        return json.dumps(obj).encode()
    except Exception:
        return body


# ---------------------------------------------------------------------------
# Backslash-powered scanner add-on
# ---------------------------------------------------------------------------

def _probe_backslash(req: HttpRequest, port: int, scanner: "ScanWorker") -> None:
    """Probe each query/body parameter with metacharacters and flag stable diffs.

    Sends a baseline, then for each metacharacter in BACKSLASH_TRIGGER_CHARS,
    appends the char to each param value and compares the response.
    A trigger is flagged when status differs from baseline OR
    |Δlen| > BACKSLASH_DELTA_THRESHOLD (64 bytes).
    Findings are emitted via `scanner.finding` at LOW severity.
    """
    host = req.host
    is_https = req.is_https

    # 1. Baseline
    baseline_raw = _rebuild_raw(req.method, req.path, req.version, req.headers, req.body)
    baseline_resp, _ = _send_raw(host, port, is_https, baseline_raw)
    baseline_status = _get_status_code(baseline_resp)
    baseline_len = len(baseline_resp)

    # 2. Enumerate params
    ct = _get_content_type(req.headers)
    is_form = "application/x-www-form-urlencoded" in ct
    is_json = "application/json" in ct

    query_params = _extract_params_from_query(req.path)
    if is_form:
        body_params = _extract_params_from_form_body(req.body)
    elif is_json:
        body_params = _extract_params_from_json_body(req.body)
    else:
        body_params = []

    def _send_variant(new_path: str, new_body: bytes) -> tuple[int, int]:
        raw = _rebuild_raw(req.method, new_path, req.version, req.headers, new_body)
        resp, _ = _send_raw(host, port, is_https, raw)
        return _get_status_code(resp), len(resp)

    def _flag(char: str, name: str, status: int, length: int) -> None:
        delta = length - baseline_len
        detail = (
            f"Char {char!r} appended to param {name!r}: "
            f"status {status} (baseline {baseline_status}), "
            f"len {length} (Δ {delta:+d}, threshold ±{BACKSLASH_DELTA_THRESHOLD})"
        )
        scanner.finding.emit(
            "Low",
            f"Backslash probe: trigger character `{char}` in param `{name}`",
            detail,
            name,
        )

    # 3. Probe each char against each parameter
    for name, value in query_params:
        if scanner._stop_requested:
            return
        for ch in BACKSLASH_TRIGGER_CHARS:
            if scanner._stop_requested:
                return
            new_path = _inject_query_param(req.path, name, value + ch)
            status, length = _send_variant(new_path, req.body)
            if status != baseline_status or abs(length - baseline_len) > BACKSLASH_DELTA_THRESHOLD:
                _flag(ch, name, status, length)

    for name, value in body_params:
        if scanner._stop_requested:
            return
        for ch in BACKSLASH_TRIGGER_CHARS:
            if scanner._stop_requested:
                return
            if is_form:
                new_body = _inject_form_param(req.body, name, value + ch)
            elif is_json:
                new_body = _inject_json_param(req.body, name, value + ch)
            else:
                continue
            status, length = _send_variant(req.path, new_body)
            if status != baseline_status or abs(length - baseline_len) > BACKSLASH_DELTA_THRESHOLD:
                _flag(ch, name, status, length)


# ---------------------------------------------------------------------------
# Scan Worker
# ---------------------------------------------------------------------------

class ScanWorker(QThread):
    """
    Runs active scans in a background thread.

    Signals:
      finding(severity, title, detail, param) — emitted for each finding
      finished()                               — emitted when scan completes or is stopped
      progress(current, total)                 — emitted after each probe
    """

    finding = pyqtSignal(str, str, str, str)   # severity, title, detail, param
    finished = pyqtSignal()
    progress = pyqtSignal(int, int)             # current, total

    def __init__(
        self,
        req: HttpRequest,
        run_sqli: bool = True,
        run_xss: bool = True,
        run_path_traversal: bool = True,
        run_ssrf: bool = True,
        run_blind_sqli_time: bool = True,
        run_blind_sqli_bool: bool = True,
        run_xxe: bool = True,
        run_jwt: bool = True,
        run_ssti: bool = True,
        run_cmdi: bool = True,
        run_crlf: bool = True,
        run_host_header: bool = True,
        run_smuggling: bool = True,
        run_open_redirect: bool = True,
        run_nosql: bool = True,
        run_ldap: bool = True,
        run_proto_pollution: bool = True,
        run_backslash: bool = False,
        parent: Optional[QThread] = None,
    ) -> None:
        super().__init__(parent)
        self._req = req
        self._run_backslash = run_backslash
        self._run_sqli = run_sqli
        self._run_xss = run_xss
        self._run_path_traversal = run_path_traversal
        self._run_ssrf = run_ssrf
        self._run_blind_sqli_time = run_blind_sqli_time
        self._run_blind_sqli_bool = run_blind_sqli_bool
        self._run_xxe = run_xxe
        self._run_jwt = run_jwt
        self._run_ssti = run_ssti
        self._run_cmdi = run_cmdi
        self._run_crlf = run_crlf
        self._run_host_header = run_host_header
        self._run_smuggling = run_smuggling
        self._run_open_redirect = run_open_redirect
        self._run_nosql = run_nosql
        self._run_ldap = run_ldap
        self._run_proto_pollution = run_proto_pollution
        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _send(self, path: str, body: bytes) -> tuple[bytes, float]:
        """Send a probe request with the given path and body, returning (response, elapsed)."""
        raw = _rebuild_raw(
            self._req.method, path, self._req.version, self._req.headers, body
        )
        return _send_raw(self._req.host, self._req.port, self._req.is_https, raw)

    def _collect_probes(self) -> list[tuple[str, str, str, bytes]]:
        """
        Build a list of (scan_type, param_name, probe_label, modified_body_or_none, modified_path).
        Returns list of (scan_type, param_name, probe_payload, modified_path, modified_body).
        """
        probes: list[tuple[str, str, str, str, bytes]] = []
        req = self._req
        ct = _get_content_type(req.headers)
        is_form = "application/x-www-form-urlencoded" in ct
        is_json = "application/json" in ct

        query_params = _extract_params_from_query(req.path)
        if is_form:
            body_params = _extract_params_from_form_body(req.body)
        elif is_json:
            body_params = _extract_params_from_json_body(req.body)
        else:
            body_params = []

        # SQL injection probes
        if self._run_sqli:
            for name, _ in query_params:
                for payload in SQLI_PAYLOADS:
                    new_path = _inject_query_param(req.path, name, payload)
                    probes.append(("sqli", name, payload, new_path, req.body))
            for name, _ in body_params:
                for payload in SQLI_PAYLOADS:
                    if is_form:
                        new_body = _inject_form_param(req.body, name, payload)
                    else:
                        new_body = _inject_json_param(req.body, name, payload)
                    probes.append(("sqli", name, payload, req.path, new_body))

        # XSS probes
        if self._run_xss:
            for name, _ in query_params:
                new_path = _inject_query_param(req.path, name, XSS_PROBE)
                probes.append(("xss", name, XSS_PROBE, new_path, req.body))
            for name, _ in body_params:
                if is_form:
                    new_body = _inject_form_param(req.body, name, XSS_PROBE)
                else:
                    new_body = _inject_json_param(req.body, name, XSS_PROBE)
                probes.append(("xss", name, XSS_PROBE, req.path, new_body))

        # Path traversal probes
        if self._run_path_traversal:
            for payload in PATH_TRAVERSAL_PAYLOADS:
                # Append to path (before query string)
                base_path = req.path.split("?")[0]
                qs_part = ("?" + req.path.split("?", 1)[1]) if "?" in req.path else ""
                new_path = base_path + "/" + payload + qs_part
                probes.append(("path_traversal", "<path>", payload, new_path, req.body))
            for name, _ in query_params:
                for payload in PATH_TRAVERSAL_PAYLOADS:
                    new_path = _inject_query_param(req.path, name, payload)
                    probes.append(("path_traversal", name, payload, new_path, req.body))
            for name, _ in body_params:
                for payload in PATH_TRAVERSAL_PAYLOADS:
                    if is_form:
                        new_body = _inject_form_param(req.body, name, payload)
                    else:
                        new_body = _inject_json_param(req.body, name, payload)
                    probes.append(("path_traversal", name, payload, req.path, new_body))

        # SSRF probes — only inject into URL-valued parameters
        if self._run_ssrf:
            url_query_params = [
                (n, v) for n, v in query_params
                if v.startswith("http://") or v.startswith("https://")
            ]
            url_body_params = [
                (n, v) for n, v in body_params
                if v.startswith("http://") or v.startswith("https://")
            ]
            for name, _ in url_query_params:
                for payload in SSRF_PAYLOADS:
                    new_path = _inject_query_param(req.path, name, payload)
                    probes.append(("ssrf", name, payload, new_path, req.body))
            for name, _ in url_body_params:
                for payload in SSRF_PAYLOADS:
                    if is_form:
                        new_body = _inject_form_param(req.body, name, payload)
                    else:
                        new_body = _inject_json_param(req.body, name, payload)
                    probes.append(("ssrf", name, payload, req.path, new_body))

        # Blind SQLi — time-based
        if self._run_blind_sqli_time:
            for name, _ in query_params:
                for payload in BLIND_SQLI_TIME_PAYLOADS:
                    new_path = _inject_query_param(req.path, name, payload)
                    probes.append(("blind_sqli_time", name, payload, new_path, req.body))
            for name, _ in body_params:
                for payload in BLIND_SQLI_TIME_PAYLOADS:
                    if is_form:
                        new_body = _inject_form_param(req.body, name, payload)
                    else:
                        new_body = _inject_json_param(req.body, name, payload)
                    probes.append(("blind_sqli_time", name, payload, req.path, new_body))

        # Blind SQLi — boolean-blind
        if self._run_blind_sqli_bool:
            for name, _ in query_params:
                for true_p, false_p in BLIND_SQLI_BOOL_PAIRS:
                    true_path = _inject_query_param(req.path, name, true_p)
                    false_path = _inject_query_param(req.path, name, false_p)
                    probes.append(("blind_sqli_bool_true", name, true_p, true_path, req.body))
                    probes.append(("blind_sqli_bool_false", name, false_p, false_path, req.body))
            for name, _ in body_params:
                for true_p, false_p in BLIND_SQLI_BOOL_PAIRS:
                    if is_form:
                        true_body = _inject_form_param(req.body, name, true_p)
                        false_body = _inject_form_param(req.body, name, false_p)
                    else:
                        true_body = _inject_json_param(req.body, name, true_p)
                        false_body = _inject_json_param(req.body, name, false_p)
                    probes.append(("blind_sqli_bool_true", name, true_p, req.path, true_body))
                    probes.append(("blind_sqli_bool_false", name, false_p, req.path, false_body))

        # XXE — only if body looks like XML
        if self._run_xxe:
            ct = _get_content_type(req.headers)
            body_start = req.body.lstrip()[:5]
            if "xml" in ct or body_start.startswith(b"<?xml") or body_start.startswith(b"<"):
                for xxe_payload in XXE_PAYLOADS:
                    probes.append(("xxe", "<body>", xxe_payload.decode(errors="replace"), req.path, xxe_payload))

        # JWT tests — detect JWTs in headers/body, add as single probe
        if self._run_jwt:
            jwt_found = None
            for v in req.headers.values():
                m = _JWT_RE.search(v)
                if m:
                    jwt_found = m.group(0)
                    break
            if jwt_found is None and req.body:
                m = _JWT_RE.search(req.body.decode(errors="replace"))
                if m:
                    jwt_found = m.group(0)
            if jwt_found:
                probes.append(("jwt_none", "<jwt>", jwt_found, req.path, req.body))
                probes.append(("jwt_weak", "<jwt>", jwt_found, req.path, req.body))

        # SSTI probes
        if self._run_ssti:
            for name, _ in query_params:
                for payload in SSTI_PAYLOADS:
                    new_path = _inject_query_param(req.path, name, payload)
                    probes.append(("ssti", name, payload, new_path, req.body))
            for name, _ in body_params:
                for payload in SSTI_PAYLOADS:
                    if is_form:
                        new_body = _inject_form_param(req.body, name, payload)
                    else:
                        new_body = _inject_json_param(req.body, name, payload)
                    probes.append(("ssti", name, payload, req.path, new_body))

        # Command injection probes
        if self._run_cmdi:
            for name, _ in query_params:
                for payload in CMDI_PAYLOADS:
                    new_path = _inject_query_param(req.path, name, payload)
                    probes.append(("cmdi", name, payload, new_path, req.body))
            for name, _ in body_params:
                for payload in CMDI_PAYLOADS:
                    if is_form:
                        new_body = _inject_form_param(req.body, name, payload)
                    else:
                        new_body = _inject_json_param(req.body, name, payload)
                    probes.append(("cmdi", name, payload, req.path, new_body))

        # CRLF injection probes
        if self._run_crlf:
            for name, _ in query_params:
                for payload in CRLF_PAYLOADS:
                    new_path = _inject_query_param(req.path, name, payload)
                    probes.append(("crlf", name, payload, new_path, req.body))
            for name, _ in body_params:
                for payload in CRLF_PAYLOADS:
                    if is_form:
                        new_body = _inject_form_param(req.body, name, payload)
                    else:
                        new_body = _inject_json_param(req.body, name, payload)
                    probes.append(("crlf", name, payload, req.path, new_body))

        # Host header injection — no parameter injection, sends modified Host header
        if self._run_host_header:
            for attacker_host in HOST_HEADER_VALUES:
                probes.append(("host_header", "<host>", attacker_host, req.path, req.body))

        # HTTP request smuggling — two fixed desync variants
        if self._run_smuggling:
            probes.append(("smuggling", "<request>", "CL.TE", req.path, req.body))
            probes.append(("smuggling", "<request>", "TE.CL", req.path, req.body))

        # Open redirect probes — only params that look URL-valued or have redirect-like names
        if self._run_open_redirect:
            redir_query = [
                (n, v) for n, v in query_params
                if v.startswith("/") or v.startswith("http") or n.lower() in OPEN_REDIRECT_PARAM_NAMES
            ]
            redir_body = [
                (n, v) for n, v in body_params
                if v.startswith("/") or v.startswith("http") or n.lower() in OPEN_REDIRECT_PARAM_NAMES
            ]
            for name, _ in redir_query:
                for payload in OPEN_REDIRECT_PAYLOADS:
                    new_path = _inject_query_param(req.path, name, payload)
                    probes.append(("open_redirect", name, payload, new_path, req.body))
            for name, _ in redir_body:
                for payload in OPEN_REDIRECT_PAYLOADS:
                    if is_form:
                        new_body = _inject_form_param(req.body, name, payload)
                    else:
                        new_body = _inject_json_param(req.body, name, payload)
                    probes.append(("open_redirect", name, payload, req.path, new_body))

        # NoSQL injection probes
        if self._run_nosql:
            for name, _ in query_params:
                for payload in NOSQL_QUERY_PAYLOADS:
                    new_path = _inject_query_param(req.path, name, payload)
                    probes.append(("nosql", name, payload, new_path, req.body))
            if is_json:
                for name, _ in body_params:
                    for payload in NOSQL_JSON_PAYLOADS:
                        new_body = _inject_json_param(req.body, name, payload)
                        probes.append(("nosql", name, payload, req.path, new_body))
            elif is_form:
                for name, _ in body_params:
                    new_body = _inject_form_param(req.body, name, "[$gt]=x")
                    probes.append(("nosql", name, "[$gt]=x", req.path, new_body))

        # LDAP injection probes
        if self._run_ldap:
            for name, _ in query_params:
                for payload in LDAP_PAYLOADS:
                    new_path = _inject_query_param(req.path, name, payload)
                    probes.append(("ldap", name, payload, new_path, req.body))
            for name, _ in body_params:
                for payload in LDAP_PAYLOADS:
                    if is_form:
                        new_body = _inject_form_param(req.body, name, payload)
                    else:
                        new_body = _inject_json_param(req.body, name, payload)
                    probes.append(("ldap", name, payload, req.path, new_body))

        # Prototype pollution probes
        if self._run_proto_pollution:
            for payload in PROTO_QUERY_PAYLOADS:
                sep = "&" if "?" in req.path else "?"
                new_path = req.path + sep + payload
                probes.append(("proto_pollution", "<query>", payload, new_path, req.body))
            if is_json:
                try:
                    obj = json.loads(req.body.decode(errors="replace"))
                    if isinstance(obj, dict):
                        polluted = dict(obj)
                        polluted["__proto__"] = {"polluted": "yes"}
                        probes.append(("proto_pollution", "<json_body>", "__proto__", req.path, json.dumps(polluted).encode()))
                        polluted2 = dict(obj)
                        polluted2["constructor"] = {"prototype": {"polluted": "yes"}}
                        probes.append(("proto_pollution", "<json_body>", "constructor.prototype", req.path, json.dumps(polluted2).encode()))
                except Exception:
                    pass

        return probes

    def _get_baseline_time(self) -> float:
        """Send the original request to measure baseline response time."""
        _, elapsed = _send_raw(
            self._req.host,
            self._req.port,
            self._req.is_https,
            _rebuild_raw(
                self._req.method,
                self._req.path,
                self._req.version,
                self._req.headers,
                self._req.body,
            ),
        )
        return elapsed

    # ------------------------------------------------------------------
    # Vulnerability checks
    # ------------------------------------------------------------------

    def _check_blind_sqli_time(self, elapsed: float, baseline: float, param: str, payload: str) -> None:
        if elapsed > baseline + 3.0:
            self.finding.emit(
                "High",
                "Blind SQL Injection (Time-based)",
                f"Response took {elapsed:.2f}s (baseline {baseline:.2f}s) for payload: {payload!r}",
                param,
            )

    def _check_xxe(self, response: bytes, param: str) -> None:
        body = _get_body(response).decode(errors="replace")
        for indicator in XXE_INDICATORS:
            if indicator in body:
                self.finding.emit(
                    "High",
                    "XXE (External Entity Injection)",
                    f"XXE indicator {indicator!r} found in response",
                    param,
                )
                return

    def _craft_alg_none_jwt(self, original_jwt: str) -> str:
        parts = original_jwt.split(".")
        if len(parts) < 2:
            return original_jwt
        try:
            payload_padded = parts[1] + "=" * (-len(parts[1]) % 4)
            payload_b64 = base64.urlsafe_b64decode(payload_padded)
            new_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
            return f"{new_header}.{parts[1]}."
        except Exception:
            return original_jwt

    def _craft_weak_secret_jwt(self, original_jwt: str, secret: str) -> str:
        parts = original_jwt.split(".")
        if len(parts) < 2:
            return original_jwt
        try:
            header_payload = f"{parts[0]}.{parts[1]}"
            new_header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
            new_header_payload = f"{new_header}.{parts[1]}"
            sig = hmac.new(secret.encode(), new_header_payload.encode(), hashlib.sha256).digest()
            sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
            return f"{new_header_payload}.{sig_b64}"
        except Exception:
            return original_jwt

    def _replace_jwt_in_request(self, original_jwt: str, new_jwt: str) -> tuple[dict, bytes]:
        headers = dict(self._req.headers)
        for k, v in headers.items():
            if original_jwt in v:
                headers[k] = v.replace(original_jwt, new_jwt)
        body = self._req.body
        if original_jwt.encode() in body:
            body = body.replace(original_jwt.encode(), new_jwt.encode())
        return headers, body

    def _check_jwt_none(self, original_jwt: str) -> None:
        new_jwt = self._craft_alg_none_jwt(original_jwt)
        if new_jwt == original_jwt:
            return
        new_headers, new_body = self._replace_jwt_in_request(original_jwt, new_jwt)
        raw = _rebuild_raw(self._req.method, self._req.path, self._req.version, new_headers, new_body)
        resp, _ = _send_raw(self._req.host, self._req.port, self._req.is_https, raw)
        status = _get_status_code(resp)
        if status not in (401, 403, 0):
            self.finding.emit(
                "Critical",
                "JWT: Algorithm None Accepted",
                f"Server accepted JWT with alg:none (HTTP {status})",
                "<jwt>",
            )

    def _check_jwt_weak(self, original_jwt: str) -> None:
        for secret in JWT_WEAK_SECRETS:
            new_jwt = self._craft_weak_secret_jwt(original_jwt, secret)
            new_headers, new_body = self._replace_jwt_in_request(original_jwt, new_jwt)
            raw = _rebuild_raw(self._req.method, self._req.path, self._req.version, new_headers, new_body)
            resp, _ = _send_raw(self._req.host, self._req.port, self._req.is_https, raw)
            status = _get_status_code(resp)
            if status not in (401, 403, 0):
                self.finding.emit(
                    "Critical",
                    "JWT: Weak Secret Accepted",
                    f"Server accepted JWT signed with weak secret: {secret!r} (HTTP {status})",
                    "<jwt>",
                )
                return

    def _check_sqli(self, response: bytes, param: str, payload: str) -> None:
        body_lower = _get_body(response).decode(errors="replace").lower()
        for indicator in SQLI_ERROR_STRINGS:
            if indicator in body_lower:
                self.finding.emit(
                    "High",
                    "SQL Injection",
                    f"Error indicator '{indicator}' found in response for payload: {payload!r}",
                    param,
                )
                return

    def _check_xss(self, response: bytes, param: str) -> None:
        body = _get_body(response).decode(errors="replace")
        if XSS_PROBE in body:
            self.finding.emit(
                "High",
                "Reflected XSS",
                f"Probe string {XSS_PROBE!r} reflected unescaped in response",
                param,
            )

    def _check_path_traversal(self, response: bytes, param: str, payload: str) -> None:
        body = _get_body(response).decode(errors="replace")
        for indicator in PATH_TRAVERSAL_INDICATORS:
            if indicator in body:
                self.finding.emit(
                    "High",
                    "Path Traversal",
                    f"Indicator '{indicator}' found in response for payload: {payload!r}",
                    param,
                )
                return

    def _check_ssrf(
        self,
        response: bytes,
        elapsed: float,
        baseline_elapsed: float,
        param: str,
        payload: str,
    ) -> None:
        body = _get_body(response).decode(errors="replace")
        status = _get_status_code(response)

        # Body indicator check
        for indicator in SSRF_BODY_INDICATORS:
            if indicator in body:
                self.finding.emit(
                    "High",
                    "SSRF",
                    f"SSRF indicator '{indicator}' found in response for payload: {payload!r}",
                    param,
                )
                return

        # Response time check (>3x baseline)
        if baseline_elapsed > 0 and elapsed > baseline_elapsed * 3 and elapsed > 3.0:
            self.finding.emit(
                "Medium",
                "SSRF (Timing)",
                (
                    f"Response time {elapsed:.2f}s is >3x baseline {baseline_elapsed:.2f}s "
                    f"for payload: {payload!r}"
                ),
                param,
            )
            return

        # Status anomaly — 200 where 4xx expected (very rough heuristic)
        if status == 200 and payload in ("http://127.0.0.1/", "http://localhost/"):
            self.finding.emit(
                "Low",
                "SSRF (Status Anomaly)",
                f"Got 200 from internal address payload: {payload!r}",
                param,
            )

    def _check_ssti(self, response: bytes, param: str, payload: str) -> None:
        if "49" in _get_body(response).decode(errors="replace"):
            self.finding.emit(
                "High",
                "Server-Side Template Injection (SSTI)",
                f"Response contained '49' (7*7 evaluated) for payload: {payload!r}",
                param,
            )

    def _check_cmdi(self, response: bytes, param: str, payload: str) -> None:
        body = _get_body(response).decode(errors="replace")
        for indicator in CMDI_INDICATORS:
            if indicator in body:
                self.finding.emit(
                    "Critical",
                    "Command Injection",
                    f"OS output indicator {indicator!r} found for payload: {payload!r}",
                    param,
                )
                return

    def _check_crlf(self, response: bytes, param: str, payload: str) -> None:
        headers_section = _get_headers_section(response)
        if "crlf=injected" in headers_section or "X-Injected" in headers_section:
            self.finding.emit(
                "Medium",
                "CRLF Injection",
                f"Injected header found in response for payload: {payload!r}",
                param,
            )

    def _send_with_host(self, attacker_host: str) -> tuple[bytes, float]:
        modified_headers = dict(self._req.headers)
        modified_headers["host"] = attacker_host
        raw = _rebuild_raw(
            self._req.method, self._req.path, self._req.version, modified_headers, self._req.body
        )
        return _send_raw(self._req.host, self._req.port, self._req.is_https, raw)

    def _check_host_header(self, response: bytes, attacker_host: str) -> None:
        body = _get_body(response).decode(errors="replace")
        location = _get_location_header(response)
        if attacker_host in body or attacker_host in location:
            self.finding.emit(
                "Medium",
                "Host Header Injection",
                f"Injected host {attacker_host!r} reflected in response body or Location header",
                "<host>",
            )

    def _check_smuggling(self, variant: str) -> None:
        host = self._req.host
        port = self._req.port
        is_https = self._req.is_https
        if variant == "CL.TE":
            raw = (
                f"POST {self._req.path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Length: 6\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "0\r\n"
                "\r\n"
                "X"
            ).encode()
        else:
            raw = (
                f"POST {self._req.path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Length: 4\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "5c\r\n"
                "SMUGGLED\r\n"
                "0\r\n"
                "\r\n"
            ).encode()
        resp, _ = _send_raw(host, port, is_https, raw)
        status = _get_status_code(resp)
        if status in (400, 500, 0):
            return
        followup = _rebuild_raw(
            self._req.method, self._req.path, self._req.version, self._req.headers, self._req.body
        )
        resp2, _ = _send_raw(host, port, is_https, followup)
        status2 = _get_status_code(resp2)
        if status2 in (400, 500) and status not in (400, 500):
            self.finding.emit(
                "High",
                f"HTTP Request Smuggling ({variant})",
                f"Follow-up request returned {status2} after {variant} probe (initial: {status})",
                "<request>",
            )

    def _check_open_redirect(self, response: bytes, param: str, payload: str) -> None:
        status = _get_status_code(response)
        if 300 <= status < 400:
            location = _get_location_header(response)
            if OPEN_REDIRECT_DOMAIN in location:
                self.finding.emit(
                    "High",
                    "Open Redirect",
                    f"3xx redirect to {location!r} for payload: {payload!r}",
                    param,
                )

    def _check_nosql(self, response: bytes, param: str, payload: str) -> None:
        body = _get_body(response).decode(errors="replace").lower()
        for indicator in NOSQL_SUCCESS_INDICATORS:
            if indicator in body:
                self.finding.emit(
                    "High",
                    "NoSQL Injection",
                    f"Success indicator {indicator!r} found for payload: {payload!r}",
                    param,
                )
                return

    def _check_ldap(self, response: bytes, param: str, payload: str) -> None:
        body = _get_body(response).decode(errors="replace").lower()
        for indicator in LDAP_ERROR_INDICATORS:
            if indicator in body:
                self.finding.emit(
                    "High",
                    "LDAP Injection",
                    f"LDAP error indicator {indicator!r} found for payload: {payload!r}",
                    param,
                )
                return

    def _check_proto_pollution(self, response: bytes, param: str, payload: str) -> None:
        if "polluted" in _get_body(response).decode(errors="replace"):
            self.finding.emit(
                "Medium",
                "Prototype Pollution",
                f"Injected value 'polluted' reflected in response for payload: {payload!r}",
                param,
            )

    # ------------------------------------------------------------------
    # Main run loop
    # ------------------------------------------------------------------

    def _run_backslash_probe(self) -> None:
        """Wrapper to call module-level _probe_backslash with this worker."""
        _probe_backslash(self._req, self._req.port, self)

    def run(self) -> None:
        probes = self._collect_probes()
        total = len(probes)
        baseline_elapsed: Optional[float] = None

        needs_baseline = (
            (self._run_ssrf and any(p[0] == "ssrf" for p in probes))
            or (self._run_blind_sqli_time and any(p[0] == "blind_sqli_time" for p in probes))
        )
        if needs_baseline:
            baseline_elapsed = self._get_baseline_time()

        # Track boolean-blind true responses to pair with false responses
        _bool_true_cache: dict[tuple[str, str], tuple[int, bytes]] = {}

        for idx, (scan_type, param, payload, path, body) in enumerate(probes):
            if self._stop_requested:
                break

            # Probe types that control their own sending
            if scan_type == "host_header":
                response, elapsed = self._send_with_host(payload)
                self.progress.emit(idx + 1, total)
                self._check_host_header(response, payload)
                continue
            elif scan_type == "smuggling":
                self.progress.emit(idx + 1, total)
                self._check_smuggling(payload)
                continue

            response, elapsed = self._send(path, body)
            self.progress.emit(idx + 1, total)

            if scan_type == "sqli":
                self._check_sqli(response, param, payload)
            elif scan_type == "xss":
                self._check_xss(response, param)
            elif scan_type == "path_traversal":
                self._check_path_traversal(response, param, payload)
            elif scan_type == "ssrf":
                self._check_ssrf(response, elapsed, baseline_elapsed or 0.0, param, payload)
            elif scan_type == "blind_sqli_time":
                self._check_blind_sqli_time(elapsed, baseline_elapsed or 0.0, param, payload)
            elif scan_type == "blind_sqli_bool_true":
                status = _get_status_code(response)
                _bool_true_cache[(param, payload[:10])] = (status, _get_body(response))
            elif scan_type == "blind_sqli_bool_false":
                # Find matching true probe by param name prefix matching
                true_key = None
                for k in _bool_true_cache:
                    if k[0] == param:
                        true_key = k
                        break
                if true_key and _get_status_code(response) == 200:
                    true_status, true_body = _bool_true_cache[true_key]
                    false_body = _get_body(response)
                    if true_status == 200 and abs(len(true_body) - len(false_body)) > 20:
                        self.finding.emit(
                            "Medium",
                            "Blind SQL Injection (Boolean-based)",
                            f"Response length differs between true/false conditions "
                            f"({len(true_body)} vs {len(false_body)} bytes) on param: {param!r}",
                            param,
                        )
            elif scan_type == "xxe":
                self._check_xxe(response, param)
            elif scan_type == "jwt_none":
                self._check_jwt_none(payload)
            elif scan_type == "jwt_weak":
                self._check_jwt_weak(payload)
            elif scan_type == "ssti":
                self._check_ssti(response, param, payload)
            elif scan_type == "cmdi":
                self._check_cmdi(response, param, payload)
            elif scan_type == "crlf":
                self._check_crlf(response, param, payload)
            elif scan_type == "open_redirect":
                self._check_open_redirect(response, param, payload)
            elif scan_type == "nosql":
                self._check_nosql(response, param, payload)
            elif scan_type == "ldap":
                self._check_ldap(response, param, payload)
            elif scan_type == "proto_pollution":
                self._check_proto_pollution(response, param, payload)

        if self._run_backslash and not self._stop_requested:
            try:
                self._run_backslash_probe()
            except Exception as exc:
                print(f"[active-scanner] backslash probe error: {exc}")

        # Custom BCheck-style scan rules loaded from ~/.fracture/bchecks/*.json
        if not self._stop_requested:
            try:
                from pathlib import Path
                from .bcheck import load_bchecks, run_bcheck
                for chk in load_bchecks(Path.home() / ".fracture" / "bchecks"):
                    if self._stop_requested:
                        break
                    finding = run_bcheck(chk, self._req)
                    if finding is not None:
                        # finding.as_emit_args() returns the right shape
                        self.finding.emit(*finding.as_emit_args())
            except Exception as exc:
                print(f"[active-scanner] bcheck error: {exc}")

        self.finished.emit()


# ---------------------------------------------------------------------------
# Severity colors (Catppuccin Mocha)
# ---------------------------------------------------------------------------

_SEVERITY_COLORS = {
    "High":   "#f38ba8",   # red
    "Medium": "#fab387",   # orange / peach
    "Low":    "#a6e3a1",   # green
    "Info":   "#89b4fa",   # blue
}


def _severity_color(severity: str) -> QColor:
    return QColor(_SEVERITY_COLORS.get(severity, _TEXT))


# ---------------------------------------------------------------------------
# ActiveScannerTab
# ---------------------------------------------------------------------------

class ActiveScannerTab(QWidget):
    """Active scanner tab widget."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._worker: Optional[ScanWorker] = None
        self._current_req: Optional[HttpRequest] = None
        self._setup_ui()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_request(self, req: HttpRequest) -> None:
        """Populate the request editor and target fields from a captured request."""
        self._current_req = req
        self.host_edit.setText(req.host)
        self.port_edit.setText(str(req.port))
        self.https_check.setChecked(req.is_https)
        raw_text = req.raw.decode(errors="replace") if req.raw else str(req)
        self.request_editor.setPlainText(raw_text)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(6)
        self.setStyleSheet(f"background: {_BG}; color: {_TEXT};")

        # --- Target bar ---------------------------------------------------
        target_bar = QHBoxLayout()
        target_bar.setSpacing(6)

        target_bar.addWidget(self._lbl("Target:"))

        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("host")
        self.host_edit.setFixedWidth(220)
        self.host_edit.setStyleSheet(_LINEEDIT_SS)
        target_bar.addWidget(self.host_edit)

        target_bar.addWidget(self._lbl(":"))

        self.port_edit = QLineEdit()
        self.port_edit.setPlaceholderText("port")
        self.port_edit.setFixedWidth(60)
        self.port_edit.setStyleSheet(_LINEEDIT_SS)
        target_bar.addWidget(self.port_edit)

        self.https_check = QCheckBox("HTTPS")
        self.https_check.setStyleSheet(_CHECKBOX_SS)
        target_bar.addWidget(self.https_check)

        target_bar.addStretch()
        root.addLayout(target_bar)

        # --- Request editor -----------------------------------------------
        req_lbl = QLabel("Request")
        req_lbl.setStyleSheet(_LABEL_SS)
        root.addWidget(req_lbl)

        self.request_editor = QTextEdit()
        self.request_editor.setFont(QFont("Monospace", 9))
        self.request_editor.setPlaceholderText(
            "Load a request from proxy history, or paste a raw HTTP request here."
        )
        self.request_editor.setStyleSheet(_TEXTEDIT_SS)
        self.request_editor.setMaximumHeight(180)
        root.addWidget(self.request_editor)

        # --- Scan type checkboxes -----------------------------------------
        scan_types_bar = QHBoxLayout()
        scan_types_bar.setSpacing(12)
        scan_types_bar.addWidget(self._lbl("Scan types:"))

        self.sqli_check = QCheckBox("SQL Injection")
        self.sqli_check.setChecked(True)
        self.sqli_check.setStyleSheet(_CHECKBOX_SS)
        scan_types_bar.addWidget(self.sqli_check)

        self.xss_check = QCheckBox("XSS")
        self.xss_check.setChecked(True)
        self.xss_check.setStyleSheet(_CHECKBOX_SS)
        scan_types_bar.addWidget(self.xss_check)

        self.path_traversal_check = QCheckBox("Path Traversal")
        self.path_traversal_check.setChecked(True)
        self.path_traversal_check.setStyleSheet(_CHECKBOX_SS)
        scan_types_bar.addWidget(self.path_traversal_check)

        self.ssrf_check = QCheckBox("SSRF")
        self.ssrf_check.setChecked(True)
        self.ssrf_check.setStyleSheet(_CHECKBOX_SS)
        scan_types_bar.addWidget(self.ssrf_check)

        self.blind_sqli_time_check = QCheckBox("Blind SQLi (Time)")
        self.blind_sqli_time_check.setChecked(True)
        self.blind_sqli_time_check.setStyleSheet(_CHECKBOX_SS)
        scan_types_bar.addWidget(self.blind_sqli_time_check)

        self.blind_sqli_bool_check = QCheckBox("Blind SQLi (Boolean)")
        self.blind_sqli_bool_check.setChecked(True)
        self.blind_sqli_bool_check.setStyleSheet(_CHECKBOX_SS)
        scan_types_bar.addWidget(self.blind_sqli_bool_check)

        self.xxe_check = QCheckBox("XXE")
        self.xxe_check.setChecked(True)
        self.xxe_check.setStyleSheet(_CHECKBOX_SS)
        scan_types_bar.addWidget(self.xxe_check)

        self.jwt_check = QCheckBox("JWT Tests")
        self.jwt_check.setChecked(True)
        self.jwt_check.setStyleSheet(_CHECKBOX_SS)
        scan_types_bar.addWidget(self.jwt_check)

        self.ssti_check = QCheckBox("SSTI")
        self.ssti_check.setChecked(True)
        self.ssti_check.setStyleSheet(_CHECKBOX_SS)
        scan_types_bar.addWidget(self.ssti_check)

        self.cmdi_check = QCheckBox("Cmd Injection")
        self.cmdi_check.setChecked(True)
        self.cmdi_check.setStyleSheet(_CHECKBOX_SS)
        scan_types_bar.addWidget(self.cmdi_check)

        self.crlf_check = QCheckBox("CRLF")
        self.crlf_check.setChecked(True)
        self.crlf_check.setStyleSheet(_CHECKBOX_SS)
        scan_types_bar.addWidget(self.crlf_check)

        self.host_header_check = QCheckBox("Host Header")
        self.host_header_check.setChecked(True)
        self.host_header_check.setStyleSheet(_CHECKBOX_SS)
        scan_types_bar.addWidget(self.host_header_check)

        self.smuggling_check = QCheckBox("HTTP Smuggling")
        self.smuggling_check.setChecked(True)
        self.smuggling_check.setStyleSheet(_CHECKBOX_SS)
        scan_types_bar.addWidget(self.smuggling_check)

        self.open_redirect_check = QCheckBox("Open Redirect")
        self.open_redirect_check.setChecked(True)
        self.open_redirect_check.setStyleSheet(_CHECKBOX_SS)
        scan_types_bar.addWidget(self.open_redirect_check)

        self.nosql_check = QCheckBox("NoSQL Injection")
        self.nosql_check.setChecked(True)
        self.nosql_check.setStyleSheet(_CHECKBOX_SS)
        scan_types_bar.addWidget(self.nosql_check)

        self.ldap_check = QCheckBox("LDAP Injection")
        self.ldap_check.setChecked(True)
        self.ldap_check.setStyleSheet(_CHECKBOX_SS)
        scan_types_bar.addWidget(self.ldap_check)

        self.proto_pollution_check = QCheckBox("Proto Pollution")
        self.proto_pollution_check.setChecked(True)
        self.proto_pollution_check.setStyleSheet(_CHECKBOX_SS)
        scan_types_bar.addWidget(self.proto_pollution_check)

        self.backslash_check = QCheckBox("Backslash probe")
        self.backslash_check.setChecked(False)
        self.backslash_check.setStyleSheet(_CHECKBOX_SS)
        scan_types_bar.addWidget(self.backslash_check)

        scan_types_bar.addStretch()
        root.addLayout(scan_types_bar)

        # --- Action bar (buttons + progress) ------------------------------
        action_bar = QHBoxLayout()
        action_bar.setSpacing(6)

        self.scan_btn = QPushButton("Scan")
        self.scan_btn.setFixedWidth(80)
        self.scan_btn.setStyleSheet(_BTN_SS)
        self.scan_btn.clicked.connect(self._start_scan)
        action_bar.addWidget(self.scan_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setFixedWidth(80)
        self.stop_btn.setStyleSheet(_BTN_SS)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_scan)
        action_bar.addWidget(self.stop_btn)

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setFixedWidth(80)
        self.clear_btn.setStyleSheet(_BTN_SS)
        self.clear_btn.clicked.connect(self._clear_results)

        self.profile_btn = QPushButton("Audit Profile…")
        self.profile_btn.setFixedWidth(130)
        self.profile_btn.setStyleSheet(_BTN_SS)
        self.profile_btn.setToolTip("Pick or save a named bundle of probe toggles")
        self.profile_btn.clicked.connect(self._open_audit_profiles)
        action_bar.addWidget(self.profile_btn)
        action_bar.addWidget(self.clear_btn)

        action_bar.addStretch()

        self.progress_lbl = QLabel("0 / 0")
        self.progress_lbl.setStyleSheet("color: #a6adc8; font-size: 10px; padding: 0 4px;")
        action_bar.addWidget(self._lbl("Progress:"))
        action_bar.addWidget(self.progress_lbl)

        root.addLayout(action_bar)

        # --- Results splitter (table + detail) ----------------------------
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Results table
        self.results_table = QTableWidget(0, 4)
        self.results_table.setHorizontalHeaderLabels(
            ["Severity", "Type", "Parameter", "Detail"]
        )
        self.results_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch
        )
        self.results_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.results_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.results_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        self.results_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.results_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.results_table.setStyleSheet(_TABLE_SS)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.itemSelectionChanged.connect(self._on_selection_changed)
        splitter.addWidget(self.results_table)

        # Detail panel
        self.detail_panel = QTextEdit()
        self.detail_panel.setFont(QFont("Monospace", 9))
        self.detail_panel.setReadOnly(True)
        self.detail_panel.setPlaceholderText("Select a finding above to see details.")
        self.detail_panel.setStyleSheet(_TEXTEDIT_SS)
        self.detail_panel.setMaximumHeight(140)
        splitter.addWidget(self.detail_panel)

        splitter.setSizes([300, 140])
        root.addWidget(splitter)

    def _lbl(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(f"color: {_TEXT};")
        return lbl

    # ------------------------------------------------------------------
    # Scan control
    # ------------------------------------------------------------------

    def _open_audit_profiles(self) -> None:
        from .audit_profiles import AuditProfileDialog
        dlg = AuditProfileDialog(self, self)
        dlg.exec()

    def _start_scan(self) -> None:
        # Parse the raw request from the editor to build a fresh HttpRequest
        raw_text = self.request_editor.toPlainText()
        host = self.host_edit.text().strip()
        port_text = self.port_edit.text().strip()
        is_https = self.https_check.isChecked()

        if not host:
            self.detail_panel.setPlainText("[Error] Host is empty.")
            return
        if not raw_text.strip():
            self.detail_panel.setPlainText("[Error] Request editor is empty.")
            return

        try:
            port = int(port_text) if port_text else (443 if is_https else 80)
        except ValueError:
            self.detail_panel.setPlainText(f"[Error] Invalid port: {port_text!r}")
            return

        req = self._parse_request_from_editor(raw_text, host, port, is_https)
        if req is None:
            self.detail_panel.setPlainText("[Error] Could not parse request.")
            return

        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_lbl.setText("0 / 0")

        self._worker = ScanWorker(
            req,
            run_sqli=self.sqli_check.isChecked(),
            run_xss=self.xss_check.isChecked(),
            run_path_traversal=self.path_traversal_check.isChecked(),
            run_ssrf=self.ssrf_check.isChecked(),
            run_blind_sqli_time=self.blind_sqli_time_check.isChecked(),
            run_blind_sqli_bool=self.blind_sqli_bool_check.isChecked(),
            run_xxe=self.xxe_check.isChecked(),
            run_jwt=self.jwt_check.isChecked(),
            run_ssti=self.ssti_check.isChecked(),
            run_cmdi=self.cmdi_check.isChecked(),
            run_crlf=self.crlf_check.isChecked(),
            run_host_header=self.host_header_check.isChecked(),
            run_smuggling=self.smuggling_check.isChecked(),
            run_open_redirect=self.open_redirect_check.isChecked(),
            run_nosql=self.nosql_check.isChecked(),
            run_ldap=self.ldap_check.isChecked(),
            run_proto_pollution=self.proto_pollution_check.isChecked(),
            run_backslash=self.backslash_check.isChecked(),
        )
        self._worker.finding.connect(self._on_finding)
        self._worker.finished.connect(self._on_finished)
        self._worker.progress.connect(self._on_progress)
        self._worker.start()

    def _stop_scan(self) -> None:
        if self._worker is not None:
            self._worker.stop()

    def _clear_results(self) -> None:
        self.results_table.setRowCount(0)
        self.detail_panel.clear()
        self.progress_lbl.setText("0 / 0")

    # ------------------------------------------------------------------
    # Request parsing
    # ------------------------------------------------------------------

    def _parse_request_from_editor(
        self, raw_text: str, host: str, port: int, is_https: bool
    ) -> Optional[HttpRequest]:
        """Parse the raw HTTP text from the editor into an HttpRequest."""
        try:
            raw_bytes = raw_text.encode(errors="replace")
            header_end = raw_bytes.find(b"\r\n\r\n")
            if header_end == -1:
                header_end = raw_bytes.find(b"\n\n")
                sep_len = 2
            else:
                sep_len = 4

            header_bytes = raw_bytes[:header_end] if header_end != -1 else raw_bytes
            body = raw_bytes[header_end + sep_len:] if header_end != -1 else b""

            lines = header_bytes.decode(errors="replace").splitlines()
            if not lines:
                return None
            first = lines[0].split()
            if len(first) < 2:
                return None

            method = first[0]
            path = first[1]
            version = first[2].replace("HTTP/", "") if len(first) >= 3 else "1.1"

            headers: dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()

            from datetime import datetime
            return HttpRequest(
                id=0,
                method=method,
                host=host,
                port=port,
                path=path,
                version=version,
                headers=headers,
                body=body,
                is_https=is_https,
                timestamp=datetime.now(),
                raw=raw_bytes,
            )
        except Exception as exc:
            print(f"[active-scanner] parse error: {exc}")
            return None

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_finding(self, severity: str, title: str, detail: str, param: str) -> None:
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)

        sev_item = QTableWidgetItem(severity)
        sev_item.setForeground(_severity_color(severity))
        self.results_table.setItem(row, 0, sev_item)

        self.results_table.setItem(row, 1, QTableWidgetItem(title))
        self.results_table.setItem(row, 2, QTableWidgetItem(param))
        self.results_table.setItem(row, 3, QTableWidgetItem(detail))

        # Store full detail in item data for the detail panel
        sev_item.setData(Qt.ItemDataRole.UserRole, (severity, title, param, detail))

    def _on_finished(self) -> None:
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        count = self.results_table.rowCount()
        current_text = self.progress_lbl.text()
        total_part = current_text.split("/")[-1].strip() if "/" in current_text else "?"
        self.progress_lbl.setText(f"{total_part} / {total_part} — done ({count} findings)")

    def _on_progress(self, current: int, total: int) -> None:
        self.progress_lbl.setText(f"{current} / {total}")

    def _on_selection_changed(self) -> None:
        selected = self.results_table.selectedItems()
        if not selected:
            self.detail_panel.clear()
            return
        row = self.results_table.currentRow()
        sev_item = self.results_table.item(row, 0)
        if sev_item is None:
            return
        data = sev_item.data(Qt.ItemDataRole.UserRole)
        if data:
            severity, title, param, detail = data
            text = (
                f"Severity:  {severity}\n"
                f"Type:      {title}\n"
                f"Parameter: {param}\n"
                f"\n"
                f"Detail:\n{detail}"
            )
            self.detail_panel.setPlainText(text)
