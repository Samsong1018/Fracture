"""
Passive Scanner tab for Fracture.

Analyses proxied traffic as it flows through the proxy — no extra requests
are sent. Findings appear in an issues panel with severity levels.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QColor, QDesktopServices
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .proxy import HttpRequest, HttpResponse

# ---------------------------------------------------------------------------
# Catppuccin Mocha palette
# ---------------------------------------------------------------------------
_BG = "#1e1e2e"
_SURFACE = "#181825"
_OVERLAY = "#313244"
_HIGHLIGHT = "#45475a"
_TEXT = "#cdd6f4"
_SUBTEXT = "#a6adc8"
_ACCENT = "#89b4fa"

# Severity colours
_SEV_COLOR: dict[str, str] = {
    "HIGH":   "#f38ba8",
    "MEDIUM": "#fab387",
    "LOW":    "#a6e3a1",
    "INFO":   "#89b4fa",
}

_LIST_STYLE = f"""
QListWidget {{
    background: {_SURFACE};
    border: 1px solid {_OVERLAY};
    color: {_TEXT};
    font-family: monospace;
    font-size: 12px;
}}
QListWidget::item:selected {{
    background: {_HIGHLIGHT};
}}
QListWidget::item:hover {{
    background: {_OVERLAY};
}}
"""

_TEXTEDIT_STYLE = f"""
QTextEdit {{
    background: {_SURFACE};
    border: 1px solid {_OVERLAY};
    color: {_TEXT};
    font-family: monospace;
    font-size: 12px;
}}
"""

_BTN_STYLE = f"""
QPushButton {{
    background: {_OVERLAY};
    color: {_TEXT};
    border: 1px solid {_HIGHLIGHT};
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 12px;
}}
QPushButton:hover {{
    background: {_HIGHLIGHT};
}}
QPushButton:pressed {{
    background: {_BG};
}}
"""

_COMBO_STYLE = f"""
QComboBox {{
    background: {_SURFACE};
    color: {_TEXT};
    border: 1px solid {_OVERLAY};
    padding: 4px;
    font-size: 12px;
    border-radius: 3px;
}}
QComboBox::drop-down {{
    border: none;
}}
QComboBox QAbstractItemView {{
    background: {_SURFACE};
    color: {_TEXT};
    selection-background-color: {_HIGHLIGHT};
    border: 1px solid {_OVERLAY};
}}
"""

_LINE_STYLE = f"""
QLineEdit {{
    background: {_SURFACE};
    color: {_TEXT};
    border: 1px solid {_OVERLAY};
    padding: 4px;
    font-size: 12px;
    border-radius: 3px;
}}
QLineEdit:focus {{
    border: 1px solid {_ACCENT};
}}
"""

_LABEL_STYLE = f"color: {_SUBTEXT}; font-size: 11px; font-family: monospace;"

# ---------------------------------------------------------------------------
# Asset-extension skip list (for header checks only)
# ---------------------------------------------------------------------------
_ASSET_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
    ".ico", ".woff", ".woff2", ".ttf", ".otf", ".svg",
}

# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    id: int
    severity: str        # "HIGH", "MEDIUM", "LOW", "INFO"
    title: str
    detail: str
    host: str
    path: str
    request_id: int


# ---------------------------------------------------------------------------
# Passive check helpers
# ---------------------------------------------------------------------------

def _is_asset(path: str) -> bool:
    """Return True if the path looks like a static asset."""
    lower = path.lower().split("?")[0]
    for ext in _ASSET_EXTENSIONS:
        if lower.endswith(ext):
            return True
    return False


def _header_case_insensitive(headers: dict[str, str], name: str) -> Optional[str]:
    """Return header value regardless of case, or None."""
    lower = name.lower()
    for k, v in headers.items():
        if k.lower() == lower:
            return v
    return None


def _check_missing_security_headers(
    req: HttpRequest,
    resp: HttpResponse,
    findings: list[Finding],
    existing: set[tuple[str, str, str]],
    counter: list[int],
) -> None:
    """Check 1 — Missing Security Headers (skip for asset paths)."""
    if _is_asset(req.path):
        return

    checks: list[tuple[str, str]] = [
        ("Content-Security-Policy", "MEDIUM"),
        ("X-Frame-Options", "LOW"),
        ("X-Content-Type-Options", "LOW"),
        ("Referrer-Policy", "LOW"),
        ("Permissions-Policy", "LOW"),
    ]
    if req.is_https:
        checks.append(("Strict-Transport-Security", "MEDIUM"))

    for header, severity in checks:
        if _header_case_insensitive(resp.headers, header) is None:
            title = "Missing Security Header"
            detail = f"Missing: {header}"
            key = (title, req.host, req.path)
            # Deduplicate per header too
            full_key = (f"{title}: {header}", req.host, req.path)
            if full_key not in existing:
                existing.add(full_key)
                counter[0] += 1
                findings.append(Finding(
                    id=counter[0],
                    severity=severity,
                    title=title,
                    detail=detail,
                    host=req.host,
                    path=req.path,
                    request_id=req.id,
                ))


def _check_insecure_cookies(
    req: HttpRequest,
    resp: HttpResponse,
    findings: list[Finding],
    existing: set[tuple[str, str, str]],
    counter: list[int],
) -> None:
    """Check 2 — Insecure Cookie Flags."""
    set_cookie_values: list[str] = []
    for k, v in resp.headers.items():
        if k.lower() == "set-cookie":
            set_cookie_values.append(v)

    for raw_cookie in set_cookie_values:
        cookie_lower = raw_cookie.lower()
        # Extract cookie name for detail messages
        name_part = raw_cookie.split(";")[0].split("=")[0].strip()

        if "httponly" not in cookie_lower:
            title = "Insecure Cookie: Missing HttpOnly"
            full_key = (f"{title}:{name_part}", req.host, req.path)
            if full_key not in existing:
                existing.add(full_key)
                counter[0] += 1
                findings.append(Finding(
                    id=counter[0],
                    severity="MEDIUM",
                    title=title,
                    detail=f"Cookie '{name_part}' missing HttpOnly flag",
                    host=req.host,
                    path=req.path,
                    request_id=req.id,
                ))

        if req.is_https and "secure" not in cookie_lower:
            title = "Insecure Cookie: Missing Secure Flag"
            full_key = (f"{title}:{name_part}", req.host, req.path)
            if full_key not in existing:
                existing.add(full_key)
                counter[0] += 1
                findings.append(Finding(
                    id=counter[0],
                    severity="MEDIUM",
                    title=title,
                    detail=f"Cookie '{name_part}' missing Secure flag on HTTPS response",
                    host=req.host,
                    path=req.path,
                    request_id=req.id,
                ))

        if "samesite" not in cookie_lower:
            title = "Insecure Cookie: Missing SameSite"
            full_key = (f"{title}:{name_part}", req.host, req.path)
            if full_key not in existing:
                existing.add(full_key)
                counter[0] += 1
                findings.append(Finding(
                    id=counter[0],
                    severity="LOW",
                    title=title,
                    detail=f"Cookie '{name_part}' missing SameSite attribute",
                    host=req.host,
                    path=req.path,
                    request_id=req.id,
                ))


_STACK_TRACE_PATTERNS = [
    "Traceback (most recent call last)",
    "NullPointerException",
    "stack trace:",
    "Fatal error:",
    "Unhandled exception",
]

_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL | re.IGNORECASE)
_SENSITIVE_COMMENT_KEYWORDS = {"todo", "fixme", "password", "secret", "api_key"}

_SERVER_VERSION_RE = re.compile(r"[a-zA-Z][\w\-]*/\d+\.\d+", re.IGNORECASE)


def _check_information_leakage(
    req: HttpRequest,
    resp: HttpResponse,
    findings: list[Finding],
    existing: set[tuple[str, str, str]],
    counter: list[int],
) -> None:
    """Check 3 — Information Leakage."""
    # Server header version
    server_val = _header_case_insensitive(resp.headers, "Server")
    if server_val and _SERVER_VERSION_RE.search(server_val):
        title = "Information Leakage: Server Version"
        full_key = (title, req.host, req.path)
        if full_key not in existing:
            existing.add(full_key)
            counter[0] += 1
            findings.append(Finding(
                id=counter[0],
                severity="LOW",
                title=title,
                detail=f"Server header reveals version: {server_val}",
                host=req.host,
                path=req.path,
                request_id=req.id,
            ))

    # X-Powered-By header
    xpb = _header_case_insensitive(resp.headers, "X-Powered-By")
    if xpb is not None:
        title = "Information Leakage: X-Powered-By"
        full_key = (title, req.host, req.path)
        if full_key not in existing:
            existing.add(full_key)
            counter[0] += 1
            findings.append(Finding(
                id=counter[0],
                severity="LOW",
                title=title,
                detail=f"X-Powered-By header present: {xpb}",
                host=req.host,
                path=req.path,
                request_id=req.id,
            ))

    # Body checks
    try:
        body_text = resp.body.decode("utf-8", errors="replace")
    except Exception:
        body_text = ""

    # Stack traces
    for pattern in _STACK_TRACE_PATTERNS:
        if pattern.lower() in body_text.lower():
            title = "Information Leakage: Stack Trace"
            full_key = (f"{title}:{pattern}", req.host, req.path)
            if full_key not in existing:
                existing.add(full_key)
                counter[0] += 1
                findings.append(Finding(
                    id=counter[0],
                    severity="HIGH",
                    title=title,
                    detail=f"Stack trace keyword found: '{pattern}'",
                    host=req.host,
                    path=req.path,
                    request_id=req.id,
                ))

    # Directory listing
    if "Index of /" in body_text or "Parent Directory" in body_text:
        title = "Information Leakage: Directory Listing"
        full_key = (title, req.host, req.path)
        if full_key not in existing:
            existing.add(full_key)
            counter[0] += 1
            findings.append(Finding(
                id=counter[0],
                severity="MEDIUM",
                title=title,
                detail="Response body suggests directory listing is enabled",
                host=req.host,
                path=req.path,
                request_id=req.id,
            ))

    # Sensitive HTML comments
    for match in _HTML_COMMENT_RE.finditer(body_text):
        comment_lower = match.group(1).lower()
        for keyword in _SENSITIVE_COMMENT_KEYWORDS:
            if keyword in comment_lower:
                title = "Information Leakage: Sensitive HTML Comment"
                full_key = (f"{title}:{keyword}", req.host, req.path)
                if full_key not in existing:
                    existing.add(full_key)
                    counter[0] += 1
                    snippet = match.group(1).strip()[:80]
                    findings.append(Finding(
                        id=counter[0],
                        severity="MEDIUM",
                        title=title,
                        detail=f"HTML comment contains '{keyword}': <!-- {snippet}… -->",
                        host=req.host,
                        path=req.path,
                        request_id=req.id,
                    ))
                break


def _check_mixed_content(
    req: HttpRequest,
    resp: HttpResponse,
    findings: list[Finding],
    existing: set[tuple[str, str, str]],
    counter: list[int],
) -> None:
    """Check 4 — Mixed Content (HTTPS page loading HTTP resources)."""
    if not req.is_https:
        return

    try:
        body_text = resp.body.decode("utf-8", errors="replace")
    except Exception:
        return

    # src="http:// or href="http:// pointing to an external host
    pattern = re.compile(r'(?:src|href)=["\']http://([^/"\']+)', re.IGNORECASE)
    for match in pattern.finditer(body_text):
        external_host = match.group(1)
        if external_host.lower() != req.host.lower():
            title = "Mixed Content"
            full_key = (f"{title}:{external_host}", req.host, req.path)
            if full_key not in existing:
                existing.add(full_key)
                counter[0] += 1
                findings.append(Finding(
                    id=counter[0],
                    severity="MEDIUM",
                    title=title,
                    detail=f"HTTPS page loads HTTP resource from '{external_host}'",
                    host=req.host,
                    path=req.path,
                    request_id=req.id,
                ))


def _check_open_redirect(
    req: HttpRequest,
    resp: HttpResponse,
    findings: list[Finding],
    existing: set[tuple[str, str, str]],
    counter: list[int],
) -> None:
    """Check 5 — Open Redirects."""
    if not (300 <= resp.status_code < 400):
        return

    location = _header_case_insensitive(resp.headers, "Location")
    if not location:
        return

    # Only flag absolute URLs pointing to a different host
    parsed = urlparse(location)
    if not parsed.netloc:
        return  # relative redirect — not open redirect

    redirect_host = parsed.netloc.lower().split(":")[0]
    request_host = req.host.lower().split(":")[0]

    if redirect_host and redirect_host != request_host:
        title = "Open Redirect"
        full_key = (f"{title}:{redirect_host}", req.host, req.path)
        if full_key not in existing:
            existing.add(full_key)
            counter[0] += 1
            findings.append(Finding(
                id=counter[0],
                severity="MEDIUM",
                title=title,
                detail=f"Redirect to external host '{redirect_host}' (Location: {location})",
                host=req.host,
                path=req.path,
                request_id=req.id,
            ))


# ---------------------------------------------------------------------------
# Check 6 — CORS misconfigurations
# ---------------------------------------------------------------------------

def _check_cors(
    req: HttpRequest,
    resp: HttpResponse,
    findings: list[Finding],
    existing: set[tuple[str, str, str]],
    counter: list[int],
) -> None:
    acao = _header_case_insensitive(resp.headers, "Access-Control-Allow-Origin")
    if not acao:
        return
    acac = _header_case_insensitive(resp.headers, "Access-Control-Allow-Credentials")
    origin = _header_case_insensitive(req.headers, "origin") or ""
    credentials_true = (acac or "").lower() == "true"

    def _flag(severity: str, title: str, detail: str) -> None:
        key = (title, req.host, req.path)
        if key not in existing:
            existing.add(key)
            counter[0] += 1
            findings.append(Finding(
                id=counter[0], severity=severity, title=title, detail=detail,
                host=req.host, path=req.path, request_id=req.id,
            ))

    if acao == "null":
        _flag("MEDIUM", "CORS: Null Origin Accepted",
              "Access-Control-Allow-Origin: null allows null-origin requests")
    elif acao == "*" and credentials_true:
        _flag("HIGH", "CORS: Wildcard with Credentials",
              "ACAO: * combined with Allow-Credentials: true (browser blocks but misconfigured)")
    elif origin and acao == origin:
        if credentials_true:
            _flag("CRITICAL", "CORS: Credentialed Cross-Origin Access",
                  f"Origin is reflected in ACAO and Allow-Credentials is true: {origin}")
        else:
            _flag("HIGH", "CORS: Origin Reflected",
                  f"ACAO reflects the Origin header: {origin}")


# ---------------------------------------------------------------------------
# Check 7 — JWT passive detection
# ---------------------------------------------------------------------------

_JWT_PASSIVE_RE = re.compile(r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*")


def _b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def _check_jwt_passive(
    req: HttpRequest,
    resp: HttpResponse,
    findings: list[Finding],
    existing: set[tuple[str, str, str]],
    counter: list[int],
) -> None:
    # Scan request headers + body for JWTs
    candidates: list[str] = []
    for v in req.headers.values():
        for m in _JWT_PASSIVE_RE.finditer(v):
            candidates.append(m.group(0))
    if req.body:
        for m in _JWT_PASSIVE_RE.finditer(req.body.decode(errors="replace")):
            candidates.append(m.group(0))

    for jwt in candidates:
        parts = jwt.split(".")
        if len(parts) < 2:
            continue
        try:
            header_data = json.loads(_b64url_decode(parts[0]))
            payload_data = json.loads(_b64url_decode(parts[1]))
        except Exception:
            continue

        alg = header_data.get("alg", "")
        detail_parts = [f"alg={alg}"]
        for claim in ("sub", "iss", "exp", "aud"):
            if claim in payload_data:
                detail_parts.append(f"{claim}={payload_data[claim]}")
        detail = ", ".join(detail_parts)

        if alg.lower() in ("none", ""):
            title = "JWT: Algorithm None"
            severity = "HIGH"
            detail = f"JWT with alg:none detected. {detail}"
        else:
            title = "JWT Detected"
            severity = "INFO"

        key = (f"{title}:{parts[0]}", req.host, req.path)
        if key not in existing:
            existing.add(key)
            counter[0] += 1
            findings.append(Finding(
                id=counter[0], severity=severity, title=title, detail=detail,
                host=req.host, path=req.path, request_id=req.id,
            ))


# ---------------------------------------------------------------------------
# Check 8 — OAuth2/OIDC flow tracker
# ---------------------------------------------------------------------------

import urllib.parse as _up


def _check_oauth(
    req: HttpRequest,
    resp: Optional[HttpResponse],
    findings: list[Finding],
    existing: set[tuple[str, str, str]],
    counter: list[int],
) -> None:
    """Detect OAuth2/OIDC flows and flag common misconfigurations."""
    path = req.path.lower()
    body_text = req.body.decode(errors="replace") if req.body else ""
    all_text = req.path + body_text

    is_auth_endpoint = any(
        k in path for k in ("oauth", "authorize", "auth", "/token", "openid", "oidc")
    )
    if not is_auth_endpoint and "response_type" not in all_text and "client_id" not in all_text:
        return

    def _flag(severity: str, title: str, detail: str) -> None:
        key = (title, req.host, req.path)
        if key not in existing:
            existing.add(key)
            counter[0] += 1
            findings.append(Finding(
                id=counter[0], severity=severity, title=title, detail=detail,
                host=req.host, path=req.path, request_id=req.id,
            ))

    # Missing state parameter — CSRF risk
    if "response_type=code" in all_text or "response_type=token" in all_text:
        if "state=" not in all_text:
            _flag(
                "MEDIUM",
                "OAuth: Missing state parameter",
                "Authorization request lacks a state parameter, leaving it vulnerable to CSRF.",
            )

    # Open redirect in redirect_uri
    for param in ("redirect_uri=", "redirect_url=", "callback="):
        if param in all_text:
            idx = all_text.index(param) + len(param)
            value = all_text[idx:].split("&")[0].split(" ")[0]
            value = _up.unquote(value)
            parsed = _up.urlparse(value)
            if parsed.hostname and parsed.hostname not in (req.host, "localhost", "127.0.0.1"):
                _flag(
                    "HIGH",
                    "OAuth: Open redirect in redirect_uri",
                    f"redirect_uri points to external host: {parsed.hostname!r}",
                )

    # Token leakage in Referer header
    referer = _header_case_insensitive(req.headers, "Referer") or ""
    if referer and (
        "access_token=" in referer or "id_token=" in referer or "code=" in referer
    ):
        _flag(
            "HIGH",
            "OAuth: Token leakage in Referer header",
            f"OAuth token or code appears in Referer header: {referer[:200]}",
        )

    # Implicit flow detection (via response body token + request param)
    if resp is not None:
        resp_body = resp.raw.decode(errors="replace") if resp.raw else ""
        if '"access_token"' in resp_body and '"token_type"' in resp_body:
            if "response_type=token" in all_text:
                _flag(
                    "MEDIUM",
                    "OAuth: Implicit flow detected",
                    "OAuth implicit flow exposes tokens in URL fragments; prefer authorization code + PKCE.",
                )


# ---------------------------------------------------------------------------
# Helper – format request/response for the bottom panel
# ---------------------------------------------------------------------------

def _format_request(req: HttpRequest) -> str:
    lines = [f"{req.method} {req.path} HTTP/{req.version}"]
    for k, v in req.headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if req.body:
        try:
            lines.append(req.body.decode("utf-8", errors="replace"))
        except Exception:
            lines.append(f"<binary {len(req.body)} bytes>")
    return "\n".join(lines)


def _format_response(resp: Optional[HttpResponse]) -> str:
    if resp is None:
        return "(no response captured)"
    lines = [f"HTTP/1.1 {resp.status_code} {resp.status_text}"]
    for k, v in resp.headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if resp.body:
        try:
            lines.append(resp.body.decode("utf-8", errors="replace"))
        except Exception:
            lines.append(f"<binary {len(resp.body)} bytes>")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# PassiveScannerTab
# ---------------------------------------------------------------------------

class PassiveScannerTab(QWidget):
    """
    Passive Scanner tab.

    Analyses proxied traffic without sending any extra requests.
    Findings are displayed in a list with severity colour-coding.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)

        # All findings in insertion order
        self._findings: list[Finding] = []
        # Deduplication key: (title_variant, host, path)
        self._seen: set[tuple[str, str, str]] = set()
        # Monotonic finding ID counter (wrapped in list so helpers can mutate)
        self._counter: list[int] = [0]

        # Map request_id -> (req, resp) for the detail panel
        self._req_map: dict[int, tuple[HttpRequest, Optional[HttpResponse]]] = {}

        self._build_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        self.setStyleSheet(f"background: {_BG}; color: {_TEXT};")

        # ---- toolbar ----
        toolbar = QWidget()
        toolbar.setStyleSheet(f"background: {_BG};")
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(8, 6, 8, 6)
        tb_layout.setSpacing(8)

        sev_label = QLabel("Severity:")
        sev_label.setStyleSheet(_LABEL_STYLE)
        tb_layout.addWidget(sev_label)

        self._sev_combo = QComboBox()
        self._sev_combo.addItems(["All", "HIGH", "MEDIUM", "LOW"])
        self._sev_combo.setStyleSheet(_COMBO_STYLE)
        self._sev_combo.currentTextChanged.connect(self._apply_filter)
        tb_layout.addWidget(self._sev_combo)

        search_label = QLabel("Search:")
        search_label.setStyleSheet(_LABEL_STYLE)
        tb_layout.addWidget(search_label)

        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("Filter findings…")
        self._search_edit.setStyleSheet(_LINE_STYLE)
        self._search_edit.textChanged.connect(self._apply_filter)
        tb_layout.addWidget(self._search_edit, stretch=1)

        clear_btn = QPushButton("Clear")
        clear_btn.setStyleSheet(_BTN_STYLE)
        clear_btn.clicked.connect(self._clear)
        tb_layout.addWidget(clear_btn)

        report_btn = QPushButton("Generate Report")
        report_btn.setStyleSheet(_BTN_STYLE)
        report_btn.clicked.connect(self._generate_report)
        tb_layout.addWidget(report_btn)

        root_layout.addWidget(toolbar)

        # ---- horizontal splitter: list | right panel ----
        h_splitter = QSplitter(Qt.Orientation.Horizontal)
        h_splitter.setStyleSheet(f"QSplitter::handle {{ background: {_OVERLAY}; }}")
        root_layout.addWidget(h_splitter, stretch=1)

        # ---- left: findings list ----
        self._list = QListWidget()
        self._list.setStyleSheet(_LIST_STYLE)
        self._list.currentRowChanged.connect(self._on_finding_selected)
        h_splitter.addWidget(self._list)

        # ---- right: vertical splitter (detail | req+resp) ----
        right_widget = QWidget()
        right_widget.setStyleSheet(f"background: {_BG};")
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        v_splitter = QSplitter(Qt.Orientation.Vertical)
        v_splitter.setStyleSheet(f"QSplitter::handle {{ background: {_OVERLAY}; }}")

        # Finding detail (top right)
        detail_container = QWidget()
        detail_container.setStyleSheet(f"background: {_BG};")
        dc_layout = QVBoxLayout(detail_container)
        dc_layout.setContentsMargins(0, 0, 0, 0)
        dc_layout.setSpacing(0)

        detail_header = QLabel("Finding Detail")
        detail_header.setStyleSheet(
            f"color: {_SUBTEXT}; font-size: 11px; font-family: monospace;"
            f" padding: 4px 8px; background: {_OVERLAY};"
        )
        dc_layout.addWidget(detail_header)

        self._detail_edit = QTextEdit()
        self._detail_edit.setReadOnly(True)
        self._detail_edit.setStyleSheet(_TEXTEDIT_STYLE)
        dc_layout.addWidget(self._detail_edit, stretch=1)

        v_splitter.addWidget(detail_container)

        # Request / Response panel (bottom right, horizontal splitter)
        req_resp_splitter = QSplitter(Qt.Orientation.Horizontal)
        req_resp_splitter.setStyleSheet(
            f"QSplitter::handle {{ background: {_OVERLAY}; }}"
        )

        # Request panel
        req_panel = QWidget()
        req_panel.setStyleSheet(f"background: {_BG};")
        rp_layout = QVBoxLayout(req_panel)
        rp_layout.setContentsMargins(0, 0, 0, 0)
        rp_layout.setSpacing(0)

        req_label = QLabel("Request")
        req_label.setStyleSheet(
            f"color: {_SUBTEXT}; font-size: 11px; font-family: monospace;"
            f" padding: 4px 8px; background: {_OVERLAY};"
        )
        rp_layout.addWidget(req_label)

        self._req_edit = QTextEdit()
        self._req_edit.setReadOnly(True)
        self._req_edit.setStyleSheet(_TEXTEDIT_STYLE)
        rp_layout.addWidget(self._req_edit, stretch=1)
        req_resp_splitter.addWidget(req_panel)

        # Response panel
        resp_panel = QWidget()
        resp_panel.setStyleSheet(f"background: {_BG};")
        resp_layout_v = QVBoxLayout(resp_panel)
        resp_layout_v.setContentsMargins(0, 0, 0, 0)
        resp_layout_v.setSpacing(0)

        resp_label = QLabel("Response")
        resp_label.setStyleSheet(
            f"color: {_SUBTEXT}; font-size: 11px; font-family: monospace;"
            f" padding: 4px 8px; background: {_OVERLAY};"
        )
        resp_layout_v.addWidget(resp_label)

        self._resp_edit = QTextEdit()
        self._resp_edit.setReadOnly(True)
        self._resp_edit.setStyleSheet(_TEXTEDIT_STYLE)
        resp_layout_v.addWidget(self._resp_edit, stretch=1)
        req_resp_splitter.addWidget(resp_panel)

        v_splitter.addWidget(req_resp_splitter)
        v_splitter.setSizes([250, 350])

        right_layout.addWidget(v_splitter, stretch=1)
        h_splitter.addWidget(right_widget)
        h_splitter.setSizes([350, 650])

        # Internal list of currently visible finding indices (into self._findings)
        self._visible_indices: list[int] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_entry(self, req: HttpRequest, resp: Optional[HttpResponse]) -> None:
        """
        Called for every proxied request/response pair.
        Runs all passive checks and appends new findings to the issues list.
        """
        if resp is None:
            return

        new_findings: list[Finding] = []

        _check_missing_security_headers(req, resp, new_findings, self._seen, self._counter)
        _check_insecure_cookies(req, resp, new_findings, self._seen, self._counter)
        _check_information_leakage(req, resp, new_findings, self._seen, self._counter)
        _check_mixed_content(req, resp, new_findings, self._seen, self._counter)
        _check_open_redirect(req, resp, new_findings, self._seen, self._counter)
        _check_cors(req, resp, new_findings, self._seen, self._counter)
        _check_jwt_passive(req, resp, new_findings, self._seen, self._counter)
        _check_oauth(req, resp, new_findings, self._seen, self._counter)

        for finding in new_findings:
            self._findings.append(finding)
            self._req_map[finding.request_id] = (req, resp)
            self._add_list_item(finding)

    def get_issues(self) -> list[Finding]:
        """Return the current list of scanner findings."""
        return list(self._findings)

    # ------------------------------------------------------------------
    # List item management
    # ------------------------------------------------------------------

    def _add_list_item(self, finding: Finding) -> None:
        """Add a new finding to the list widget, respecting current filter."""
        if not self._matches_filter(finding):
            # Track it in _visible_indices? No — we rebuild on filter change.
            # Just track every finding index.
            pass

        label = f"[{finding.severity}] {finding.title} — {finding.host}{finding.path}"
        item = QListWidgetItem(label)
        item.setForeground(QColor(_SEV_COLOR.get(finding.severity, _TEXT)))
        item.setData(Qt.ItemDataRole.UserRole, len(self._findings) - 1)
        item.setHidden(not self._matches_filter(finding))
        self._list.addItem(item)

    def _matches_filter(self, finding: Finding) -> bool:
        sev_filter = self._sev_combo.currentText() if hasattr(self, "_sev_combo") else "All"
        search_text = self._search_edit.text().strip().lower() if hasattr(self, "_search_edit") else ""

        if sev_filter != "All" and finding.severity != sev_filter:
            return False

        if search_text:
            combined = f"{finding.title} {finding.detail} {finding.host} {finding.path}".lower()
            if search_text not in combined:
                return False

        return True

    # ------------------------------------------------------------------
    # Filter
    # ------------------------------------------------------------------

    def _apply_filter(self, _text: str = "") -> None:
        for i in range(self._list.count()):
            item = self._list.item(i)
            if item is None:
                continue
            idx = item.data(Qt.ItemDataRole.UserRole)
            if idx is None or idx >= len(self._findings):
                continue
            finding = self._findings[idx]
            item.setHidden(not self._matches_filter(finding))

    # ------------------------------------------------------------------
    # Clear
    # ------------------------------------------------------------------

    def _clear(self) -> None:
        self._findings.clear()
        self._seen.clear()
        self._counter[0] = 0
        self._req_map.clear()
        self._list.clear()
        self._detail_edit.clear()
        self._req_edit.clear()
        self._resp_edit.clear()

    # ------------------------------------------------------------------
    # Selection handler
    # ------------------------------------------------------------------

    def _on_finding_selected(self, row: int) -> None:
        if row < 0:
            return

        item = self._list.item(row)
        if item is None:
            return

        idx = item.data(Qt.ItemDataRole.UserRole)
        if idx is None or idx >= len(self._findings):
            return

        finding = self._findings[idx]

        # Populate detail panel
        detail_lines = [
            f"ID:       {finding.id}",
            f"Severity: {finding.severity}",
            f"Title:    {finding.title}",
            f"Detail:   {finding.detail}",
            f"Host:     {finding.host}",
            f"Path:     {finding.path}",
            f"Req ID:   {finding.request_id}",
        ]
        self._detail_edit.setPlainText("\n".join(detail_lines))

        # Populate request/response panels
        pair = self._req_map.get(finding.request_id)
        if pair:
            req, resp = pair
            self._req_edit.setPlainText(_format_request(req))
            self._resp_edit.setPlainText(_format_response(resp))
        else:
            self._req_edit.clear()
            self._resp_edit.clear()

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def _generate_report(self) -> None:
        if not self._findings:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.information(self, "No Findings", "No findings to export.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Scan Report", "fracture_report.html", "HTML Files (*.html)"
        )
        if not path:
            return
        try:
            from .scanner_report import generate_html_report
            generate_html_report(self._findings, path)
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))
        except Exception as e:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.critical(self, "Report Error", str(e))
