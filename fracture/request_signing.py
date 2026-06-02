"""Request signing helpers for Fracture Repeater.

Provides:
- ``sign_aws_sigv4``: AWS Signature Version 4 signing using stdlib only.
- ``sign_hmac``: generic HMAC request signer.
- ``RequestSigningDialog``: PyQt6 dialog for configuring per-tab signing.
- ``apply_signing``: parses a raw HTTP/1.1 request, applies configured
  signers, and re-serializes the result.

The module is intentionally self-contained and does not import from the
Repeater module to avoid circular dependencies — wiring is performed in
``repeater.py``/``gui.py``.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote, urlsplit

from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)


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
_CHECKBOX_SS = f"QCheckBox {{ spacing: 6px; color: {_TEXT}; }}"
_LABEL_SS = f"color: {_SUBTEXT}; font-size: 11px;"
_TABS_SS = (
    f"QTabWidget::pane {{ border: 1px solid {_OVERLAY}; background: {_BG}; }}"
    f"QTabBar::tab {{ background: {_SURFACE}; color: {_SUBTEXT}; padding: 4px 12px; "
    f"border: 1px solid {_OVERLAY}; border-bottom: none; margin-right: 2px; }}"
    f"QTabBar::tab:selected {{ background: {_OVERLAY}; color: {_TEXT}; }}"
    f"QTabBar::tab:hover {{ background: {_HIGHLIGHT}; color: {_TEXT}; }}"
)


# ---------------------------------------------------------------------------
# AWS SigV4
# ---------------------------------------------------------------------------

# SHA-256 of empty payload (used when body is b'')
_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def _canonical_uri(path: str) -> str:
    """Return URI-encoded path. Empty path becomes '/'."""
    if not path:
        return "/"
    # AWS requires double-encoding for some services, but for the general
    # signing pipeline we encode each path segment once and preserve '/'.
    return quote(path, safe="/~")


def _canonical_query(query: str) -> str:
    """Return canonical query string per SigV4 rules: sorted, URI-encoded."""
    if not query:
        return ""
    pairs: list[tuple[str, str]] = []
    for raw_pair in query.split("&"):
        if not raw_pair:
            continue
        if "=" in raw_pair:
            k, _, v = raw_pair.partition("=")
        else:
            k, v = raw_pair, ""
        pairs.append((quote(k, safe="~"), quote(v, safe="~")))
    pairs.sort()
    return "&".join(f"{k}={v}" for k, v in pairs)


def sign_aws_sigv4(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
    access_key: str,
    secret_key: str,
    region: str,
    service: str,
) -> dict[str, str]:
    """Sign a request using AWS Signature Version 4.

    Returns a *new* headers dict (the input is not mutated) including
    ``Authorization``, ``X-Amz-Date``, and ``X-Amz-Content-Sha256``.

    The implementation uses only the standard library.
    """
    method = method.upper()
    body = body or b""
    split = urlsplit(url)
    host = split.hostname or headers.get("Host") or headers.get("host") or ""
    if split.port:
        # Include port in Host header value to keep canonical headers stable.
        host_header = f"{host}:{split.port}"
    else:
        host_header = host
    canonical_uri = _canonical_uri(split.path or "/")
    canonical_qs = _canonical_query(split.query)

    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    payload_hash = _EMPTY_SHA256 if not body else _sha256_hex(body)

    # Build merged headers dict (case-preserving copy).
    merged: dict[str, str] = dict(headers)
    # Drop any existing case-insensitive matches we are replacing.
    for k in list(merged.keys()):
        lk = k.lower()
        if lk in ("authorization", "x-amz-date", "x-amz-content-sha256", "host"):
            del merged[k]
    merged["Host"] = host_header
    merged["X-Amz-Date"] = amz_date
    merged["X-Amz-Content-Sha256"] = payload_hash

    # Canonical headers — lowercased names, trimmed values, sorted.
    canonical_pairs: list[tuple[str, str]] = []
    for name, value in merged.items():
        lname = name.lower().strip()
        # Collapse internal runs of whitespace per RFC, but be conservative
        # and just strip outer whitespace (matches AWS reference behaviour
        # for normal header values).
        canonical_pairs.append((lname, str(value).strip()))
    canonical_pairs.sort(key=lambda kv: kv[0])
    canonical_headers = "".join(f"{k}:{v}\n" for k, v in canonical_pairs)
    signed_headers = ";".join(k for k, _ in canonical_pairs)

    canonical_request = "\n".join(
        [
            method,
            canonical_uri,
            canonical_qs,
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )

    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            credential_scope,
            _sha256_hex(canonical_request.encode("utf-8")),
        ]
    )

    k_date = _hmac_sha256(("AWS4" + secret_key).encode("utf-8"), date_stamp.encode("utf-8"))
    k_region = _hmac_sha256(k_date, region.encode("utf-8"))
    k_service = _hmac_sha256(k_region, service.encode("utf-8"))
    k_signing = _hmac_sha256(k_service, b"aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    merged["Authorization"] = authorization
    return merged


# ---------------------------------------------------------------------------
# Generic HMAC
# ---------------------------------------------------------------------------

_HMAC_ALGOS: dict[str, str] = {
    "sha256": "sha256",
    "sha1": "sha1",
    "sha512": "sha512",
}


def sign_hmac(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
    secret: str,
    header_name: str = "X-Signature",
    algorithm: str = "sha256",
    body_only: bool = False,
) -> dict[str, str]:
    """Sign a request with a generic HMAC scheme.

    When ``body_only`` is True the signature is computed over the request
    body only; otherwise it is computed over ``method + path + body``.

    The path is extracted from ``url`` if it parses as a URL, otherwise
    ``url`` is treated as a path.
    """
    body = body or b""
    algo_name = algorithm.lower()
    if algo_name not in _HMAC_ALGOS:
        raise ValueError(f"Unsupported HMAC algorithm: {algorithm!r}")
    digestmod = getattr(hashlib, _HMAC_ALGOS[algo_name])

    if body_only:
        message = body
    else:
        split = urlsplit(url)
        if split.scheme and split.netloc:
            path = split.path or "/"
            if split.query:
                path = f"{path}?{split.query}"
        else:
            path = url or "/"
        message = method.upper().encode("ascii") + path.encode("utf-8") + body

    signature = hmac.new(secret.encode("utf-8"), message, digestmod).hexdigest()

    merged: dict[str, str] = dict(headers)
    # Drop any existing case-insensitive match.
    for k in list(merged.keys()):
        if k.lower() == header_name.lower():
            del merged[k]
    merged[header_name] = signature
    return merged


# ---------------------------------------------------------------------------
# Raw HTTP request parser
# ---------------------------------------------------------------------------

def _parse_raw_request(raw: str) -> tuple[str, str, str, dict[str, str], bytes, str]:
    """Parse a raw HTTP/1.1 request.

    Returns (method, path, version, headers, body_bytes, line_ending).
    Header ordering and case are preserved.
    """
    # Detect line ending — prefer CRLF if present.
    if "\r\n" in raw:
        eol = "\r\n"
    else:
        eol = "\n"
    sep = eol + eol
    if sep in raw:
        head, body_text = raw.split(sep, 1)
    else:
        head, body_text = raw, ""

    lines = head.split(eol)
    if not lines:
        raise ValueError("Empty raw request")
    request_line = lines[0]
    parts = request_line.split(" ", 2)
    if len(parts) < 3:
        raise ValueError(f"Malformed request line: {request_line!r}")
    method, path, version = parts[0], parts[1], parts[2]

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers[name.strip()] = value.strip()

    return method, path, version, headers, body_text.encode("utf-8", errors="replace"), eol


def _serialize_request(
    method: str,
    path: str,
    version: str,
    headers: dict[str, str],
    body: bytes,
    eol: str,
) -> str:
    out_lines = [f"{method} {path} {version}"]
    for name, value in headers.items():
        out_lines.append(f"{name}: {value}")
    head = eol.join(out_lines) + eol + eol
    try:
        body_text = body.decode("utf-8")
    except UnicodeDecodeError:
        body_text = body.decode("latin-1", errors="replace")
    return head + body_text


def apply_signing(raw_request: str, host: str, is_https: bool, config: dict) -> str:
    """Parse ``raw_request``, apply configured signers, return new raw request.

    ``config`` shape mirrors :py:meth:`RequestSigningDialog.config`::

        {"aws": {...} | None, "hmac": {...} | None}

    If neither signer is enabled the input is returned unchanged.
    """
    if not config:
        return raw_request
    aws_cfg = config.get("aws")
    hmac_cfg = config.get("hmac")
    if not aws_cfg and not hmac_cfg:
        return raw_request

    try:
        method, path, version, headers, body, eol = _parse_raw_request(raw_request)
    except ValueError:
        return raw_request

    scheme = "https" if is_https else "http"
    # Use the Host header from the request if present and non-empty,
    # otherwise fall back to the supplied host.
    host_value = headers.get("Host") or headers.get("host") or host
    url = f"{scheme}://{host_value}{path}"

    if aws_cfg:
        headers = sign_aws_sigv4(
            method=method,
            url=url,
            headers=headers,
            body=body,
            access_key=aws_cfg.get("access_key", ""),
            secret_key=aws_cfg.get("secret_key", ""),
            region=aws_cfg.get("region", ""),
            service=aws_cfg.get("service", ""),
        )

    if hmac_cfg:
        headers = sign_hmac(
            method=method,
            url=url,
            headers=headers,
            body=body,
            secret=hmac_cfg.get("secret", ""),
            header_name=hmac_cfg.get("header_name", "X-Signature"),
            algorithm=hmac_cfg.get("algorithm", "sha256"),
            body_only=bool(hmac_cfg.get("body_only", False)),
        )

    return _serialize_request(method, path, version, headers, body, eol)


# ---------------------------------------------------------------------------
# Configuration dialog
# ---------------------------------------------------------------------------

class RequestSigningDialog(QDialog):
    """Per-Repeater-tab signing configuration dialog.

    Usage::

        dlg = RequestSigningDialog(self, initial=existing_config)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._signing_config = dlg.config()
    """

    def __init__(
        self,
        parent: Optional[QWidget] = None,
        initial: Optional[dict] = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Request Signing")
        self.setMinimumWidth(440)
        self.setStyleSheet(f"background: {_BG}; color: {_TEXT};")

        root = QVBoxLayout(self)

        intro = QLabel(
            "Configure outbound request signing for this Repeater tab. "
            "Enabled signers are applied right before the request is sent."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet(_LABEL_SS)
        root.addWidget(intro)

        self._tabs = QTabWidget()
        self._tabs.setStyleSheet(_TABS_SS)
        root.addWidget(self._tabs)

        self._build_aws_tab()
        self._build_hmac_tab()

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        for btn in buttons.buttons():
            btn.setStyleSheet(_BTN_SS)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

        if initial:
            self._load_initial(initial)

    # -- AWS tab --------------------------------------------------------
    def _build_aws_tab(self) -> None:
        page = QWidget()
        page.setStyleSheet(f"background: {_BG};")
        layout = QFormLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)

        self._aws_enable = QCheckBox("Enable AWS SigV4 signing")
        self._aws_enable.setStyleSheet(_CHECKBOX_SS)
        layout.addRow(self._aws_enable)

        self._aws_access_key = QLineEdit()
        self._aws_access_key.setStyleSheet(_LINEEDIT_SS)
        self._aws_access_key.setPlaceholderText("AKIA…")
        layout.addRow(self._labeled("Access Key"), self._aws_access_key)

        self._aws_secret_key = QLineEdit()
        self._aws_secret_key.setStyleSheet(_LINEEDIT_SS)
        self._aws_secret_key.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow(self._labeled("Secret Key"), self._aws_secret_key)

        self._aws_region = QLineEdit("us-east-1")
        self._aws_region.setStyleSheet(_LINEEDIT_SS)
        layout.addRow(self._labeled("Region"), self._aws_region)

        self._aws_service = QLineEdit()
        self._aws_service.setStyleSheet(_LINEEDIT_SS)
        self._aws_service.setPlaceholderText("e.g. s3, execute-api, lambda")
        layout.addRow(self._labeled("Service"), self._aws_service)

        self._tabs.addTab(page, "AWS SigV4")

    # -- HMAC tab -------------------------------------------------------
    def _build_hmac_tab(self) -> None:
        page = QWidget()
        page.setStyleSheet(f"background: {_BG};")
        layout = QFormLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)

        self._hmac_enable = QCheckBox("Enable Generic HMAC signing")
        self._hmac_enable.setStyleSheet(_CHECKBOX_SS)
        layout.addRow(self._hmac_enable)

        self._hmac_secret = QLineEdit()
        self._hmac_secret.setStyleSheet(_LINEEDIT_SS)
        self._hmac_secret.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow(self._labeled("Secret"), self._hmac_secret)

        self._hmac_header = QLineEdit("X-Signature")
        self._hmac_header.setStyleSheet(_LINEEDIT_SS)
        layout.addRow(self._labeled("Header Name"), self._hmac_header)

        self._hmac_algo = QComboBox()
        self._hmac_algo.addItems(["sha256", "sha1", "sha512"])
        self._hmac_algo.setStyleSheet(_COMBO_SS)
        layout.addRow(self._labeled("Algorithm"), self._hmac_algo)

        self._hmac_body_only = QCheckBox("Sign body only (otherwise: METHOD + path + body)")
        self._hmac_body_only.setStyleSheet(_CHECKBOX_SS)
        layout.addRow(self._hmac_body_only)

        self._tabs.addTab(page, "Generic HMAC")

    def _labeled(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(_LABEL_SS)
        return lbl

    # -- Initial state --------------------------------------------------
    def _load_initial(self, initial: dict) -> None:
        aws = initial.get("aws") or {}
        if aws:
            self._aws_enable.setChecked(True)
            self._aws_access_key.setText(str(aws.get("access_key", "")))
            self._aws_secret_key.setText(str(aws.get("secret_key", "")))
            self._aws_region.setText(str(aws.get("region", "us-east-1")))
            self._aws_service.setText(str(aws.get("service", "")))

        hmac_cfg = initial.get("hmac") or {}
        if hmac_cfg:
            self._hmac_enable.setChecked(True)
            self._hmac_secret.setText(str(hmac_cfg.get("secret", "")))
            self._hmac_header.setText(str(hmac_cfg.get("header_name", "X-Signature")))
            algo = str(hmac_cfg.get("algorithm", "sha256"))
            idx = self._hmac_algo.findText(algo)
            if idx >= 0:
                self._hmac_algo.setCurrentIndex(idx)
            self._hmac_body_only.setChecked(bool(hmac_cfg.get("body_only", False)))

    # -- Public API -----------------------------------------------------
    def config(self) -> dict:
        """Return the configured signers."""
        aws: Optional[dict] = None
        if self._aws_enable.isChecked():
            aws = {
                "access_key": self._aws_access_key.text().strip(),
                "secret_key": self._aws_secret_key.text(),
                "region": self._aws_region.text().strip() or "us-east-1",
                "service": self._aws_service.text().strip(),
            }

        hmac_cfg: Optional[dict] = None
        if self._hmac_enable.isChecked():
            hmac_cfg = {
                "secret": self._hmac_secret.text(),
                "header_name": self._hmac_header.text().strip() or "X-Signature",
                "algorithm": self._hmac_algo.currentText(),
                "body_only": self._hmac_body_only.isChecked(),
            }

        return {"aws": aws, "hmac": hmac_cfg}


__all__ = [
    "sign_aws_sigv4",
    "sign_hmac",
    "apply_signing",
    "RequestSigningDialog",
]
