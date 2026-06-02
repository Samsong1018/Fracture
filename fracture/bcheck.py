"""
BCheck-style declarative scan checks.

JSON-based custom checks loaded from ~/.fracture/bchecks/*.json.
Each check describes how to mutate an HttpRequest and what response pattern
counts as a hit. Returns a Finding mirroring scanner_active emit signature.

Schema (per file):

    {
      "id": "custom-debug-leak",
      "name": "Debug parameter leak",
      "severity": "MEDIUM",
      "send": {"append_param": "debug=1"},
      "match": {"response_contains": "DEBUG", "case_sensitive": false},
      "report": "Server reveals debug info when debug=1 is appended."
    }

Supported "send" shapes:
    - append_param: "name=value"            -> add to query string
    - set_header:   {"X-Foo": "bar"}        -> set/override header (case-insensitive)
    - body_suffix:  "literal"               -> append to body

Supported "match" shapes:
    - response_contains: substring (with case_sensitive bool, default false)
    - status_in:         list of int status codes
    - response_regex:    regex pattern
"""

from __future__ import annotations

import json
import logging
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .proxy import HttpRequest

log = logging.getLogger(__name__)

BUFFER = 65536
DEFAULT_BCHECK_DIR = Path.home() / ".fracture" / "bchecks"

_VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """Mirror of scanner_active.ScanWorker.finding payload."""

    severity: str
    title: str
    detail: str
    param: str

    def as_emit_args(self) -> tuple[str, str, str, str]:
        return (self.severity, self.title, self.detail, self.param)


@dataclass
class BCheck:
    """One declarative scan check loaded from a JSON file."""

    id: str
    name: str
    severity: str
    send: dict[str, Any]
    match: dict[str, Any]
    report: str
    source_path: Optional[Path] = field(default=None)

    @classmethod
    def from_dict(cls, data: dict[str, Any], source: Optional[Path] = None) -> "BCheck":
        missing = [k for k in ("id", "name", "severity", "send", "match", "report") if k not in data]
        if missing:
            raise ValueError(f"BCheck missing required fields: {missing}")
        sev = str(data["severity"]).upper()
        if sev not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity {sev!r}; expected one of {sorted(_VALID_SEVERITIES)}")
        if not isinstance(data["send"], dict) or not isinstance(data["match"], dict):
            raise ValueError("'send' and 'match' must be objects")
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            severity=sev,
            send=dict(data["send"]),
            match=dict(data["match"]),
            report=str(data["report"]),
            source_path=source,
        )


# ---------------------------------------------------------------------------
# Default example
# ---------------------------------------------------------------------------


EXAMPLE_BCHECK = {
    "id": "example-debug-leak",
    "name": "Debug parameter leak",
    "severity": "MEDIUM",
    "send": {"append_param": "debug=1"},
    "match": {"response_contains": "DEBUG", "case_sensitive": False},
    "report": "Server reveals debug info when debug=1 is appended to the query string.",
}


def _write_example_if_empty(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    has_json = any(directory.glob("*.json"))
    if has_json:
        return
    example_path = directory / "example_debug.json"
    try:
        example_path.write_text(json.dumps(EXAMPLE_BCHECK, indent=2), encoding="utf-8")
        log.info("Wrote example BCheck to %s", example_path)
    except OSError as exc:
        log.warning("Could not write example BCheck %s: %s", example_path, exc)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def load_bchecks(directory: Path | str = DEFAULT_BCHECK_DIR) -> list[BCheck]:
    """Load all *.json BChecks from a directory. Writes example if empty."""
    d = Path(directory)
    _write_example_if_empty(d)

    checks: list[BCheck] = []
    for path in sorted(d.glob("*.json")):
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
            check = BCheck.from_dict(data, source=path)
            checks.append(check)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            log.warning("Skipping invalid BCheck %s: %s", path, exc)
    return checks


# ---------------------------------------------------------------------------
# Request mutation helpers
# ---------------------------------------------------------------------------


def _apply_send(send: dict[str, Any], req: HttpRequest) -> HttpRequest:
    """Return a new HttpRequest with the mutation applied. Original untouched."""
    new_path = req.path
    new_headers = dict(req.headers)
    new_body = req.body

    if "append_param" in send:
        param = str(send["append_param"]).lstrip("&?")
        if "?" in new_path:
            new_path = new_path + "&" + param
        else:
            new_path = new_path + "?" + param

    if "set_header" in send:
        header_dict = send["set_header"]
        if not isinstance(header_dict, dict):
            raise ValueError("'set_header' must be an object")
        # Override case-insensitively
        lowered = {k.lower(): k for k in new_headers}
        for k, v in header_dict.items():
            existing = lowered.get(k.lower())
            if existing is not None:
                new_headers[existing] = str(v)
            else:
                new_headers[k] = str(v)

    if "body_suffix" in send:
        suffix = str(send["body_suffix"])
        new_body = new_body + suffix.encode(errors="replace")

    return HttpRequest(
        id=req.id,
        method=req.method,
        host=req.host,
        port=req.port,
        path=new_path,
        version=req.version,
        headers=new_headers,
        body=new_body,
        is_https=req.is_https,
        timestamp=req.timestamp,
        raw=b"",  # rebuilt below
    )


def _rebuild_raw(req: HttpRequest) -> bytes:
    headers = dict(req.headers)
    if req.body is not None:
        headers["content-length"] = str(len(req.body))
    lines = [f"{req.method} {req.path} HTTP/{req.version}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    header_text = "\r\n".join(lines) + "\r\n\r\n"
    return header_text.encode(errors="replace") + req.body


def _send_raw(host: str, port: int, is_https: bool, raw_request: bytes) -> bytes:
    """Send raw HTTP request bytes. Returns response bytes (possibly b'')."""
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
        return response_data
    except Exception as exc:
        log.warning("bcheck send error %s:%d %s", host, port, exc)
        return b""


def _status_code(response: bytes) -> int:
    try:
        first_line = response.split(b"\r\n", 1)[0]
        parts = first_line.split(b" ", 2)
        return int(parts[1])
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Match evaluation
# ---------------------------------------------------------------------------


def _evaluate_match(match: dict[str, Any], response: bytes) -> tuple[bool, str]:
    """Return (matched, evidence_str)."""
    text = response.decode(errors="replace")

    if "response_contains" in match:
        needle = str(match["response_contains"])
        case_sensitive = bool(match.get("case_sensitive", False))
        if case_sensitive:
            hit = needle in text
        else:
            hit = needle.lower() in text.lower()
        if hit:
            return True, f"Response contains {needle!r} (case_sensitive={case_sensitive})"

    if "status_in" in match:
        codes = match["status_in"]
        if not isinstance(codes, list):
            raise ValueError("'status_in' must be a list")
        code = _status_code(response)
        if code in codes:
            return True, f"Response status {code} in {codes}"

    if "response_regex" in match:
        pattern = str(match["response_regex"])
        try:
            m = re.search(pattern, text)
        except re.error as exc:
            log.warning("Invalid regex in match: %s", exc)
            m = None
        if m:
            return True, f"Regex {pattern!r} matched {m.group(0)!r}"

    return False, ""


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


_SEV_MAP = {
    "INFO": "Info",
    "LOW": "Low",
    "MEDIUM": "Medium",
    "HIGH": "High",
    "CRITICAL": "Critical",
}


def run_bcheck(check: BCheck, req: HttpRequest) -> Optional[Finding]:
    """Send the mutated request and evaluate the match. Returns Finding or None."""
    try:
        mutated = _apply_send(check.send, req)
    except ValueError as exc:
        log.warning("BCheck %s send-config invalid: %s", check.id, exc)
        return None

    raw = _rebuild_raw(mutated)
    start = time.monotonic()
    response = _send_raw(mutated.host, mutated.port, mutated.is_https, raw)
    elapsed = time.monotonic() - start

    if not response:
        return None

    try:
        matched, evidence = _evaluate_match(check.match, response)
    except ValueError as exc:
        log.warning("BCheck %s match-config invalid: %s", check.id, exc)
        return None

    if not matched:
        return None

    severity = _SEV_MAP.get(check.severity, check.severity.title())
    detail = f"{check.report}\n\nEvidence: {evidence}\nElapsed: {elapsed:.2f}s"
    return Finding(
        severity=severity,
        title=f"[BCheck] {check.name}",
        detail=detail,
        param=check.id,
    )


__all__ = [
    "BCheck",
    "Finding",
    "DEFAULT_BCHECK_DIR",
    "load_bchecks",
    "run_bcheck",
]
