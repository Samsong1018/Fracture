"""
Match & Replace rule engine for Fracture.

Supports regex and plain-string substitution across request/response
headers, bodies, and URLs.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class MRTarget(Enum):
    REQUEST_HEADER = "Request Header"
    REQUEST_BODY = "Request Body"
    REQUEST_URL = "Request URL"
    RESPONSE_HEADER = "Response Header"
    RESPONSE_BODY = "Response Body"


@dataclass
class MRRule:
    id: int
    enabled: bool
    target: MRTarget
    pattern: str
    replacement: str
    is_regex: bool = True
    comment: str = ""


class MatchReplaceManager:
    def __init__(self) -> None:
        self._rules: list[MRRule] = []
        self._next_id: int = 1

    def add_rule(
        self,
        target: MRTarget,
        pattern: str,
        replacement: str,
        is_regex: bool = True,
        comment: str = "",
    ) -> MRRule:
        rule = MRRule(
            id=self._next_id,
            enabled=True,
            target=target,
            pattern=pattern,
            replacement=replacement,
            is_regex=is_regex,
            comment=comment,
        )
        self._rules.append(rule)
        self._next_id += 1
        return rule

    def remove_rule(self, rule_id: int) -> None:
        self._rules = [r for r in self._rules if r.id != rule_id]

    def toggle_rule(self, rule_id: int) -> None:
        for rule in self._rules:
            if rule.id == rule_id:
                rule.enabled = not rule.enabled
                break

    def rules(self) -> list[MRRule]:
        return list(self._rules)

    def _apply_rules(self, text: str, target: MRTarget) -> str:
        """Apply all enabled rules matching *target* to *text*."""
        for rule in self._rules:
            if not rule.enabled or rule.target != target:
                continue
            try:
                if rule.is_regex:
                    text = re.sub(rule.pattern, rule.replacement, text)
                else:
                    text = text.replace(rule.pattern, rule.replacement)
            except re.error as exc:
                print(
                    f"[match_replace] WARNING: invalid regex in rule {rule.id} "
                    f"({rule.pattern!r}): {exc} — skipping"
                )
        return text

    def apply_to_request(self, raw: bytes) -> bytes:
        """Apply all enabled REQUEST_* rules to raw request bytes."""
        # Split header section from body at the blank line separator.
        separator = b"\r\n\r\n"
        sep_idx = raw.find(separator)
        if sep_idx == -1:
            header_section = raw
            body_bytes = b""
        else:
            header_section = raw[:sep_idx]
            body_bytes = raw[sep_idx + 4:]

        # Further split header section into the request line and the rest.
        first_line_end = header_section.find(b"\r\n")
        if first_line_end == -1:
            request_line = header_section.decode(errors="replace")
            headers_text = ""
        else:
            request_line = header_section[:first_line_end].decode(errors="replace")
            headers_text = header_section[first_line_end + 2:].decode(errors="replace")

        # Apply rules to each section.
        request_line = self._apply_rules(request_line, MRTarget.REQUEST_URL)
        headers_text = self._apply_rules(headers_text, MRTarget.REQUEST_HEADER)

        body_str = body_bytes.decode(errors="replace")
        body_str = self._apply_rules(body_str, MRTarget.REQUEST_BODY)

        # Reassemble.
        if first_line_end == -1:
            new_header_section = request_line.encode()
        else:
            new_header_section = (request_line + "\r\n" + headers_text).encode()

        if sep_idx == -1:
            return new_header_section
        return new_header_section + separator + body_str.encode()

    def apply_to_response(self, raw: bytes) -> bytes:
        """Apply all enabled RESPONSE_* rules to raw response bytes."""
        separator = b"\r\n\r\n"
        sep_idx = raw.find(separator)
        if sep_idx == -1:
            headers_bytes = raw
            body_bytes = b""
        else:
            headers_bytes = raw[:sep_idx]
            body_bytes = raw[sep_idx + 4:]

        headers_text = headers_bytes.decode(errors="replace")
        headers_text = self._apply_rules(headers_text, MRTarget.RESPONSE_HEADER)

        body_str = body_bytes.decode(errors="replace")
        body_str = self._apply_rules(body_str, MRTarget.RESPONSE_BODY)

        if sep_idx == -1:
            return headers_text.encode()
        return headers_text.encode() + separator + body_str.encode()
