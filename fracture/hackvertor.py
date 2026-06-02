"""
Hackvertor-style nested encoding tags.

Syntax:  <@tag>content</@tag>  or  <@tag(arg1,arg2)>content</@tag>
Tags evaluate inside-out, so `<@base64><@hex>foo</@hex></@base64>` first
hex-encodes "foo" and then base64-encodes the result.

Self-closing tags `<@uuid/>` produce values with no inner content.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import hmac
import html
import re
import time
import urllib.parse
import uuid
import zlib
from typing import Callable


# ---------------------------------------------------------------------------
# Built-in encoders / hashes / generators
# ---------------------------------------------------------------------------

def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _b64url(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).rstrip(b"=").decode()


def _hex(s: str) -> str:
    return s.encode().hex()


def _unhex(s: str) -> str:
    try:
        return bytes.fromhex(s).decode("utf-8", errors="replace")
    except ValueError:
        return s


def _url(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def _urldecode(s: str) -> str:
    return urllib.parse.unquote(s)


def _html_enc(s: str) -> str:
    return html.escape(s, quote=True)


def _html_dec(s: str) -> str:
    return html.unescape(s)


def _gzip_enc(s: str) -> str:
    return base64.b64encode(gzip.compress(s.encode())).decode()


def _deflate_enc(s: str) -> str:
    return base64.b64encode(zlib.compress(s.encode())).decode()


def _rot13(s: str) -> str:
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def _reverse(s: str) -> str:
    return s[::-1]


def _md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def _sha1(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _sha512(s: str) -> str:
    return hashlib.sha512(s.encode()).hexdigest()


def _hmac_sha256(s: str, key: str = "") -> str:
    return hmac.new(key.encode(), s.encode(), hashlib.sha256).hexdigest()


# --- Random / generator tags (ignore inner content) ---

def _rand_int(_: str, low: str = "0", high: str = "100") -> str:
    import random
    try:
        lo, hi = int(low), int(high)
    except ValueError:
        return _
    return str(random.randint(lo, hi))


def _rand_str(_: str, length: str = "8") -> str:
    import random
    import string
    try:
        n = int(length)
    except ValueError:
        n = 8
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choices(alphabet, k=n))


def _uuid_tag(_: str) -> str:
    return uuid.uuid4().hex


def _timestamp(_: str, fmt: str = "unix") -> str:
    if fmt == "unix":
        return str(int(time.time()))
    if fmt == "iso":
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return str(int(time.time()))


_TAGS: dict[str, Callable[..., str]] = {
    "base64":   lambda s: _b64(s),
    "base64url":lambda s: _b64url(s),
    "hex":      lambda s: _hex(s),
    "unhex":    lambda s: _unhex(s),
    "url":      lambda s: _url(s),
    "urldecode":lambda s: _urldecode(s),
    "html":     lambda s: _html_enc(s),
    "htmldecode": lambda s: _html_dec(s),
    "gzip":     lambda s: _gzip_enc(s),
    "deflate":  lambda s: _deflate_enc(s),
    "rot13":    lambda s: _rot13(s),
    "reverse":  lambda s: _reverse(s),
    "md5":      lambda s: _md5(s),
    "sha1":     lambda s: _sha1(s),
    "sha256":   lambda s: _sha256(s),
    "sha512":   lambda s: _sha512(s),
    "hmac_sha256": _hmac_sha256,
    "rand_int": _rand_int,
    "rand_str": _rand_str,
    "uuid":     _uuid_tag,
    "timestamp":_timestamp,
}


def list_tags() -> list[str]:
    return sorted(_TAGS.keys())


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

_SELF_CLOSE_RE = re.compile(
    r"<@(?P<name>[A-Za-z_][\w]*)(?:\((?P<args>[^)]*)\))?\s*/>"
)
# Matches an innermost open/close pair (no nested <@...> in between)
_PAIR_RE = re.compile(
    r"<@(?P<name>[A-Za-z_][\w]*)(?:\((?P<args>[^)]*)\))?>"
    r"(?P<content>(?:(?!<@).)*?)"
    r"</@(?P=name)>",
    re.DOTALL,
)


def _split_args(raw: str) -> list[str]:
    if not raw:
        return []
    return [a.strip() for a in raw.split(",")]


def _call(tag: str, content: str, args: list[str]) -> str:
    fn = _TAGS.get(tag)
    if fn is None:
        return content  # unknown tag → leave content untouched
    try:
        return fn(content, *args)
    except TypeError:
        # Bad arg count — fall back to just content
        try:
            return fn(content)
        except Exception:
            return content
    except Exception:
        return content


def transform(text: str, max_passes: int = 100) -> str:
    """Evaluate all Hackvertor-style tags in *text*, innermost first."""
    if not text or "<@" not in text:
        return text

    out = text
    for _ in range(max_passes):
        # Self-closing tags first
        m = _SELF_CLOSE_RE.search(out)
        if m:
            args = _split_args(m.group("args") or "")
            value = _call(m.group("name"), "", args)
            out = out[: m.start()] + value + out[m.end():]
            continue

        # Innermost pair
        m = _PAIR_RE.search(out)
        if m:
            args = _split_args(m.group("args") or "")
            value = _call(m.group("name"), m.group("content"), args)
            out = out[: m.start()] + value + out[m.end():]
            continue

        break
    return out
