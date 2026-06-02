"""
Transparent response-body decompression.

Looks at the Content-Encoding header and returns a best-effort decoded copy
of the body.  The original raw bytes are never mutated — callers keep both
the wire form (for re-send) and the decoded form (for display).
"""

from __future__ import annotations

import gzip
import zlib
from typing import Optional

try:
    import brotli as _brotli
except Exception:  # pragma: no cover
    _brotli = None

try:
    import zstandard as _zstd
except Exception:  # pragma: no cover
    _zstd = None


def _header_ci(headers: dict, name: str) -> str:
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return ""


def decompress(body: bytes, headers: dict) -> tuple[bytes, str]:
    """Decompress *body* per Content-Encoding header.

    Returns (decoded_bytes, label).  label is "" when no decoding was done,
    or "gzip"/"deflate"/"br"/"zstd"/"identity" otherwise.  Decoding failures
    silently fall back to the original bytes.
    """
    if not body:
        return body, ""
    encoding = _header_ci(headers, "Content-Encoding").lower().strip()
    if not encoding or encoding == "identity":
        return body, ""

    # Handle comma-separated chains by working outermost-first
    for enc in reversed([e.strip() for e in encoding.split(",")]):
        if enc == "gzip":
            try:
                body = gzip.decompress(body)
            except Exception:
                return body, encoding + " (decode-failed)"
        elif enc == "deflate":
            try:
                body = zlib.decompress(body)
            except Exception:
                try:
                    body = zlib.decompress(body, -zlib.MAX_WBITS)
                except Exception:
                    return body, encoding + " (decode-failed)"
        elif enc == "br":
            if _brotli is None:
                return body, encoding + " (brotli unavailable)"
            try:
                body = _brotli.decompress(body)
            except Exception:
                return body, encoding + " (decode-failed)"
        elif enc == "zstd":
            if _zstd is None:
                return body, encoding + " (zstandard unavailable)"
            try:
                body = _zstd.ZstdDecompressor().decompress(body)
            except Exception:
                return body, encoding + " (decode-failed)"
        else:
            return body, encoding + " (unknown)"

    return body, encoding


def format_response_for_display(raw: bytes, headers: dict) -> tuple[bytes, str]:
    """Decompress + replace Content-Encoding header for display.

    Returns (rebuilt_raw_response, note).  The original wire bytes are not
    modified.  Used by the proxy/repeater viewers.
    """
    decoded, label = decompress(raw, headers)
    if not label or "failed" in label or "unavailable" in label or "unknown" in label:
        return raw, label
    # Rebuild a fake raw response that shows decoded body, with a note
    # appended to the headers so the viewer indicates decompression happened.
    return decoded, label
