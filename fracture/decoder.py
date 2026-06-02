"""
Fracture Decoder tab — encode/decode text in various formats.
Mirrors Burp Suite's Decoder functionality.
"""

import base64
import binascii
import gzip
import hashlib
import html
import json
import urllib.parse
import zlib
from typing import Callable

try:
    import brotli as _brotli  # type: ignore[import]
    _BROTLI_OK = True
except ImportError:
    _brotli = None  # type: ignore[assignment]
    _BROTLI_OK = False

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

_MONO = QFont("Monospace", 9)

_STYLE = """
    QTextEdit {
        background: #181825;
        border: 1px solid #313244;
        color: #cdd6f4;
    }
    QPushButton {
        background: #313244;
        border: 1px solid #45475a;
        padding: 4px 10px;
        border-radius: 4px;
        color: #cdd6f4;
    }
    QPushButton:hover {
        background: #45475a;
    }
    QLabel {
        color: #cdd6f4;
    }
"""

# ---------------------------------------------------------------------------
# Codec helpers
# ---------------------------------------------------------------------------


def _b64_decode(text: str) -> str:
    # Add padding if needed before decoding.
    padded = text.strip()
    missing = len(padded) % 4
    if missing:
        padded += "=" * (4 - missing)
    decoded_bytes = base64.b64decode(padded)
    return decoded_bytes.decode("utf-8", errors="replace")


def _b64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _url_decode(text: str) -> str:
    return urllib.parse.unquote_plus(text)


def _url_encode(text: str) -> str:
    return urllib.parse.quote_plus(text)


def _html_decode(text: str) -> str:
    return html.unescape(text)


def _html_encode(text: str) -> str:
    return html.escape(text, quote=True)


def _hex_decode(text: str) -> str:
    cleaned = text.strip().replace(" ", "").replace("\n", "")
    raw = bytes.fromhex(cleaned)
    return raw.decode("utf-8", errors="replace")


def _hex_encode(text: str) -> str:
    return text.encode("utf-8").hex()


# ---------------------------------------------------------------------------
# New codec helpers
# ---------------------------------------------------------------------------


def _gzip_decompress(text: str) -> str:
    raw = text.strip()
    # Try treating input as base64-encoded gzip first, then raw bytes
    try:
        data = base64.b64decode(raw + "==")
        return gzip.decompress(data).decode("utf-8", errors="replace")
    except Exception:
        pass
    return gzip.decompress(raw.encode("latin-1")).decode("utf-8", errors="replace")


def _gzip_compress(text: str) -> str:
    compressed = gzip.compress(text.encode("utf-8"))
    return base64.b64encode(compressed).decode("ascii")


def _deflate_decompress(text: str) -> str:
    raw = text.strip()
    try:
        data = base64.b64decode(raw + "==")
        return zlib.decompress(data).decode("utf-8", errors="replace")
    except Exception:
        pass
    return zlib.decompress(raw.encode("latin-1")).decode("utf-8", errors="replace")


def _brotli_decompress(text: str) -> str:
    if not _BROTLI_OK:
        raise RuntimeError("brotli package not installed — run: pip install brotli")
    raw = text.strip()
    try:
        data = base64.b64decode(raw + "==")
        return _brotli.decompress(data).decode("utf-8", errors="replace")
    except Exception:
        pass
    return _brotli.decompress(raw.encode("latin-1")).decode("utf-8", errors="replace")


def _jwt_decode(text: str) -> str:
    parts = text.strip().split(".")
    if len(parts) < 2:
        raise ValueError("Not a valid JWT (expected at least 2 dot-separated parts)")

    def _b64url_decode(s: str) -> str:
        s = s.replace("-", "+").replace("_", "/")
        s += "=" * (-len(s) % 4)
        return base64.b64decode(s).decode("utf-8", errors="replace")

    header_raw = _b64url_decode(parts[0])
    payload_raw = _b64url_decode(parts[1])

    try:
        header_fmt = json.dumps(json.loads(header_raw), indent=2)
    except Exception:
        header_fmt = header_raw

    try:
        payload_fmt = json.dumps(json.loads(payload_raw), indent=2)
    except Exception:
        payload_fmt = payload_raw

    sig_note = "(not verified)" if len(parts) == 3 else "(no signature)"
    return (
        f"=== Header ===\n{header_fmt}\n\n"
        f"=== Payload ===\n{payload_fmt}\n\n"
        f"=== Signature ===\n{parts[2] if len(parts) == 3 else '(none)'} {sig_note}"
    )


def _sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha512_hash(text: str) -> str:
    return hashlib.sha512(text.encode("utf-8")).hexdigest()


def _binary_encode(text: str) -> str:
    return " ".join(f"{b:08b}" for b in text.encode("utf-8"))


def _binary_decode(text: str) -> str:
    tokens = text.strip().split()
    byte_vals = [int(t, 2) for t in tokens if t]
    return bytes(byte_vals).decode("utf-8", errors="replace")


def _octal_encode(text: str) -> str:
    return " ".join(f"{b:03o}" for b in text.encode("utf-8"))


def _octal_decode(text: str) -> str:
    tokens = text.strip().split()
    byte_vals = [int(t, 8) for t in tokens if t]
    return bytes(byte_vals).decode("utf-8", errors="replace")


def _is_clean(text: str) -> bool:
    """Return True if text has no replacement chars or non-printable control chars."""
    if "�" in text:
        return False
    return all(c >= " " or c in "\t\n\r" for c in text)


def _smart_decode(text: str) -> str:
    """
    Chain decode: URL → Base64 → Hex, stopping when output stabilises.
    Each step is attempted in turn; if it succeeds, changes the value, and
    produces clean (printable) output, the result becomes the new input.
    """
    steps: list[Callable[[str], str]] = [_url_decode, _b64_decode, _hex_decode]
    current = text
    changed = True
    while changed:
        changed = False
        for step in steps:
            try:
                result = step(current)
                if result != current and _is_clean(result):
                    current = result
                    changed = True
                    break
            except Exception:
                continue
    return current


# ---------------------------------------------------------------------------
# DecoderTab widget
# ---------------------------------------------------------------------------


class DecoderTab(QWidget):
    """Encode / decode text in various formats (Base64, URL, HTML, Hex)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setStyleSheet(_STYLE)
        self._setup_ui()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_text(self, text: str) -> None:
        """Set the input area — called from other tabs to send data here."""
        self._input.setPlainText(text)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        # ---- Input area ----
        input_label = QLabel("Input")
        input_label.setStyleSheet("font-weight: bold; color: #89b4fa;")
        root.addWidget(input_label)

        self._input = QTextEdit()
        self._input.setFont(_MONO)
        self._input.setPlaceholderText("Paste text to encode / decode here…")
        root.addWidget(self._input, stretch=3)

        # ---- Button rows ----
        decode_row = QHBoxLayout()
        decode_row.setSpacing(4)
        encode_row = QHBoxLayout()
        encode_row.setSpacing(4)

        decode_row2 = QHBoxLayout()
        decode_row2.setSpacing(4)
        encode_row2 = QHBoxLayout()
        encode_row2.setSpacing(4)

        buttons: list[tuple[QHBoxLayout, str, Callable[[str], str]]] = [
            # Row 1: classic operations
            (decode_row, "Decode as Base64", _b64_decode),
            (encode_row, "Encode as Base64", _b64_encode),
            (decode_row, "URL Decode", _url_decode),
            (encode_row, "URL Encode", _url_encode),
            (decode_row, "HTML Decode", _html_decode),
            (encode_row, "HTML Encode", _html_encode),
            (decode_row, "Hex Decode", _hex_decode),
            (encode_row, "Hex Encode", _hex_encode),
            # Row 2: extended operations
            (decode_row2, "Gzip Decompress", _gzip_decompress),
            (encode_row2, "Gzip Compress", _gzip_compress),
            (decode_row2, "Deflate Decompress", _deflate_decompress),
            (decode_row2, "Brotli Decompress", _brotli_decompress),
            (decode_row2, "Binary Decode", _binary_decode),
            (encode_row2, "Binary Encode", _binary_encode),
            (decode_row2, "Octal Decode", _octal_decode),
            (encode_row2, "Octal Encode", _octal_encode),
            (encode_row2, "SHA-256", _sha256_hash),
            (encode_row2, "SHA-512", _sha512_hash),
        ]

        for row_layout, label, fn in buttons:
            btn = QPushButton(label)
            btn.clicked.connect(self._make_transform_handler(fn))
            row_layout.addWidget(btn)

        for row in (decode_row, encode_row, decode_row2, encode_row2):
            row.addStretch()

        root.addLayout(decode_row)
        root.addLayout(encode_row)
        root.addLayout(decode_row2)
        root.addLayout(encode_row2)

        # ---- Extra-action row ----
        action_row = QHBoxLayout()
        action_row.setSpacing(4)

        smart_btn = QPushButton("Smart Decode")
        smart_btn.setToolTip("Auto-detect and chain decode (URL → Base64 → Hex)")
        smart_btn.clicked.connect(self._smart_decode)
        action_row.addWidget(smart_btn)

        jwt_btn = QPushButton("JWT Decode")
        jwt_btn.setToolTip("Decode JWT header and payload (no verification)")
        jwt_btn.clicked.connect(self._make_transform_handler(_jwt_decode))
        action_row.addWidget(jwt_btn)

        swap_btn = QPushButton("↕ Swap")
        swap_btn.setToolTip("Move output back to input")
        swap_btn.clicked.connect(self._swap)
        action_row.addWidget(swap_btn)

        copy_btn = QPushButton("Copy Output")
        copy_btn.clicked.connect(self._copy_output)
        action_row.addWidget(copy_btn)

        action_row.addStretch()
        root.addLayout(action_row)

        # ---- Output area ----
        output_label = QLabel("Output")
        output_label.setStyleSheet("font-weight: bold; color: #89b4fa;")
        root.addWidget(output_label)

        self._output = QTextEdit()
        self._output.setFont(_MONO)
        self._output.setReadOnly(True)
        self._output.setPlaceholderText("Result will appear here…")
        root.addWidget(self._output, stretch=3)

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    def _make_transform_handler(
        self, fn: Callable[[str], str]
    ) -> Callable[[], None]:
        """Return a zero-argument slot that applies *fn* to the current input."""

        def handler() -> None:
            self._apply(fn)

        return handler

    def _apply(self, fn: Callable[[str], str]) -> None:
        """Apply *fn* to input text and write result (or error) to output."""
        text = self._input.toPlainText()
        try:
            result = fn(text)
            self._output.setStyleSheet("")  # reset any error colour
            self._output.setPlainText(result)
        except Exception as exc:
            self._output.setStyleSheet("color: #f38ba8;")  # Mocha red
            self._output.setPlainText(f"Error: {exc}")

    def _smart_decode(self) -> None:
        self._apply(_smart_decode)

    def _swap(self) -> None:
        """Move the output text back into the input area."""
        output_text = self._output.toPlainText()
        if output_text:
            self._output.setStyleSheet("")
            self._output.clear()
            self._input.setPlainText(output_text)

    def _copy_output(self) -> None:
        text = self._output.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
