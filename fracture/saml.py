"""
SAML Decoder/Analyzer tab for Fracture.

Decodes base64-encoded SAML assertions or raw XML, displays a pretty-printed
view, allows in-place editing and re-encoding, and extracts key SAML fields.
"""

from __future__ import annotations

import base64
import urllib.parse
import xml.dom.minidom
from typing import Optional

from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from PyQt6.QtCore import Qt

from .proxy import HttpRequest

# ---------------------------------------------------------------------------
# Catppuccin Mocha theme
# ---------------------------------------------------------------------------

_BG = "#1e1e2e"
_SURFACE = "#181825"
_OVERLAY = "#313244"
_HIGHLIGHT = "#45475a"
_TEXT = "#cdd6f4"
_SUBTEXT = "#a6adc8"
_TEXTEDIT_SS = "QTextEdit { background: #181825; border: 1px solid #313244; color: #cdd6f4; font-family: monospace; font-size: 12px; }"
_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
    "QPushButton:hover { background: #45475a; }"
    "QPushButton:disabled { color: #585b70; }"
)
_TABS_SS = (
    f"QTabWidget::pane {{ border: 1px solid {_OVERLAY}; background: {_BG}; }}"
    f"QTabBar::tab {{ background: {_SURFACE}; color: {_SUBTEXT}; padding: 4px 12px; "
    f"border: 1px solid {_OVERLAY}; border-bottom: none; margin-right: 2px; }}"
    f"QTabBar::tab:selected {{ background: {_OVERLAY}; color: {_TEXT}; }}"
    f"QTabBar::tab:hover {{ background: {_HIGHLIGHT}; color: {_TEXT}; }}"
)
_LABEL_SS = f"color: {_SUBTEXT}; font-size: 11px;"

_SAML_PARAM_NAMES = ("SAMLRequest", "SAMLResponse", "SAMLart")


# ---------------------------------------------------------------------------
# SAMLTab
# ---------------------------------------------------------------------------

class SAMLTab(QWidget):
    """SAML Decoder/Analyzer — decode, inspect, edit, and re-encode SAML assertions."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._current_xml: bytes = b""
        self._build_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        self.setStyleSheet(f"background: {_BG}; color: {_TEXT};")
        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(6)

        # ---- top bar ----
        top_bar = QHBoxLayout()
        top_bar.setSpacing(6)

        decode_btn = QPushButton("Decode")
        decode_btn.setStyleSheet(_BTN_SS)
        decode_btn.clicked.connect(self._on_decode)
        top_bar.addWidget(decode_btn)

        encode_btn = QPushButton("Encode & Copy")
        encode_btn.setStyleSheet(_BTN_SS)
        encode_btn.clicked.connect(self._encode_and_copy)
        top_bar.addWidget(encode_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.setStyleSheet(_BTN_SS)
        clear_btn.clicked.connect(self._clear)
        top_bar.addWidget(clear_btn)

        top_bar.addStretch()
        root.addLayout(top_bar)

        # ---- main vertical splitter ----
        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.setStyleSheet(f"QSplitter::handle {{ background: {_OVERLAY}; }}")

        # ---- top: input panel ----
        input_panel = QWidget()
        input_panel.setStyleSheet(f"background: {_BG};")
        input_layout = QVBoxLayout(input_panel)
        input_layout.setContentsMargins(0, 0, 0, 0)
        input_layout.setSpacing(4)

        input_header = QLabel("SAML Input")
        input_header.setStyleSheet(
            f"color: {_SUBTEXT}; font-size: 11px; font-family: monospace;"
            f" padding: 4px 8px; background: {_OVERLAY};"
        )
        input_layout.addWidget(input_header)

        self._input_edit = QTextEdit()
        self._input_edit.setPlaceholderText(
            "Paste base64-encoded SAML assertion or raw XML here…"
        )
        self._input_edit.setStyleSheet(_TEXTEDIT_SS)
        input_layout.addWidget(self._input_edit, stretch=1)

        main_splitter.addWidget(input_panel)

        # ---- bottom: output tabs ----
        self._output_tabs = QTabWidget()
        self._output_tabs.setStyleSheet(_TABS_SS)

        self._decoded_view = QTextEdit()
        self._decoded_view.setReadOnly(True)
        self._decoded_view.setStyleSheet(_TEXTEDIT_SS)
        self._output_tabs.addTab(self._decoded_view, "Decoded XML")

        self._edit_view = QTextEdit()
        self._edit_view.setStyleSheet(_TEXTEDIT_SS)
        self._output_tabs.addTab(self._edit_view, "Editable")

        self._analysis_view = QTextEdit()
        self._analysis_view.setReadOnly(True)
        self._analysis_view.setStyleSheet(_TEXTEDIT_SS)
        self._output_tabs.addTab(self._analysis_view, "Analysis")

        main_splitter.addWidget(self._output_tabs)
        main_splitter.setSizes([250, 450])
        root.addWidget(main_splitter, stretch=1)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_request(self, req: HttpRequest) -> None:
        """Auto-decode a SAML assertion found in the request query string or body."""
        candidates: list[str] = []

        # Check query string
        if "?" in req.path:
            qs = req.path.split("?", 1)[1]
            params = urllib.parse.parse_qs(qs, keep_blank_values=True)
            for name in _SAML_PARAM_NAMES:
                if name in params:
                    candidates.extend(params[name])

        # Check body
        if req.body:
            body_str = req.body.decode(errors="replace")
            try:
                body_params = urllib.parse.parse_qs(body_str, keep_blank_values=True)
                for name in _SAML_PARAM_NAMES:
                    if name in body_params:
                        candidates.extend(body_params[name])
            except Exception:
                pass

        if candidates:
            self._input_edit.setPlainText(candidates[0])
            self._decode_saml(candidates[0])

    # ------------------------------------------------------------------
    # Decode / encode
    # ------------------------------------------------------------------

    def _on_decode(self) -> None:
        raw_input = self._input_edit.toPlainText()
        if raw_input.strip():
            self._decode_saml(raw_input)

    def _decode_saml(self, raw_input: str) -> None:
        text = raw_input.strip()
        xml_bytes: Optional[bytes] = None
        for attempt in (text, text.replace(" ", "+"), text + "=="):
            try:
                xml_bytes = base64.b64decode(attempt)
                # Basic sanity check — decoded XML should start with '<'
                stripped = xml_bytes.lstrip()
                if stripped and stripped[0:1] != b"<":
                    xml_bytes = None
                    continue
                break
            except Exception:
                xml_bytes = None

        if xml_bytes is None:
            xml_bytes = text.encode()

        try:
            dom = xml.dom.minidom.parseString(xml_bytes)
            pretty = dom.toprettyxml(indent="  ")
            lines = [
                line for line in pretty.splitlines()
                if line.strip() and not line.startswith("<?xml")
            ]
            pretty = "\n".join(lines)
        except Exception as exc:
            pretty = f"[Parse error: {exc}]\n\n{xml_bytes.decode(errors='replace')}"

        self._decoded_view.setPlainText(pretty)
        self._edit_view.setPlainText(pretty)
        self._analyze_saml(xml_bytes)
        self._current_xml = xml_bytes
        self._output_tabs.setCurrentIndex(0)

    def _encode_and_copy(self) -> None:
        xml_text = self._edit_view.toPlainText().strip()
        if not xml_text:
            return
        encoded = base64.b64encode(xml_text.encode()).decode()
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(encoded)

    def _clear(self) -> None:
        self._input_edit.clear()
        self._decoded_view.clear()
        self._edit_view.clear()
        self._analysis_view.clear()
        self._current_xml = b""

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def _analyze_saml(self, xml_bytes: bytes) -> None:
        lines: list[str] = []
        try:
            dom = xml.dom.minidom.parseString(xml_bytes)

            def get_text(tag: str) -> str:
                els = dom.getElementsByTagNameNS("*", tag)
                if not els:
                    els = dom.getElementsByTagName(tag)
                if els and els[0].firstChild:
                    return els[0].firstChild.nodeValue or ""
                return ""

            lines.append(f"Issuer:     {get_text('Issuer')}")
            lines.append(f"Subject:    {get_text('NameID')}")

            conditions = dom.getElementsByTagNameNS("*", "Conditions")
            if not conditions:
                conditions = dom.getElementsByTagName("Conditions")
            if conditions:
                c = conditions[0]
                lines.append(f"NotBefore:  {c.getAttribute('NotBefore')}")
                lines.append(f"NotAfter:   {c.getAttribute('NotOnOrAfter')}")

            audience_els = dom.getElementsByTagNameNS("*", "AudienceRestriction")
            if not audience_els:
                audience_els = dom.getElementsByTagName("AudienceRestriction")
            if audience_els:
                lines.append(f"Audience:   {get_text('Audience')}")

            sig_els = dom.getElementsByTagNameNS("*", "Signature")
            if not sig_els:
                sig_els = dom.getElementsByTagName("Signature")
            lines.append(f"\nSignature:  {'PRESENT' if sig_els else 'NOT FOUND'}")
            if sig_els:
                sig_method = sig_els[0].getElementsByTagName("SignatureMethod")
                if sig_method:
                    lines.append(f"  Algorithm: {sig_method[0].getAttribute('Algorithm')}")

            attrs = dom.getElementsByTagNameNS("*", "Attribute")
            if not attrs:
                attrs = dom.getElementsByTagName("Attribute")
            if attrs:
                lines.append(f"\nAttributes ({len(attrs)}):")
                for attr in attrs:
                    name = attr.getAttribute("Name") or attr.getAttribute("AttributeName")
                    vals = attr.getElementsByTagName("AttributeValue")
                    if not vals:
                        vals = attr.getElementsByTagNameNS("*", "AttributeValue")
                    val_texts = [
                        v.firstChild.nodeValue if v.firstChild else "" for v in vals
                    ]
                    lines.append(f"  {name}: {', '.join(val_texts)}")

        except Exception as exc:
            lines.append(f"[Analysis error: {exc}]")

        self._analysis_view.setPlainText("\n".join(lines))
