"""
Session Handling / Macros tab for Fracture.

Record, store and replay sequences of HTTP requests (macros) to maintain
session cookies across tool operations.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from typing import Optional

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
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

from .proxy import HttpRequest

# ---------------------------------------------------------------------------
# Catppuccin Mocha constants
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
_LIST_SS = (
    "QListWidget { background: #181825; border: 1px solid #313244; color: #cdd6f4; }"
    "QListWidget::item:selected { background: #45475a; }"
)

BUFFER = 65536


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class MacroStep:
    raw_request: str
    host: str
    port: int
    is_https: bool
    extracted_cookies: dict[str, str] = field(default_factory=dict)


@dataclass
class Macro:
    name: str
    steps: list[MacroStep] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Raw request sender
# ---------------------------------------------------------------------------

def _send_raw(host: str, port: int, is_https: bool, raw: bytes) -> bytes:
    sock = socket.create_connection((host, port), timeout=10)
    if is_https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    sock.sendall(raw)
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


def _extract_set_cookies(raw_response: bytes) -> dict[str, str]:
    cookies: dict[str, str] = {}
    try:
        text = raw_response.decode(errors="replace")
    except Exception:
        return cookies
    for line in text.splitlines():
        if line.lower().startswith("set-cookie:"):
            cookie_part = line[len("set-cookie:"):].strip()
            name_val = cookie_part.split(";")[0].strip()
            if "=" in name_val:
                name, _, value = name_val.partition("=")
                cookies[name.strip()] = value.strip()
    return cookies


# ---------------------------------------------------------------------------
# Macro runner worker
# ---------------------------------------------------------------------------

class MacroRunWorker(QThread):
    step_done = pyqtSignal(int, str, dict)   # step_index, response_preview, cookies
    finished = pyqtSignal()
    error = pyqtSignal(int, str)             # step_index, message

    def __init__(self, macro: Macro, parent: Optional[QThread] = None) -> None:
        super().__init__(parent)
        self._macro = macro

    def run(self) -> None:
        for idx, step in enumerate(self._macro.steps):
            try:
                raw_resp = _send_raw(
                    step.host,
                    step.port,
                    step.is_https,
                    step.raw_request.encode(errors="replace"),
                )
            except Exception as exc:
                self.error.emit(idx, str(exc))
                continue

            cookies = _extract_set_cookies(raw_resp)
            preview = raw_resp[:500].decode(errors="replace")
            self.step_done.emit(idx, preview, cookies)

        self.finished.emit()


# ---------------------------------------------------------------------------
# MacroTab
# ---------------------------------------------------------------------------

class MacroTab(QWidget):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._macros: list[Macro] = []
        self._active_cookies: dict[str, str] = {}
        self._worker: Optional[MacroRunWorker] = None
        self._setup_ui()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_request(self, req: HttpRequest) -> None:
        """Add req as a new step in the currently selected macro."""
        row = self._macro_list.currentRow()
        if row < 0 or row >= len(self._macros):
            return
        macro = self._macros[row]
        step = MacroStep(
            raw_request=req.raw.decode(errors="replace"),
            host=req.host,
            port=req.port,
            is_https=req.is_https,
        )
        macro.steps.append(step)
        self._refresh_steps(macro)

    def get_active_cookies(self) -> dict[str, str]:
        return dict(self._active_cookies)

    def macro_names(self) -> list[str]:
        return [m.name for m in self._macros]

    def run_macro_sync(self, name: str, wanted: Optional[set[str]] = None
                       ) -> dict[str, str]:
        """Synchronously run a macro by name and return its extracted cookies.

        If *wanted* is provided, only return cookies whose name is in that set.
        Used by the session-rule engine to inject auth before outbound requests.
        """
        macro = next((m for m in self._macros if m.name == name), None)
        if macro is None:
            return {}
        cookies: dict[str, str] = {}
        for step in macro.steps:
            try:
                raw_resp = _send_raw(
                    step.host, step.port, step.is_https,
                    step.raw_request.encode(errors="replace"),
                )
            except Exception:
                continue
            cookies.update(_extract_set_cookies(raw_resp))
        if wanted:
            cookies = {k: v for k, v in cookies.items() if k in wanted}
        return cookies

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        root = QHBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(6)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: macro list
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(4)
        left_layout.addWidget(QLabel("Macros"))

        self._macro_list = QListWidget()
        self._macro_list.setStyleSheet(_LIST_SS)
        self._macro_list.currentRowChanged.connect(self._on_macro_selected)
        left_layout.addWidget(self._macro_list, stretch=1)

        btn_row = QHBoxLayout()
        new_btn = QPushButton("New Macro")
        new_btn.setStyleSheet(_BTN_SS)
        new_btn.clicked.connect(self._new_macro)
        del_btn = QPushButton("Delete Macro")
        del_btn.setStyleSheet(_BTN_SS)
        del_btn.clicked.connect(self._delete_macro)
        run_btn = QPushButton("Run Macro")
        run_btn.setStyleSheet(_BTN_SS)
        run_btn.clicked.connect(self._run_macro)
        btn_row.addWidget(new_btn)
        btn_row.addWidget(del_btn)
        btn_row.addWidget(run_btn)
        left_layout.addLayout(btn_row)

        splitter.addWidget(left)

        # Right: macro detail
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(4)

        name_row = QHBoxLayout()
        name_row.addWidget(QLabel("Name:"))
        self._name_edit = QLineEdit()
        self._name_edit.setStyleSheet(_LINEEDIT_SS)
        self._name_edit.setPlaceholderText("Macro name")
        self._name_edit.textChanged.connect(self._on_name_changed)
        name_row.addWidget(self._name_edit)
        right_layout.addLayout(name_row)

        right_layout.addWidget(QLabel("Steps:"))
        self._steps_list = QListWidget()
        self._steps_list.setStyleSheet(_LIST_SS)
        right_layout.addWidget(self._steps_list, stretch=1)

        step_btns = QHBoxLayout()
        add_step_btn = QPushButton("Add Step from Clipboard")
        add_step_btn.setStyleSheet(_BTN_SS)
        add_step_btn.clicked.connect(self._add_step_from_clipboard)
        remove_step_btn = QPushButton("Remove Step")
        remove_step_btn.setStyleSheet(_BTN_SS)
        remove_step_btn.clicked.connect(self._remove_step)
        up_btn = QPushButton("Move Up")
        up_btn.setStyleSheet(_BTN_SS)
        up_btn.clicked.connect(self._move_step_up)
        down_btn = QPushButton("Move Down")
        down_btn.setStyleSheet(_BTN_SS)
        down_btn.clicked.connect(self._move_step_down)
        step_btns.addWidget(add_step_btn)
        step_btns.addWidget(remove_step_btn)
        step_btns.addWidget(up_btn)
        step_btns.addWidget(down_btn)
        right_layout.addLayout(step_btns)

        right_layout.addWidget(QLabel("Cookie Jar (from last run):"))
        self._cookie_view = QTextEdit()
        self._cookie_view.setReadOnly(True)
        self._cookie_view.setMaximumHeight(80)
        self._cookie_view.setFont(QFont("Monospace", 9))
        self._cookie_view.setStyleSheet(_TEXTEDIT_SS)
        right_layout.addWidget(self._cookie_view)

        right_layout.addWidget(QLabel("Run Log:"))
        self._log_view = QTextEdit()
        self._log_view.setReadOnly(True)
        self._log_view.setFont(QFont("Monospace", 9))
        self._log_view.setStyleSheet(_TEXTEDIT_SS)
        right_layout.addWidget(self._log_view, stretch=1)

        splitter.addWidget(right)
        splitter.setSizes([220, 600])
        root.addWidget(splitter)

    # ------------------------------------------------------------------
    # Macro list actions
    # ------------------------------------------------------------------

    def _new_macro(self) -> None:
        macro = Macro(name=f"Macro {len(self._macros) + 1}")
        self._macros.append(macro)
        item = QListWidgetItem(macro.name)
        self._macro_list.addItem(item)
        self._macro_list.setCurrentRow(len(self._macros) - 1)

    def _delete_macro(self) -> None:
        row = self._macro_list.currentRow()
        if row < 0 or row >= len(self._macros):
            return
        self._macros.pop(row)
        self._macro_list.takeItem(row)
        self._steps_list.clear()
        self._name_edit.clear()

    def _run_macro(self) -> None:
        row = self._macro_list.currentRow()
        if row < 0 or row >= len(self._macros):
            return
        macro = self._macros[row]
        if not macro.steps:
            self._log_view.setPlainText("No steps to run.")
            return

        self._active_cookies.clear()
        self._log_view.setPlainText("Running macro...")
        self._cookie_view.clear()

        self._worker = MacroRunWorker(macro)
        self._worker.step_done.connect(self._on_step_done)
        self._worker.finished.connect(self._on_run_finished)
        self._worker.error.connect(self._on_step_error)
        self._worker.start()

    def _on_macro_selected(self, row: int) -> None:
        if row < 0 or row >= len(self._macros):
            self._steps_list.clear()
            self._name_edit.clear()
            return
        macro = self._macros[row]
        self._name_edit.blockSignals(True)
        self._name_edit.setText(macro.name)
        self._name_edit.blockSignals(False)
        self._refresh_steps(macro)

    def _on_name_changed(self, text: str) -> None:
        row = self._macro_list.currentRow()
        if row < 0 or row >= len(self._macros):
            return
        self._macros[row].name = text
        self._macro_list.item(row).setText(text)

    def _refresh_steps(self, macro: Macro) -> None:
        self._steps_list.clear()
        for i, step in enumerate(macro.steps):
            first_line = step.raw_request.split("\n")[0].strip()
            self._steps_list.addItem(f"Step {i + 1}: {first_line}")

    # ------------------------------------------------------------------
    # Step actions
    # ------------------------------------------------------------------

    def _add_step_from_clipboard(self) -> None:
        row = self._macro_list.currentRow()
        if row < 0 or row >= len(self._macros):
            return
        from PyQt6.QtWidgets import QApplication
        text = QApplication.clipboard().text().strip()
        if not text:
            return
        first_line = text.split("\n")[0].strip()
        parts = first_line.split()
        host = "localhost"
        port = 80
        is_https = False
        for line in text.splitlines():
            if line.lower().startswith("host:"):
                host = line[5:].strip()
                break
        step = MacroStep(raw_request=text, host=host, port=port, is_https=is_https)
        macro = self._macros[row]
        macro.steps.append(step)
        self._refresh_steps(macro)

    def _remove_step(self) -> None:
        row = self._macro_list.currentRow()
        if row < 0 or row >= len(self._macros):
            return
        step_row = self._steps_list.currentRow()
        macro = self._macros[row]
        if step_row < 0 or step_row >= len(macro.steps):
            return
        macro.steps.pop(step_row)
        self._refresh_steps(macro)

    def _move_step_up(self) -> None:
        row = self._macro_list.currentRow()
        if row < 0 or row >= len(self._macros):
            return
        step_row = self._steps_list.currentRow()
        macro = self._macros[row]
        if step_row <= 0 or step_row >= len(macro.steps):
            return
        macro.steps[step_row - 1], macro.steps[step_row] = (
            macro.steps[step_row],
            macro.steps[step_row - 1],
        )
        self._refresh_steps(macro)
        self._steps_list.setCurrentRow(step_row - 1)

    def _move_step_down(self) -> None:
        row = self._macro_list.currentRow()
        if row < 0 or row >= len(self._macros):
            return
        step_row = self._steps_list.currentRow()
        macro = self._macros[row]
        if step_row < 0 or step_row >= len(macro.steps) - 1:
            return
        macro.steps[step_row], macro.steps[step_row + 1] = (
            macro.steps[step_row + 1],
            macro.steps[step_row],
        )
        self._refresh_steps(macro)
        self._steps_list.setCurrentRow(step_row + 1)

    # ------------------------------------------------------------------
    # Worker callbacks
    # ------------------------------------------------------------------

    def _on_step_done(self, idx: int, preview: str, cookies: dict) -> None:
        self._active_cookies.update(cookies)
        current = self._log_view.toPlainText()
        entry = f"\n--- Step {idx + 1} OK ---\n{preview}\n"
        self._log_view.setPlainText(current + entry)
        cookie_text = "\n".join(f"{k}={v}" for k, v in self._active_cookies.items())
        self._cookie_view.setPlainText(cookie_text)

    def _on_step_error(self, idx: int, message: str) -> None:
        current = self._log_view.toPlainText()
        self._log_view.setPlainText(current + f"\n--- Step {idx + 1} ERROR: {message} ---\n")

    def _on_run_finished(self) -> None:
        current = self._log_view.toPlainText()
        self._log_view.setPlainText(current + "\n[Macro run complete]")
