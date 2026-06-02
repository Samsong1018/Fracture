"""
Bambdas — tiny Python snippets that filter the proxy history.

A bambda body is the expression part of `lambda req, resp: <body>`.  The
returned truthy/falsy value decides whether the row is kept.  Snippets are
evaluated in a restricted namespace exposing only `req`, `resp`, and a
small builtins subset (len, str, int, ...).
"""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


_SAFE_BUILTINS = {
    "len": len, "str": str, "int": int, "float": float, "bool": bool,
    "any": any, "all": all, "abs": abs, "min": min, "max": max,
    "sum": sum, "sorted": sorted, "list": list, "tuple": tuple,
    "set": set, "dict": dict, "range": range,
}


def compile_bambda(body: str):
    """Compile a body expression into a callable(req, resp) -> bool.

    Raises SyntaxError if the body doesn't parse.
    """
    code = compile(f"lambda req, resp: ({body})", "<bambda>", "eval")
    fn = eval(code, {"__builtins__": _SAFE_BUILTINS})
    return fn


def evaluate(fn, req, resp) -> bool:
    """Run a compiled bambda against (req, resp); return False on any error."""
    try:
        return bool(fn(req, resp))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
    "QPushButton:hover { background: #45475a; }"
)
_LIST_SS = (
    "QListWidget { background: #181825; border: 1px solid #313244; color: #cdd6f4; }"
    "QListWidget::item:selected { background: #45475a; }"
)
_EDIT_SS = (
    "QPlainTextEdit { background: #181825; border: 1px solid #313244; "
    "color: #cdd6f4; font-family: monospace; font-size: 12px; }"
)


class BambdasDialog(QDialog):
    """Manage a named list of bambda snippets and pick one to apply."""

    def __init__(self, store: dict[str, str], parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Bambdas — filter snippets")
        self.resize(720, 460)
        self._store = store
        self._chosen_body: Optional[str] = None

        root = QHBoxLayout(self)

        left = QVBoxLayout()
        left.addWidget(QLabel("Saved bambdas"))
        self._list = QListWidget()
        self._list.setStyleSheet(_LIST_SS)
        self._list.currentItemChanged.connect(self._on_select)
        left.addWidget(self._list, 1)

        ctrl = QHBoxLayout()
        save_btn = QPushButton("Save")
        save_btn.setStyleSheet(_BTN_SS)
        save_btn.clicked.connect(self._save_current)
        ctrl.addWidget(save_btn)
        del_btn = QPushButton("Delete")
        del_btn.setStyleSheet(_BTN_SS)
        del_btn.clicked.connect(self._delete_current)
        ctrl.addWidget(del_btn)
        left.addLayout(ctrl)
        root.addLayout(left, 1)

        right = QVBoxLayout()
        right.addWidget(QLabel(
            "Bambda body — expression evaluated with locals `req` and `resp`:"
        ))
        self._edit = QPlainTextEdit()
        self._edit.setStyleSheet(_EDIT_SS)
        self._edit.setPlaceholderText(
            'req.method == "POST" and resp and resp.status_code >= 400'
        )
        right.addWidget(self._edit, 1)

        hint = QLabel(
            "Available: req.method, req.host, req.path, req.headers, req.body, "
            "req.is_https; resp.status_code, resp.headers, resp.body."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #a6adc8; font-size: 11px;")
        right.addWidget(hint)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        cancel = QPushButton("Cancel")
        cancel.setStyleSheet(_BTN_SS)
        cancel.clicked.connect(self.reject)
        btn_row.addWidget(cancel)

        clear = QPushButton("Clear filter")
        clear.setStyleSheet(_BTN_SS)
        clear.clicked.connect(self._accept_clear)
        btn_row.addWidget(clear)

        apply_btn = QPushButton("Apply")
        apply_btn.setStyleSheet(_BTN_SS)
        apply_btn.clicked.connect(self._accept_apply)
        btn_row.addWidget(apply_btn)
        right.addLayout(btn_row)

        root.addLayout(right, 2)
        self._refresh_list()

    def _refresh_list(self) -> None:
        self._list.clear()
        for name in sorted(self._store):
            self._list.addItem(QListWidgetItem(name))

    def _on_select(self, item) -> None:
        if item is None:
            return
        self._edit.setPlainText(self._store.get(item.text(), ""))

    def _save_current(self) -> None:
        name, ok = QInputDialog.getText(self, "Save bambda", "Name:")
        if not ok or not name.strip():
            return
        self._store[name.strip()] = self._edit.toPlainText()
        self._refresh_list()

    def _delete_current(self) -> None:
        item = self._list.currentItem()
        if not item:
            return
        self._store.pop(item.text(), None)
        self._refresh_list()

    def _accept_apply(self) -> None:
        body = self._edit.toPlainText().strip()
        if not body:
            self._chosen_body = None
            self.accept()
            return
        try:
            compile_bambda(body)
        except SyntaxError as e:
            QMessageBox.critical(self, "Bambda error", f"Cannot parse:\n{e}")
            return
        self._chosen_body = body
        self.accept()

    def _accept_clear(self) -> None:
        self._chosen_body = None
        self._edit.clear()
        self.accept()

    def chosen_body(self) -> Optional[str]:
        return self._chosen_body
