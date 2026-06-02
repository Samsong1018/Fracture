"""
Session handling rule engine.

A rule has:
  - scope:   substring matched against the request host (blank = all hosts)
  - actions: ordered list, applied to outbound requests
      type=set_header     name/value
      type=set_cookie     name/value
      type=run_macro      macro_id (handled externally)
      type=drop           (skip the request entirely)

Tools that send requests can call `apply(req)` which returns either a
modified request dict (host/path/headers/body) or None to drop.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
    "QPushButton:hover { background: #45475a; }"
)
_LINEEDIT_SS = (
    "QLineEdit { background: #181825; border: 1px solid #313244; "
    "padding: 4px; color: #cdd6f4; }"
)
_LIST_SS = (
    "QListWidget { background: #181825; border: 1px solid #313244; color: #cdd6f4; }"
    "QListWidget::item:selected { background: #45475a; }"
)
_TABLE_SS = (
    "QTableWidget { background: #181825; gridline-color: #313244; color: #cdd6f4; }"
    "QHeaderView::section { background: #313244; color: #cdd6f4; border: 0; padding: 4px; }"
)


@dataclass
class SessionAction:
    type: str           # "set_header" | "set_cookie" | "drop"
    name: str = ""
    value: str = ""


@dataclass
class SessionRule:
    name: str
    scope: str
    enabled: bool = True
    apply_to: set = field(default_factory=lambda: {"Repeater", "Intruder", "Scanner"})
    actions: list = field(default_factory=list)


class SessionRuleEngine:
    """Stores rules and applies them to outbound requests."""

    def __init__(self) -> None:
        self.rules: list[SessionRule] = []
        # Callable[str, set] -> dict[str, str]   (macro_name, extracted_cookie_names)
        # Configured by the GUI to expose MacroTab cookie extraction.
        self._macro_runner = None

    def set_macro_runner(self, runner) -> None:
        """Register a callable that runs a macro by name and returns its cookies."""
        self._macro_runner = runner

    def add(self, rule: SessionRule) -> None:
        self.rules.append(rule)

    def remove(self, idx: int) -> None:
        if 0 <= idx < len(self.rules):
            self.rules.pop(idx)

    def apply(self, host: str, headers: dict[str, str], tool: str = "Repeater"
              ) -> Optional[dict[str, str]]:
        """Return mutated headers, or None if any rule says drop."""
        for rule in self.rules:
            if not rule.enabled:
                continue
            if rule.scope and rule.scope.lower() not in host.lower():
                continue
            if tool not in rule.apply_to:
                continue
            for action in rule.actions:
                if action.type == "drop":
                    return None
                if action.type == "set_header":
                    headers = {
                        k: v for k, v in headers.items()
                        if k.lower() != action.name.lower()
                    }
                    headers[action.name] = action.value
                elif action.type == "set_cookie":
                    existing = headers.get("Cookie", "")
                    parts = [p.strip() for p in existing.split(";") if p.strip()]
                    parts = [p for p in parts if not p.startswith(f"{action.name}=")]
                    parts.append(f"{action.name}={action.value}")
                    headers["Cookie"] = "; ".join(parts)
                elif action.type == "run_macro":
                    # action.name = macro name, action.value = optional comma-sep
                    # list of cookie names to inject (blank = all)
                    if self._macro_runner is None:
                        continue
                    wanted = (
                        {c.strip() for c in action.value.split(",") if c.strip()}
                        if action.value else set()
                    )
                    try:
                        cookies = self._macro_runner(action.name, wanted) or {}
                    except Exception:
                        cookies = {}
                    if cookies:
                        existing = headers.get("Cookie", "")
                        parts = [p.strip() for p in existing.split(";") if p.strip()]
                        kept = []
                        for p in parts:
                            name = p.split("=", 1)[0]
                            if name not in cookies:
                                kept.append(p)
                        for k, v in cookies.items():
                            kept.append(f"{k}={v}")
                        headers["Cookie"] = "; ".join(kept)
        return headers


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

class SessionRulesTab(QWidget):
    """Editor for the session rule list."""

    def __init__(self, engine: SessionRuleEngine,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._engine = engine

        root = QHBoxLayout(self)

        # Left: rules list
        left = QVBoxLayout()
        left.addWidget(QLabel("Rules"))
        self._rules_list = QListWidget()
        self._rules_list.setStyleSheet(_LIST_SS)
        self._rules_list.currentRowChanged.connect(self._on_rule_selected)
        left.addWidget(self._rules_list, 1)

        btns = QHBoxLayout()
        add_btn = QPushButton("Add Rule")
        add_btn.setStyleSheet(_BTN_SS)
        add_btn.clicked.connect(self._add_rule)
        btns.addWidget(add_btn)
        del_btn = QPushButton("Delete")
        del_btn.setStyleSheet(_BTN_SS)
        del_btn.clicked.connect(self._delete_rule)
        btns.addWidget(del_btn)
        left.addLayout(btns)
        root.addLayout(left, 1)

        # Right: rule editor
        right = QVBoxLayout()
        form = QFormLayout()
        self._scope_edit = QLineEdit()
        self._scope_edit.setStyleSheet(_LINEEDIT_SS)
        self._scope_edit.setPlaceholderText("example.com  (blank = all hosts)")
        self._scope_edit.editingFinished.connect(self._sync_current_rule)
        form.addRow("Scope:", self._scope_edit)

        self._enabled_check = QCheckBox("Enabled")
        self._enabled_check.setStyleSheet("color: #cdd6f4;")
        self._enabled_check.stateChanged.connect(self._sync_current_rule)
        form.addRow(self._enabled_check)

        tools_row = QHBoxLayout()
        self._tool_checks: dict[str, QCheckBox] = {}
        for tool in ("Repeater", "Intruder", "Scanner"):
            cb = QCheckBox(tool)
            cb.setChecked(True)
            cb.setStyleSheet("color: #cdd6f4;")
            cb.stateChanged.connect(self._sync_current_rule)
            self._tool_checks[tool] = cb
            tools_row.addWidget(cb)
        tools_row.addStretch()
        form.addRow("Apply to:", _wrap(tools_row))
        right.addLayout(form)

        right.addWidget(QLabel("Actions (top-to-bottom):"))
        self._actions_table = QTableWidget(0, 3)
        self._actions_table.setHorizontalHeaderLabels(["Type", "Name", "Value"])
        self._actions_table.setStyleSheet(_TABLE_SS)
        self._actions_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._actions_table.cellChanged.connect(self._on_action_edited)
        right.addWidget(self._actions_table, 1)

        act_btns = QHBoxLayout()
        for label, atype in (
            ("+ Set Header", "set_header"),
            ("+ Set Cookie", "set_cookie"),
            ("+ Run Macro", "run_macro"),
            ("+ Drop", "drop"),
        ):
            b = QPushButton(label)
            b.setStyleSheet(_BTN_SS)
            b.clicked.connect(lambda _, t=atype: self._add_action(t))
            act_btns.addWidget(b)
        remove_btn = QPushButton("Remove selected")
        remove_btn.setStyleSheet(_BTN_SS)
        remove_btn.clicked.connect(self._remove_action)
        act_btns.addWidget(remove_btn)
        act_btns.addStretch()
        right.addLayout(act_btns)

        root.addLayout(right, 2)

    # ------------------------------------------------------------------
    def _current_rule(self) -> Optional[SessionRule]:
        idx = self._rules_list.currentRow()
        if 0 <= idx < len(self._engine.rules):
            return self._engine.rules[idx]
        return None

    def _refresh_list(self) -> None:
        self._rules_list.clear()
        for r in self._engine.rules:
            self._rules_list.addItem(
                f"{'●' if r.enabled else '○'} {r.name}  ({r.scope or 'all hosts'})"
            )

    def _add_rule(self) -> None:
        name, ok = QInputDialog.getText(self, "Add Rule", "Rule name:")
        if not ok or not name.strip():
            return
        self._engine.add(SessionRule(name=name.strip(), scope=""))
        self._refresh_list()
        self._rules_list.setCurrentRow(len(self._engine.rules) - 1)

    def _delete_rule(self) -> None:
        idx = self._rules_list.currentRow()
        if idx < 0:
            return
        self._engine.remove(idx)
        self._refresh_list()

    def _on_rule_selected(self, idx: int) -> None:
        rule = self._current_rule()
        if rule is None:
            self._scope_edit.clear()
            self._enabled_check.setChecked(False)
            self._actions_table.setRowCount(0)
            return
        # Block signals to avoid feedback loops while filling
        for w in (self._scope_edit, self._enabled_check, *self._tool_checks.values()):
            w.blockSignals(True)
        self._scope_edit.setText(rule.scope)
        self._enabled_check.setChecked(rule.enabled)
        for name, cb in self._tool_checks.items():
            cb.setChecked(name in rule.apply_to)
        for w in (self._scope_edit, self._enabled_check, *self._tool_checks.values()):
            w.blockSignals(False)
        self._reload_actions(rule)

    def _sync_current_rule(self) -> None:
        rule = self._current_rule()
        if rule is None:
            return
        rule.scope = self._scope_edit.text().strip()
        rule.enabled = self._enabled_check.isChecked()
        rule.apply_to = {n for n, cb in self._tool_checks.items() if cb.isChecked()}
        self._refresh_list_label()

    def _refresh_list_label(self) -> None:
        idx = self._rules_list.currentRow()
        rule = self._current_rule()
        if rule is None or idx < 0:
            return
        self._rules_list.item(idx).setText(
            f"{'●' if rule.enabled else '○'} {rule.name}  ({rule.scope or 'all hosts'})"
        )

    # ------------------------------------------------------------------
    def _reload_actions(self, rule: SessionRule) -> None:
        self._actions_table.blockSignals(True)
        self._actions_table.setRowCount(0)
        for action in rule.actions:
            row = self._actions_table.rowCount()
            self._actions_table.insertRow(row)
            self._actions_table.setItem(row, 0, QTableWidgetItem(action.type))
            self._actions_table.setItem(row, 1, QTableWidgetItem(action.name))
            self._actions_table.setItem(row, 2, QTableWidgetItem(action.value))
        self._actions_table.blockSignals(False)

    def _add_action(self, atype: str) -> None:
        rule = self._current_rule()
        if rule is None:
            return
        rule.actions.append(SessionAction(type=atype))
        self._reload_actions(rule)

    def _remove_action(self) -> None:
        rule = self._current_rule()
        if rule is None:
            return
        row = self._actions_table.currentRow()
        if 0 <= row < len(rule.actions):
            rule.actions.pop(row)
            self._reload_actions(rule)

    def _on_action_edited(self, row: int, col: int) -> None:
        rule = self._current_rule()
        if rule is None or row >= len(rule.actions):
            return
        text = self._actions_table.item(row, col).text()
        action = rule.actions[row]
        if col == 0:
            action.type = text
        elif col == 1:
            action.name = text
        elif col == 2:
            action.value = text


def _wrap(layout) -> QWidget:
    w = QWidget()
    w.setLayout(layout)
    return w
