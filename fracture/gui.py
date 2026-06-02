"""
Fracture main GUI.
"""

import sys
import json
import os
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QAction, QColor, QFont, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMenuBar,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .proxy import HttpRequest, HttpResponse, ProxyServer
from .repeater import RepeaterTab
from .intruder import IntruderTab
from .decoder import DecoderTab
from .comparer import ComparerTab
from .sitemap import SiteMapTab
from .project import ProjectManager, RecentProjects, export_csv, export_burp_xml
from .match_replace import MatchReplaceManager, MRRule, MRTarget
from .scanner_passive import PassiveScannerTab
from .scanner_active import ActiveScannerTab
from .sequencer import SequencerTab
from .ws_tab import WebSocketTab
from .collaborator import CollaboratorTab
from .plugins import PluginManagerTab
from .dashboard import DashboardTab
from .logger import TrafficLogger
from .inspector import InspectorWidget
from .spider import SpiderTab
from .macros import MacroTab
from .content_discovery import ContentDiscoveryTab
from .organizer import OrganizerTab
from .graphql import GraphQLTab
from .saml import SAMLTab
from .param_miner import ParamMinerTab
from .curl_import import CurlImportDialog
from .engagement import (
    CertViewerDialog,
    FindResultsDialog,
    find_comments,
    find_emails,
    find_references,
    find_scripts,
)
from .jwt_editor import JWTEditorTab
from .logger_plus import LoggerTab
from .authz import AuthzTab
from .browser import BrowserTab, configure_chromium_flags
from .session_rules import SessionRuleEngine, SessionRulesTab
from .turbo_intruder import TurboIntruderTab
from .ws_intruder import WebSocketIntruderTab
from .notes import NotesTab
from .live_tasks import LiveTasksTab, TaskSource
from .cookie_jar import CookieJar, CookieJarTab
from .findings import FindingsTab
from .flask_tools import FlaskToolsTab
from .revshell import RevShellTab
from .hash_id import HashIdTab
from .payload_lib import PayloadLibTab
from .dns_recon import DnsReconTab
from .sec_headers import SecHeadersTab
from .mtls import ClientCertStore, ClientCertDialog
from .preauth import CredentialStore, PreAuthDialog


class HistorySignal(QThread):
    new_entry = pyqtSignal(object)

    def __init__(self, proxy: ProxyServer):
        super().__init__()
        self.proxy = proxy

    def run(self):
        self.proxy.add_history_callback(self.new_entry.emit)


_ANNOTATION_COLORS = {
    "Red":    "#f38ba8",
    "Orange": "#fab387",
    "Green":  "#a6e3a1",
    "Blue":   "#89b4fa",
}

_COLOR_DOTS = {
    "Red":    "🔴",
    "Orange": "🟠",
    "Green":  "🟢",
    "Blue":   "🔵",
}

_BTN_STYLE = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 4px 10px; border-radius: 4px; } "
    "QPushButton:hover { background: #45475a; }"
)

_BTN_ON_STYLE = (
    "QPushButton { background: #c62828; border: 1px solid #45475a; "
    "padding: 4px 10px; border-radius: 4px; color: white; } "
    "QPushButton:hover { background: #e53935; }"
)


class _ScopeDialog(QDialog):
    """Simple dialog for editing proxy scope patterns."""

    def __init__(self, proxy: ProxyServer, parent=None):
        super().__init__(parent)
        self.proxy = proxy
        self.setWindowTitle("Scope Manager")
        self.setMinimumWidth(420)
        self.setStyleSheet(
            "QDialog { background: #1e1e2e; color: #cdd6f4; } "
            "QListWidget { background: #181825; border: 1px solid #313244; } "
            "QListWidget::item:selected { background: #45475a; } "
            "QLineEdit { background: #181825; border: 1px solid #313244; "
            "padding: 4px; color: #cdd6f4; } " + _BTN_STYLE
        )
        layout = QVBoxLayout(self)

        self.pattern_list = QListWidget()
        self._reload_patterns()
        layout.addWidget(QLabel("Scope patterns (empty = all in scope):"))
        layout.addWidget(self.pattern_list)

        add_row = QHBoxLayout()
        self.pattern_input = QLineEdit()
        self.pattern_input.setPlaceholderText("e.g. example.com or *.example.com")
        add_btn = QPushButton("Add")
        add_btn.clicked.connect(self._add_pattern)
        self.pattern_input.returnPressed.connect(self._add_pattern)
        add_row.addWidget(self.pattern_input)
        add_row.addWidget(add_btn)
        layout.addLayout(add_row)

        remove_btn = QPushButton("Remove Selected")
        remove_btn.clicked.connect(self._remove_pattern)
        layout.addWidget(remove_btn)

        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(self.accept)
        layout.addWidget(ok_btn)

    def _reload_patterns(self):
        self.pattern_list.clear()
        for p in self.proxy.scope.patterns():
            self.pattern_list.addItem(p)

    def _add_pattern(self):
        text = self.pattern_input.text().strip()
        if text:
            self.proxy.scope.add(text)
            self.pattern_input.clear()
            self._reload_patterns()

    def _remove_pattern(self):
        item = self.pattern_list.currentItem()
        if item:
            self.proxy.scope.remove(item.text())
            self._reload_patterns()


class _AddMRRuleDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Match & Replace Rule")
        self.setMinimumWidth(460)
        self.setStyleSheet(
            "QDialog { background: #1e1e2e; color: #cdd6f4; } "
            "QLineEdit, QComboBox { background: #181825; border: 1px solid #313244; padding: 4px; color: #cdd6f4; } "
            "QCheckBox { spacing: 6px; } " + _BTN_STYLE
        )
        form = QFormLayout(self)
        self.target_combo = QComboBox()
        for t in MRTarget:
            self.target_combo.addItem(t.value, t)
        self.pattern_edit = QLineEdit()
        self.pattern_edit.setPlaceholderText("regex or literal pattern")
        self.replacement_edit = QLineEdit()
        self.replacement_edit.setPlaceholderText("replacement (supports \\1 backrefs)")
        self.comment_edit = QLineEdit()
        self.regex_check = QCheckBox("Use regex")
        self.regex_check.setChecked(True)
        form.addRow("Target:", self.target_combo)
        form.addRow("Pattern:", self.pattern_edit)
        form.addRow("Replacement:", self.replacement_edit)
        form.addRow("Comment:", self.comment_edit)
        form.addRow("", self.regex_check)
        btns = QHBoxLayout()
        ok = QPushButton("Add")
        ok.clicked.connect(self.accept)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        btns.addStretch()
        btns.addWidget(ok)
        btns.addWidget(cancel)
        form.addRow(btns)

    def get_rule_params(self):
        return {
            "target": self.target_combo.currentData(),
            "pattern": self.pattern_edit.text(),
            "replacement": self.replacement_edit.text(),
            "is_regex": self.regex_check.isChecked(),
            "comment": self.comment_edit.text(),
        }


class _MatchReplaceDialog(QDialog):
    def __init__(self, proxy: ProxyServer, parent=None):
        super().__init__(parent)
        self.proxy = proxy
        self.setWindowTitle("Match & Replace Rules")
        self.setMinimumSize(600, 400)
        self.setStyleSheet(
            "QDialog { background: #1e1e2e; color: #cdd6f4; } "
            "QListWidget { background: #181825; border: 1px solid #313244; font-family: monospace; } "
            "QListWidget::item:selected { background: #45475a; } " + _BTN_STYLE
        )
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Rules are applied in order to all proxied traffic:"))
        self.rule_list = QListWidget()
        layout.addWidget(self.rule_list)
        btns = QHBoxLayout()
        add_btn = QPushButton("Add Rule")
        add_btn.clicked.connect(self._add_rule)
        toggle_btn = QPushButton("Toggle Enable")
        toggle_btn.clicked.connect(self._toggle_rule)
        remove_btn = QPushButton("Remove")
        remove_btn.clicked.connect(self._remove_rule)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        btns.addWidget(add_btn)
        btns.addWidget(toggle_btn)
        btns.addWidget(remove_btn)
        btns.addStretch()
        btns.addWidget(close_btn)
        layout.addLayout(btns)
        self._reload()

    def _reload(self):
        self.rule_list.clear()
        for rule in self.proxy.match_replace.rules():
            state = "✓" if rule.enabled else "✗"
            label = f"[{state}] {rule.target.value}  {rule.pattern!r} → {rule.replacement!r}"
            if rule.comment:
                label += f"  ({rule.comment})"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, rule.id)
            if not rule.enabled:
                item.setForeground(QColor("#585b70"))
            self.rule_list.addItem(item)

    def _add_rule(self):
        dlg = _AddMRRuleDialog(self)
        if dlg.exec():
            p = dlg.get_rule_params()
            self.proxy.match_replace.add_rule(
                p["target"], p["pattern"], p["replacement"],
                p["is_regex"], p["comment"]
            )
            self._reload()

    def _toggle_rule(self):
        item = self.rule_list.currentItem()
        if item:
            self.proxy.match_replace.toggle_rule(item.data(Qt.ItemDataRole.UserRole))
            self._reload()

    def _remove_rule(self):
        item = self.rule_list.currentItem()
        if item:
            self.proxy.match_replace.remove_rule(item.data(Qt.ItemDataRole.UserRole))
            self._reload()


class _SettingsDialog(QDialog):
    """Settings dialog: upstream proxy, listeners, TLS passthrough, logger."""

    def __init__(self, proxy: ProxyServer, logger_holder: dict,
                 collaborator_tab=None, parent=None):
        super().__init__(parent)
        self.proxy = proxy
        self.logger_holder = logger_holder
        self.collaborator_tab = collaborator_tab
        self.setWindowTitle("Fracture Settings")
        self.setMinimumSize(540, 420)
        self.setStyleSheet(
            "QDialog { background: #1e1e2e; color: #cdd6f4; } "
            "QTabWidget::pane { border: 1px solid #313244; } "
            "QTabBar::tab { background: #313244; padding: 5px 14px; } "
            "QTabBar::tab:selected { background: #45475a; } "
            "QLineEdit, QComboBox { background: #181825; border: 1px solid #313244; padding: 4px; color: #cdd6f4; } "
            "QListWidget { background: #181825; border: 1px solid #313244; } "
            "QListWidget::item:selected { background: #45475a; } " + _BTN_STYLE
        )
        tabs = QTabWidget()
        tabs.addTab(self._build_upstream_tab(), "Upstream Proxy")
        tabs.addTab(self._build_listeners_tab(), "Listeners")
        tabs.addTab(self._build_tls_tab(), "TLS Passthrough")
        tabs.addTab(self._build_logger_tab(), "Logger")
        if self.collaborator_tab is not None:
            tabs.addTab(self._build_collaborator_tab(), "Collaborator")
        main = QVBoxLayout(self)
        main.addWidget(tabs)
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        main.addWidget(close)

    def _build_upstream_tab(self):
        w = QWidget()
        form = QFormLayout(w)
        self._up_host = QLineEdit(self.proxy.upstream_host or "")
        self._up_host.setPlaceholderText("e.g. 127.0.0.1")
        self._up_port = QLineEdit(str(self.proxy.upstream_port or ""))
        self._up_port.setPlaceholderText("e.g. 8118")
        self._up_type = QComboBox()
        self._up_type.addItems(["http", "socks5"])
        if self.proxy.upstream_type == "socks5":
            self._up_type.setCurrentIndex(1)
        form.addRow("Host:", self._up_host)
        form.addRow("Port:", self._up_port)
        form.addRow("Type:", self._up_type)
        btns = QHBoxLayout()
        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self._apply_upstream)
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self._clear_upstream)
        btns.addWidget(apply_btn)
        btns.addWidget(clear_btn)
        btns.addStretch()
        form.addRow(btns)
        return w

    def _apply_upstream(self):
        host = self._up_host.text().strip()
        port_s = self._up_port.text().strip()
        if not host or not port_s:
            return
        try:
            port = int(port_s)
        except ValueError:
            return
        self.proxy.set_upstream_proxy(host, port, self._up_type.currentText())

    def _clear_upstream(self):
        self.proxy.clear_upstream_proxy()
        self._up_host.clear()
        self._up_port.clear()

    def _build_listeners_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        self._listener_list = QListWidget()
        self._refresh_listeners()
        layout.addWidget(self._listener_list)
        row = QHBoxLayout()
        host_edit = QLineEdit()
        host_edit.setPlaceholderText("host (e.g. 127.0.0.1)")
        port_edit = QLineEdit()
        port_edit.setPlaceholderText("port")
        port_edit.setFixedWidth(70)
        add_btn = QPushButton("Add")

        def _add():
            h = host_edit.text().strip() or "127.0.0.1"
            try:
                p = int(port_edit.text().strip())
            except ValueError:
                return
            self.proxy.add_listener(h, p)
            self._refresh_listeners()
        add_btn.clicked.connect(_add)
        trans_btn = QPushButton("Add Transparent")

        def _add_trans():
            h = host_edit.text().strip() or "127.0.0.1"
            try:
                p = int(port_edit.text().strip())
            except ValueError:
                return
            self.proxy.add_transparent_listener(h, p)
            self._refresh_listeners()
        trans_btn.clicked.connect(_add_trans)
        remove_btn = QPushButton("Remove")

        def _remove():
            item = self._listener_list.currentItem()
            if item:
                text = item.text()
                parts = text.replace("transparent", "").strip().split(":")
                if len(parts) == 2:
                    try:
                        self.proxy.remove_listener(parts[0].strip(), int(parts[1].strip()))
                        self._refresh_listeners()
                    except Exception:
                        pass
        remove_btn.clicked.connect(_remove)
        row.addWidget(host_edit)
        row.addWidget(port_edit)
        row.addWidget(add_btn)
        row.addWidget(trans_btn)
        row.addWidget(remove_btn)
        layout.addLayout(row)
        return w

    def _refresh_listeners(self):
        self._listener_list.clear()
        for entry in self.proxy.list_listeners():
            flag = " [transparent]" if entry.get("transparent") else ""
            self._listener_list.addItem(f"{entry['host']}:{entry['port']}{flag}")

    def _build_tls_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        self._tls_list = QListWidget()
        for h in sorted(self.proxy.tls_passthrough_hosts):
            self._tls_list.addItem(h)
        layout.addWidget(self._tls_list)
        row = QHBoxLayout()
        host_edit = QLineEdit()
        host_edit.setPlaceholderText("hostname to passthrough")
        add_btn = QPushButton("Add")

        def _add():
            h = host_edit.text().strip()
            if h:
                self.proxy.add_tls_passthrough(h)
                self._tls_list.addItem(h)
                host_edit.clear()
        add_btn.clicked.connect(_add)
        host_edit.returnPressed.connect(_add)
        remove_btn = QPushButton("Remove")

        def _remove():
            item = self._tls_list.currentItem()
            if item:
                self.proxy.remove_tls_passthrough(item.text())
                self._tls_list.takeItem(self._tls_list.row(item))
        remove_btn.clicked.connect(_remove)
        row.addWidget(host_edit)
        row.addWidget(add_btn)
        row.addWidget(remove_btn)
        layout.addLayout(row)
        return w

    def _build_logger_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        self._log_enable = QCheckBox("Enable traffic logging")
        self._log_enable.setChecked(self.logger_holder.get("logger") is not None)
        layout.addWidget(self._log_enable)
        path_row = QHBoxLayout()
        self._log_path = QLineEdit(
            self.logger_holder.get("logger").path
            if self.logger_holder.get("logger")
            else ""
        )
        self._log_path.setPlaceholderText("Path to .jsonl file")
        browse_btn = QPushButton("Browse")

        def _browse():
            p, _ = QFileDialog.getSaveFileName(self, "Log File", "", "JSONL Files (*.jsonl)")
            if p:
                self._log_path.setText(p)
        browse_btn.clicked.connect(_browse)
        path_row.addWidget(self._log_path)
        path_row.addWidget(browse_btn)
        layout.addLayout(path_row)
        apply_btn = QPushButton("Apply")

        def _apply():
            enabled = self._log_enable.isChecked()
            path = self._log_path.text().strip()
            existing = self.logger_holder.get("logger")
            if enabled and path:
                if existing:
                    existing.close()
                self.logger_holder["logger"] = TrafficLogger(path)
            elif not enabled and existing:
                existing.close()
                self.logger_holder["logger"] = None
        apply_btn.clicked.connect(_apply)
        layout.addWidget(apply_btn)
        layout.addStretch()
        return w

    def _build_collaborator_tab(self):
        from .tunnel import detect_tools

        w = QWidget()
        form = QFormLayout(w)
        srv = self.collaborator_tab._server
        self._pub_host = QLineEdit(srv.get_public_host())
        self._pub_host.setPlaceholderText("e.g. abc123.ngrok.io  (blank = localhost only)")
        self._pub_scheme = QComboBox()
        self._pub_scheme.addItems(["https", "http"])
        if getattr(srv, "_public_scheme", "https") == "http":
            self._pub_scheme.setCurrentIndex(1)

        form.addRow("Public host:", self._pub_host)
        form.addRow("Scheme:", self._pub_scheme)

        hint = QLabel(
            "Set a public host manually, or launch a local tunnel below.\n"
            "Generated payload URLs use the public host so internet-bound\n"
            "targets can reach the local listener."
        )
        hint.setStyleSheet("color: #a6adc8; font-size: 11px;")
        form.addRow(hint)

        btn_row = QHBoxLayout()
        apply_btn = QPushButton("Apply")
        clear_btn = QPushButton("Clear (use localhost)")
        btn_row.addWidget(apply_btn)
        btn_row.addWidget(clear_btn)
        form.addRow(btn_row)

        # --- Tunnel launcher ---
        tools = detect_tools()
        form.addRow(QLabel("─" * 40))

        tunnel_row = QHBoxLayout()
        ngrok_btn = QPushButton("Start ngrok tunnel")
        ngrok_btn.setEnabled(bool(tools.get("ngrok")))
        if not tools.get("ngrok"):
            ngrok_btn.setToolTip("ngrok binary not found on PATH")
        cf_btn = QPushButton("Start cloudflared tunnel")
        cf_btn.setEnabled(bool(tools.get("cloudflared")))
        if not tools.get("cloudflared"):
            cf_btn.setToolTip("cloudflared binary not found on PATH")
        stop_btn = QPushButton("Stop tunnel")
        stop_btn.setEnabled(False)
        tunnel_row.addWidget(ngrok_btn)
        tunnel_row.addWidget(cf_btn)
        tunnel_row.addWidget(stop_btn)
        form.addRow(tunnel_row)

        self._tunnel_status = QLabel("Tunnel: not running")
        self._tunnel_status.setStyleSheet("color: #a6adc8;")
        form.addRow(self._tunnel_status)

        col_port = getattr(srv, "_port", 0)

        def _on_public_host(host: str, scheme: str) -> None:
            # Called from the tunnel reader thread; marshall via timer
            self._pub_host.setText(host)
            self._pub_scheme.setCurrentText(scheme)
            srv.set_public_host(host, scheme)
            self._tunnel_status.setText(f"Tunnel: {scheme}://{host}")
            stop_btn.setEnabled(True)

        def _start_ngrok():
            if col_port == 0:
                self._tunnel_status.setText("Tunnel: Collaborator server not running")
                return
            ok, msg = self.collaborator_tab.tunnel.start_ngrok(col_port, _on_public_host)
            self._tunnel_status.setText(f"Tunnel: {msg}")
            if ok:
                stop_btn.setEnabled(True)

        def _start_cf():
            if col_port == 0:
                self._tunnel_status.setText("Tunnel: Collaborator server not running")
                return
            ok, msg = self.collaborator_tab.tunnel.start_cloudflared(col_port, _on_public_host)
            self._tunnel_status.setText(f"Tunnel: {msg}")
            if ok:
                stop_btn.setEnabled(True)

        def _stop_tunnel():
            self.collaborator_tab.tunnel.stop()
            self._tunnel_status.setText("Tunnel: stopped")
            stop_btn.setEnabled(False)

        ngrok_btn.clicked.connect(_start_ngrok)
        cf_btn.clicked.connect(_start_cf)
        stop_btn.clicked.connect(_stop_tunnel)

        def _apply():
            srv.set_public_host(
                self._pub_host.text().strip(),
                self._pub_scheme.currentText(),
            )

        def _clear():
            self._pub_host.clear()
            srv.set_public_host("", self._pub_scheme.currentText())

        apply_btn.clicked.connect(_apply)
        clear_btn.clicked.connect(_clear)
        return w


class _GlobalSearchDialog(QDialog):
    """Global search across proxy history and scanner findings."""

    def __init__(self, proxy_tab, scanner_tab, parent=None):
        super().__init__(parent)
        self._proxy_tab = proxy_tab
        self._scanner_tab = scanner_tab
        self.setWindowTitle("Global Search")
        self.setMinimumSize(600, 400)
        self.setStyleSheet(
            "QDialog { background: #1e1e2e; color: #cdd6f4; } "
            "QLineEdit { background: #181825; border: 1px solid #313244; padding: 6px; color: #cdd6f4; } "
            "QTreeWidget { background: #181825; border: 1px solid #313244; color: #cdd6f4; } "
            "QTreeWidget::item:selected { background: #45475a; } " + _BTN_STYLE
        )
        layout = QVBoxLayout(self)
        self._search = QLineEdit()
        self._search.setPlaceholderText("Search across all tools…")
        self._search.textChanged.connect(self._do_search)
        layout.addWidget(self._search)
        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.itemDoubleClicked.connect(self._on_activate)
        layout.addWidget(self._tree)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)

    def _do_search(self, text: str) -> None:
        self._tree.clear()
        if len(text) < 2:
            return
        text_lower = text.lower()

        # Proxy history
        proxy_matches = []
        for i, (req, resp) in enumerate(self._proxy_tab._entries):
            code = getattr(resp, "status_code", "---") if resp else "---"
            label = f"[{code}] {req.method} {req.host}{req.path}"
            if text_lower in label.lower():
                proxy_matches.append((i, label))
        if proxy_matches:
            parent = QTreeWidgetItem(self._tree, ["Proxy History"])
            parent.setExpanded(True)
            for idx, label in proxy_matches[:50]:
                child = QTreeWidgetItem(parent, [label])
                child.setData(0, Qt.ItemDataRole.UserRole, ("proxy", idx))

        # Scanner findings
        scanner_matches = []
        for i, finding in enumerate(self._scanner_tab._findings):
            combined = f"{finding.title} {finding.detail} {finding.host}{finding.path}"
            if text_lower in combined.lower():
                scanner_matches.append((i, f"[{finding.severity}] {finding.title} — {finding.host}"))
        if scanner_matches:
            parent = QTreeWidgetItem(self._tree, ["Scanner Findings"])
            parent.setExpanded(True)
            for idx, label in scanner_matches[:50]:
                child = QTreeWidgetItem(parent, [label])
                child.setData(0, Qt.ItemDataRole.UserRole, ("scanner", idx))

    def _on_activate(self, item: QTreeWidgetItem, _col: int) -> None:
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data:
            return
        kind, idx = data
        self.accept()
        if self.parent():
            main = self.parent()
            if kind == "proxy":
                main._tabs.setCurrentWidget(main.proxy_tab)
                main.proxy_tab.history_list.setCurrentRow(idx)
            elif kind == "scanner":
                main._tabs.setCurrentWidget(main._scanner_wrapper)
                main.passive_scanner_tab._list.setCurrentRow(idx)


class ProxyTab(QWidget):
    send_to_repeater = pyqtSignal(object)
    send_to_intruder = pyqtSignal(object)
    send_to_comparer_left = pyqtSignal(object)
    send_to_comparer_right = pyqtSignal(object)
    send_to_scanner = pyqtSignal(object)
    send_to_sequencer = pyqtSignal(object)
    send_to_organizer = pyqtSignal(object)
    send_to_param_miner = pyqtSignal(object)
    render_in_browser = pyqtSignal(object, object)  # req, resp
    generate_csrf_poc = pyqtSignal(object)
    generate_clickjacking_poc = pyqtSignal(object)

    def __init__(self, proxy: ProxyServer):
        super().__init__()
        self.proxy = proxy
        self._entries: list[tuple[HttpRequest, HttpResponse | None]] = []
        # annotations keyed by request id: {"color": str, "note": str}
        self._annotations: dict[int, dict] = {}
        self._setup_ui()
        self._setup_signals()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # ── toolbar ────────────────────────────────────────────────────
        toolbar = QHBoxLayout()

        self.intercept_btn = QPushButton("Intercept: OFF")
        self.intercept_btn.setCheckable(True)
        self.intercept_btn.setFixedWidth(140)
        self.intercept_btn.clicked.connect(self._toggle_intercept)

        self.forward_btn = QPushButton("Forward")
        self.forward_btn.setEnabled(False)
        self.forward_btn.setFixedWidth(100)
        self.forward_btn.clicked.connect(self._forward_intercepted)

        self.resp_intercept_btn = QPushButton("Resp Intercept: OFF")
        self.resp_intercept_btn.setCheckable(True)
        self.resp_intercept_btn.setFixedWidth(160)
        self.resp_intercept_btn.clicked.connect(self._toggle_resp_intercept)

        self.forward_resp_btn = QPushButton("Forward Response")
        self.forward_resp_btn.setEnabled(False)
        self.forward_resp_btn.setFixedWidth(140)
        self.forward_resp_btn.clicked.connect(self._forward_resp_intercepted)

        self.drop_btn = QPushButton("Drop Req")
        self.drop_btn.setEnabled(False)
        self.drop_btn.setFixedWidth(90)
        self.drop_btn.clicked.connect(self._drop_intercepted)

        self.drop_resp_btn = QPushButton("Drop Resp")
        self.drop_resp_btn.setEnabled(False)
        self.drop_resp_btn.setFixedWidth(100)
        self.drop_resp_btn.clicked.connect(self._drop_resp_intercepted)

        self.scope_btn = QPushButton("Scope")
        self.scope_btn.setFixedWidth(80)
        self.scope_btn.clicked.connect(self._open_scope_dialog)

        self.mr_btn = QPushButton("M&R Rules")
        self.mr_btn.setFixedWidth(90)
        self.mr_btn.clicked.connect(self._open_mr_dialog)

        self.clear_btn = QPushButton("Clear History")
        self.clear_btn.setFixedWidth(110)
        self.clear_btn.clicked.connect(self._clear_history)

        status_label = QLabel("Proxy: 127.0.0.1:8080")
        status_label.setStyleSheet("color: #4caf50; font-weight: bold;")

        toolbar.addWidget(self.intercept_btn)
        toolbar.addWidget(self.forward_btn)
        toolbar.addWidget(self.drop_btn)
        toolbar.addWidget(self.resp_intercept_btn)
        toolbar.addWidget(self.forward_resp_btn)
        toolbar.addWidget(self.drop_resp_btn)
        toolbar.addWidget(self.scope_btn)
        toolbar.addWidget(self.mr_btn)
        toolbar.addWidget(self.clear_btn)
        toolbar.addStretch()
        toolbar.addWidget(status_label)
        layout.addLayout(toolbar)

        # ── search bar + bambda button ────────────────────────────────
        sb_row = QHBoxLayout()
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Filter history…")
        self.search_bar.setStyleSheet(
            "QLineEdit { background: #181825; border: 1px solid #313244; "
            "padding: 4px; color: #cdd6f4; }"
        )
        self.search_bar.textChanged.connect(self._filter_history)
        sb_row.addWidget(self.search_bar, 1)

        self._bambda_btn = QPushButton("Bambda…")
        self._bambda_btn.setStyleSheet(_BTN_STYLE if "_BTN_STYLE" in globals() else "")
        self._bambda_btn.setToolTip("Filter history with a Python snippet (lambda req, resp: …)")
        self._bambda_btn.clicked.connect(self._open_bambdas)
        sb_row.addWidget(self._bambda_btn)

        layout.addLayout(sb_row)

        # Bambda state — preserved across history reloads
        self._bambdas_store: dict[str, str] = {}
        self._active_bambda = None  # compiled callable or None

        # ── main splitter ──────────────────────────────────────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.history_list = QListWidget()
        self.history_list.setFont(QFont("Monospace", 9))
        self.history_list.currentRowChanged.connect(self._on_select)
        self.history_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.history_list.customContextMenuRequested.connect(self._context_menu)
        splitter.addWidget(self.history_list)

        detail_splitter = QSplitter(Qt.Orientation.Vertical)

        self.req_view = QTextEdit()
        self.req_view.setFont(QFont("Monospace", 9))
        self.req_view.setReadOnly(True)
        self.req_view.setPlaceholderText("Request")

        self.resp_view = QTextEdit()
        self.resp_view.setFont(QFont("Monospace", 9))
        self.resp_view.setReadOnly(True)
        self.resp_view.setPlaceholderText("Response")

        detail_splitter.addWidget(self.req_view)
        detail_splitter.addWidget(self.resp_view)

        self.inspector = InspectorWidget()
        self.inspector.content_modified.connect(self._on_inspector_modified)

        right_splitter = QSplitter(Qt.Orientation.Horizontal)
        right_splitter.addWidget(detail_splitter)
        right_splitter.addWidget(self.inspector)
        right_splitter.setSizes([600, 300])

        splitter.addWidget(right_splitter)
        splitter.setSizes([300, 900])

        layout.addWidget(splitter)

        # ── annotation note bar ────────────────────────────────────────
        self.note_bar = QLabel("")
        self.note_bar.setStyleSheet(
            "color: #a6adc8; font-style: italic; padding: 2px 4px;"
        )
        self.note_bar.setWordWrap(True)
        layout.addWidget(self.note_bar)

    def _setup_signals(self):
        self._signal_thread = HistorySignal(self.proxy)
        self._signal_thread.new_entry.connect(self._add_entry)
        self._signal_thread.start()

    # ------------------------------------------------------------------
    # Toolbar actions
    # ------------------------------------------------------------------

    def _toggle_intercept(self, checked: bool):
        self.proxy.intercept_enabled = checked
        self.intercept_btn.setText("Intercept: ON" if checked else "Intercept: OFF")
        self.intercept_btn.setStyleSheet(_BTN_ON_STYLE if checked else _BTN_STYLE)
        self.forward_btn.setEnabled(checked)
        self.drop_btn.setEnabled(checked)

    def _forward_intercepted(self):
        try:
            req = self.proxy.intercept_queue.get_nowait()
            self.proxy.release_request(req)
        except Exception:
            pass

    def _drop_intercepted(self):
        try:
            req = self.proxy.intercept_queue.get_nowait()
            self.proxy.drop_request(req)
        except Exception:
            pass

    def _toggle_resp_intercept(self, checked: bool):
        self.proxy.response_intercept_enabled = checked
        self.resp_intercept_btn.setText(
            "Resp Intercept: ON" if checked else "Resp Intercept: OFF"
        )
        self.resp_intercept_btn.setStyleSheet(_BTN_ON_STYLE if checked else _BTN_STYLE)
        self.forward_resp_btn.setEnabled(checked)
        self.drop_resp_btn.setEnabled(checked)

    def _forward_resp_intercepted(self):
        try:
            resp = self.proxy.response_intercept_queue.get_nowait()
            self.proxy.release_response(resp)
        except Exception:
            pass

    def _drop_resp_intercepted(self):
        try:
            resp = self.proxy.response_intercept_queue.get_nowait()
            self.proxy.drop_response(resp)
        except Exception:
            pass

    def _open_scope_dialog(self):
        dlg = _ScopeDialog(self.proxy, parent=self)
        dlg.exec()

    def _open_mr_dialog(self):
        dlg = _MatchReplaceDialog(self.proxy, parent=self)
        dlg.exec()

    def _clear_history(self):
        self._entries.clear()
        self._annotations.clear()
        self.history_list.clear()
        self.req_view.clear()
        self.resp_view.clear()
        self.note_bar.setText("")

    # ------------------------------------------------------------------
    # History list management
    # ------------------------------------------------------------------

    def _add_entry(self, entry):
        req, resp = entry
        self._entries.append(entry)
        code = resp.status_code if resp else "---"
        label = self._build_label(req, resp)
        item = QListWidgetItem(label)
        self._apply_annotation_style(item, req.id)
        self.history_list.addItem(item)
        self._apply_search_filter(item, label)
        self.history_list.scrollToBottom()

    def _build_label(self, req: HttpRequest, resp) -> str:
        code = resp.status_code if resp else "---"
        base = f"[{code}] {req.method} {req.host}{req.path}"
        ann = self._annotations.get(req.id)
        if ann and ann.get("color"):
            dot = _COLOR_DOTS.get(ann["color"], "●")
            base = f"{dot} {base}"
        return base

    def _apply_annotation_style(self, item: QListWidgetItem, req_id: int):
        ann = self._annotations.get(req_id)
        if ann and ann.get("color"):
            hex_color = _ANNOTATION_COLORS[ann["color"]]
            item.setForeground(QColor(hex_color))

    def _refresh_item(self, row: int):
        """Re-render the list item at *row* to reflect current annotation."""
        if row < 0 or row >= self.history_list.count():
            return
        req, resp = self._entries[row]
        label = self._build_label(req, resp)
        item = self.history_list.item(row)
        item.setText(label)
        self._apply_annotation_style(item, req.id)
        self._apply_search_filter(item, label)

    def _row_matches_bambda(self, row: int) -> bool:
        """Return True if the row passes the active bambda (or no bambda set)."""
        if self._active_bambda is None:
            return True
        if not (0 <= row < len(self._entries)):
            return True
        from .bambdas import evaluate as _bambda_eval
        req, resp = self._entries[row]
        return _bambda_eval(self._active_bambda, req, resp)

    def _apply_search_filter(self, item: QListWidgetItem, label: str):
        text = self.search_bar.text()
        row = self.history_list.row(item)
        text_hidden = bool(text) and text.lower() not in label.lower()
        bambda_hidden = not self._row_matches_bambda(row)
        item.setHidden(text_hidden or bambda_hidden)

    def _filter_history(self, text: str):
        for i in range(self.history_list.count()):
            item = self.history_list.item(i)
            label = item.text()
            text_hidden = bool(text) and text.lower() not in label.lower()
            bambda_hidden = not self._row_matches_bambda(i)
            item.setHidden(text_hidden or bambda_hidden)

    def _open_bambdas(self):
        from .bambdas import BambdasDialog, compile_bambda
        dlg = BambdasDialog(self._bambdas_store, parent=self)
        if not dlg.exec():
            return
        body = dlg.chosen_body()
        if body is None:
            self._active_bambda = None
            self._bambda_btn.setText("Bambda…")
        else:
            try:
                self._active_bambda = compile_bambda(body)
                self._bambda_btn.setText("Bambda ●")
            except SyntaxError:
                self._active_bambda = None
                self._bambda_btn.setText("Bambda…")
        # Refresh visibility
        self._filter_history(self.search_bar.text())

    # ------------------------------------------------------------------
    # Detail view / selection
    # ------------------------------------------------------------------

    def _on_inspector_modified(self, raw: bytes) -> None:
        self.req_view.blockSignals(True)
        self.req_view.setPlainText(raw.decode(errors="replace"))
        self.req_view.blockSignals(False)

    def _on_select(self, row: int):
        if row < 0 or row >= len(self._entries):
            self.note_bar.setText("")
            return
        req, resp = self._entries[row]
        self.req_view.setPlainText(req.raw.decode(errors="replace"))
        self.inspector.load(req.raw, is_request=True)
        if resp:
            # Auto-decompress for display while preserving raw bytes.
            from .decompress import decompress as _decompress
            decoded_body, label = _decompress(resp.body or b"", resp.headers or {})
            if label and "failed" not in label and "unavailable" not in label and "unknown" not in label:
                head_str = resp.raw.split(b"\r\n\r\n", 1)[0].decode(errors="replace") if resp.raw else ""
                shown = (
                    f"{head_str}\r\nX-Fracture-Decoded: {label}\r\n\r\n"
                    + decoded_body.decode(errors="replace")
                )
                self.resp_view.setPlainText(shown)
            else:
                self.resp_view.setPlainText(resp.raw.decode(errors="replace"))
        else:
            self.resp_view.setPlainText("(no response)")

        ann = self._annotations.get(req.id)
        if ann and ann.get("note"):
            self.note_bar.setText(f"Note: {ann['note']}")
        else:
            self.note_bar.setText("")

    # ------------------------------------------------------------------
    # Context menu (annotations + send-to actions)
    # ------------------------------------------------------------------

    def _context_menu(self, pos):
        row = self.history_list.currentRow()
        if row < 0 or row >= len(self._entries):
            return
        req, _ = self._entries[row]

        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu { background: #181825; color: #cdd6f4; border: 1px solid #313244; } "
            "QMenu::item:selected { background: #45475a; }"
        )

        menu.addAction("Send to Repeater", lambda: self.send_to_repeater.emit(req))
        menu.addAction("Send to Intruder", lambda: self.send_to_intruder.emit(req))
        menu.addAction("Send to Active Scanner", lambda: self.send_to_scanner.emit(req))
        menu.addAction("Send to Sequencer", lambda: self.send_to_sequencer.emit(req))
        menu.addAction("Send to Organizer", lambda: self.send_to_organizer.emit(req))
        menu.addAction("Send to Param Miner", lambda: self.send_to_param_miner.emit(req))
        menu.addSeparator()

        # Engagement tools (search across all history)
        engage_menu = menu.addMenu("Engagement Tools")
        engage_menu.setStyleSheet(menu.styleSheet())
        engage_menu.addAction("Find comments", self._engagement_find_comments)
        engage_menu.addAction("Find scripts", self._engagement_find_scripts)
        engage_menu.addAction("Find references", self._engagement_find_references)
        engage_menu.addAction("Find emails", self._engagement_find_emails)

        if req.is_https:
            menu.addAction("View Certificate…", lambda: self._view_certificate(req))

        # Render response in embedded browser
        resp = self._entries[row][1] if row < len(self._entries) else None
        if resp is not None and resp.body:
            menu.addAction(
                "Render in Browser",
                lambda: self.render_in_browser.emit(req, resp),
            )
        menu.addSeparator()

        if req.method.upper() in ("POST", "PUT", "PATCH"):
            menu.addAction("Generate CSRF PoC", lambda: self._generate_csrf_poc(req))

        menu.addAction("Generate Clickjacking PoC", lambda: self._generate_clickjacking_poc(req))

        menu.addAction("Send to Comparer (left)", lambda: self.send_to_comparer_left.emit(req))
        menu.addAction("Send to Comparer (right)", lambda: self.send_to_comparer_right.emit(req))
        menu.addSeparator()

        def _export_selected_csv():
            p, _ = QFileDialog.getSaveFileName(self, "Export as CSV", "", "CSV (*.csv)")
            if p:
                try:
                    resp_obj = self._entries[row][1]
                    export_csv([(req, resp_obj)], p)
                except Exception as exc:
                    QMessageBox.critical(self, "Export Error", str(exc))
        menu.addAction("Export as CSV", _export_selected_csv)
        menu.addSeparator()

        # Add Note
        def _add_note():
            current_note = (self._annotations.get(req.id) or {}).get("note", "")
            text, ok = QInputDialog.getText(
                self, "Add Note", "Note:", text=current_note
            )
            if ok:
                ann = self._annotations.setdefault(req.id, {"color": "", "note": ""})
                ann["note"] = text
                self._refresh_item(row)
                # update note bar if this row is still selected
                if self.history_list.currentRow() == row:
                    self.note_bar.setText(f"Note: {text}" if text else "")

        menu.addAction("Add Note", _add_note)

        # Highlight submenu
        highlight_menu = menu.addMenu("Highlight")
        highlight_menu.setStyleSheet(menu.styleSheet())
        for color_name, hex_val in _ANNOTATION_COLORS.items():
            dot = _COLOR_DOTS[color_name]
            action = highlight_menu.addAction(f"{dot} {color_name}")
            # capture loop variable
            def _set_color(_, c=color_name, r=row, req_id=req.id):
                ann = self._annotations.setdefault(req_id, {"color": "", "note": ""})
                ann["color"] = c
                self._refresh_item(r)
            action.triggered.connect(_set_color)

        menu.exec(self.history_list.mapToGlobal(pos))

    # ------------------------------------------------------------------
    # Engagement tools
    # ------------------------------------------------------------------

    def _engagement_find_comments(self):
        FindResultsDialog("Find comments", find_comments(self._entries), self).exec()

    def _engagement_find_scripts(self):
        FindResultsDialog("Find scripts", find_scripts(self._entries), self).exec()

    def _engagement_find_references(self):
        FindResultsDialog("Find references", find_references(self._entries), self).exec()

    def _engagement_find_emails(self):
        FindResultsDialog("Find emails", find_emails(self._entries), self).exec()

    def _view_certificate(self, req):
        CertViewerDialog(req.host, req.port, self).exec()

    def _generate_csrf_poc(self, req) -> None:
        """Generate a self-submitting HTML CSRF PoC form."""
        import urllib.parse

        fields = []
        ct = ""
        for k, v in req.headers.items():
            if k.lower() == "content-type":
                ct = v.lower()

        if "application/x-www-form-urlencoded" in ct and req.body:
            for part in req.body.decode(errors="replace").split("&"):
                if "=" in part:
                    name, _, value = part.partition("=")
                    name = urllib.parse.unquote_plus(name)
                    value = urllib.parse.unquote_plus(value)
                    fields.append(f'  <input type="hidden" name="{name}" value="{value}">')

        scheme = "https" if req.is_https else "http"
        action = f"{scheme}://{req.host}{req.path}"

        poc = f"""<!DOCTYPE html>
<html>
<body>
<h1>CSRF PoC</h1>
<form method="{req.method}" action="{action}" enctype="application/x-www-form-urlencoded">
{chr(10).join(fields) if fields else "  <!-- No form fields detected -->"}
  <input type="submit" value="Submit">
</form>
<script>document.forms[0].submit();</script>
</body>
</html>"""

        self._show_poc_dialog("CSRF PoC", poc, ".html")

    def _generate_clickjacking_poc(self, req) -> None:
        """Generate an iframe-based clickjacking PoC."""
        scheme = "https" if req.is_https else "http"
        target_url = f"{scheme}://{req.host}{req.path}"

        poc = f"""<!DOCTYPE html>
<html>
<head>
<style>
  #target {{ opacity: 0.1; position: absolute; top: 0; left: 0; width: 100%; height: 100%; border: none; z-index: 1; }}
  #overlay {{ position: absolute; top: 200px; left: 200px; z-index: 2; background: #ff5555; color: white; padding: 20px; cursor: pointer; font-size: 18px; border-radius: 6px; }}
</style>
</head>
<body>
<iframe id="target" src="{target_url}"></iframe>
<div id="overlay">Click Me!</div>
</body>
</html>"""

        self._show_poc_dialog("Clickjacking PoC", poc, ".html")

    def _show_poc_dialog(self, title: str, content: str, ext: str) -> None:
        """Show a dialog with the PoC content and copy/save buttons."""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton, QHBoxLayout, QFileDialog
        from PyQt6.QtGui import QFont

        dlg = QDialog(self)
        dlg.setWindowTitle(title)
        dlg.setMinimumSize(700, 450)
        dlg.setStyleSheet(
            "QDialog { background: #1e1e2e; color: #cdd6f4; } "
            "QTextEdit { background: #181825; border: 1px solid #313244; color: #cdd6f4; } "
            "QPushButton { background: #313244; border: 1px solid #45475a; padding: 4px 10px; border-radius: 4px; color: #cdd6f4; } "
            "QPushButton:hover { background: #45475a; }"
        )
        layout = QVBoxLayout(dlg)
        editor = QTextEdit()
        editor.setFont(QFont("Monospace", 9))
        editor.setPlainText(content)
        layout.addWidget(editor)
        btn_row = QHBoxLayout()

        copy_btn = QPushButton("Copy to Clipboard")

        def _copy() -> None:
            from PyQt6.QtWidgets import QApplication
            QApplication.clipboard().setText(editor.toPlainText())
        copy_btn.clicked.connect(_copy)

        save_btn = QPushButton(f"Save as {ext}")

        def _save() -> None:
            path, _ = QFileDialog.getSaveFileName(dlg, f"Save {title}", "", f"HTML Files (*{ext})")
            if path:
                with open(path, "w") as f:
                    f.write(editor.toPlainText())
        save_btn.clicked.connect(_save)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        btn_row.addWidget(copy_btn)
        btn_row.addWidget(save_btn)
        btn_row.addStretch()
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)
        dlg.exec()


class MainWindow(QMainWindow):
    def __init__(self, proxy: ProxyServer):
        super().__init__()
        self._proxy = proxy
        self._project_manager = ProjectManager()
        self._recent_projects = RecentProjects()
        self._logger_holder: dict = {"logger": None}

        self.setWindowTitle("Fracture")
        self.resize(1280, 760)
        self.setMinimumSize(900, 560)
        self.setStyleSheet("""
            QMainWindow { background: #1e1e2e; }
            QWidget { background: #1e1e2e; color: #cdd6f4; }
            QTabWidget::pane { border: 1px solid #313244; }
            QTabBar { qproperty-drawBase: 0; }
            QTabBar::tab { background: #313244; padding: 6px 14px; min-width: 0; }
            QTabBar::tab:selected { background: #45475a; }
            QTabBar::scroller { width: 24px; }
            QListWidget { background: #181825; border: 1px solid #313244; }
            QListWidget::item:selected { background: #45475a; }
            QTextEdit { background: #181825; border: 1px solid #313244; }
            QPushButton { background: #313244; border: 1px solid #45475a; padding: 4px 10px; border-radius: 4px; }
            QPushButton:hover { background: #45475a; }
            QSplitter::handle { background: #313244; }
            QMenuBar { background: #181825; color: #cdd6f4; border-bottom: 1px solid #313244; }
            QMenuBar::item:selected { background: #313244; }
            QMenu { background: #181825; color: #cdd6f4; border: 1px solid #313244; }
            QMenu::item:selected { background: #45475a; }
        """)

        self._build_menu()

        tabs = QTabWidget()

        self.dashboard_tab = DashboardTab()
        self.proxy_tab = ProxyTab(proxy)
        self.repeater_tab = RepeaterTab()
        self.intruder_tab = IntruderTab()
        self.decoder_tab = DecoderTab()
        self.comparer_tab = ComparerTab()
        self.sitemap_tab = SiteMapTab()
        self.passive_scanner_tab = PassiveScannerTab()
        self.active_scanner_tab = ActiveScannerTab()
        self.sequencer_tab = SequencerTab()
        self.ws_tab = WebSocketTab()
        self.collaborator_tab = CollaboratorTab()
        self.plugin_manager_tab = PluginManagerTab(proxy.plugin_manager)
        self.spider_tab = SpiderTab()
        self.macros_tab = MacroTab()
        self.content_discovery_tab = ContentDiscoveryTab()
        self.organizer_tab = OrganizerTab()
        self.graphql_tab = GraphQLTab()
        self.saml_tab = SAMLTab()
        self.param_miner_tab = ParamMinerTab()
        self.jwt_editor_tab = JWTEditorTab()
        self.logger_tab = LoggerTab()
        self.authz_tab = AuthzTab()
        self.browser_tab = BrowserTab()
        self.session_rule_engine = SessionRuleEngine()
        self.session_rules_tab = SessionRulesTab(self.session_rule_engine)
        # Wire macro-action support
        self.session_rule_engine.set_macro_runner(self.macros_tab.run_macro_sync)
        self.turbo_intruder_tab = TurboIntruderTab()
        self.ws_intruder_tab = WebSocketIntruderTab()
        self.notes_tab = NotesTab()
        self.live_tasks_tab = LiveTasksTab()
        self.findings_tab = FindingsTab()
        self.flask_tools_tab = FlaskToolsTab()
        self.revshell_tab = RevShellTab()
        self.hash_id_tab = HashIdTab()
        self.payload_lib_tab = PayloadLibTab()
        self.dns_recon_tab = DnsReconTab()
        self.sec_headers_tab = SecHeadersTab()

        # P15 stores + tabs
        self.cookie_jar = CookieJar()
        self.cookie_jar_tab = CookieJarTab(self.cookie_jar)
        self.mtls_store = ClientCertStore()
        self.mtls_store.load() if hasattr(self.mtls_store, "load") else None
        self.preauth_store = CredentialStore()
        self.preauth_store.load() if hasattr(self.preauth_store, "load") else None

        # Hook the cookie jar into the proxy history pipeline
        proxy.add_history_callback(
            lambda entry: self.cookie_jar.observe(entry[0], entry[1]) if entry[1] else None
        )

        # Dirty-state tracking
        self._dirty = False
        self._current_project_path: Optional[str] = None  # type: ignore[name-defined]
        self.notes_tab.modified.connect(self._mark_dirty)

        # ── Tab bar polish (works for all QTabWidgets in the window) ──
        def _polish_tabs(tw: QTabWidget) -> QTabWidget:
            tw.setUsesScrollButtons(True)
            tw.setElideMode(Qt.TextElideMode.ElideRight)
            tw.setMovable(False)
            tb = tw.tabBar()
            tb.setExpanding(False)
            tb.setUsesScrollButtons(True)
            return tw

        _polish_tabs(tabs)

        # Attack group: Intruder | Turbo Intruder | WS Intruder | Sequencer
        self._attack_group = _polish_tabs(QTabWidget())
        self._attack_group.addTab(self.intruder_tab, "Intruder")
        self._attack_group.addTab(self.turbo_intruder_tab, "Turbo")
        self._attack_group.addTab(self.ws_intruder_tab, "WS")
        self._attack_group.addTab(self.sequencer_tab, "Sequencer")

        # Scanner group: Passive | Active | Authz | Param Miner
        self._scanner_wrapper = _polish_tabs(QTabWidget())
        self._scanner_wrapper.addTab(self.passive_scanner_tab, "Passive")
        self._scanner_wrapper.addTab(self.active_scanner_tab, "Active")
        self._scanner_wrapper.addTab(self.authz_tab, "Authz")
        self._scanner_wrapper.addTab(self.param_miner_tab, "Param Miner")

        # Discovery group: Site Map | Spider | Content Discovery | DNS/Recon
        self._discovery_group = _polish_tabs(QTabWidget())
        self._discovery_group.addTab(self.sitemap_tab, "Site Map")
        self._discovery_group.addTab(self.spider_tab, "Spider")
        self._discovery_group.addTab(self.content_discovery_tab, "Content")
        self._discovery_group.addTab(self.dns_recon_tab, "DNS / Recon")

        # Tools group
        self._tools_group = _polish_tabs(QTabWidget())
        self._tools_group.addTab(self.decoder_tab, "Decoder")
        self._tools_group.addTab(self.comparer_tab, "Comparer")
        self._tools_group.addTab(self.organizer_tab, "Organizer")
        self._tools_group.addTab(self.macros_tab, "Macros")
        self._tools_group.addTab(self.logger_tab, "Logger")
        self._tools_group.addTab(self.notes_tab, "Notes")
        self._tools_group.addTab(self.flask_tools_tab, "Flask Tools")
        self._tools_group.addTab(self.revshell_tab, "Rev Shell")
        self._tools_group.addTab(self.hash_id_tab, "Hash ID")
        self._tools_group.addTab(self.payload_lib_tab, "Payloads")
        self._tools_group.addTab(self.sec_headers_tab, "Sec Headers")

        # Auth/Crypto group: JWT | SAML | GraphQL
        self._auth_group = _polish_tabs(QTabWidget())
        self._auth_group.addTab(self.jwt_editor_tab, "JWT Editor")
        self._auth_group.addTab(self.saml_tab, "SAML")
        self._auth_group.addTab(self.graphql_tab, "GraphQL")

        # OOB group: WebSockets | Collaborator | Browser | Session Rules | Extensions | Tasks
        self._oob_group = _polish_tabs(QTabWidget())
        self._oob_group.addTab(self.ws_tab, "WebSockets")
        self._oob_group.addTab(self.collaborator_tab, "Collaborator")
        self._oob_group.addTab(self.browser_tab, "Browser")
        self._oob_group.addTab(self.session_rules_tab, "Session Rules")
        self._oob_group.addTab(self.plugin_manager_tab, "Extensions")
        self._oob_group.addTab(self.cookie_jar_tab, "Cookies")
        self._oob_group.addTab(self.live_tasks_tab, "Tasks")

        # Register long-running workers with the Live Tasks panel
        for name, tab in (
            ("Intruder", self.intruder_tab),
            ("Turbo Intruder", self.turbo_intruder_tab),
            ("WS Intruder", self.ws_intruder_tab),
            ("Spider", self.spider_tab),
            ("Content Discovery", self.content_discovery_tab),
            ("Sequencer", self.sequencer_tab),
            ("Active Scanner", self.active_scanner_tab),
            ("Param Miner", self.param_miner_tab),
        ):
            self.live_tasks_tab.register(TaskSource(
                name=name,
                get_worker=lambda t=tab: getattr(t, "_worker", None),
                focus=lambda t=tab: self._focus_tab(t),
            ))

        # Top-level tab bar
        tabs.addTab(self.dashboard_tab, "Dashboard")
        tabs.addTab(self.proxy_tab, "Proxy")
        tabs.addTab(self.repeater_tab, "Repeater")
        tabs.addTab(self._attack_group, "Attack")
        tabs.addTab(self._scanner_wrapper, "Scanner")
        tabs.addTab(self._discovery_group, "Discovery")
        tabs.addTab(self._tools_group, "Tools")
        tabs.addTab(self._auth_group, "Auth/Crypto")
        tabs.addTab(self._oob_group, "OOB & More")
        tabs.addTab(self.findings_tab, "Findings")

        self.proxy_tab.send_to_repeater.connect(self._open_in_repeater)
        self.proxy_tab.send_to_intruder.connect(self._open_in_intruder)
        self.proxy_tab.send_to_comparer_left.connect(self._open_in_comparer_left)
        self.proxy_tab.send_to_comparer_right.connect(self._open_in_comparer_right)
        self.proxy_tab.send_to_scanner.connect(self._open_in_active_scanner)
        self.proxy_tab.send_to_sequencer.connect(self._open_in_sequencer)
        self.proxy_tab.send_to_organizer.connect(self._open_in_organizer)
        self.proxy_tab.send_to_param_miner.connect(self._open_in_param_miner)
        self.proxy_tab.render_in_browser.connect(self._render_in_browser)
        self.logger_tab.send_to_repeater.connect(self._open_in_repeater)
        self.logger_tab.send_to_intruder.connect(self._open_in_intruder)

        proxy.add_history_callback(self._on_history_entry)

        # Dashboard quick-launch wiring
        self.dashboard_tab.open_tab.connect(self._open_named_tab)

        self._tabs = tabs
        self.setCentralWidget(tabs)
        self._setup_shortcuts()
        self._setup_status_bar()
        self._setup_autosave()
        # Offer to reopen the last project on next event-loop tick
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(0, self._offer_last_project)

    # ------------------------------------------------------------------
    # Status bar — live counters, click to jump
    # ------------------------------------------------------------------
    def _setup_status_bar(self):
        bar = self.statusBar()
        bar.setStyleSheet(
            "QStatusBar { background: #181825; color: #cdd6f4; "
            "border-top: 1px solid #313244; }"
            "QStatusBar QLabel { color: #cdd6f4; padding: 0 8px; }"
        )

        def _make_counter(text: str, click_target):
            from PyQt6.QtCore import Qt as _Qt
            lbl = QLabel(text)
            lbl.setCursor(_Qt.CursorShape.PointingHandCursor)
            lbl.mousePressEvent = lambda _ev, t=click_target: self._focus_tab(t)
            return lbl

        self._sb_history = _make_counter("History: 0", self.proxy_tab)
        self._sb_findings = _make_counter("Findings: 0", self._scanner_wrapper)
        self._sb_intruder = _make_counter("Intruder: idle", self.intruder_tab)
        self._sb_turbo = _make_counter("Turbo: idle", self.turbo_intruder_tab)
        self._sb_spider = _make_counter("Spider: idle", self.spider_tab)

        for lbl in (self._sb_history, self._sb_findings, self._sb_intruder,
                    self._sb_turbo, self._sb_spider):
            bar.addPermanentWidget(lbl)

        # Refresh on a 1-second timer
        from PyQt6.QtCore import QTimer
        self._sb_timer = QTimer(self)
        self._sb_timer.setInterval(1000)
        self._sb_timer.timeout.connect(self._refresh_status_bar)
        self._sb_timer.start()

    def _refresh_status_bar(self):
        try:
            self._sb_history.setText(f"History: {len(self._proxy.history)}")
        except Exception:
            pass
        try:
            n = len(self.passive_scanner_tab.get_issues())
            self._sb_findings.setText(f"Findings: {n}")
        except Exception:
            pass
        try:
            w = getattr(self.intruder_tab, "_worker", None)
            running = bool(w and w.isRunning())
            self._sb_intruder.setText("Intruder: running" if running else "Intruder: idle")
        except Exception:
            pass
        try:
            w = getattr(self.turbo_intruder_tab, "_worker", None)
            running = bool(w and w.isRunning())
            self._sb_turbo.setText("Turbo: running" if running else "Turbo: idle")
        except Exception:
            pass
        try:
            w = getattr(self.spider_tab, "_worker", None)
            running = bool(w and w.isRunning())
            self._sb_spider.setText("Spider: running" if running else "Spider: idle")
        except Exception:
            pass

    def _build_menu(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")

        save_act = QAction("Save Project…", self)
        save_act.setShortcut("Ctrl+S")
        save_act.triggered.connect(self._save_project)
        file_menu.addAction(save_act)

        open_act = QAction("Open Project…", self)
        open_act.setShortcut("Ctrl+O")
        open_act.triggered.connect(self._load_project)
        file_menu.addAction(open_act)

        file_menu.addSeparator()

        self._recent_menu = file_menu.addMenu("Recent Projects")
        self._rebuild_recent_menu()

        file_menu.addSeparator()

        exp_csv_act = QAction("Export History as CSV…", self)
        exp_csv_act.triggered.connect(self._export_csv)
        file_menu.addAction(exp_csv_act)

        exp_xml_act = QAction("Export History as Burp XML…", self)
        exp_xml_act.triggered.connect(self._export_burp_xml)
        file_menu.addAction(exp_xml_act)

        file_menu.addSeparator()

        import_curl_act = QAction("Import from curl…", self)
        import_curl_act.triggered.connect(self._import_from_curl)
        file_menu.addAction(import_curl_act)

        file_menu.addSeparator()

        # Profiles
        save_prof_act = QAction("Save Profile…", self)
        save_prof_act.triggered.connect(self._save_profile)
        file_menu.addAction(save_prof_act)

        self._profiles_menu = file_menu.addMenu("Load Profile")
        self._rebuild_profiles_menu()

        del_prof_act = QAction("Delete Profile…", self)
        del_prof_act.triggered.connect(self._delete_profile)
        file_menu.addAction(del_prof_act)

        file_menu.addSeparator()

        quit_act = QAction("Quit", self)
        quit_act.setShortcut("Ctrl+Q")
        quit_act.triggered.connect(self.close)
        file_menu.addAction(quit_act)

        # Edit menu
        edit_menu = menubar.addMenu("Edit")
        search_act = QAction("Global Search…", self)
        search_act.setShortcut("Ctrl+Shift+F")
        search_act.triggered.connect(self._open_global_search)
        edit_menu.addAction(search_act)

        # Settings menu
        settings_menu = menubar.addMenu("Settings")
        settings_act = QAction("Settings…", self)
        settings_act.setShortcut("Ctrl+,")
        settings_act.triggered.connect(self._open_settings)
        settings_menu.addAction(settings_act)

        # Auth menu — client certs + pre-auth
        auth_menu = menubar.addMenu("Auth")
        mtls_act = QAction("Client Certificates…", self)
        mtls_act.triggered.connect(self._open_mtls)
        auth_menu.addAction(mtls_act)

        preauth_act = QAction("Pre-Auth Credentials…", self)
        preauth_act.triggered.connect(self._open_preauth)
        auth_menu.addAction(preauth_act)

    def _focus_tab(self, widget):
        """Bring *widget* to the front, walking through any nested QTabWidgets."""
        cur = widget
        # Walk up the parent chain. Each time we find an enclosing QTabWidget,
        # select the page that contains `cur` and continue from that QTabWidget.
        guard = 0
        while cur is not None and guard < 20:
            guard += 1
            parent = cur.parentWidget()
            anc = parent
            while anc is not None and not isinstance(anc, QTabWidget):
                anc = anc.parentWidget()
            if anc is None:
                return
            # Find the page in anc that is `cur` or an ancestor of `cur`.
            for i in range(anc.count()):
                page = anc.widget(i)
                if page is cur or page.isAncestorOf(cur):
                    anc.setCurrentIndex(i)
                    break
            cur = anc

    def _setup_shortcuts(self):
        # Ctrl+R — send selected proxy entry to Repeater
        sc_r = QShortcut(QKeySequence("Ctrl+R"), self)
        sc_r.activated.connect(self._shortcut_send_to_repeater)

        # Ctrl+I — send selected proxy entry to Intruder
        sc_i = QShortcut(QKeySequence("Ctrl+I"), self)
        sc_i.activated.connect(self._shortcut_send_to_intruder)

        # Ctrl+F — focus search on active tab
        sc_f = QShortcut(QKeySequence("Ctrl+F"), self)
        sc_f.activated.connect(self._shortcut_focus_search)

        # Ctrl+W — close active Repeater sub-tab
        sc_w = QShortcut(QKeySequence("Ctrl+W"), self)
        sc_w.activated.connect(self._shortcut_close_repeater_tab)

        # Ctrl+Shift+F — global search
        sc_gsf = QShortcut(QKeySequence("Ctrl+Shift+F"), self)
        sc_gsf.activated.connect(self._open_global_search)

    def _shortcut_send_to_repeater(self):
        row = self.proxy_tab.history_list.currentRow()
        if 0 <= row < len(self.proxy_tab._entries):
            req, _ = self.proxy_tab._entries[row]
            self._open_in_repeater(req)

    def _shortcut_send_to_intruder(self):
        row = self.proxy_tab.history_list.currentRow()
        if 0 <= row < len(self.proxy_tab._entries):
            req, _ = self.proxy_tab._entries[row]
            self._open_in_intruder(req)

    def _shortcut_focus_search(self):
        current = self._tabs.currentWidget()
        if current is self.proxy_tab:
            self.proxy_tab.search_bar.setFocus()

    def _shortcut_close_repeater_tab(self):
        if hasattr(self.repeater_tab, "close_current_tab"):
            self.repeater_tab.close_current_tab()

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export as CSV", "", "CSV (*.csv)")
        if path:
            try:
                export_csv(self._proxy.history, path)
            except Exception as e:
                QMessageBox.critical(self, "Export Error", str(e))

    def _export_burp_xml(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export as Burp XML", "", "XML (*.xml)")
        if path:
            try:
                export_burp_xml(self._proxy.history, path)
            except Exception as e:
                QMessageBox.critical(self, "Export Error", str(e))

    def _open_settings(self):
        dlg = _SettingsDialog(
            self._proxy, self._logger_holder,
            collaborator_tab=self.collaborator_tab, parent=self,
        )
        dlg.exec()

    def _open_mtls(self):
        dlg = ClientCertDialog(self.mtls_store, parent=self)
        dlg.exec()
        if hasattr(self.mtls_store, "save"):
            self.mtls_store.save()

    def _open_preauth(self):
        dlg = PreAuthDialog(self.preauth_store, parent=self)
        dlg.exec()
        if hasattr(self.preauth_store, "save"):
            self.preauth_store.save()

    def _open_global_search(self):
        dlg = _GlobalSearchDialog(self.proxy_tab, self.passive_scanner_tab, parent=self)
        dlg.exec()

    def _open_named_tab(self, name: str):
        tab_map = {
            "Repeater": self.repeater_tab,
            "Scanner": self._scanner_wrapper,
            "Intruder": self.intruder_tab,
        }
        widget = tab_map.get(name)
        if widget:
            self._focus_tab(widget)

    def _rebuild_recent_menu(self):
        self._recent_menu.clear()
        recent = self._recent_projects.get()
        if not recent:
            self._recent_menu.addAction("(none)").setEnabled(False)
        for path in recent:
            act = QAction(path, self)
            act.triggered.connect(lambda checked, p=path: self._load_project_from(p))
            self._recent_menu.addAction(act)

    def _save_project(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Project", "", "Fracture Project (*.cough)"
        )
        if not path:
            return
        if not path.endswith(".frac"):
            path += ".frac"
        try:
            mr_rules = [
                {"id": r.id, "enabled": r.enabled, "target": r.target.value,
                 "pattern": r.pattern, "replacement": r.replacement,
                 "is_regex": r.is_regex, "comment": r.comment}
                for r in self._proxy.match_replace.rules()
            ]
            self._project_manager.save(
                path=path,
                history=self._proxy.history,
                scope_patterns=self._proxy.scope.patterns(),
                mr_rules=mr_rules,
                annotations=self.proxy_tab._annotations,
                notes=self.notes_tab.get_text(),
            )
            self._current_project_path = path
            self._recent_projects.add(path)
            self._save_last_project_pointer(path)
            self._rebuild_recent_menu()
            self._clear_dirty()
        except Exception as e:
            QMessageBox.critical(self, "Save Failed", str(e))

    def _load_project(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Project", "", "Fracture Project (*.cough)"
        )
        if path:
            self._load_project_from(path)

    def _load_project_from(self, path: str):
        try:
            data = self._project_manager.load(path)
        except Exception as e:
            QMessageBox.critical(self, "Load Failed", str(e))
            return

        # Restore scope
        for p in data.get("scope_patterns", []):
            self._proxy.scope.add(p)

        # Restore M&R rules
        for r in data.get("mr_rules", []):
            try:
                self._proxy.match_replace.add_rule(
                    MRTarget(r["target"]), r["pattern"], r["replacement"],
                    r.get("is_regex", True), r.get("comment", "")
                )
            except Exception:
                pass

        # Restore annotations
        self.proxy_tab._annotations.update(data.get("annotations", {}))

        # Restore notes
        self.notes_tab.set_text(data.get("notes", ""))

        # Restore history entries into proxy and UI
        for entry in data.get("history", []):
            req, resp = entry
            self._proxy.history.append(entry)
            self.proxy_tab._add_entry(entry)
            self.sitemap_tab.add_entry(req, resp)

        self._current_project_path = path
        self._recent_projects.add(path)
        self._save_last_project_pointer(path)
        self._rebuild_recent_menu()
        self._clear_dirty()

    def _on_history_entry(self, entry):
        req, resp = entry
        self.sitemap_tab.add_entry(req, resp)
        self.passive_scanner_tab.add_entry(req, resp)
        self.dashboard_tab.add_history_entry(req, resp)
        self.dashboard_tab.update_stats(
            len(self._proxy.history),
            self.passive_scanner_tab.get_issues(),
        )
        self.logger_tab.add_entry(req, resp)
        self.authz_tab.add_entry(req, resp)
        self._mark_dirty()
        logger = self._logger_holder.get("logger")
        if logger and logger.is_open():
            logger.log_entry(req, resp)

    def _open_in_repeater(self, req):
        self.repeater_tab.load_request(req)
        self._focus_tab(self.repeater_tab)

    def _open_in_intruder(self, req):
        self.intruder_tab.load_request(req)
        self._focus_tab(self.intruder_tab)

    def _open_in_comparer_left(self, req):
        self.comparer_tab.load_left(req.raw.decode(errors="replace"))
        self._focus_tab(self.comparer_tab)

    def _open_in_comparer_right(self, req):
        self.comparer_tab.load_right(req.raw.decode(errors="replace"))
        self._focus_tab(self.comparer_tab)

    def _open_in_active_scanner(self, req):
        self.active_scanner_tab.load_request(req)
        self._focus_tab(self.active_scanner_tab)

    def _open_in_sequencer(self, req):
        self.sequencer_tab.load_request(req)
        self._focus_tab(self.sequencer_tab)

    def _open_in_organizer(self, req):
        self.organizer_tab.add_request(req)
        self._focus_tab(self.organizer_tab)

    def _open_in_param_miner(self, req):
        self.param_miner_tab.load_request(req)
        self._focus_tab(self.param_miner_tab)

    def _render_in_browser(self, req, resp):
        # Decompress for display if needed
        from .decompress import decompress as _decompress
        body, _ = _decompress(resp.body or b"", resp.headers or {})
        # Best-effort base URL for relative links
        scheme = "https" if req.is_https else "http"
        base = f"{scheme}://{req.host}{req.path}"
        try:
            html = body.decode("utf-8", errors="replace")
            self.browser_tab.render_html(html, base)
            self._focus_tab(self.browser_tab)
        except Exception:
            QMessageBox.warning(self, "Render in Browser",
                                "Browser engine is not available.")

    # ------------------------------------------------------------------
    # Profiles
    # ------------------------------------------------------------------
    def _rebuild_profiles_menu(self):
        from . import profiles as _prof
        self._profiles_menu.clear()
        names = _prof.list_profiles()
        if not names:
            self._profiles_menu.addAction("(none)").setEnabled(False)
            return
        for name in names:
            act = QAction(name, self)
            act.triggered.connect(lambda checked, n=name: self._load_profile(n))
            self._profiles_menu.addAction(act)

    def _save_profile(self):
        from . import profiles as _prof
        name, ok = QInputDialog.getText(self, "Save profile", "Profile name:")
        if not ok or not name.strip():
            return
        data = _prof.capture(self)
        _prof.save_profile(name.strip(), data)
        self._rebuild_profiles_menu()
        self.setWindowTitle(f"Fracture — profile: {name.strip()}")

    def _load_profile(self, name: str):
        from . import profiles as _prof
        data = _prof.load_profile(name)
        if data is None:
            QMessageBox.warning(self, "Load profile", f"Profile not found: {name}")
            return
        try:
            _prof.restore(self, data)
        except Exception as e:
            QMessageBox.critical(self, "Load profile", f"Failed: {e}")
            return
        self.setWindowTitle(f"Fracture — profile: {name}")

    def _delete_profile(self):
        from . import profiles as _prof
        names = _prof.list_profiles()
        if not names:
            QMessageBox.information(self, "Delete profile", "No profiles to delete.")
            return
        name, ok = QInputDialog.getItem(
            self, "Delete profile", "Choose profile:", names, 0, False
        )
        if not ok or not name:
            return
        _prof.delete_profile(name)
        self._rebuild_profiles_menu()

    # ------------------------------------------------------------------
    # Dirty state, auto-save, last-project memory
    # ------------------------------------------------------------------
    def _mark_dirty(self):
        if not self._dirty:
            self._dirty = True
            self._refresh_title()

    def _clear_dirty(self):
        self._dirty = False
        self._refresh_title()

    def _refresh_title(self):
        marker = " ●" if self._dirty else ""
        if self._current_project_path:
            self.setWindowTitle(f"Fracture — {self._current_project_path}{marker}")
        else:
            self.setWindowTitle(f"Fracture{marker}")

    def _autosave_path(self) -> Path:
        return Path(os.path.expanduser("~/.fracture/autosave.frac"))

    def _last_project_pointer(self) -> Path:
        return Path(os.path.expanduser("~/.fracture/last_project.json"))

    def _save_last_project_pointer(self, path: str):
        try:
            self._last_project_pointer().parent.mkdir(parents=True, exist_ok=True)
            self._last_project_pointer().write_text(
                json.dumps({"path": path}), encoding="utf-8"
            )
        except Exception:
            pass

    def _load_last_project_pointer(self) -> Optional[str]:
        try:
            data = json.loads(self._last_project_pointer().read_text(encoding="utf-8"))
            p = data.get("path", "")
            return p if p and os.path.exists(p) else None
        except Exception:
            return None

    def _setup_autosave(self):
        from PyQt6.QtCore import QTimer
        self._autosave_timer = QTimer(self)
        self._autosave_timer.setInterval(120_000)  # 2 minutes
        self._autosave_timer.timeout.connect(self._do_autosave)
        self._autosave_timer.start()

    def _do_autosave(self):
        if not self._dirty:
            return
        try:
            mr_rules = [
                {"id": r.id, "enabled": r.enabled, "target": r.target.value,
                 "pattern": r.pattern, "replacement": r.replacement,
                 "is_regex": r.is_regex, "comment": r.comment}
                for r in self._proxy.match_replace.rules()
            ]
            self._autosave_path().parent.mkdir(parents=True, exist_ok=True)
            self._project_manager.save(
                path=str(self._autosave_path()),
                history=self._proxy.history,
                scope_patterns=self._proxy.scope.patterns(),
                mr_rules=mr_rules,
                annotations=self.proxy_tab._annotations,
                notes=self.notes_tab.get_text(),
            )
        except Exception:
            pass

    def closeEvent(self, ev):
        if self._dirty:
            choice = QMessageBox.question(
                self, "Unsaved changes",
                "There are unsaved changes. Save the project before closing?",
                QMessageBox.StandardButton.Save
                | QMessageBox.StandardButton.Discard
                | QMessageBox.StandardButton.Cancel,
            )
            if choice == QMessageBox.StandardButton.Cancel:
                ev.ignore()
                return
            if choice == QMessageBox.StandardButton.Save:
                self._save_project()
                if self._dirty:  # save was cancelled
                    ev.ignore()
                    return
        super().closeEvent(ev)

    def _offer_last_project(self):
        path = self._load_last_project_pointer()
        if not path:
            return
        choice = QMessageBox.question(
            self, "Reopen last project?",
            f"Reopen the last project?\n\n{path}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if choice == QMessageBox.StandardButton.Yes:
            self._load_project_from(path)

    def _import_from_curl(self):
        dlg = CurlImportDialog(self)
        if dlg.exec() and dlg.request() is not None:
            req = dlg.request()
            self.repeater_tab.load_request(req)
            self._focus_tab(self.repeater_tab)


def run():
    # Configure the embedded browser to route through our proxy.
    # Must happen before QApplication is constructed.
    configure_chromium_flags("127.0.0.1", 8080)

    proxy = ProxyServer()
    proxy.start()

    app = QApplication(sys.argv)
    window = MainWindow(proxy)
    window.show()
    sys.exit(app.exec())
