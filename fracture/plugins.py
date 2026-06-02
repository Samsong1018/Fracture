"""
Fracture Plugin System

Loads Python .py files from ~/.fracture/plugins/ and exposes hooks into
proxy traffic, scanner findings, and custom checks.
"""

from __future__ import annotations

import importlib.util
import inspect
import subprocess
import sys
import traceback
from abc import ABC
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

# ---------------------------------------------------------------------------
# Base plugin class
# ---------------------------------------------------------------------------

EXAMPLE_PLUGIN_SOURCE = '''\
# Example Fracture plugin
from fracture.plugins import FracturePlugin


class ExamplePlugin(FracturePlugin):
    name = "Example Plugin"
    version = "1.0"
    description = "Adds X-Fracture header to all requests"

    def on_request(self, req):
        # Demonstrate modifying a request
        # (In real use, modify req.headers or req.raw and return a new dataclass)
        return req
'''


class FracturePlugin(ABC):
    name: str = "Unnamed Plugin"
    version: str = "0.1"
    description: str = ""
    author: str = ""

    def on_load(self) -> None:
        """Called once when the plugin is loaded."""

    def on_unload(self) -> None:
        """Called once when the plugin is unloaded."""

    def on_request(self, req) -> object:
        """
        Called for every proxied request.
        Return a modified HttpRequest to change it, or return req unchanged.
        req is an HttpRequest dataclass instance.
        """
        return req

    def on_response(self, req, resp) -> object:
        """
        Called for every proxied response.
        Return a modified HttpResponse to change it, or return resp unchanged.
        """
        return resp

    def on_finding(self, finding) -> None:
        """Called when the passive scanner finds an issue."""


# ---------------------------------------------------------------------------
# Plugin Manager
# ---------------------------------------------------------------------------

class PluginManager:
    def __init__(self) -> None:
        self._plugins: list[FracturePlugin] = []
        # Track per-plugin metadata: name -> {error, path}
        self._meta: dict[str, dict] = {}
        self._plugin_dir = Path.home() / ".fracture" / "plugins"
        self._plugin_dir.mkdir(parents=True, exist_ok=True)
        self._write_example_if_empty()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write_example_if_empty(self) -> None:
        """Write example_plugin.py only when no plugins exist yet."""
        example = self._plugin_dir / "example_plugin.py"
        existing = list(self._plugin_dir.glob("*.py"))
        if not existing:
            example.write_text(EXAMPLE_PLUGIN_SOURCE, encoding="utf-8")

    def _find_plugin_classes(self, module) -> list[type]:
        """Return all FracturePlugin concrete subclasses defined in *module*."""
        classes = []
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, FracturePlugin)
                and obj is not FracturePlugin
                and obj.__module__ == module.__name__
            ):
                classes.append(obj)
        return classes

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_file(self, path: Path) -> tuple[bool, str]:
        """
        Load a single plugin file.
        Returns (True, plugin_name) or (False, error_message).
        """
        try:
            module_name = f"_fracture_plugin_{path.stem}"
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                return False, f"Cannot create module spec for {path}"
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)  # type: ignore[attr-defined]

            plugin_classes = self._find_plugin_classes(module)
            if not plugin_classes:
                del sys.modules[module_name]
                return False, f"No FracturePlugin subclass found in {path.name}"

            loaded_names: list[str] = []
            for cls in plugin_classes:
                instance: FracturePlugin = cls()
                # Unload any existing plugin with the same name first
                self.unload(instance.name)
                instance.on_load()
                self._plugins.append(instance)
                self._meta[instance.name] = {"error": None, "path": str(path)}
                loaded_names.append(instance.name)

            return True, ", ".join(loaded_names)

        except Exception:
            err = traceback.format_exc()
            return False, err

    def load_all(self) -> list[str]:
        """
        Load all .py files from the plugins directory.
        Returns a list of human-readable status strings.
        """
        messages: list[str] = []
        for py_file in sorted(self._plugin_dir.glob("*.py")):
            ok, msg = self.load_file(py_file)
            if ok:
                messages.append(f"[OK] {py_file.name}: loaded {msg}")
            else:
                messages.append(f"[ERROR] {py_file.name}: {msg}")
                # Store error so the UI can display it
                stem = py_file.stem
                self._meta[stem] = {"error": msg, "path": str(py_file)}
        return messages

    def unload(self, plugin_name: str) -> bool:
        """Unload a plugin by name, calling on_unload()."""
        for i, p in enumerate(self._plugins):
            if p.name == plugin_name:
                try:
                    p.on_unload()
                except Exception as e:
                    print(f"[plugin] {p.name}.on_unload error: {e}")
                self._plugins.pop(i)
                self._meta.pop(plugin_name, None)
                return True
        return False

    def reload_all(self) -> list[str]:
        """Unload all plugins then load_all() again."""
        for p in list(self._plugins):
            try:
                p.on_unload()
            except Exception as e:
                print(f"[plugin] {p.name}.on_unload error: {e}")
        self._plugins.clear()
        self._meta.clear()
        return self.load_all()

    # ------------------------------------------------------------------
    # Hook dispatchers
    # ------------------------------------------------------------------

    def call_on_request(self, req):
        """Call all plugins' on_request in order. Return final req."""
        for p in self._plugins:
            try:
                result = p.on_request(req)
                if result is not None:
                    req = result
            except Exception as e:
                print(f"[plugin] {p.name}.on_request error: {e}")
        return req

    def call_on_response(self, req, resp):
        """Call all plugins' on_response in order. Return final resp."""
        for p in self._plugins:
            try:
                result = p.on_response(req, resp)
                if result is not None:
                    resp = result
            except Exception as e:
                print(f"[plugin] {p.name}.on_response error: {e}")
        return resp

    def call_on_finding(self, finding) -> None:
        for p in self._plugins:
            try:
                p.on_finding(finding)
            except Exception as e:
                print(f"[plugin] {p.name}.on_finding error: {e}")

    def loaded_plugins(self) -> list[FracturePlugin]:
        return list(self._plugins)

    @property
    def plugin_dir(self) -> Path:
        return self._plugin_dir

    # ------------------------------------------------------------------
    # Directory / installation helpers
    # ------------------------------------------------------------------

    def install_from_path(self, src_path: Path) -> tuple[bool, str]:
        """Copy a .py file into the plugins directory and load it."""
        import shutil
        if not src_path.exists() or src_path.suffix != ".py":
            return False, "Plugin must be a .py file"
        dest = self._plugin_dir / src_path.name
        try:
            shutil.copyfile(src_path, dest)
        except Exception as e:
            return False, f"Copy failed: {e}"
        return self.load_file(dest)

    def uninstall(self, plugin_file_stem: str) -> bool:
        """Remove a plugin file by stem (filename without .py) and unload it."""
        # Find matching loaded plugins by file path
        to_unload = [
            p.name for p in self._plugins
            if self._meta.get(p.name, {}).get("path", "").endswith(f"{plugin_file_stem}.py")
        ]
        for name in to_unload:
            self.unload(name)
        path = self._plugin_dir / f"{plugin_file_stem}.py"
        if path.exists():
            try:
                path.unlink()
                return True
            except Exception:
                pass
        return False

    def list_installed_files(self) -> list[Path]:
        """All .py files currently in the plugin directory."""
        return sorted(self._plugin_dir.glob("*.py"))

    def read_index(self) -> list[dict]:
        """Read the local curated index file at ~/.fracture/plugins/index.json.

        Each entry: {"name": ..., "description": ..., "path": "<local file path>"}
        Paths must be absolute and end in .py.  No network — purely a local registry.
        """
        import json
        idx_path = self._plugin_dir / "index.json"
        if not idx_path.exists():
            return []
        try:
            data = json.loads(idx_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return [e for e in data if isinstance(e, dict)]
        except Exception:
            return []
        return []


# ---------------------------------------------------------------------------
# Catppuccin Mocha palette
# ---------------------------------------------------------------------------

_MOCHA = {
    "base": "#1e1e2e",
    "surface": "#181825",
    "overlay": "#313244",
    "highlight": "#45475a",
    "text": "#cdd6f4",
    "green": "#a6e3a1",
    "red": "#f38ba8",
}

_TAB_STYLE = f"""
    QWidget {{
        background: {_MOCHA['base']};
        color: {_MOCHA['text']};
    }}
    QTableWidget {{
        background: {_MOCHA['surface']};
        border: 1px solid {_MOCHA['overlay']};
        gridline-color: {_MOCHA['overlay']};
        color: {_MOCHA['text']};
        selection-background-color: {_MOCHA['highlight']};
    }}
    QHeaderView::section {{
        background: {_MOCHA['overlay']};
        color: {_MOCHA['text']};
        padding: 4px;
        border: none;
    }}
    QTextEdit {{
        background: {_MOCHA['surface']};
        border: 1px solid {_MOCHA['overlay']};
        color: {_MOCHA['text']};
        font-family: monospace;
    }}
    QPushButton {{
        background: {_MOCHA['overlay']};
        border: 1px solid {_MOCHA['highlight']};
        color: {_MOCHA['text']};
        padding: 4px 10px;
        border-radius: 4px;
    }}
    QPushButton:hover {{
        background: {_MOCHA['highlight']};
    }}
    QLabel {{
        color: {_MOCHA['text']};
    }}
    QSplitter::handle {{
        background: {_MOCHA['overlay']};
    }}
"""

_COL_NAME = 0
_COL_VERSION = 1
_COL_AUTHOR = 2
_COL_STATUS = 3
_COL_DESC = 4
_COLUMNS = ["Name", "Version", "Author", "Status", "Description"]


# ---------------------------------------------------------------------------
# Plugin Manager Tab (UI)
# ---------------------------------------------------------------------------

class PluginManagerTab(QWidget):
    def __init__(self, plugin_manager: Optional[PluginManager] = None, parent=None) -> None:
        super().__init__(parent)
        self._pm = plugin_manager or PluginManager()
        self._setup_ui()
        self.setStyleSheet(_TAB_STYLE)
        self._refresh()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        # --- Toolbar ---
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self._btn_reload = QPushButton("Reload All")
        self._btn_reload.clicked.connect(self._on_reload)
        toolbar.addWidget(self._btn_reload)

        self._btn_open_dir = QPushButton("Open Plugins Dir")
        self._btn_open_dir.clicked.connect(self._on_open_dir)
        toolbar.addWidget(self._btn_open_dir)

        self._btn_install = QPushButton("Install from file…")
        self._btn_install.clicked.connect(self._on_install_file)
        toolbar.addWidget(self._btn_install)

        self._btn_directory = QPushButton("Directory…")
        self._btn_directory.setToolTip("Browse and install plugins from the local index.json")
        self._btn_directory.clicked.connect(self._on_open_directory)
        toolbar.addWidget(self._btn_directory)

        dir_label = QLabel(str(self._pm.plugin_dir))
        dir_label.setStyleSheet(f"color: {_MOCHA['text']}; font-family: monospace;")
        toolbar.addWidget(dir_label)
        toolbar.addStretch()
        root.addLayout(toolbar)

        # --- Splitter (table + detail) ---
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(4)

        # Table
        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.horizontalHeader().setSectionResizeMode(
            _COL_DESC, QHeaderView.ResizeMode.Stretch
        )
        self._table.horizontalHeader().setSectionResizeMode(
            _COL_NAME, QHeaderView.ResizeMode.ResizeToContents
        )
        self._table.verticalHeader().setVisible(False)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        splitter.addWidget(self._table)

        # Detail panel
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(4)

        self._detail_label = QLabel("Select a plugin to see details.")
        self._detail_label.setWordWrap(True)
        detail_layout.addWidget(self._detail_label)

        self._error_text = QTextEdit()
        self._error_text.setReadOnly(True)
        self._error_text.setPlaceholderText("Error details will appear here.")
        self._error_text.setMaximumHeight(100)
        self._error_text.setVisible(False)
        detail_layout.addWidget(self._error_text)

        splitter.addWidget(detail_widget)
        splitter.setSizes([300, 120])
        root.addWidget(splitter)

        # --- Load log ---
        log_label = QLabel("Load Log")
        root.addWidget(log_label)

        self._log = QTextEdit()
        self._log.setReadOnly(True)
        self._log.setMaximumHeight(130)
        root.addWidget(self._log)

    # ------------------------------------------------------------------
    # Slot handlers
    # ------------------------------------------------------------------

    def _on_reload(self) -> None:
        msgs = self._pm.reload_all()
        self._log.clear()
        self._log.setPlainText("\n".join(msgs))
        self._refresh()

    def _on_open_dir(self) -> None:
        subprocess.Popen(["xdg-open", str(self._pm.plugin_dir)])

    def _on_install_file(self) -> None:
        from PyQt6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getOpenFileName(
            self, "Install plugin (.py)", "", "Python (*.py)"
        )
        if not path:
            return
        from pathlib import Path
        ok, msg = self._pm.install_from_path(Path(path))
        self._log.append(f"[{'OK' if ok else 'ERROR'}] install: {msg}")
        self._refresh()

    def _on_open_directory(self) -> None:
        dlg = _PluginDirectoryDialog(self._pm, parent=self)
        dlg.exec()
        self._refresh()

    def _on_selection_changed(self) -> None:
        rows = self._table.selectedItems()
        if not rows:
            self._detail_label.setText("Select a plugin to see details.")
            self._error_text.setVisible(False)
            return

        row = self._table.currentRow()
        name_item = self._table.item(row, _COL_NAME)
        if name_item is None:
            return

        plugin_name = name_item.text()
        # Find the plugin or its error metadata
        plugin = next(
            (p for p in self._pm.loaded_plugins() if p.name == plugin_name),
            None,
        )
        meta = self._pm._meta.get(plugin_name, {})

        if plugin is not None:
            detail = (
                f"<b>{plugin.name}</b> v{plugin.version}"
                + (f" — {plugin.author}" if plugin.author else "")
                + (f"<br>{plugin.description}" if plugin.description else "")
            )
            self._detail_label.setText(detail)
            self._error_text.setVisible(False)
        else:
            # Error state — name might be the stem key
            err = meta.get("error", "")
            path = meta.get("path", "")
            self._detail_label.setText(
                f"<b>{plugin_name}</b> — failed to load<br><small>{path}</small>"
            )
            if err:
                self._error_text.setPlainText(err)
                self._error_text.setVisible(True)
            else:
                self._error_text.setVisible(False)

    # ------------------------------------------------------------------
    # Table population
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        """Rebuild the table from the current plugin manager state."""
        self._table.setRowCount(0)

        # Loaded plugins
        for plugin in self._pm.loaded_plugins():
            self._add_row(
                name=plugin.name,
                version=plugin.version,
                author=plugin.author,
                description=plugin.description,
                status="Loaded",
                error=None,
            )

        # Failed entries (stored in _meta but not in loaded_plugins)
        loaded_names = {p.name for p in self._pm.loaded_plugins()}
        for key, meta in self._pm._meta.items():
            if key not in loaded_names and meta.get("error"):
                self._add_row(
                    name=key,
                    version="",
                    author="",
                    description=meta.get("path", ""),
                    status="Error",
                    error=meta.get("error"),
                )

    def _add_row(
        self,
        name: str,
        version: str,
        author: str,
        description: str,
        status: str,
        error: Optional[str],
    ) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)

        self._table.setItem(row, _COL_NAME, QTableWidgetItem(name))
        self._table.setItem(row, _COL_VERSION, QTableWidgetItem(version))
        self._table.setItem(row, _COL_AUTHOR, QTableWidgetItem(author))
        self._table.setItem(row, _COL_DESC, QTableWidgetItem(description))

        status_item = QTableWidgetItem(status)
        if status == "Loaded":
            status_item.setForeground(QColor(_MOCHA["green"]))
        else:
            status_item.setForeground(QColor(_MOCHA["red"]))
        status_item.setTextAlignment(
            Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignVCenter
        )
        self._table.setItem(row, _COL_STATUS, status_item)


# ---------------------------------------------------------------------------
# Plugin directory browser
# ---------------------------------------------------------------------------

from PyQt6.QtWidgets import QDialog, QListWidget, QListWidgetItem, QMessageBox


class _PluginDirectoryDialog(QDialog):
    """Browse the local index.json + currently installed plugins.

    No network access — index.json is curated locally (or by a separate
    sync tool the user runs).  Entries point at local .py files; clicking
    Install copies that file into the plugins dir and loads it.
    """

    def __init__(self, pm: PluginManager, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._pm = pm
        self.setWindowTitle("Plugin Directory")
        self.resize(640, 460)
        self.setStyleSheet(
            "QDialog { background: #1e1e2e; color: #cdd6f4; }"
            "QListWidget { background: #181825; border: 1px solid #313244; color: #cdd6f4; }"
            "QListWidget::item:selected { background: #45475a; }"
            "QPushButton { background: #313244; border: 1px solid #45475a; "
            "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
            "QPushButton:hover { background: #45475a; }"
            "QLabel { color: #cdd6f4; }"
        )

        root = QVBoxLayout(self)

        # Index entries
        root.addWidget(QLabel("Available plugins (from local index.json):"))
        self._index_list = QListWidget()
        root.addWidget(self._index_list, 1)
        for entry in self._pm.read_index():
            label = f"{entry.get('name', '?')} — {entry.get('description', '')}"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, entry)
            self._index_list.addItem(item)
        if self._index_list.count() == 0:
            self._index_list.addItem("(no entries — drop an index.json in the plugins dir)")
            self._index_list.item(0).setFlags(Qt.ItemFlag.NoItemFlags)

        idx_btns = QHBoxLayout()
        idx_btns.addStretch()
        install_btn = QPushButton("Install selected")
        install_btn.clicked.connect(self._install_selected)
        idx_btns.addWidget(install_btn)
        root.addLayout(idx_btns)

        # Installed
        root.addWidget(QLabel("Installed plugin files:"))
        self._installed_list = QListWidget()
        root.addWidget(self._installed_list, 1)
        self._refresh_installed()

        inst_btns = QHBoxLayout()
        inst_btns.addStretch()
        uninstall_btn = QPushButton("Uninstall selected")
        uninstall_btn.clicked.connect(self._uninstall_selected)
        inst_btns.addWidget(uninstall_btn)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        inst_btns.addWidget(close_btn)
        root.addLayout(inst_btns)

    def _refresh_installed(self) -> None:
        self._installed_list.clear()
        for f in self._pm.list_installed_files():
            self._installed_list.addItem(f.name)

    def _install_selected(self) -> None:
        item = self._index_list.currentItem()
        if item is None or item.data(Qt.ItemDataRole.UserRole) is None:
            return
        entry = item.data(Qt.ItemDataRole.UserRole)
        src = Path(entry.get("path", ""))
        ok, msg = self._pm.install_from_path(src)
        if ok:
            QMessageBox.information(self, "Installed", f"Loaded: {msg}")
        else:
            QMessageBox.warning(self, "Install failed", msg)
        self._refresh_installed()

    def _uninstall_selected(self) -> None:
        item = self._installed_list.currentItem()
        if item is None:
            return
        stem = item.text().rsplit(".py", 1)[0]
        ok = self._pm.uninstall(stem)
        if ok:
            QMessageBox.information(self, "Uninstalled", f"Removed {stem}.py")
        else:
            QMessageBox.warning(self, "Uninstall failed", "Could not remove plugin file")
        self._refresh_installed()

