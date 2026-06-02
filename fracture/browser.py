"""
Embedded browser tab.

QtWebEngine-based browser pre-configured to route traffic through the local
proxy.  The proxy server flag is set via QTWEBENGINE_CHROMIUM_FLAGS at process
start (see __main__).  Cert errors are auto-accepted inside this profile since
all traffic is MITM'd through our own CA.

A user-script ("DOM Invader Lite") wraps eval / document.write / innerHTML /
postMessage / location-href and forwards events to a Python-side panel using
window.coughLog (installed via QWebChannel).  Falls back to console.log polling
when QWebChannel is unavailable.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from PyQt6.QtCore import Qt, QUrl, pyqtSignal, pyqtSlot, QObject
from PyQt6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

try:
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    from PyQt6.QtWebEngineCore import (
        QWebEnginePage,
        QWebEngineScript,
        QWebEngineProfile,
    )
    _ENGINE_OK = True
except Exception:  # pragma: no cover
    _ENGINE_OK = False
    QWebEngineView = None  # type: ignore[assignment,misc]
    QWebEnginePage = None  # type: ignore[assignment,misc]
    QWebEngineScript = None  # type: ignore[assignment,misc]
    QWebEngineProfile = None  # type: ignore[assignment,misc]

try:
    from PyQt6.QtWebChannel import QWebChannel
    _CHANNEL_OK = True
except Exception:  # pragma: no cover
    _CHANNEL_OK = False
    QWebChannel = None  # type: ignore[assignment,misc]


_LINEEDIT_SS = (
    "QLineEdit { background: #181825; border: 1px solid #313244; "
    "padding: 4px; color: #cdd6f4; }"
)
_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
    "QPushButton:hover { background: #45475a; }"
)
_TEXT_SS = (
    "QPlainTextEdit { background: #181825; border: 1px solid #313244; "
    "color: #cdd6f4; font-family: monospace; font-size: 12px; }"
)


# ---------------------------------------------------------------------------
# Hook script — runs in every frame at document start
# ---------------------------------------------------------------------------

_HOOK_JS = r"""
(function() {
  'use strict';
  if (window.__coughHooked) return;
  window.__coughHooked = true;

  function report(kind, value, stack) {
    try {
      var msg = { kind: kind, value: String(value).slice(0, 500),
                  stack: (stack || '').slice(0, 500),
                  url: location.href };
      if (window.coughLog && typeof window.coughLog.event === 'function') {
        window.coughLog.event(JSON.stringify(msg));
      } else {
        // Fallback channel: console with a magic prefix
        console.log('[[COUGH]] ' + JSON.stringify(msg));
      }
    } catch (e) {}
  }

  // eval()
  var _eval = window.eval;
  window.eval = function(src) {
    report('eval', src, new Error().stack);
    return _eval.apply(this, arguments);
  };

  // document.write()
  var _dw = document.write;
  document.write = function(s) {
    report('document.write', s, new Error().stack);
    return _dw.apply(document, arguments);
  };

  // innerHTML / outerHTML setter
  ['innerHTML', 'outerHTML'].forEach(function(prop) {
    var proto = Element.prototype;
    var desc = Object.getOwnPropertyDescriptor(proto, prop);
    if (!desc || !desc.set) return;
    var origSet = desc.set;
    Object.defineProperty(proto, prop, {
      configurable: true,
      enumerable: desc.enumerable,
      get: desc.get,
      set: function(v) {
        report(prop, v, new Error().stack);
        return origSet.call(this, v);
      }
    });
  });

  // location assignments
  ['href', 'replace', 'assign'].forEach(function(key) {
    try {
      var orig = location[key];
      if (typeof orig === 'function') {
        location[key] = function(v) {
          report('location.' + key, v, new Error().stack);
          return orig.call(location, v);
        };
      }
    } catch (e) {}
  });

  // postMessage receive — record source origin + data
  window.addEventListener('message', function(ev) {
    report('postMessage', JSON.stringify({ origin: ev.origin, data: ev.data }),
           new Error().stack);
  }, true);

  // setTimeout / setInterval with string args
  ['setTimeout', 'setInterval'].forEach(function(name) {
    var orig = window[name];
    window[name] = function(fn) {
      if (typeof fn === 'string') {
        report(name + '(string)', fn, new Error().stack);
      }
      return orig.apply(this, arguments);
    };
  });

  report('hooks-installed', '', '');
})();
"""


if _ENGINE_OK:

    class _AcceptCertsPage(QWebEnginePage):
        """Page that auto-accepts cert errors AND forwards console messages."""

        def __init__(self, parent=None):
            super().__init__(parent)
            self.on_console: Optional[callable] = None  # set by BrowserTab

        def certificateError(self, error) -> bool:  # type: ignore[override]
            try:
                error.acceptCertificate()
            except Exception:
                pass
            return True

        def javaScriptConsoleMessage(self, level, message, line_number, source_id):
            # Catch the "[[COUGH]] {...}" fallback channel
            if message.startswith("[[COUGH]] "):
                if self.on_console:
                    try:
                        self.on_console(message[len("[[COUGH]] "):])
                    except Exception:
                        pass
                return  # don't propagate to default sink
            return super().javaScriptConsoleMessage(level, message, line_number, source_id)


class _LogBridge(QObject):
    """QObject exposed to JavaScript via QWebChannel as window.coughLog."""

    event_received = pyqtSignal(str)

    @pyqtSlot(str)
    def event(self, payload: str) -> None:
        self.event_received.emit(payload)


class BrowserTab(QWidget):
    """Address-bar + WebView routed through the local proxy with DOM hooks."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)

        root = QVBoxLayout(self)

        # Top bar
        bar = QHBoxLayout()
        self.back_btn = QPushButton("◀")
        self.back_btn.setStyleSheet(_BTN_SS)
        bar.addWidget(self.back_btn)

        self.fwd_btn = QPushButton("▶")
        self.fwd_btn.setStyleSheet(_BTN_SS)
        bar.addWidget(self.fwd_btn)

        self.reload_btn = QPushButton("⟳")
        self.reload_btn.setStyleSheet(_BTN_SS)
        bar.addWidget(self.reload_btn)

        self.address_edit = QLineEdit()
        self.address_edit.setStyleSheet(_LINEEDIT_SS)
        self.address_edit.setPlaceholderText("https://example.com")
        bar.addWidget(self.address_edit, 1)

        self.go_btn = QPushButton("Go")
        self.go_btn.setStyleSheet(_BTN_SS)
        bar.addWidget(self.go_btn)

        self.hooks_check = QCheckBox("DOM hooks")
        self.hooks_check.setChecked(True)
        self.hooks_check.setStyleSheet("color: #cdd6f4;")
        self.hooks_check.setToolTip("Hook eval, document.write, innerHTML, postMessage, etc.")
        bar.addWidget(self.hooks_check)

        root.addLayout(bar)

        if _ENGINE_OK:
            split = QSplitter(Qt.Orientation.Vertical)

            self._view = QWebEngineView()
            self._page = _AcceptCertsPage(self._view)
            self._page.on_console = self._on_console_event
            self._view.setPage(self._page)
            split.addWidget(self._view)

            # Log panel
            panel = QWidget()
            pv = QVBoxLayout(panel)
            pv.setContentsMargins(0, 0, 0, 0)
            ctl = QHBoxLayout()
            ctl.addWidget(QLabel("DOM events:"))
            clear_btn = QPushButton("Clear")
            clear_btn.setStyleSheet(_BTN_SS)
            ctl.addStretch()
            ctl.addWidget(clear_btn)
            pv.addLayout(ctl)
            self._log = QPlainTextEdit()
            self._log.setReadOnly(True)
            self._log.setStyleSheet(_TEXT_SS)
            pv.addWidget(self._log)
            split.addWidget(panel)
            split.setSizes([520, 200])
            root.addWidget(split, 1)

            clear_btn.clicked.connect(self._log.clear)

            self.back_btn.clicked.connect(self._view.back)
            self.fwd_btn.clicked.connect(self._view.forward)
            self.reload_btn.clicked.connect(self._view.reload)
            self.go_btn.clicked.connect(self._go)
            self.address_edit.returnPressed.connect(self._go)
            self._view.urlChanged.connect(self._on_url_changed)
            self.hooks_check.stateChanged.connect(self._toggle_hooks)

            # Set up the QWebChannel bridge once a profile is available.
            self._bridge: Optional[_LogBridge] = None
            self._channel = None
            if _CHANNEL_OK:
                self._bridge = _LogBridge()
                self._bridge.event_received.connect(self._on_bridge_event)
                self._channel = QWebChannel(self._page)
                self._channel.registerObject("coughLog", self._bridge)
                self._page.setWebChannel(self._channel)

            self._install_hook_script()
        else:
            placeholder = QLabel(
                "QtWebEngine is not installed.\n\n"
                "Install with:  pip install PyQt6-WebEngine\n\n"
                "Once installed, the embedded browser will route traffic\n"
                "through the local proxy automatically."
            )
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            placeholder.setStyleSheet("color: #a6adc8; font-size: 14px;")
            root.addWidget(placeholder, 1)
            self._log = None

    # ------------------------------------------------------------------
    def _install_hook_script(self) -> None:
        if not _ENGINE_OK:
            return
        profile = self._page.profile() if hasattr(self._page, "profile") else QWebEngineProfile.defaultProfile()
        scripts = profile.scripts()
        # Remove any previous hook so toggling is clean
        for s in scripts.find("coughHooks"):
            scripts.remove(s)
        if not self.hooks_check.isChecked():
            return

        # Optional QWebChannel boot script
        channel_boot = ""
        if _CHANNEL_OK:
            channel_boot = """
            (function() {
              var s = document.createElement('script');
              s.src = 'qrc:///qtwebchannel/qwebchannel.js';
              s.onload = function() {
                new QWebChannel(qt.webChannelTransport, function(channel) {
                  window.coughLog = channel.objects.coughLog;
                });
              };
              (document.head || document.documentElement).appendChild(s);
            })();
            """

        script = QWebEngineScript()
        script.setName("coughHooks")
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        script.setRunsOnSubFrames(True)
        script.setSourceCode(channel_boot + _HOOK_JS)
        scripts.insert(script)

    def _toggle_hooks(self) -> None:
        self._install_hook_script()
        # Reload current page so the new state takes effect
        if _ENGINE_OK:
            try:
                self._view.reload()
            except Exception:
                pass

    def _on_console_event(self, payload: str) -> None:
        self._append_event(payload)

    def _on_bridge_event(self, payload: str) -> None:
        self._append_event(payload)

    def _append_event(self, payload: str) -> None:
        if self._log is None:
            return
        ts = datetime.now().strftime("%H:%M:%S")
        self._log.appendPlainText(f"[{ts}] {payload}")

    def _go(self) -> None:
        if not _ENGINE_OK:
            return
        url_text = self.address_edit.text().strip()
        if not url_text:
            return
        if "://" not in url_text:
            url_text = "http://" + url_text
        self._view.setUrl(QUrl(url_text))

    def _on_url_changed(self, url: QUrl) -> None:
        self.address_edit.setText(url.toString())

    def render_html(self, html: str, base_url: str = "") -> None:
        """Render raw HTML in the embedded view. Used by 'Render in Browser'."""
        if not _ENGINE_OK:
            return
        try:
            self._view.setHtml(html, QUrl(base_url) if base_url else QUrl())
        except Exception:
            pass


def configure_chromium_flags(proxy_host: str = "127.0.0.1", proxy_port: int = 8080) -> None:
    """Set QTWEBENGINE_CHROMIUM_FLAGS so the embedded browser uses our proxy.

    Must be called BEFORE QApplication is constructed.
    """
    import os
    flags = (
        f"--proxy-server={proxy_host}:{proxy_port} "
        "--ignore-certificate-errors "
        "--ignore-urlfetcher-cert-requests"
    )
    existing = os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "")
    if flags not in existing:
        os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
            existing + " " + flags if existing else flags
        ).strip()
