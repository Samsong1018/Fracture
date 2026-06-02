"""
System proxy manager — set/restore the OS-level HTTP/HTTPS proxy.

Supported platforms:
  - Linux (GNOME): gsettings
  - macOS: networksetup
  - Windows: registry (winreg) + WinINet refresh

Unsupported: KDE, XFCE, LXDE, i3, and other non-GNOME Linux desktops.
On those, users must set the proxy manually in their desktop settings.

Note: Firefox manages its own proxy settings independently of the system
proxy on all platforms. Set Firefox to "Use system proxy settings" in
about:preferences#general, or configure it manually as 127.0.0.1:8080.
"""

import platform
import shutil
import subprocess
from dataclasses import dataclass, field


@dataclass
class ProxySnapshot:
    """Saved state of the system proxy before Fracture touched it."""
    mode: str = "none"           # GNOME: none / manual / auto
    http_host: str = ""
    http_port: int = 0
    https_host: str = ""
    https_port: int = 0
    enabled: bool = False        # Windows: ProxyEnable
    server: str = ""             # Windows: ProxyServer
    services: list = field(default_factory=list)  # macOS: active network services


def _detect_platform() -> str:
    sys = platform.system()
    if sys == "Linux":
        if shutil.which("gsettings"):
            try:
                r = subprocess.run(
                    ["gsettings", "get", "org.gnome.system.proxy", "mode"],
                    capture_output=True, text=True, timeout=3,
                )
                if r.returncode == 0:
                    return "gnome"
            except Exception:
                pass
        return "unsupported"
    if sys == "Darwin":
        return "macos" if shutil.which("networksetup") else "unsupported"
    if sys == "Windows":
        return "windows"
    return "unsupported"


_PLATFORM = _detect_platform()


def is_supported() -> bool:
    return _PLATFORM != "unsupported"


def platform_label() -> str:
    return {
        "gnome": "GNOME (gsettings)",
        "macos": "macOS (networksetup)",
        "windows": "Windows (registry)",
        "unsupported": "unsupported",
    }.get(_PLATFORM, "unsupported")


def get_current() -> ProxySnapshot:
    """Snapshot the current system proxy settings."""
    if _PLATFORM == "gnome":
        return _gnome_get()
    if _PLATFORM == "macos":
        return _macos_get()
    if _PLATFORM == "windows":
        return _windows_get()
    return ProxySnapshot()


def set_proxy(host: str, port: int) -> bool:
    """Point the system proxy at host:port. Returns True on success."""
    try:
        if _PLATFORM == "gnome":
            _gnome_set(host, port)
        elif _PLATFORM == "macos":
            _macos_set(host, port)
        elif _PLATFORM == "windows":
            _windows_set(host, port)
        else:
            return False
        return True
    except Exception:
        return False


def restore(snapshot: ProxySnapshot) -> bool:
    """Restore proxy settings from a saved snapshot. Returns True on success."""
    try:
        if _PLATFORM == "gnome":
            _gnome_restore(snapshot)
        elif _PLATFORM == "macos":
            _macos_restore(snapshot)
        elif _PLATFORM == "windows":
            _windows_restore(snapshot)
        else:
            return False
        return True
    except Exception:
        return False


# ── GNOME ──────────────────────────────────────────────────────────────────

def _gs(schema: str, key: str, value: str | None = None) -> str:
    if value is None:
        r = subprocess.run(
            ["gsettings", "get", schema, key],
            capture_output=True, text=True, timeout=3,
        )
        return r.stdout.strip().strip("'")
    subprocess.run(
        ["gsettings", "set", schema, key, value],
        timeout=3, check=True,
    )
    return ""


def _gnome_get() -> ProxySnapshot:
    try:
        return ProxySnapshot(
            mode=_gs("org.gnome.system.proxy", "mode"),
            http_host=_gs("org.gnome.system.proxy.http", "host"),
            http_port=int(_gs("org.gnome.system.proxy.http", "port") or 0),
            https_host=_gs("org.gnome.system.proxy.https", "host"),
            https_port=int(_gs("org.gnome.system.proxy.https", "port") or 0),
        )
    except Exception:
        return ProxySnapshot()


def _gnome_set(host: str, port: int) -> None:
    _gs("org.gnome.system.proxy", "mode", "manual")
    _gs("org.gnome.system.proxy.http", "host", host)
    _gs("org.gnome.system.proxy.http", "port", str(port))
    _gs("org.gnome.system.proxy.https", "host", host)
    _gs("org.gnome.system.proxy.https", "port", str(port))


def _gnome_restore(snap: ProxySnapshot) -> None:
    _gs("org.gnome.system.proxy", "mode", snap.mode or "none")
    _gs("org.gnome.system.proxy.http", "host", snap.http_host)
    _gs("org.gnome.system.proxy.http", "port", str(snap.http_port))
    _gs("org.gnome.system.proxy.https", "host", snap.https_host)
    _gs("org.gnome.system.proxy.https", "port", str(snap.https_port))


# ── macOS ──────────────────────────────────────────────────────────────────

def _macos_services() -> list[str]:
    r = subprocess.run(
        ["networksetup", "-listallnetworkservices"],
        capture_output=True, text=True, timeout=5,
    )
    lines = r.stdout.splitlines()
    return [l for l in lines[1:] if l and not l.startswith("*")]


def _macos_get() -> ProxySnapshot:
    return ProxySnapshot(services=_macos_services())


def _macos_set(host: str, port: int) -> None:
    for svc in _macos_services():
        subprocess.run(["networksetup", "-setwebproxy", svc, host, str(port)], timeout=5)
        subprocess.run(["networksetup", "-setsecurewebproxy", svc, host, str(port)], timeout=5)
        subprocess.run(["networksetup", "-setwebproxystate", svc, "on"], timeout=5)
        subprocess.run(["networksetup", "-setsecurewebproxystate", svc, "on"], timeout=5)


def _macos_restore(snap: ProxySnapshot) -> None:
    for svc in snap.services:
        subprocess.run(["networksetup", "-setwebproxystate", svc, "off"], timeout=5)
        subprocess.run(["networksetup", "-setsecurewebproxystate", svc, "off"], timeout=5)


# ── Windows ────────────────────────────────────────────────────────────────

def _windows_get() -> ProxySnapshot:
    try:
        import winreg  # type: ignore[import]
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        )
        enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
        try:
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
        except FileNotFoundError:
            server = ""
        winreg.CloseKey(key)
        return ProxySnapshot(enabled=bool(enabled), server=server)
    except Exception:
        return ProxySnapshot()


def _windows_set(host: str, port: int) -> None:
    import winreg  # type: ignore[import]
    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0, winreg.KEY_SET_VALUE,
    )
    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"{host}:{port}")
    winreg.CloseKey(key)
    _windows_notify()


def _windows_restore(snap: ProxySnapshot) -> None:
    import winreg  # type: ignore[import]
    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0, winreg.KEY_SET_VALUE,
    )
    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, int(snap.enabled))
    if snap.server:
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, snap.server)
    winreg.CloseKey(key)
    _windows_notify()


def _windows_notify() -> None:
    """Broadcast the proxy change to running processes via WinINet."""
    try:
        import ctypes
        wininet = ctypes.windll.wininet  # type: ignore[attr-defined]
        wininet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        wininet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH
    except Exception:
        pass
