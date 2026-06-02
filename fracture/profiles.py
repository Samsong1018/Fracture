"""
Project configuration profiles.

A profile bundles non-history config — scope patterns, M&R rules, TLS
passthrough hosts, upstream proxy settings, collaborator public host, and
session-handling rules — so users can switch contexts (engagement-to-
engagement) without re-typing them.

Persisted as JSON under ~/.fracture/profiles/<name>.json.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional


def profiles_dir() -> Path:
    base = Path(os.path.expanduser("~/.fracture/profiles"))
    base.mkdir(parents=True, exist_ok=True)
    return base


def list_profiles() -> list[str]:
    return sorted(p.stem for p in profiles_dir().glob("*.json"))


def _profile_path(name: str) -> Path:
    safe = "".join(c for c in name if c.isalnum() or c in "-_") or "default"
    return profiles_dir() / f"{safe}.json"


def save_profile(name: str, data: dict) -> Path:
    path = _profile_path(name)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def load_profile(name: str) -> Optional[dict]:
    path = _profile_path(name)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def delete_profile(name: str) -> bool:
    path = _profile_path(name)
    if path.exists():
        path.unlink()
        return True
    return False


# ---------------------------------------------------------------------------
# Capture / restore helpers — operate on a MainWindow
# ---------------------------------------------------------------------------

def capture(window) -> dict:
    """Snapshot the current non-history state of a MainWindow."""
    proxy = window._proxy
    data: dict = {
        "scope_patterns": list(proxy.scope.patterns()),
        "tls_passthrough_hosts": list(proxy.tls_passthrough_hosts),
        "upstream": {
            "host": proxy.upstream_host or "",
            "port": proxy.upstream_port or 0,
            "type": proxy.upstream_type or "http",
        },
        "mr_rules": [
            {"id": r.id, "enabled": r.enabled, "target": r.target.value,
             "pattern": r.pattern, "replacement": r.replacement,
             "is_regex": r.is_regex, "comment": r.comment}
            for r in proxy.match_replace.rules()
        ],
        "collaborator_public_host": window.collaborator_tab._server.get_public_host(),
        "session_rules": [
            {
                "name": r.name, "scope": r.scope, "enabled": r.enabled,
                "apply_to": sorted(r.apply_to),
                "actions": [{"type": a.type, "name": a.name, "value": a.value}
                            for a in r.actions],
            }
            for r in window.session_rule_engine.rules
        ],
    }
    return data


def restore(window, data: dict) -> None:
    """Replace the current non-history state with values from *data*."""
    from .match_replace import MRTarget
    from .session_rules import SessionAction, SessionRule

    proxy = window._proxy

    # Scope
    for p in list(proxy.scope.patterns()):
        proxy.scope.remove(p)
    for p in data.get("scope_patterns", []):
        proxy.scope.add(p)

    # TLS passthrough
    for h in list(proxy.tls_passthrough_hosts):
        proxy.remove_tls_passthrough(h)
    for h in data.get("tls_passthrough_hosts", []):
        proxy.add_tls_passthrough(h)

    # Upstream
    up = data.get("upstream") or {}
    if up.get("host"):
        proxy.upstream_host = up["host"]
        proxy.upstream_port = up.get("port") or 0
        proxy.upstream_type = up.get("type", "http")
    else:
        proxy.upstream_host = None
        proxy.upstream_port = None

    # M&R rules
    for r in list(proxy.match_replace.rules()):
        proxy.match_replace.remove_rule(r.id)
    for r in data.get("mr_rules", []):
        try:
            proxy.match_replace.add_rule(
                MRTarget(r["target"]), r["pattern"], r["replacement"],
                r.get("is_regex", True), r.get("comment", ""),
            )
        except Exception:
            pass

    # Collaborator
    pub = data.get("collaborator_public_host", "")
    window.collaborator_tab._server.set_public_host(pub)

    # Session rules
    window.session_rule_engine.rules.clear()
    for r in data.get("session_rules", []):
        rule = SessionRule(
            name=r.get("name", ""), scope=r.get("scope", ""),
            enabled=r.get("enabled", True),
            apply_to=set(r.get("apply_to", ["Repeater", "Intruder", "Scanner"])),
            actions=[SessionAction(**a) for a in r.get("actions", [])],
        )
        window.session_rule_engine.rules.append(rule)
    # Refresh session-rules UI if it has a list widget
    try:
        window.session_rules_tab._refresh_list()
    except Exception:
        pass
