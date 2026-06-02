"""
Scope management for Fracture proxy.

ScopeManager tracks a list of host patterns and reports whether a given
host is in scope.  An empty pattern list means everything is in scope.
"""

import fnmatch


class ScopeManager:
    def __init__(self) -> None:
        self._patterns: list[str] = []

    def add(self, pattern: str) -> None:
        """Add a scope pattern (e.g. 'example.com' or '*.example.com')."""
        pattern = pattern.strip()
        if pattern and pattern not in self._patterns:
            self._patterns.append(pattern)

    def remove(self, pattern: str) -> None:
        """Remove a scope pattern if it exists."""
        try:
            self._patterns.remove(pattern)
        except ValueError:
            pass

    def in_scope(self, host: str) -> bool:
        """Return True if host is in scope.

        If no patterns are defined every host is considered in scope.
        Matching rules (first match wins):
          - Empty list → always True
          - '*.example.com' → matches any direct subdomain via fnmatch
          - 'example.com'   → exact equality
          - Any other string → startswith or equality check
        """
        if not self._patterns:
            return True
        host = host.lower()
        for pattern in self._patterns:
            p = pattern.lower()
            if "*" in p:
                if fnmatch.fnmatch(host, p):
                    return True
            else:
                if host == p or host.startswith(p):
                    return True
        return False

    def patterns(self) -> list[str]:
        """Return a copy of the current pattern list."""
        return list(self._patterns)
