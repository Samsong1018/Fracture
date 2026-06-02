"""
Project save/load for Fracture.

Saves and loads Fracture sessions to/from gzip-compressed JSON files
with the `.cough` extension. A project file contains proxy history,
scope patterns, match & replace rules, annotations, and metadata.
"""

import base64
import csv
import gzip
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Optional

from .proxy import HttpRequest, HttpResponse

# Project file format version — increment when the schema changes in a
# backwards-incompatible way.
FORMAT_VERSION = 1

# Where recent-project state is persisted.
_RECENT_FILE = Path.home() / ".fracture" / "recent.json"
_RECENT_MAX = 10


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def _serialize_request(req: HttpRequest) -> dict:
    return {
        "id": req.id,
        "method": req.method,
        "host": req.host,
        "port": req.port,
        "path": req.path,
        "version": req.version,
        "headers": req.headers,
        "body": base64.b64encode(req.body).decode(),
        "is_https": req.is_https,
        "timestamp": req.timestamp.isoformat(),
        "raw": base64.b64encode(req.raw).decode(),
    }


def _deserialize_request(d: dict) -> HttpRequest:
    return HttpRequest(
        id=d["id"],
        method=d["method"],
        host=d["host"],
        port=d["port"],
        path=d["path"],
        version=d["version"],
        headers=d["headers"],
        body=base64.b64decode(d["body"]),
        is_https=d["is_https"],
        timestamp=datetime.fromisoformat(d["timestamp"]),
        raw=base64.b64decode(d["raw"]),
    )


def _serialize_response(resp: HttpResponse) -> dict:
    return {
        "request_id": resp.request_id,
        "status_code": resp.status_code,
        "status_text": resp.status_text,
        "headers": resp.headers,
        "body": base64.b64encode(resp.body).decode(),
        "raw": base64.b64encode(resp.raw).decode(),
    }


def _deserialize_response(d: dict) -> HttpResponse:
    return HttpResponse(
        request_id=d["request_id"],
        status_code=d["status_code"],
        status_text=d["status_text"],
        headers=d["headers"],
        body=base64.b64decode(d["body"]),
        raw=base64.b64decode(d["raw"]),
    )


# ---------------------------------------------------------------------------
# ProjectManager
# ---------------------------------------------------------------------------


class ProjectManager:
    """Save and load Fracture project files (`.cough`)."""

    def save(
        self,
        path: "str | Path",
        history: list[tuple],
        scope_patterns: list[str],
        mr_rules: list[dict],
        annotations: dict[int, dict],
        project_name: str = "",
        notes: str = "",
    ) -> None:
        """Serialize the current session to *path* as a gzip-compressed JSON file.

        Args:
            path: Destination file path (should end with `.cough`).
            history: List of ``(HttpRequest, HttpResponse | None)`` tuples.
            scope_patterns: List of scope pattern strings.
            mr_rules: List of serialized match-and-replace rule dicts.
            annotations: Mapping of request id → ``{color, note}`` dict.
            project_name: Human-readable project label stored in metadata.
        """
        path = Path(path)

        serialized_history = []
        for req, resp in history:
            entry: dict = {"request": _serialize_request(req)}
            if resp is not None:
                entry["response"] = _serialize_response(resp)
            else:
                entry["response"] = None
            serialized_history.append(entry)

        # JSON requires string keys; convert int annotation keys.
        serialized_annotations = {str(k): v for k, v in annotations.items()}

        payload = {
            "format_version": FORMAT_VERSION,
            "project_name": project_name,
            "saved_at": datetime.now().isoformat(),
            "history": serialized_history,
            "scope_patterns": scope_patterns,
            "mr_rules": mr_rules,
            "annotations": serialized_annotations,
            "notes": notes,
        }

        data = json.dumps(payload, indent=2).encode()
        path.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(path, "wb") as f:
            f.write(data)

    def load(self, path: "str | Path") -> dict:
        """Deserialize a `.cough` project file.

        Returns a dict with keys:
            ``history``         – list of ``(HttpRequest, HttpResponse | None)``
            ``scope_patterns``  – list of str
            ``mr_rules``        – list of dict
            ``annotations``     – ``{int: {color, note}}``
            ``project_name``    – str
            ``saved_at``        – str (ISO-8601 timestamp)
        """
        path = Path(path)

        with gzip.open(path, "rb") as f:
            data = f.read()

        payload: dict = json.loads(data.decode())

        file_version = payload.get("format_version", 1)
        if file_version > FORMAT_VERSION:
            raise ValueError(
                f"Project file version {file_version} is newer than this version of "
                f"Fracture (supports up to {FORMAT_VERSION}). Please upgrade."
            )

        history: list[tuple] = []
        for entry in payload.get("history", []):
            req = _deserialize_request(entry["request"])
            resp_data = entry.get("response")
            resp: Optional[HttpResponse] = (
                _deserialize_response(resp_data) if resp_data is not None else None
            )
            history.append((req, resp))

        # Restore int keys for annotations.
        raw_annotations: dict = payload.get("annotations", {})
        annotations: dict[int, dict] = {int(k): v for k, v in raw_annotations.items()}

        return {
            "history": history,
            "scope_patterns": payload.get("scope_patterns", []),
            "mr_rules": payload.get("mr_rules", []),
            "annotations": annotations,
            "project_name": payload.get("project_name", ""),
            "saved_at": payload.get("saved_at", ""),
            "notes": payload.get("notes", ""),
        }


# ---------------------------------------------------------------------------
# RecentProjects
# ---------------------------------------------------------------------------


class RecentProjects:
    """Persist a capped list of recently opened project file paths.

    Paths are stored in ``~/.fracture/recent.json`` (most-recent first).
    Only paths that still exist on disk are returned by :meth:`get`.
    """

    def __init__(self, recent_file: Path = _RECENT_FILE, max_entries: int = _RECENT_MAX):
        self._file = recent_file
        self._max = max_entries

    def _read(self) -> list[str]:
        if not self._file.exists():
            return []
        try:
            with self._file.open("r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError):
            return []

    def _write(self, entries: list[str]) -> None:
        self._file.parent.mkdir(parents=True, exist_ok=True)
        with self._file.open("w", encoding="utf-8") as f:
            json.dump(entries, f, indent=2)

    def add(self, path: str) -> None:
        """Prepend *path* to the recent list, deduplicating and capping at max."""
        path = str(Path(path).resolve())
        entries = self._read()
        # Remove any existing occurrence so it rises to the top.
        entries = [e for e in entries if e != path]
        entries.insert(0, path)
        entries = entries[: self._max]
        self._write(entries)

    def get(self) -> list[str]:
        """Return recent paths, most-recent first, filtered to existing files."""
        return [p for p in self._read() if Path(p).exists()]

    def clear(self) -> None:
        """Remove all recorded recent project paths."""
        self._write([])


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------


def export_csv(history: list, path: str) -> None:
    """Write proxy history to a CSV file."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["#", "Method", "Host", "Path", "Status", "Req Length", "Resp Length"])
        for i, (req, resp) in enumerate(history, start=1):
            status = getattr(resp, "status_code", "") if resp else ""
            req_len = len(getattr(req, "raw", b""))
            resp_len = len(getattr(resp, "raw", b"")) if resp else 0
            writer.writerow([i, req.method, req.host, req.path, status, req_len, resp_len])


def export_burp_xml(history: list, path: str) -> None:
    """Write proxy history as Burp-compatible XML."""
    root = ET.Element("items", attrib={
        "burpVersion": "Fracture",
        "exportTime": datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y"),
    })
    for req, resp in history:
        item = ET.SubElement(root, "item")
        scheme = "https" if getattr(req, "is_https", False) else "http"
        ET.SubElement(item, "url").text = f"{scheme}://{req.host}{req.path}"
        ET.SubElement(item, "host", attrib={"ip": ""}).text = req.host
        ET.SubElement(item, "port").text = str(getattr(req, "port", 443 if req.is_https else 80))
        ET.SubElement(item, "protocol").text = scheme
        ET.SubElement(item, "method").text = req.method
        ET.SubElement(item, "path").text = req.path
        ET.SubElement(item, "extension")
        req_b64 = base64.b64encode(getattr(req, "raw", b"")).decode("ascii")
        ET.SubElement(item, "request", attrib={"base64": "true"}).text = req_b64
        if resp:
            ET.SubElement(item, "status").text = str(resp.status_code)
            ET.SubElement(item, "responselength").text = str(len(getattr(resp, "raw", b"")))
            content_type = (getattr(resp, "headers", {}) or {}).get("content-type", "")
            ET.SubElement(item, "mimetype").text = content_type.split(";")[0].strip()
            resp_b64 = base64.b64encode(getattr(resp, "raw", b"")).decode("ascii")
            ET.SubElement(item, "response", attrib={"base64": "true"}).text = resp_b64
        else:
            ET.SubElement(item, "status").text = ""
            ET.SubElement(item, "responselength").text = "0"
            ET.SubElement(item, "mimetype").text = ""
            ET.SubElement(item, "response", attrib={"base64": "true"}).text = ""
        ET.SubElement(item, "comment")

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    with open(path, "wb") as f:
        f.write(b'<?xml version="1.0"?>\n')
        tree.write(f, encoding="utf-8", xml_declaration=False)
