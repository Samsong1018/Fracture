import json
from pathlib import Path
from .models import Finding, Session

DATA_DIR = Path.home() / ".pentest-notes"

_FINDING_FIELDS = set(Finding.__dataclass_fields__.keys())
_SESSION_FIELDS = set(Session.__dataclass_fields__.keys())


def _ensure():
    DATA_DIR.mkdir(exist_ok=True)


def load_settings() -> dict:
    _ensure()
    path = DATA_DIR / "settings.json"
    if path.exists():
        with open(path) as fp:
            return json.load(fp)
    return {"vault_path": str(Path.home() / "AmosH")}


def save_settings(settings: dict):
    _ensure()
    path = DATA_DIR / "settings.json"
    with open(path, "w") as fp:
        json.dump(settings, fp, indent=2)


def save_session(session: Session):
    _ensure()
    path = DATA_DIR / f"{session.id}.json"
    data = {
        "id": session.id,
        "name": session.name,
        "target_host": session.target_host,
        "exec_summary": session.exec_summary,
        "recon_notes": session.recon_notes,
        "important_notes": session.important_notes,
        "created_at": session.created_at,
        "findings": [
            {
                "id": f.id,
                "vuln_type": f.vuln_type,
                "target": f.target,
                "severity": f.severity,
                "phase": f.phase,
                "status": f.status,
                "payload": f.payload,
                "request_raw": f.request_raw,
                "response_raw": f.response_raw,
                "accessed": f.accessed,
                "notes": f.notes,
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "images": f.images,
                "created_at": f.created_at,
                "updated_at": f.updated_at,
            }
            for f in session.findings
        ],
    }
    with open(path, "w") as fp:
        json.dump(data, fp, indent=2)


def load_sessions() -> list:
    _ensure()
    sessions = []
    for p in DATA_DIR.glob("*.json"):
        if p.name == "settings.json":
            continue
        try:
            with open(p) as fp:
                data = json.load(fp)
            findings = []
            for f in data.get("findings", []):
                findings.append(Finding(**{k: v for k, v in f.items() if k in _FINDING_FIELDS}))
            s = Session(
                id=data["id"],
                name=data["name"],
                target_host=data.get("target_host", ""),
                exec_summary=data.get("exec_summary", ""),
                recon_notes=data.get("recon_notes", ""),
                important_notes=data.get("important_notes", ""),
                findings=findings,
                created_at=data["created_at"],
            )
            sessions.append(s)
        except Exception:
            continue
    return sorted(sessions, key=lambda s: s.created_at, reverse=True)


def delete_session(session_id: str):
    _ensure()
    path = DATA_DIR / f"{session_id}.json"
    if path.exists():
        path.unlink()
