from pathlib import Path
from datetime import datetime
from .models import Finding, Session, CVSS_RANGES, REMEDIATION, SEVERITIES


def _safe(s: str) -> str:
    for ch in r' /\:*?"<>|':
        s = s.replace(ch, "-")
    return s


def _or(s: str, fallback: str) -> str:
    return s.strip() if s.strip() else fallback


# ---------------------------------------------------------------------------
# Single finding export
# ---------------------------------------------------------------------------

def export_finding(finding: Finding, session: Session, vault_path: str) -> str:
    vault = Path(vault_path)
    findings_dir = vault / "Findings"
    findings_dir.mkdir(parents=True, exist_ok=True)

    date = datetime.now().strftime("%Y-%m-%d")
    target_safe = (_safe(finding.target)[:30] if finding.target else "unknown")
    vuln_safe = _safe(finding.vuln_type)
    filename = f"{date}-{vuln_safe}-{target_safe}.md"
    filepath = findings_dir / filename

    remediation = REMEDIATION.get(finding.vuln_type, REMEDIATION["Other"])
    cvss = CVSS_RANGES.get(finding.severity, "N/A")
    tags = [
        _safe(finding.vuln_type).lower(),
        finding.severity.lower(),
        _safe(finding.phase).lower(),
        "pentest",
        "finding",
    ]

    score_line = f"{finding.cvss_score} ({finding.cvss_vector})" if finding.cvss_score else cvss

    payload_block  = _or(finding.payload, "_No payload recorded._")
    accessed_block = _or(finding.accessed, "_Not specified._")
    notes_block    = _or(finding.notes, "_No notes._")

    request_section = ""
    if finding.request_raw.strip():
        request_section = f"\n## HTTP Request\n\n```http\n{finding.request_raw.strip()}\n```\n"

    response_section = ""
    if finding.response_raw.strip():
        response_section = f"\n## HTTP Response\n\n```http\n{finding.response_raw.strip()}\n```\n"

    images_section = ""
    if finding.images:
        images_section = "\n## Screenshots\n\n"
        for img in finding.images:
            images_section += f"![[{Path(img).name}]]\n"

    md = f"""---
type: finding
vuln: {finding.vuln_type}
severity: {finding.severity}
target: "{finding.target}"
phase: {finding.phase}
status: {finding.status}
engagement: "{session.name}"
cvss: "{score_line}"
date: {date}
tags: [{", ".join(tags)}]
---

# {finding.vuln_type} — {finding.target}

| Field | Value |
|-------|-------|
| **Severity** | {finding.severity} |
| **Phase** | {finding.phase} |
| **Status** | {finding.status} |
| **CVSS** | {score_line} |
| **Engagement** | {session.name} |

## Payload / Code Used

```
{payload_block}
```
{request_section}{response_section}
## What Was Accessed / Impact

{accessed_block}

## Notes & Evidence

{notes_block}
{images_section}
## Remediation

{remediation}

---
*Exported: {datetime.now().strftime("%Y-%m-%d %H:%M")}*
"""

    filepath.write_text(md, encoding="utf-8")
    return str(filepath)


# ---------------------------------------------------------------------------
# Session summary export
# ---------------------------------------------------------------------------

def export_session_summary(session: Session, vault_path: str) -> str:
    vault = Path(vault_path)
    engagements_dir = vault / "Engagements"
    engagements_dir.mkdir(parents=True, exist_ok=True)

    date = datetime.now().strftime("%Y-%m-%d")
    safe_name = _safe(session.name)
    filename = f"{safe_name}-{date}.md"
    filepath = engagements_dir / filename

    severity_counts: dict = {}
    for f in session.findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    findings_rows = ""
    for f in session.findings:
        score = str(f.cvss_score) if f.cvss_score else "—"
        findings_rows += f"| {f.vuln_type} | {f.target} | {f.severity} | {score} | {f.status} | {f.phase} |\n"

    severity_summary = " · ".join(
        f"{k}: **{v}**" for k, v in severity_counts.items()
    ) or "None"

    md = f"""---
type: engagement
name: "{session.name}"
target: "{session.target_host}"
date: {date}
total_findings: {len(session.findings)}
tags: [pentest, engagement]
---

# {session.name}

| Field | Value |
|-------|-------|
| **Target** | {session.target_host or "N/A"} |
| **Date** | {date} |
| **Total Findings** | {len(session.findings)} |
| **Severity Breakdown** | {severity_summary} |

## Findings

| Finding | Target | Severity | CVSS | Status | Phase |
|---------|--------|----------|------|--------|-------|
{findings_rows or "| _No findings recorded._ | | | | | |\n"}

---
*Exported: {datetime.now().strftime("%Y-%m-%d %H:%M")}*
"""

    filepath.write_text(md, encoding="utf-8")
    return str(filepath)


# ---------------------------------------------------------------------------
# Full report — matches writeup structure
# ---------------------------------------------------------------------------

def generate_full_report(session: Session, vault_path: str) -> str:
    vault = Path(vault_path)
    reports_dir = vault / "Reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    date = datetime.now().strftime("%Y-%m-%d")
    safe_name = _safe(session.name)
    filename = f"{safe_name}-Report-{date}.md"
    filepath = reports_dir / filename

    # Group findings by severity in SEVERITIES order
    by_severity: dict[str, list[Finding]] = {s: [] for s in SEVERITIES}
    for f in session.findings:
        bucket = f.severity if f.severity in by_severity else "Informational"
        by_severity[bucket].append(f)

    # --- Executive Summary ---
    total = len(session.findings)
    counts = {s: len(v) for s, v in by_severity.items() if v}
    count_str = ", ".join(f"{v} {k}" for k, v in counts.items())

    if session.exec_summary.strip():
        exec_section = session.exec_summary.strip()
    else:
        exec_section = (
            f"Vulnerability testing on **{session.name}** "
            f"({session.target_host or 'target'}) identified **{total} finding(s)**: {count_str}. "
            f"Critical and high severity issues allow unauthorized access to sensitive data "
            f"and should be remediated immediately."
        )

    # --- Reconnaissance ---
    recon_section = _or(
        session.recon_notes,
        "_No reconnaissance notes recorded._"
    )

    # --- Important Notes ---
    important_section = _or(
        session.important_notes,
        "_None._"
    )

    # --- Findings sections by severity ---
    findings_body = ""
    for severity in SEVERITIES:
        group = by_severity[severity]
        if not group:
            continue
        findings_body += f"\n### {severity} Findings\n"
        for f in group:
            score_line = f"{f.cvss_score} — {f.cvss_vector}" if f.cvss_score else CVSS_RANGES.get(f.severity, "")
            payload_block = f.payload.strip() or "_Not recorded._"
            accessed_block = _or(f.accessed, "_Not specified._")
            notes_block = _or(f.notes, "_No notes._")
            remediation = REMEDIATION.get(f.vuln_type, REMEDIATION["Other"])

            request_block = ""
            if f.request_raw.strip():
                request_block = f"\n**HTTP Request:**\n```http\n{f.request_raw.strip()}\n```\n"

            response_block = ""
            if f.response_raw.strip():
                response_block = f"\n**HTTP Response:**\n```http\n{f.response_raw.strip()}\n```\n"

            findings_body += f"""
#### {f.vuln_type} — {f.target or "N/A"}

| | |
|-|-|
| **Severity** | {f.severity} |
| **CVSS** | {score_line} |
| **Phase** | {f.phase} |
| **Status** | {f.status} |

**Payload / Code Used:**
```
{payload_block}
```
{request_block}{response_block}
**What Was Accessed / Impact:**
{accessed_block}

**Notes:**
{notes_block}

**Remediation:** {remediation}

---
"""

    # --- Impact summary ---
    impact_items = []
    for f in session.findings:
        if f.accessed.strip():
            impact_items.append(f"- ({f.severity}) **{f.vuln_type}** ({f.target}): {f.accessed.strip()}")
    impact_section = "\n".join(impact_items) if impact_items else "_No impact notes recorded._"

    # --- Remediation checklist by severity ---
    remediation_section = ""
    for severity in SEVERITIES:
        group = by_severity[severity]
        if not group:
            continue
        remediation_section += f"\n### {severity}\n"
        for f in group:
            rem = REMEDIATION.get(f.vuln_type, REMEDIATION["Other"])
            remediation_section += f"- [ ] **{f.vuln_type}** ({f.target or 'N/A'}): {rem}\n"

    md = f"""---
type: report
engagement: "{session.name}"
target: "{session.target_host}"
date: {date}
total_findings: {total}
tags: [pentest, report]
---

# {session.name} — Security Assessment Report

**Target:** {session.target_host or "N/A"}
**Date:** {date}
**Total Findings:** {total}

---

## Executive Summary

{exec_section}

---

## Reconnaissance

{recon_section}

---

## Important Notes

{important_section}

---

## Vulnerabilities
{findings_body}

---

## Impact

With the identified vulnerabilities, an attacker could potentially access:

{impact_section}

---

## Remediation
{remediation_section}

---

*Report generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}*
"""

    filepath.write_text(md, encoding="utf-8")
    return str(filepath)
