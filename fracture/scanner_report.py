"""
Fracture scan report generator — produces a self-contained HTML report.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional


_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_SEV_COLORS = {
    "CRITICAL": "#f38ba8",
    "HIGH":     "#f38ba8",
    "MEDIUM":   "#fab387",
    "LOW":      "#f9e2af",
    "INFO":     "#89b4fa",
}
_SEV_BG = {
    "CRITICAL": "rgba(243,139,168,0.15)",
    "HIGH":     "rgba(243,139,168,0.1)",
    "MEDIUM":   "rgba(250,179,135,0.1)",
    "LOW":      "rgba(249,226,175,0.1)",
    "INFO":     "rgba(137,180,250,0.1)",
}


def generate_html_report(
    issues: list,
    path: str,
    severity_filter: Optional[list[str]] = None,
) -> None:
    """Write a self-contained HTML report to *path*."""
    if severity_filter:
        issues = [f for f in issues if getattr(f, "severity", "") in severity_filter]

    issues = sorted(issues, key=lambda f: _SEV_ORDER.get(getattr(f, "severity", "INFO"), 99))

    counts: dict[str, int] = {}
    for f in issues:
        sev = getattr(f, "severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(issues)

    summary_rows = ""
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = counts.get(sev, 0)
        color = _SEV_COLORS.get(sev, "#cdd6f4")
        summary_rows += (
            f'<tr><td style="color:{color};font-weight:bold">{sev}</td>'
            f'<td style="color:#cdd6f4">{n}</td></tr>\n'
        )

    finding_cards = ""
    for i, f in enumerate(issues, start=1):
        sev = getattr(f, "severity", "INFO")
        title = getattr(f, "title", "")
        detail = getattr(f, "detail", "")
        host = getattr(f, "host", "")
        path_attr = getattr(f, "path", "")
        color = _SEV_COLORS.get(sev, "#cdd6f4")
        bg = _SEV_BG.get(sev, "transparent")

        finding_cards += f"""
<div class="card" style="border-left:3px solid {color};background:{bg}">
  <div class="card-header">
    <span class="badge" style="background:{color};color:#1e1e2e">{sev}</span>
    <span class="card-title">{_esc(title)}</span>
    <span class="card-num">#{i}</span>
  </div>
  <div class="card-body">
    <p class="detail">{_esc(detail)}</p>
    <p class="location"><strong>Host:</strong> {_esc(host)}<strong style="margin-left:12px">Path:</strong> {_esc(path_attr)}</p>
  </div>
</div>
"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Fracture Scan Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #1e1e2e; color: #cdd6f4; font-family: 'Segoe UI', system-ui, sans-serif; padding: 32px; }}
  h1 {{ color: #cba6f7; font-size: 28px; margin-bottom: 4px; }}
  .meta {{ color: #a6adc8; font-size: 13px; margin-bottom: 24px; }}
  .summary {{ background: #313244; border-radius: 8px; padding: 16px; display: inline-block; margin-bottom: 28px; }}
  .summary table {{ border-collapse: collapse; }}
  .summary td {{ padding: 4px 16px 4px 0; font-size: 13px; }}
  .summary th {{ color: #a6adc8; font-size: 11px; text-align: left; padding-bottom: 6px; }}
  .findings {{ display: flex; flex-direction: column; gap: 12px; }}
  .card {{ border-radius: 6px; padding: 16px; }}
  .card-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
  .badge {{ font-size: 10px; font-weight: bold; padding: 2px 8px; border-radius: 4px; }}
  .card-title {{ font-weight: 600; font-size: 15px; flex: 1; }}
  .card-num {{ color: #585b70; font-size: 12px; }}
  .detail {{ color: #bac2de; font-size: 13px; margin-bottom: 6px; }}
  .location {{ color: #a6adc8; font-size: 12px; }}
  strong {{ color: #cdd6f4; }}
  .total-badge {{ display: inline-block; background: #45475a; border-radius: 4px; padding: 2px 10px; font-size: 13px; margin-left: 8px; }}
</style>
</head>
<body>
<h1>Fracture Scan Report</h1>
<p class="meta">Generated: {ts} &nbsp;|&nbsp; Total findings: <span class="total-badge">{total}</span></p>
<div class="summary">
  <table>
    <tr><th>Severity</th><th>Count</th></tr>
    {summary_rows}
  </table>
</div>
<div class="findings">
{finding_cards}
</div>
</body>
</html>
"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)


def _esc(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


_VERDICT_COLORS = {
    "BYPASSED": "#f38ba8",
    "PARTIAL":  "#fab387",
    "ENFORCED": "#a6e3a1",
    "SAME":     "#a6adc8",
    "ERROR":    "#585b70",
}


def generate_authz_html_report(
    rows: list[dict],
    path: str,
    verdict_filter: Optional[list[str]] = None,
) -> None:
    """Write an Authz testing report to *path*.

    Each *row* should have keys: id, host, path, method, orig_status,
    orig_len, replay_status, replay_len, verdict.
    """
    if verdict_filter:
        rows = [r for r in rows if r.get("verdict") in verdict_filter]

    counts: dict[str, int] = {}
    for r in rows:
        v = r.get("verdict", "")
        counts[v] = counts.get(v, 0) + 1

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(rows)

    summary_rows = ""
    for verdict in ("BYPASSED", "PARTIAL", "ENFORCED", "SAME", "ERROR"):
        n = counts.get(verdict, 0)
        color = _VERDICT_COLORS.get(verdict, "#cdd6f4")
        summary_rows += (
            f'<tr><td style="color:{color};font-weight:bold">{verdict}</td>'
            f'<td style="color:#cdd6f4">{n}</td></tr>\n'
        )

    finding_rows = ""
    for r in rows:
        verdict = r.get("verdict", "")
        color = _VERDICT_COLORS.get(verdict, "#cdd6f4")
        finding_rows += (
            "<tr>"
            f"<td>{_esc(r.get('id', ''))}</td>"
            f"<td>{_esc(r.get('method', ''))}</td>"
            f"<td>{_esc(r.get('host', ''))}</td>"
            f"<td>{_esc(r.get('path', ''))}</td>"
            f"<td>{_esc(r.get('orig_status', ''))} "
            f"({_esc(r.get('orig_len', ''))}b)</td>"
            f"<td>{_esc(r.get('replay_status', ''))} "
            f"({_esc(r.get('replay_len', ''))}b)</td>"
            f'<td style="color:{color};font-weight:bold">{_esc(verdict)}</td>'
            "</tr>\n"
        )

    html = f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>Fracture Authz Report — {ts}</title>
<style>
  body {{ background:#1e1e2e; color:#cdd6f4; font-family: -apple-system, system-ui, sans-serif; margin: 20px; }}
  h1 {{ color:#89b4fa; margin-bottom:4px; }}
  p.meta {{ color:#a6adc8; font-size:13px; }}
  table {{ border-collapse: collapse; margin-bottom: 20px; }}
  th, td {{ padding: 6px 12px; text-align:left; border-bottom:1px solid #313244; }}
  th {{ background:#181825; color:#a6adc8; }}
  .total-badge {{ background:#313244; padding:2px 8px; border-radius:10px; color:#cdd6f4; }}
  .summary table td {{ font-size: 14px; }}
  .findings table {{ width: 100%; font-size: 12px; }}
</style></head>
<body>
<h1>Fracture Authorization Testing Report</h1>
<p class="meta">Generated: {ts} &nbsp;|&nbsp; Total rows: <span class="total-badge">{total}</span></p>
<div class="summary">
  <table>
    <tr><th>Verdict</th><th>Count</th></tr>
    {summary_rows}
  </table>
</div>
<div class="findings">
  <table>
    <tr><th>#</th><th>Method</th><th>Host</th><th>Path</th>
        <th>Original</th><th>Replay</th><th>Verdict</th></tr>
    {finding_rows}
  </table>
</div>
</body></html>
"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)

