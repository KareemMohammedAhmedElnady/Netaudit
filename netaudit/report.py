"""Render an AuditReport as text or self-contained HTML."""
import datetime
import html

from .models import SEVERITIES

_COLORS = {"critical": "#c0392b", "warning": "#e67e22", "info": "#2980b9"}


def _summary_lines(report):
    c = report.counts()
    return (f"Devices audited: {len(report.devices)}   "
            f"Critical: {c['critical']}   Warning: {c['warning']}   Info: {c['info']}")


def render_text(report):
    out = ["NetAudit report - " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
           _summary_lines(report), ""]
    current = None
    for f in report.findings:
        if f.device != current:
            current = f.device
            out.append(f"== {current} ==")
        line = f"[{f.severity.upper():8}] ({f.category}) {f.title}"
        out.append(line)
        if f.detail:
            out.append(f"           {f.detail}")
        if f.recommendation:
            out.append(f"           -> {f.recommendation}")
    return "\n".join(out) + "\n"


def render_html(report):
    rows = []
    for f in report.findings:
        color = _COLORS.get(f.severity, "#333")
        rows.append(
            "<tr>"
            f"<td><span style='background:{color};color:#fff;padding:2px 8px;"
            f"border-radius:4px;font-size:12px'>{f.severity.upper()}</span></td>"
            f"<td>{html.escape(f.device)}</td>"
            f"<td>{html.escape(f.category)}</td>"
            f"<td><b>{html.escape(f.title)}</b>"
            + (f"<br><small>{html.escape(f.detail)}</small>" if f.detail else "")
            + (f"<br><small><i>Fix: {html.escape(f.recommendation)}</i></small>"
               if f.recommendation else "")
            + "</td></tr>")
    devices = "".join(f"<li>{html.escape(d.hostname)} "
                      f"<small>({html.escape(d.source)})</small></li>"
                      for d in report.devices)
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>NetAudit report</title>
<style>
body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 32px; color:#222; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 16px; }}
td, th {{ border-bottom: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }}
th {{ background: #f5f5f5; }}
</style></head><body>
<h1>NetAudit report</h1>
<p>{html.escape(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))} &mdash; {html.escape(_summary_lines(report))}</p>
<h2>Devices</h2><ul>{devices}</ul>
<h2>Findings</h2>
<table><tr><th>Severity</th><th>Device</th><th>Category</th><th>Finding</th></tr>
{''.join(rows)}
</table></body></html>"""
