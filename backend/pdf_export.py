from io import BytesIO
from datetime import datetime
from typing import Any, Dict, List

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    ListFlowable,
    ListItem,
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart


def _fmt(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        return ", ".join(_fmt(x) for x in v)
    return str(v)


def _kpi_table(results: Dict) -> Table:
    subdomains = len(results.get("subdomains", []) or [])
    hosts = len(results.get("hosts", []) or [])
    open_ports = sum(len(h.get("open_ports", []) or []) for h in results.get("hosts", []) or [])
    emails = len((results.get("harvester") or {}).get("emails", []) or [])
    github = len(results.get("github_hits", []) or [])
    pastes = len(results.get("paste_hits", []) or [])
    cves = 0
    cves_data = results.get("cves") or {}
    if isinstance(cves_data, dict):
        try:
            cves = sum(len(v) for v in cves_data.values())
        except Exception:
            cves = 0

    data = [
        ["Metric", "Value"],
        ["Subdomains", subdomains],
        ["Hosts", hosts],
        ["Open Ports", open_ports],
        ["Emails", emails],
        ["GitHub Hits", github],
        ["Pastes", pastes],
        ["CVEs", cves],
    ]

    # Present KPIs in two columns for a card-like look
    # Convert rows (excluding header) into a 2-column layout
    kpi_rows = data[1:]
    grid: List[List[Any]] = [["Metric", "Value", "Metric", "Value"]]
    for i in range(0, len(kpi_rows), 2):
        left = kpi_rows[i]
        right = kpi_rows[i + 1] if i + 1 < len(kpi_rows) else ["", ""]
        grid.append([left[0], left[1], right[0], right[1]])

    t = Table(grid, hAlign="LEFT", colWidths=[90, 80, 90, 80])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f1f1f")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#fafafa")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#fafafa"), colors.HexColor("#f2f2f2")]),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("INNERGRID", (0, 1), (-1, -1), 0.25, colors.HexColor("#e0e0e0")),
    ]))
    return t


def _subdomains_table(results: Dict) -> Table:
    subs: List[str] = results.get("subdomains") or []
    hosts = results.get("hosts") or []
    head = ["Subdomain", "IP(s)"]
    rows = [head]
    if subs:
        for sd in subs:
            ip_str = ""
            try:
                host = next((h for h in hosts if h.get("hostname") == sd), None)
                if host:
                    ip_str = ", ".join(host.get("ips", []) or [])
            except Exception:
                ip_str = ""
            rows.append([sd, ip_str or "N/A"])
    else:
        rows.append(["No subdomains found", "-"])

    t = Table(rows, hAlign="LEFT", colWidths=[220, 260])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f1f1f")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f7f7f7")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
    ]))
    return t


def _hosts_table(results: Dict) -> Table:
    hosts = results.get("hosts") or []
    rows = [["Host", "IP(s)", "Open Ports", "Services"]]
    if hosts:
        for h in hosts:
            rows.append([
                _fmt(h.get("hostname")),
                _fmt(h.get("ips", [])),
                _fmt(h.get("open_ports", [])),
                _fmt(h.get("services", [])),
            ])
    else:
        rows.append(["No hosts detected", "-", "-", "-"])

    t = Table(rows, hAlign="LEFT", colWidths=[140, 150, 90, 100])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f1f1f")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f7f7f7")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
    ]))
    return t


def _sf_block(sf_enhanced: Dict) -> Table:
    rows = [["Field", "Value"]]
    if not sf_enhanced:
        rows.append(["Status", "No SpiderFoot enhancement provided"])
    else:
        modules = sf_enhanced.get("modules_used") or (sf_enhanced.get("results") or {}).get("modules_run") or []
        events_found = (sf_enhanced.get("results") or {}).get("events_found")
        rows.append(["Modules Used", _fmt(modules) or "N/A"])
        rows.append(["Events Found", _fmt(events_found) or "N/A"])

    t = Table(rows, hAlign="LEFT", colWidths=[150, 350])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
    ]))
    return t


def _compute_summary(results: Dict) -> Dict[str, int]:
    subdomains = len(results.get("subdomains", []) or [])
    hosts = len(results.get("hosts", []) or [])
    open_ports = sum(len(h.get("open_ports", []) or []) for h in results.get("hosts", []) or [])
    emails = len((results.get("harvester") or {}).get("emails", []) or [])
    github = len(results.get("github_hits", []) or [])
    pastes = len(results.get("paste_hits", []) or [])
    cves = 0
    cves_data = results.get("cves") or {}
    if isinstance(cves_data, dict):
        try:
            cves = sum(len(v) for v in cves_data.values())
        except Exception:
            cves = 0
    return {
        "subdomains": subdomains,
        "hosts": hosts,
        "open_ports": open_ports,
        "emails": emails,
        "github": github,
        "pastes": pastes,
        "cves": cves,
    }


def _risk_assessment(results: Dict) -> Dict[str, Any]:
    s = _compute_summary(results)
    score = 0
    if s["open_ports"] > 10:
        score += 3
    elif s["open_ports"] > 5:
        score += 2
    elif s["open_ports"] > 0:
        score += 1
    if s["cves"] > 10:
        score += 4
    elif s["cves"] > 5:
        score += 3
    elif s["cves"] > 0:
        score += 2
    if s["github"] > 5 or s["pastes"] > 0:
        score += 2
    elif s["github"] > 0:
        score += 1

    if score >= 7:
        level = "Critical"; color = colors.HexColor("#c62828"); desc = "Multiple high-risk issues identified"
    elif score >= 5:
        level = "High"; color = colors.HexColor("#ef6c00"); desc = "Several security concerns detected"
    elif score >= 3:
        level = "Medium"; color = colors.HexColor("#1565c0"); desc = "Some security issues present"
    else:
        level = "Low"; color = colors.HexColor("#2e7d32"); desc = "Minimal security concerns detected"
    return {"level": level, "color": color, "description": desc, "score": score}


def _risk_block(results: Dict) -> Table:
    r = _risk_assessment(results)
    text = f"Risk Level: <b>{r['level']}</b> — {r['description']}"
    t = Table([[Paragraph(text, getSampleStyleSheet()["BodyText"])]], colWidths=[360])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), r["color"]),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.whitesmoke),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#333333")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def _top_ports(results: Dict, top_n: int = 10) -> Dict[str, List[Any]]:
    counts: Dict[int, int] = {}
    for h in results.get("hosts", []) or []:
        for p in h.get("open_ports", []) or []:
            try:
                p_int = int(p)
            except Exception:
                continue
            counts[p_int] = counts.get(p_int, 0) + 1
    pairs = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    labels = [str(p) for p, _ in pairs]
    values = [c for _, c in pairs]
    return {"labels": labels, "values": values}


def _ports_chart(results: Dict) -> Drawing | None:
    data = _top_ports(results, 10)
    if not data["labels"]:
        return None
    width, height = 400, 180
    d = Drawing(width, height)
    chart = VerticalBarChart()
    chart.x = 40
    chart.y = 30
    chart.width = width - 80
    chart.height = height - 60
    chart.data = [data["values"]]
    chart.categoryAxis.categoryNames = data["labels"]
    chart.bars[0].fillColor = colors.HexColor("#1e88e5")
    chart.valueAxis.valueMin = 0
    chart.valueAxis.visibleGrid = True
    chart.valueAxis.gridStrokeColor = colors.HexColor("#dddddd")
    d.add(chart)
    return d


def _insights_list(results: Dict) -> ListFlowable:
    s = _compute_summary(results)
    ports = _top_ports(results, 1)
    common_port = ports["labels"][0] if ports["labels"] else "N/A"
    # Host with most open ports
    host_name = "N/A"; max_ports = 0
    for h in results.get("hosts", []) or []:
        c = len(h.get("open_ports", []) or [])
        if c > max_ports:
            max_ports = c
            host_name = h.get("hostname") or "N/A"

    items = [
        f"Most common open port across hosts: <b>{common_port}</b>",
        f"Host with most open ports: <b>{host_name}</b> ({max_ports})",
        f"Subdomains discovered: <b>{s['subdomains']}</b>; Hosts analyzed: <b>{s['hosts']}</b>",
    ]
    style = getSampleStyleSheet()["BodyText"]
    return ListFlowable([Paragraph(i, style) for i in items], bulletType="bullet", start="circle")


def render_report_pdf(results: Dict, target: str, sf_enhanced: Dict | None = None) -> bytes:
    """Render results JSON into a nicely formatted PDF and return raw bytes."""
    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        title=f"Recon Report - {target}",
        leftMargin=24,
        rightMargin=24,
        topMargin=24,
        bottomMargin=24,
    )

    styles = getSampleStyleSheet()
    h1 = styles["Heading1"]
    h1.fontName = "Helvetica-Bold"
    h2 = styles["Heading2"]
    h2.fontName = "Helvetica-Bold"
    normal = styles["BodyText"]

    story: List[Any] = []

    # Header
    story.append(Paragraph("Red Team Recon Report", h1))
    meta = f"Target: <b>{target}</b> &nbsp;&nbsp; Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    story.append(Paragraph(meta, normal))
    story.append(Spacer(1, 6))
    # Risk banner
    story.append(_risk_block(results))
    story.append(Spacer(1, 12))

    # Executive Summary
    story.append(Paragraph("Executive Summary", h2))
    story.append(_kpi_table(results))
    story.append(Spacer(1, 10))
    # Top open ports chart (if available)
    story.append(Paragraph("Top Open Ports (by frequency)", h2))
    chart = _ports_chart(results)
    if chart:
        story.append(chart)
        story.append(Spacer(1, 12))

    # Subdomains
    story.append(Paragraph("Subdomains", h2))
    story.append(_subdomains_table(results))
    story.append(Spacer(1, 12))

    # Hosts & Ports
    story.append(Paragraph("Hosts & Ports", h2))
    story.append(_hosts_table(results))
    story.append(Spacer(1, 12))

    # OSINT & Cloud (summary + links)
    story.append(Paragraph("OSINT & Cloud", h2))
    github = results.get("github_hits", []) or []
    pastes = results.get("paste_hits", []) or []
    s3 = results.get("s3_buckets", []) or []
    story.append(Paragraph(
        f"GitHub findings: <b>{len(github)}</b> &nbsp;&nbsp; Pastes: <b>{len(pastes)}</b> &nbsp;&nbsp; S3 Buckets: <b>{len(s3)}</b>",
        normal,
    ))
    # Show top 5 links for each, if present
    if github:
        story.append(Spacer(1, 6))
        story.append(Paragraph("Top GitHub hits:", getSampleStyleSheet()["Heading3"]))
        gh_items = []
        for item in github[:5]:
            url = item.get("url") or item.get("html_url") or ""
            if url:
                gh_items.append(Paragraph(f"<link href='{url}' color='blue'>{url}</link>", normal))
        if gh_items:
            story.append(ListFlowable(gh_items, bulletType="bullet", start="circle"))
    if pastes:
        story.append(Spacer(1, 6))
        story.append(Paragraph("Top Paste links:", getSampleStyleSheet()["Heading3"]))
        pt_items = []
        for item in pastes[:5]:
            url = item.get("url") or ""
            if url:
                pt_items.append(Paragraph(f"<link href='{url}' color='blue'>{url}</link>", normal))
        if pt_items:
            story.append(ListFlowable(pt_items, bulletType="bullet", start="circle"))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Insights & Recommendations", h2))
    story.append(_insights_list(results))
    story.append(Spacer(1, 12))

    # SpiderFoot section (optional)
    if sf_enhanced is not None:
        story.append(Paragraph("SpiderFoot Enrichment", h2))
        story.append(_sf_block(sf_enhanced))
        story.append(Spacer(1, 12))

    # Build PDF with simple header/footer
    def _on_page(canvas, doc_):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#e0e0e0"))
        canvas.setLineWidth(0.5)
        canvas.line(24, 28, A4[0] - 24, 28)  # footer line
        page = canvas.getPageNumber()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#666666"))
        canvas.drawRightString(A4[0] - 24, 16, f"Page {page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    return buffer.getvalue()
