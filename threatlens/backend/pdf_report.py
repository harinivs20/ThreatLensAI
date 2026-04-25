"""
pdf_report.py — Generate professional PDF threat reports using ReportLab.
"""
import io
from datetime import datetime

def generate_pdf_report(scan_data: dict) -> bytes:
    """Generate a PDF report for a scan result. Returns bytes."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles    import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units     import mm
        from reportlab.lib           import colors
        from reportlab.platypus      import (SimpleDocTemplate, Paragraph, Spacer,
                                             Table, TableStyle, HRFlowable)
        from reportlab.lib.enums     import TA_CENTER, TA_LEFT, TA_RIGHT

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4,
            leftMargin=20*mm, rightMargin=20*mm,
            topMargin=20*mm, bottomMargin=20*mm)

        # ── Colors ────────────────────────────────────────────────────────
        NAVY   = colors.HexColor("#0f2044")
        BLUE   = colors.HexColor("#2563eb")
        TEAL   = colors.HexColor("#0d9488")
        RED    = colors.HexColor("#dc2626")
        GREEN  = colors.HexColor("#16a34a")
        AMBER  = colors.HexColor("#d97706")
        GRAY   = colors.HexColor("#475569")
        LGRAY  = colors.HexColor("#f1f5f9")
        WHITE  = colors.white

        verdict      = scan_data.get("verdict","UNKNOWN")
        risk         = scan_data.get("overall_risk", 0)
        threat_level = scan_data.get("threat_level","NONE")
        input_type   = scan_data.get("input_type","url")
        input_value  = scan_data.get("input_value","")
        explanation  = scan_data.get("explanation","")
        report_card  = scan_data.get("report_card", {})
        campaign     = scan_data.get("campaign", {})
        shap_vals    = scan_data.get("shap_values", [])
        scan_id      = scan_data.get("id","N/A")

        VERDICT_COLOR = RED if verdict == "PHISHING" else GREEN
        styles = getSampleStyleSheet()

        def style(name="Normal", size=10, bold=False, color=NAVY, align=TA_LEFT):
            return ParagraphStyle(name, parent=styles["Normal"],
                fontSize=size, textColor=color, fontName="Helvetica-Bold" if bold else "Helvetica",
                alignment=align, leading=size*1.4)

        story = []

        # ── Header ────────────────────────────────────────────────────────
        hdr_data = [[
            Paragraph("<b>🛡️ ThreatLens AI</b>", style("h",14,True,WHITE,TA_LEFT)),
            Paragraph(f"<b>THREAT INTELLIGENCE REPORT</b>",style("h2",10,True,colors.HexColor("#93c5fd"),TA_RIGHT)),
        ]]
        hdr_tbl = Table(hdr_data, colWidths=[95*mm, 75*mm])
        hdr_tbl.setStyle(TableStyle([
            ("BACKGROUND",  (0,0),(-1,-1), NAVY),
            ("PADDING",     (0,0),(-1,-1), 12),
            ("VALIGN",      (0,0),(-1,-1), "MIDDLE"),
        ]))
        story.append(hdr_tbl)
        story.append(Spacer(1, 8*mm))

        # ── Meta info ─────────────────────────────────────────────────────
        now = datetime.now().strftime("%d %B %Y, %I:%M %p")
        meta = [
            ["Scan ID",     scan_id],
            ["Date / Time", now],
            ["Input Type",  input_type.upper()],
            ["Scanned",     (input_value[:80]+"...") if len(input_value)>80 else input_value],
        ]
        meta_tbl = Table([[Paragraph(k, style("mk",9,True,BLUE)),
                           Paragraph(v, style("mv",9,False,GRAY))] for k,v in meta],
                         colWidths=[40*mm, 130*mm])
        meta_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(0,-1), LGRAY),
            ("GRID",       (0,0),(-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ("PADDING",    (0,0),(-1,-1), 6),
            ("VALIGN",     (0,0),(-1,-1), "MIDDLE"),
        ]))
        story.append(meta_tbl)
        story.append(Spacer(1, 6*mm))

        # ── Verdict banner ────────────────────────────────────────────────
        verd_data = [[
            Paragraph(f"<b>{verdict}</b>", style("v",26,True,WHITE,TA_CENTER)),
            Paragraph(f"<b>Risk Score: {risk}/100</b><br/>"
                     f"<font size=11>Confidence: {scan_data.get('confidence',0)}% &nbsp;|&nbsp; Threat Level: {threat_level}</font>",
                     style("vs",13,True,WHITE,TA_CENTER)),
        ]]
        verd_tbl = Table(verd_data, colWidths=[60*mm, 110*mm])
        verd_tbl.setStyle(TableStyle([
            ("BACKGROUND",  (0,0),(-1,-1), VERDICT_COLOR),
            ("PADDING",     (0,0),(-1,-1), 14),
            ("VALIGN",      (0,0),(-1,-1), "MIDDLE"),
            ("ROUNDEDCORNERS", [6]),
        ]))
        story.append(verd_tbl)
        story.append(Spacer(1,5*mm))

        # ── AI Explanation ────────────────────────────────────────────────
        story.append(Paragraph("<b>AI Analysis</b>", style("s1",12,True,NAVY)))
        story.append(HRFlowable(width="100%", thickness=1.5, color=BLUE, spaceAfter=4))
        story.append(Paragraph(explanation or "No explanation available.",
                               style("exp",10,False,GRAY)))
        story.append(Spacer(1,5*mm))

        # ── Report card ───────────────────────────────────────────────────
        if report_card:
            story.append(Paragraph("<b>Threat Report Card</b>", style("s2",12,True,NAVY)))
            story.append(HRFlowable(width="100%", thickness=1.5, color=BLUE, spaceAfter=4))

            GRADE_COLORS = {"A": GREEN, "B": BLUE, "C": AMBER, "D": colors.HexColor("#ea580c"), "F": RED}
            dim_labels = {
                "domain_reputation":    "Domain Reputation",
                "link_safety":          "Link Safety",
                "structure_risk":       "URL Structure",
                "keyword_risk":         "Keyword Risk",
                "sender_authenticity":  "Sender Authenticity",
                "language_manipulation":"Language Manipulation",
                "credential_risk":      "Credential Risk",
            }
            rc_data = [["Dimension","Score","Grade","Assessment"]]
            for key, label in dim_labels.items():
                if key in report_card and isinstance(report_card[key], dict):
                    d = report_card[key]
                    grade = d.get("grade","?")
                    score = d.get("score",0)
                    reason = d.get("reason","")
                    gc = GRADE_COLORS.get(grade, GRAY)
                    rc_data.append([
                        Paragraph(label,  style("rl",9,False,GRAY)),
                        Paragraph(f"{score}/100", style("rs",9,True,gc,TA_CENTER)),
                        Paragraph(f"<b>{grade}</b>", style("rg",12,True,gc,TA_CENTER)),
                        Paragraph(reason[:90], style("rr",8,False,GRAY)),
                    ])
            rc_tbl = Table(rc_data, colWidths=[42*mm,22*mm,18*mm,88*mm])
            rc_style = [
                ("BACKGROUND", (0,0),(-1,0), NAVY),
                ("TEXTCOLOR",  (0,0),(-1,0), WHITE),
                ("FONTNAME",   (0,0),(-1,0), "Helvetica-Bold"),
                ("FONTSIZE",   (0,0),(-1,0), 9),
                ("GRID",       (0,0),(-1,-1), 0.5, colors.HexColor("#e2e8f0")),
                ("PADDING",    (0,0),(-1,-1), 6),
                ("VALIGN",     (0,0),(-1,-1), "MIDDLE"),
                ("ALIGN",      (1,1),(2,-1), "CENTER"),
            ]
            for i in range(1, len(rc_data)):
                if i % 2 == 0:
                    rc_style.append(("BACKGROUND",(0,i),(-1,i), LGRAY))
            rc_tbl.setStyle(TableStyle(rc_style))
            story.append(rc_tbl)
            story.append(Spacer(1,5*mm))

        # ── SHAP Feature Importance ───────────────────────────────────────
        if shap_vals:
            story.append(Paragraph("<b>Feature Importance (SHAP / XAI)</b>", style("s3",12,True,NAVY)))
            story.append(HRFlowable(width="100%", thickness=1.5, color=BLUE, spaceAfter=4))
            story.append(Paragraph(
                "The following features had the greatest influence on this verdict:",
                style("si",9,False,GRAY)))
            story.append(Spacer(1,3*mm))

            shap_data = [["Feature","Value","Impact","Direction"]]
            for sv in shap_vals[:8]:
                impact_color = RED if sv.get("impact")=="increases_risk" else GREEN
                shap_data.append([
                    Paragraph(sv.get("description", sv["feature"]).replace("_"," ").title(),
                              style("sf",9,False,GRAY)),
                    Paragraph(str(sv["value"]), style("sv",9,False,GRAY,TA_CENTER)),
                    Paragraph(f"{abs(sv['shap']):.3f}", style("ss",9,True,impact_color,TA_CENTER)),
                    Paragraph("↑ Risk" if sv.get("impact")=="increases_risk" else "↓ Risk",
                              style("sd",9,True,impact_color,TA_CENTER)),
                ])
            shap_tbl = Table(shap_data, colWidths=[75*mm,25*mm,30*mm,40*mm])
            shap_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0,0),(-1,0), NAVY),
                ("TEXTCOLOR",  (0,0),(-1,0), WHITE),
                ("FONTNAME",   (0,0),(-1,0), "Helvetica-Bold"),
                ("FONTSIZE",   (0,0),(-1,0), 9),
                ("GRID",       (0,0),(-1,-1), 0.5, colors.HexColor("#e2e8f0")),
                ("PADDING",    (0,0),(-1,-1), 6),
                ("VALIGN",     (0,0),(-1,-1), "MIDDLE"),
                ("ALIGN",      (1,1),(-1,-1), "CENTER"),
            ]))
            story.append(shap_tbl)
            story.append(Spacer(1,5*mm))

        # ── Campaign Intelligence ─────────────────────────────────────────
        if campaign and campaign.get("name"):
            story.append(Paragraph("<b>Campaign Intelligence</b>", style("s4",12,True,NAVY)))
            story.append(HRFlowable(width="100%", thickness=1.5, color=AMBER, spaceAfter=4))
            camp_rows = [
                ["Campaign Name",   campaign.get("name","")],
                ["Total Orgs Hit",  str(campaign.get("total_orgs",""))],
                ["Active Since",    campaign.get("first_seen","")],
                ["Region",          campaign.get("region","")],
                ["Match Similarity",f"{campaign.get('similarity',0)}%"],
            ]
            camp_tbl = Table([[Paragraph(k,style("ck",9,True,AMBER)),
                               Paragraph(v,style("cv",9,False,GRAY))] for k,v in camp_rows],
                             colWidths=[50*mm, 120*mm])
            camp_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0,0),(0,-1), colors.HexColor("#fffbeb")),
                ("GRID",       (0,0),(-1,-1), 0.5, colors.HexColor("#fde68a")),
                ("PADDING",    (0,0),(-1,-1), 6),
            ]))
            story.append(camp_tbl)

            # Org breakdown
            org_types = campaign.get("org_types",{})
            if org_types:
                story.append(Spacer(1,3*mm))
                story.append(Paragraph("Organisations Targeted by This Group:",
                                       style("ot",9,True,AMBER)))
                org_data = [[Paragraph(t,style("ok",9,False,GRAY)),
                             Paragraph(str(c),style("ov",9,True,AMBER,TA_CENTER))]
                            for t,c in org_types.items()]
                org_tbl  = Table(org_data, colWidths=[140*mm,30*mm])
                org_tbl.setStyle(TableStyle([
                    ("GRID",    (0,0),(-1,-1), 0.5, colors.HexColor("#fde68a")),
                    ("PADDING", (0,0),(-1,-1), 5),
                    ("ALIGN",   (1,0),(1,-1), "CENTER"),
                ]))
                story.append(org_tbl)
            story.append(Spacer(1,5*mm))

        # ── Footer ────────────────────────────────────────────────────────
        story.append(HRFlowable(width="100%", thickness=1, color=GRAY))
        story.append(Spacer(1,3*mm))
        story.append(Paragraph(
            "ThreatLens AI — Unified Phishing Intelligence Platform &nbsp;|&nbsp; "
            "Dept. of Computer Science &amp; Engineering &nbsp;|&nbsp; Final Year Project 2024–25 &nbsp;|&nbsp; "
            "This report is generated automatically and should be reviewed by a security professional.",
            style("ft",7,False,GRAY,TA_CENTER)))

        doc.build(story)
        return buf.getvalue()

    except ImportError:
        # Fallback: return a plain text PDF-like response
        return _plain_text_report(scan_data)

def _plain_text_report(scan_data):
    """Minimal fallback if reportlab not installed."""
    text = f"""ThreatLens AI — Threat Report
{'='*50}
Verdict:      {scan_data.get('verdict')}
Risk Score:   {scan_data.get('overall_risk')}/100
Threat Level: {scan_data.get('threat_level')}
Confidence:   {scan_data.get('confidence')}%
Input:        {scan_data.get('input_value','')}

Analysis:
{scan_data.get('explanation','')}

Generated: {datetime.now().strftime('%d %B %Y %I:%M %p')}
ThreatLens AI — CSE Dept. Final Year Project 2024-25
"""
    return text.encode()
