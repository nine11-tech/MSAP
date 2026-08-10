"""Deterministic, in-memory PDF reporting for persisted MSAP results."""

from collections import Counter, defaultdict
from html import escape
from io import BytesIO
import re

from django.conf import settings
from django.utils import timezone
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
    XPreformatted,
)

from apps.reports.models import Report
from apps.reports.services.json_report import generate_json_report


NAVY = colors.HexColor("#17324D")
BLUE = colors.HexColor("#285F8F")
PALE_BLUE = colors.HexColor("#EAF1F7")
TEXT = colors.HexColor("#263746")
MUTED = colors.HexColor("#607384")
BORDER = colors.HexColor("#C9D5DF")
LIGHT_GREY = colors.HexColor("#F4F6F8")
WHITE = colors.white

SEVERITY_COLORS = {
    "critical": colors.HexColor("#8B1E2D"),
    "high": colors.HexColor("#C14632"),
    "medium": colors.HexColor("#D98419"),
    "low": colors.HexColor("#4A7396"),
    "informational": colors.HexColor("#62727F"),
    "info": colors.HexColor("#62727F"),
}
SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Informational")
FALLBACK_REMEDIATION = (
    "Refer to the mapped MASVS control and validate remediation with the "
    "application owner."
)
ATTCK_NOTICE = (
    "ATT&CK Mobile mappings are investigative signals and do not constitute "
    "a malicious/benign classification."
)
SNIPPET_LIMIT = 350
FIELD_LIMIT = 1400


def generate_pdf_report(audit_id: int) -> bytes:
    """Generate the current audit PDF without temporary files or APK access."""
    report_data = generate_json_report(audit_id)

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=20 * mm,
        bottomMargin=18 * mm,
        title="MSAP Mobile Application Security Assessment Report",
        author=settings.MSAP_REPORT_AUTHOR,
        subject="Deterministic static Android security assessment",
    )
    styles = _build_styles()
    story = _build_story(report_data, styles)
    document.build(
        story,
        onFirstPage=_draw_cover_page,
        onLaterPages=_draw_report_page,
    )
    pdf_bytes = buffer.getvalue()
    Report.objects.get_or_create(
        audit_id=audit_id,
        report_type=Report.ReportType.PDF,
    )
    return pdf_bytes


def build_pdf_filename(project_name: str, audit_id: int) -> str:
    project = re.sub(r"[^A-Za-z0-9._-]+", "_", project_name).strip("._-")
    project = project[:80] or "Project"
    return f"MSAP_{project}_{audit_id}_Security_Report.pdf"


def _build_styles() -> dict[str, ParagraphStyle]:
    sample = getSampleStyleSheet()
    return {
        "cover_brand": ParagraphStyle(
            "MSAPCoverBrand",
            parent=sample["Title"],
            fontName="Helvetica-Bold",
            fontSize=32,
            leading=36,
            textColor=NAVY,
            alignment=TA_LEFT,
            spaceAfter=5 * mm,
        ),
        "cover_platform": ParagraphStyle(
            "MSAPCoverPlatform",
            parent=sample["Normal"],
            fontName="Helvetica",
            fontSize=13,
            leading=18,
            textColor=BLUE,
            spaceAfter=14 * mm,
        ),
        "cover_title": ParagraphStyle(
            "MSAPCoverTitle",
            parent=sample["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=27,
            textColor=TEXT,
            spaceAfter=8 * mm,
        ),
        "cover_classification": ParagraphStyle(
            "MSAPCoverClassification",
            parent=sample["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=WHITE,
            backColor=NAVY,
            borderPadding=(5, 8, 5, 8),
            alignment=TA_CENTER,
            spaceAfter=12 * mm,
        ),
        "section": ParagraphStyle(
            "MSAPSection",
            parent=sample["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=15,
            leading=19,
            textColor=NAVY,
            spaceBefore=5 * mm,
            spaceAfter=3 * mm,
            keepWithNext=True,
        ),
        "body": ParagraphStyle(
            "MSAPBody",
            parent=sample["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=TEXT,
            spaceAfter=2.5 * mm,
        ),
        "small": ParagraphStyle(
            "MSAPSmall",
            parent=sample["BodyText"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=TEXT,
        ),
        "small_muted": ParagraphStyle(
            "MSAPSmallMuted",
            parent=sample["BodyText"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=MUTED,
        ),
        "table_header": ParagraphStyle(
            "MSAPTableHeader",
            parent=sample["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9,
            textColor=WHITE,
            alignment=TA_LEFT,
        ),
        "notice": ParagraphStyle(
            "MSAPNotice",
            parent=sample["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=12,
            textColor=NAVY,
            backColor=PALE_BLUE,
            borderColor=BLUE,
            borderWidth=0.5,
            borderPadding=7,
            spaceBefore=2 * mm,
            spaceAfter=4 * mm,
        ),
        "finding_title": ParagraphStyle(
            "MSAPFindingTitle",
            parent=sample["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=NAVY,
            spaceBefore=3 * mm,
            spaceAfter=1.5 * mm,
            keepWithNext=True,
        ),
        "source_heading": ParagraphStyle(
            "MSAPSourceHeading",
            parent=sample["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=10,
            textColor=BLUE,
            spaceBefore=2 * mm,
            spaceAfter=1 * mm,
        ),
        "source_code": ParagraphStyle(
            "MSAPSourceCode",
            parent=sample["Code"],
            fontName="Courier",
            fontSize=6.4,
            leading=8.2,
            textColor=TEXT,
        ),
    }


def _build_story(data: dict, styles: dict[str, ParagraphStyle]) -> list:
    generated_at = timezone.localtime(timezone.now())
    audit = data["audit"]
    project = data["project"]
    apk = data.get("apk") or {}
    summary = data["summary"]
    findings = data.get("findings", [])
    indicators = data.get("indicators", [])
    evidence = data.get("evidence", [])
    evidence_by_finding = _evidence_index(evidence, "finding_id")
    evidence_by_indicator = _evidence_index(evidence, "indicator_id")

    story = [
        Spacer(1, 20 * mm),
        Paragraph("MSAP", styles["cover_brand"]),
        Paragraph(
            "Mobile Security Assessment &amp; Triage Platform",
            styles["cover_platform"],
        ),
        Paragraph(
            "Mobile Application Security Assessment Report",
            styles["cover_title"],
        ),
        Paragraph(
            _text(settings.MSAP_REPORT_CLASSIFICATION),
            styles["cover_classification"],
        ),
        _cover_details(data, generated_at, styles),
        Spacer(1, 12 * mm),
        Paragraph(
            "This report is generated deterministically from persisted MSAP "
            "results. It contains no AI-generated assessment.",
            styles["small_muted"],
        ),
        PageBreak(),
    ]

    story.extend(_executive_summary(summary, findings, indicators, styles))
    story.extend(_scope_and_methodology(styles))
    story.extend(_apk_information(apk, audit, styles))
    story.extend(_risk_and_compliance(summary, styles))
    story.extend(_coverage_section(summary.get("coverage", {}), styles))
    story.extend(
        _findings_section(
            findings,
            evidence_by_finding,
            styles,
        )
    )
    story.extend(
        _indicators_section(
            indicators,
            evidence_by_indicator,
            styles,
        )
    )
    story.extend(_evidence_section(evidence, findings, indicators, styles))
    story.extend(_limitations_section(data.get("limitations", []), styles))
    story.extend(_technical_appendix(data, generated_at, styles))
    return story


def _cover_details(
    data: dict,
    generated_at,
    styles: dict[str, ParagraphStyle],
) -> Table:
    audit = data["audit"]
    project = data["project"]
    apk = data.get("apk") or {}
    rows = [
        ["Project", project.get("name")],
        ["Audit identifier", audit.get("id")],
        ["Audit name", audit.get("name")],
        ["APK filename", apk.get("filename") or "Not recorded"],
        ["Package name", apk.get("package_name") or "Not available"],
        ["Generated", generated_at.strftime("%Y-%m-%d %H:%M:%S %Z")],
        ["Organization", settings.MSAP_REPORT_ORGANIZATION],
        ["Analyst", settings.MSAP_REPORT_AUTHOR],
        ["Report version", settings.MSAP_REPORT_VERSION],
    ]
    table = Table(
        [
            [
                Paragraph(f"<b>{_text(label)}</b>", styles["body"]),
                Paragraph(_text(value), styles["body"]),
            ]
            for label, value in rows
        ],
        colWidths=[42 * mm, 112 * mm],
        hAlign="LEFT",
    )
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LINEBELOW", (0, 0), (-1, -1), 0.35, BORDER),
                ("BACKGROUND", (0, 0), (0, -1), LIGHT_GREY),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _executive_summary(summary, findings, indicators, styles) -> list:
    risk = summary["risk"]
    compliance = summary["masvs_compliance"]
    counts = Counter(_severity_label(item.get("severity")) for item in findings)
    elements = [
        Paragraph("Executive Summary", styles["section"]),
        Paragraph(
            "MSAP evaluated the persisted static-analysis results for this Android "
            "application. The assessment recorded "
            f"<b>{len(findings)}</b> finding(s) and "
            f"<b>{len(indicators)}</b> ATT&amp;CK Mobile triage indicator(s).",
            styles["body"],
        ),
        _metric_table(
            [
                ("Overall risk", f"{risk.get('score', 0)}/100"),
                ("Risk level", risk.get("severity", "Unknown")),
                ("MASVS compliance", f"{compliance.get('score', 0)}%"),
                ("Findings", len(findings)),
                ("ATT&CK signals", len(indicators)),
            ],
            styles,
        ),
        Spacer(1, 2 * mm),
        _severity_count_table(counts, styles),
        Paragraph(_text(ATTCK_NOTICE), styles["notice"]),
    ]
    return elements


def _scope_and_methodology(styles) -> list:
    return [
        Paragraph("Scope and Methodology", styles["section"]),
        Paragraph(
            "The assessment performs static Android APK analysis: manifest "
            "metadata extraction, deterministic evaluation of the implemented "
            "OWASP MASVS rules, cautious MITRE ATT&amp;CK Mobile triage, evidence "
            "capture, and transparent risk and compliance scoring. The APK is not "
            "executed and no runtime or dynamic behavior is observed.",
            styles["body"],
        ),
    ]


def _apk_information(apk, audit, styles) -> list:
    rows = [
        ("Filename", apk.get("filename") or "Not recorded"),
        ("SHA-256", apk.get("sha256") or "Not recorded"),
        ("File size", _format_bytes(apk.get("size_bytes"))),
        ("Package name", apk.get("package_name") or "Not available"),
        ("Version name", apk.get("version_name") or "Not available"),
        ("Storage status", apk.get("storage_status") or "Not recorded"),
        ("Audit status", audit.get("status") or "Not recorded"),
    ]
    return [
        Paragraph("APK Information", styles["section"]),
        _key_value_table(rows, styles),
    ]


def _risk_and_compliance(summary, styles) -> list:
    risk = summary["risk"]
    compliance = summary["masvs_compliance"]
    triage = summary["attack_mobile_triage"]
    rows = [
        ("Risk score", f"{risk.get('score', 0)}/100"),
        ("Risk severity", risk.get("severity", "Unknown")),
        ("Raw risk weight", risk.get("raw_weight", 0)),
        ("MASVS compliance", f"{compliance.get('score', 0)}%"),
        ("Evaluated MASVS rules", compliance.get("evaluated_rules", 0)),
        ("Applicable MASVS rules", compliance.get("applicable_rules", 0)),
        ("Passed MASVS rules", compliance.get("passed_rules", 0)),
        ("Failed MASVS rules", compliance.get("failed_rules", 0)),
        ("Review-required MASVS rules", compliance.get("review_required", 0)),
        ("Unevaluated MASVS rules", compliance.get("not_evaluated", 0)),
        ("ATT&CK triage level", triage.get("triage_level", "Unknown")),
        ("ATT&CK indicator count", triage.get("triage_indicators", 0)),
    ]
    return [
        Paragraph("Risk and Compliance Summary", styles["section"]),
        _key_value_table(rows, styles),
        Paragraph(
            _text(
                compliance.get("coverage_warning")
                or "All catalog rules with required artifacts were evaluated."
            ),
            styles["notice"] if compliance.get("partial_coverage") else styles["small_muted"],
        ),
    ]


def _coverage_section(coverage, styles) -> list:
    analyzers = coverage.get("analyzers", {})
    rows = [
        ("Catalog evaluations", coverage.get("total_catalog_rules", 0)),
        ("Applicable", coverage.get("applicable", 0)),
        ("Evaluated", coverage.get("evaluated", 0)),
        ("Passed", coverage.get("passed", 0)),
        ("Failed", coverage.get("failed", 0)),
        ("Review required", coverage.get("review_required", 0)),
        ("Not evaluated", coverage.get("not_evaluated", 0)),
        ("Analyzers completed", ", ".join(analyzers.get("completed", [])) or "None"),
        (
            "Analyzers skipped",
            ", ".join(item.get("name", "") for item in analyzers.get("skipped", []))
            or "None",
        ),
        (
            "Analyzers failed",
            ", ".join(item.get("name", "") for item in analyzers.get("failed", []))
            or "None",
        ),
    ]
    return [
        Paragraph("Analyzer and Rule Coverage", styles["section"]),
        _key_value_table(rows, styles),
    ]


def _findings_section(findings, evidence_index, styles) -> list:
    elements = [Paragraph(f"Findings ({len(findings)})", styles["section"])]
    if not findings:
        elements.append(
            Paragraph(
                "No findings were persisted for this audit. This does not prove "
                "the absence of vulnerabilities.",
                styles["body"],
            )
        )
        return elements

    for finding in findings:
        severity = _severity_label(finding.get("severity"))
        title = f"{finding.get('rule_id') or 'Unmapped'} — {finding.get('title') or 'Untitled finding'}"
        evidence_summary = _joined_evidence(evidence_index.get(finding.get("id"), []))
        mapping = " / ".join(
            str(item)
            for item in (finding.get("standard"), finding.get("category"))
            if item
        )
        rows = [
            ("Severity", severity),
            ("Confidence", finding.get("confidence") or "Not recorded"),
            ("MASVS mapping/category", mapping or "Not recorded"),
            (
                "Description",
                finding.get("description")
                or "No additional description was persisted for this finding.",
            ),
            (
                "MASVS controls",
                ", ".join((finding.get("mappings") or {}).get("masvs_controls", []))
                or "Not recorded",
            ),
            (
                "MASWE weaknesses",
                ", ".join((finding.get("mappings") or {}).get("maswe_ids", []))
                or "Not recorded",
            ),
            (
                "MASTG references",
                ", ".join((finding.get("mappings") or {}).get("mastg_references", []))
                or "Not recorded",
            ),
            ("Evidence summary", evidence_summary or "No linked evidence recorded."),
            (
                "Remediation",
                finding.get("recommendation") or FALLBACK_REMEDIATION,
            ),
            (
                "False-positive considerations",
                finding.get("false_positive_guidance") or "Validate in application context.",
            ),
            (
                "Manual validation",
                "Required" if finding.get("requires_manual_validation") else "Not required for the static condition",
            ),
            ("Status", finding.get("status") or "Not recorded"),
        ]
        elements.extend(
            [
                Paragraph(_text(title), styles["finding_title"]),
                _result_block(rows, severity, styles),
            ]
        )
        elements.extend(
            _finding_source_evidence(finding.get("source_evidence", []), styles)
        )
    return elements


def _finding_source_evidence(source_evidence, styles) -> list:
    elements = [Paragraph("SOURCE EVIDENCE", styles["source_heading"])]
    if not source_evidence:
        elements.append(
            Paragraph(
                "No source-provenance reference was recorded.",
                styles["small_muted"],
            )
        )
        return elements

    for reference in source_evidence[:2]:
        representation = (
            reference.get("representation_label")
            or reference.get("representation")
            or "Generated representation"
        )
        path = reference.get("path") or "Path not recorded"
        location = ""
        if reference.get("source_lines_available"):
            location = (
                f" · lines {reference.get('start_line')}–"
                f"{reference.get('end_line')}"
            )
        symbol = " / ".join(
            value
            for value in (
                reference.get("class_name"),
                reference.get("method_name"),
                reference.get("symbol"),
            )
            if value
        )
        elements.append(
            Paragraph(
                _text(
                    f"{representation} · {path}{location}"
                    + (f" · {symbol}" if symbol else ""),
                    800,
                ),
                styles["small"],
            )
        )
        if reference.get("source_lines_available"):
            excerpt_lines = str(reference.get("excerpt") or "").splitlines()[:15]
            bounded_lines = [
                expanded_line[:120] + ("…" if len(expanded_line) > 120 else "")
                for line in excerpt_lines
                for expanded_line in (line.expandtabs(4),)
            ]
            elements.append(_source_code_block(bounded_lines, styles))
            elements.append(
                Paragraph(
                    _text(reference.get("provenance") or "Generated by MSAP.", 900),
                    styles["small_muted"],
                )
            )
        else:
            elements.append(
                Paragraph(
                    _text(
                        "Source lines not applicable. "
                        + str(reference.get("reason") or "Metadata evidence only."),
                        900,
                    ),
                    styles["small_muted"],
                )
            )
    return elements


def _source_code_block(lines, styles) -> Table:
    """Render code without painting beyond the height reserved by ReportLab."""
    content = escape("\n".join(lines)) or "No excerpt recorded."
    code = XPreformatted(content, styles["source_code"])
    block = Table(
        [[code]],
        colWidths=[A4[0] - (36 * mm)],
        splitByRow=True,
        hAlign="LEFT",
    )
    block.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GREY),
                ("BOX", (0, 0), (-1, -1), 0.4, BORDER),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    block.spaceAfter = 1.5 * mm
    return block


def _indicators_section(indicators, evidence_index, styles) -> list:
    elements = [
        Paragraph(
            f"MITRE ATT&amp;CK Mobile Triage ({len(indicators)})",
            styles["section"],
        ),
        Paragraph(_text(ATTCK_NOTICE), styles["notice"]),
    ]
    if not indicators:
        elements.append(
            Paragraph("No ATT&amp;CK Mobile triage indicators were persisted.", styles["body"])
        )
        return elements

    for indicator in indicators:
        severity = _severity_label(indicator.get("severity"))
        title = (
            f"{indicator.get('indicator_id') or 'Unmapped'} — "
            f"{indicator.get('title') or 'Untitled indicator'}"
        )
        technique = " — ".join(
            str(item)
            for item in (
                indicator.get("technique_id"),
                indicator.get("technique_name"),
            )
            if item
        )
        rows = [
            ("Severity", severity),
            ("Confidence", indicator.get("confidence") or "Not recorded"),
            ("Tactic", indicator.get("tactic") or "Not recorded"),
            ("ATT&CK technique", technique or "Not recorded"),
            (
                "What this means",
                indicator.get("auditor_explanation")
                or indicator.get("triage_interpretation")
                or "No additional auditor explanation was persisted.",
            ),
            (
                "Mapping rationale",
                indicator.get("mapping_rationale")
                or "Static capability mapping requires validation.",
            ),
            (
                "False-positive considerations",
                indicator.get("false_positive_considerations")
                or "Legitimate use is possible.",
            ),
            (
                "Suggested dynamic verification",
                indicator.get("dynamic_verification_scenario")
                or (
                    "Exercise the related feature in an authorized test environment "
                    "and correlate runtime behavior with this static signal."
                ),
            ),
            (
                "Evidence",
                _joined_evidence(evidence_index.get(indicator.get("id"), []))
                or "No linked evidence recorded.",
            ),
            (
                "Triage note",
                indicator.get("non_malware_verdict_note")
                or "Triage signal — not a malware verdict.",
            ),
        ]
        elements.extend(
            [
                Paragraph(_text(title), styles["finding_title"]),
                _result_block(rows, severity, styles),
            ]
        )
        elements.extend(
            _indicator_source_evidence(indicator.get("source_evidence", []), styles)
        )
    return elements


def _indicator_source_evidence(source_evidence, styles) -> list:
    elements = [Paragraph("SUPPORTING SOURCE EVIDENCE", styles["source_heading"])]
    if not source_evidence:
        elements.append(
            Paragraph(
                "No source line was recorded for this indicator. Re-run static "
                "analysis to resolve newly indexed source evidence.",
                styles["small_muted"],
            )
        )
        return elements

    for reference in source_evidence[:3]:
        representation = (
            reference.get("representation_label")
            or reference.get("representation")
            or "Generated representation"
        )
        path = reference.get("path") or "Path not recorded"
        if reference.get("source_lines_available"):
            start_line = reference.get("start_line")
            end_line = reference.get("end_line")
            location = (
                f"line {start_line}"
                if start_line == end_line
                else f"lines {start_line}–{end_line}"
            )
            elements.append(
                Paragraph(
                    _text(f"{representation} · {path} · {location}", 800),
                    styles["small"],
                )
            )
            excerpt = str(reference.get("excerpt") or "No excerpt recorded.")
            elements.append(
                _source_code_block([f"{start_line:>4}  {excerpt}"], styles)
            )
            elements.append(
                Paragraph(
                    _text(reference.get("provenance") or "Generated by MSAP.", 900),
                    styles["small_muted"],
                )
            )
        else:
            elements.append(
                Paragraph(
                    _text(
                        f"{representation} · {path}. Source lines not applicable or unavailable. "
                        + str(reference.get("reason") or "Metadata evidence only."),
                        900,
                    ),
                    styles["small_muted"],
                )
            )
    return elements


def _evidence_section(evidence, findings, indicators, styles) -> list:
    elements = [Paragraph(f"Evidence ({len(evidence)})", styles["section"])]
    if not evidence:
        elements.append(Paragraph("No evidence records were persisted.", styles["body"]))
        return elements

    finding_labels = {
        item.get("id"): item.get("rule_id") or f"Finding #{item.get('id')}"
        for item in findings
    }
    indicator_labels = {
        item.get("id"): item.get("indicator_id") or f"Indicator #{item.get('id')}"
        for item in indicators
    }
    rows = [
        [
            Paragraph("Related result", styles["table_header"]),
            Paragraph("Type", styles["table_header"]),
            Paragraph("Source", styles["table_header"]),
            Paragraph("Snippet", styles["table_header"]),
        ]
    ]
    for item in evidence:
        related = (
            finding_labels.get(item.get("finding_id"))
            or indicator_labels.get(item.get("indicator_id"))
            or "Audit"
        )
        rows.append(
            [
                Paragraph(_text(related, 120), styles["small"]),
                Paragraph(_text(item.get("evidence_type") or "Not recorded", 120), styles["small"]),
                Paragraph(_text(_evidence_source(item), 160), styles["small"]),
                Paragraph(_text(_evidence_snippet(item)), styles["small"]),
            ]
        )
    table = Table(
        rows,
        colWidths=[31 * mm, 32 * mm, 37 * mm, 59 * mm],
        repeatRows=1,
        splitByRow=1,
        splitInRow=1,
    )
    table.setStyle(_standard_table_style())
    elements.append(table)
    return elements


def _limitations_section(limitations, styles) -> list:
    elements = [Paragraph("Limitations", styles["section"])]
    for limitation in limitations:
        elements.append(Paragraph(f"• {_text(limitation)}", styles["body"]))
    return elements


def _technical_appendix(data, generated_at, styles) -> list:
    job = data.get("analysis_job") or {}
    job_summary = job.get("summary") if isinstance(job.get("summary"), dict) else {}
    artifact_summary = data.get("normalized_artifacts") or {}
    by_type = artifact_summary.get("by_type") or {}
    analyzer_names = job_summary.get("analyzer_names") or []
    rows = [
        ("Report generated", generated_at.isoformat()),
        ("Report version", settings.MSAP_REPORT_VERSION),
        ("Analysis job status", job.get("status") or "No analysis job recorded"),
        (
            "Analyzers",
            ", ".join(str(name) for name in analyzer_names)
            if analyzer_names
            else "Not recorded",
        ),
        ("Normalized artifact count", artifact_summary.get("count", 0)),
        (
            "Normalized artifact types",
            ", ".join(f"{key}: {value}" for key, value in sorted(by_type.items()))
            or "None",
        ),
        ("Analyzer count", job_summary.get("analyzer_count", 0)),
        ("Analysis error count", job_summary.get("error_count", 0)),
    ]
    return [
        Paragraph("Technical Appendix", styles["section"]),
        _key_value_table(rows, styles),
    ]


def _metric_table(metrics, styles) -> Table:
    cells = [
        [
            Paragraph(f"<b>{_text(label)}</b><br/>{_text(value)}", styles["body"])
            for label, value in metrics
        ]
    ]
    table = Table(cells, colWidths=[31.8 * mm] * len(metrics))
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GREY),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.35, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    return table


def _severity_count_table(counts, styles) -> Table:
    rows = [
        [Paragraph("Findings by severity", styles["table_header"])]
        + [Paragraph(label, styles["table_header"]) for label in SEVERITY_ORDER],
        [Paragraph("Count", styles["small"])]
        + [Paragraph(str(counts.get(label, 0)), styles["small"]) for label in SEVERITY_ORDER],
    ]
    table = Table(rows, colWidths=[42 * mm] + [23.4 * mm] * len(SEVERITY_ORDER))
    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.35, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 1), (-1, 1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for index, label in enumerate(SEVERITY_ORDER, start=1):
        commands.append(
            ("BACKGROUND", (index, 1), (index, 1), _severity_color(label, pale=True))
        )
    table.setStyle(TableStyle(commands))
    return table


def _key_value_table(rows, styles) -> Table:
    table = Table(
        [
            [
                Paragraph(f"<b>{_text(label)}</b>", styles["small"]),
                Paragraph(_text(value, FIELD_LIMIT), styles["small"]),
            ]
            for label, value in rows
        ],
        colWidths=[48 * mm, 111 * mm],
        splitByRow=1,
        splitInRow=1,
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), LIGHT_GREY),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.35, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _result_block(rows, severity, styles) -> Table:
    table = _key_value_table(rows, styles)
    table.setStyle(
        TableStyle(
            [
                ("LINEBEFORE", (0, 0), (0, -1), 3, _severity_color(severity)),
                ("BACKGROUND", (1, 0), (1, 0), _severity_color(severity, pale=True)),
            ]
        )
    )
    return table


def _standard_table_style() -> TableStyle:
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.35, BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]
    )


def _draw_cover_page(canvas, document) -> None:
    canvas.saveState()
    canvas.setTitle("MSAP Mobile Application Security Assessment Report")
    canvas.setAuthor(settings.MSAP_REPORT_AUTHOR)
    canvas.setStrokeColor(BLUE)
    canvas.setLineWidth(2)
    canvas.line(18 * mm, A4[1] - 15 * mm, A4[0] - 18 * mm, A4[1] - 15 * mm)
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(
        18 * mm,
        10 * mm,
        f"MSAP • {settings.MSAP_REPORT_CLASSIFICATION}",
    )
    canvas.restoreState()


def _draw_report_page(canvas, document) -> None:
    canvas.saveState()
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(18 * mm, A4[1] - 13 * mm, A4[0] - 18 * mm, A4[1] - 13 * mm)
    canvas.setFillColor(NAVY)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(18 * mm, A4[1] - 10 * mm, "MSAP Security Assessment Report")
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawRightString(
        A4[0] - 18 * mm,
        A4[1] - 10 * mm,
        settings.MSAP_REPORT_CLASSIFICATION,
    )
    canvas.line(18 * mm, 12 * mm, A4[0] - 18 * mm, 12 * mm)
    canvas.drawString(18 * mm, 8 * mm, f"Version {settings.MSAP_REPORT_VERSION}")
    canvas.drawRightString(A4[0] - 18 * mm, 8 * mm, f"Page {document.page}")
    canvas.restoreState()


def _evidence_index(evidence: list[dict], key: str) -> dict:
    index = defaultdict(list)
    for item in evidence:
        linked_id = item.get(key)
        if linked_id is not None:
            index[linked_id].append(item)
    return index


def _joined_evidence(items: list[dict]) -> str:
    snippets = [_evidence_snippet(item) for item in items[:3]]
    return " | ".join(snippet for snippet in snippets if snippet)


def _evidence_snippet(item: dict) -> str:
    if item.get("redacted"):
        return "[Redacted evidence]"
    value = str(item.get("snippet") or "").strip()
    if "<manifest" in value.lower() and "</manifest>" in value.lower():
        return "[Full AndroidManifest.xml omitted]"
    if re.search(r"(?i)[?&]X-Amz-(?:Algorithm|Credential|Signature)=", value):
        return "[Presigned URL omitted]"
    value = re.sub(
        r"(?i)\b(password|secret|token|api[_-]?key|access[_-]?key)"
        r"\s*[:=]\s*([^\s,;]+)",
        r"\1=[REDACTED]",
        value,
    )
    value = re.sub(r"(?i)(X-Amz-(?:Credential|Signature)=[^&\s]+)", "[REDACTED]", value)
    return _plain_limit(value, SNIPPET_LIMIT) or "No snippet recorded."


def _evidence_source(item: dict) -> str:
    source = str(item.get("source") or "").strip()
    if source.startswith("projects/"):
        return "Persisted artifact"
    if re.match(r"(?i)^https?://", source):
        return "External URL omitted"
    return source or "Not recorded"


def _text(value, limit: int = FIELD_LIMIT) -> str:
    text = _plain_limit(value, limit)
    return escape(text).replace("\n", "<br/>")


def _plain_limit(value, limit: int) -> str:
    text = str(value if value is not None else "Not recorded").strip()
    if len(text) <= limit:
        return text
    return f"{text[: limit - 1].rstrip()}…"


def _severity_label(value) -> str:
    label = str(value or "Informational").strip()
    if label.lower() == "info":
        return "Informational"
    return label.title()


def _severity_color(value, pale: bool = False):
    color = SEVERITY_COLORS.get(str(value).lower(), SEVERITY_COLORS["informational"])
    return colors.Color(
        1 - ((1 - color.red) * (0.16 if pale else 1)),
        1 - ((1 - color.green) * (0.16 if pale else 1)),
        1 - ((1 - color.blue) * (0.16 if pale else 1)),
    )


def _format_bytes(value) -> str:
    if value is None:
        return "Not recorded"
    size = float(value)
    for unit in ("bytes", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "bytes" else f"{size:.2f} {unit}"
        size /= 1024
    return f"{value} bytes"
