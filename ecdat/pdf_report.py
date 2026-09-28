"""Bounded executive PDF export; source evidence is never interpreted as markup."""
from collections import Counter
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


def build_pdf(report):
    output = BytesIO()
    styles = getSampleStyleSheet()
    styles['BodyText'].wordWrap = 'CJK'
    story = []

    def paragraph(value, style='BodyText', limit=1200):
        text = str(value)
        if len(text) > limit:
            text = text[:limit] + ' [truncated]'
        text = ''.join(c for c in text if c in '\n\t' or ord(c) >= 32)
        return Paragraph(escape(text).replace('\n', '<br/>'), styles[style])

    def add(value, style='BodyText'):
        story.append(paragraph(value, style))
        story.append(Spacer(1, 6))

    add('ECDAT Executive Scan Report', 'Title')
    add(report.get('source', 'Unknown source'), 'Heading2')
    add('Scan ID: ' + str(report.get('id', 'Unknown')))
    timestamp = (report.get('cbom') or {}).get('metadata', {}).get('timestamp')
    if timestamp:
        add('Scan timestamp: ' + str(timestamp))
    findings = report.get('findings') or []
    stats = report.get('stats') or {}
    add('Coverage: ' + ('PARTIAL - review skipped entries before drawing conclusions.' if report.get('partial') else 'Completed within scanner limits.'))
    add(f"Files scanned: {stats.get('files_scanned', 0)} | Skipped: {stats.get('files_skipped', 0)} | Evidence records: {len(findings)} | Duration: {stats.get('duration_seconds', 'unknown')} seconds")
    add('Priority distribution', 'Heading2')
    counts = Counter(str(f.get('severity', 'unknown')).lower() for f in findings)
    rows = [[paragraph('Priority'), paragraph('Evidence records')]]
    rows += [[paragraph(k), paragraph(v)] for k, v in sorted(counts.items())]
    if not counts:
        rows.append([paragraph('No detections'), paragraph(0)])
    table = Table(rows, colWidths=[3.8 * inch, 2.5 * inch], repeatRows=1)
    table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e8eef8')), ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('BOTTOMPADDING', (0, 0), (-1, -1), 8)]))
    story.append(table)
    add('Risk context', 'Heading2')
    profile = report.get('profile') or {}
    add(' | '.join(f'{k.replace("_", " ")}: {v}' for k, v in profile.items()) or 'Risk profile unavailable for this historical scan.')
    summary = report.get('risk_summary') or {}
    add(f"Quantum-vulnerable detections: {summary.get('quantum_vulnerable_assets', 'unavailable')} | At risk under the selected Mosca profile: {summary.get('at_risk_now', 'unavailable')} | Average crypto-agility score: {summary.get('average_crypto_agility_score', 'unavailable')}")
    add(f"Application crypto-agility score (unique file/asset pairs): {summary.get('application_crypto_agility_score', 'unavailable')}")
    if report.get('coverage'):
        add('Analysis modes: ' + '; '.join(f'{mode}: {count}' for mode, count in report['coverage'].items()))
    add('Prioritized findings', 'Heading2')
    add(f'Showing up to 20 of {len(findings)} evidence records. Download the full JSON report for all evidence and remediation suggestions. Repeated references are not unique assets.')
    rank = {'critical': 0, 'high': 1, 'review': 2, 'medium': 2, 'low': 3, 'info': 4}
    selected = sorted(findings, key=lambda f: rank.get(str(f.get('severity', '')).lower(), 5))[:20]
    for finding in selected:
        add(f"{finding.get('pattern', 'Unknown asset')} - {finding.get('severity', 'unknown')}", 'Heading3')
        add(f"{finding.get('file', 'Unknown file')} | Line: {finding.get('line') or 'n/a'} | Kind: {finding.get('kind', 'unknown')}")
        add(finding.get('recommendation') or 'Review the source context before changing cryptography.')
    add('Coverage and interpretation', 'Heading2')
    add('Detection uses signatures and metadata. Findings require review; absence of detections does not prove absence of cryptography. Binary strings and source references do not prove runtime use. This report is not a compliance certification. Migration suggestions require testing before deployment.')
    for warning in (report.get('warnings') or [])[:10]:
        add(warning)
    if len(report.get('warnings') or []) > 10:
        add('Additional coverage warnings are available in the full JSON report.')
    add('Audit record', 'Heading2')
    if report.get('audit_error'):
        add('This scan was not added to the audit chain: ' + str(report['audit_error']))
    elif report.get('audit_block_hash'):
        add('Stored audit block hash: ' + str(report['audit_block_hash']))
        add('This reference is not a digital signature. Use Verify audit in the dashboard to check the current chain and CBOM integrity.')
    else:
        add('No audit reference is available for this scan.')

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 9)
        canvas.drawString(42, 24, 'ECDAT | Executive report')
        canvas.drawRightString(doc.pagesize[0] - 42, 24, f'Page {doc.page}')
        canvas.restoreState()

    SimpleDocTemplate(output, rightMargin=42, leftMargin=42, topMargin=42, bottomMargin=42, title='ECDAT Executive Scan Report').build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()
