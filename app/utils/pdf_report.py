from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from datetime import datetime
import os


def generate_breach_report(incident, output_dir=None):
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'reports')
    """generates a proper article 33 breach report as a pdf"""

    # make sure the reports folder exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    filename = f"breach_report_{incident.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(output_dir, filename)

    doc = SimpleDocTemplate(filepath, pagesize=A4,
        topMargin=20*mm, bottomMargin=20*mm,
        leftMargin=20*mm, rightMargin=20*mm)

    styles = getSampleStyleSheet()

    # custom styles
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'],
        fontSize=18, textColor=colors.HexColor('#1e1b4b'), spaceAfter=12)
    heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'],
        fontSize=13, textColor=colors.HexColor('#1e1b4b'), spaceAfter=8, spaceBefore=16)
    body_style = ParagraphStyle('CustomBody', parent=styles['Normal'],
        fontSize=10, leading=14, textColor=colors.HexColor('#374151'))
    label_style = ParagraphStyle('Label', parent=styles['Normal'],
        fontSize=9, textColor=colors.HexColor('#6b7280'))

    elements = []

    # title
    elements.append(Paragraph("DATA BREACH INCIDENT REPORT", title_style))
    elements.append(Paragraph("Article 33 GDPR — Notification to Supervisory Authority", label_style))
    elements.append(Spacer(1, 8*mm))

    # report info table
    report_data = [
        ['Report Reference', f'BR-{incident.id:04d}'],
        ['Date Generated', datetime.now().strftime('%d/%m/%Y %H:%M')],
        ['Status', incident.status.title() if incident.status else 'Open'],
        ['Severity', incident.severity or 'Unclassified'],
        ['Reportable to ICO', 'Yes' if incident.is_reportable else 'No'],
    ]

    report_table = Table(report_data, colWidths=[55*mm, 110*mm])
    report_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8f9fb')),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#6b7280')),
        ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#1e1b4b')),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(report_table)
    elements.append(Spacer(1, 6*mm))

    # section 1 - incident details
    elements.append(Paragraph("1. Nature of the Breach", heading_style))

    incident_data = [
        ['Threat Type', incident.threat_type.replace('_', ' ').title() if incident.threat_type else 'Unknown'],
        ['Description', incident.description or 'No description available'],
        ['Date and Time Detected', incident.timestamp.strftime('%d/%m/%Y %H:%M:%S UTC') if incident.timestamp else 'Unknown'],
        ['Source IP Address', incident.source_ip or 'Unknown'],
        ['Target URL / System', incident.target_url or 'Unknown'],
        ['Attack Payload', incident.payload or 'Not captured'],
    ]

    incident_table = Table(incident_data, colWidths=[55*mm, 110*mm])
    incident_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8f9fb')),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#6b7280')),
        ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#374151')),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(incident_table)
    elements.append(Spacer(1, 6*mm))

    # section 2 - risk assessment
    elements.append(Paragraph("2. AI Risk Assessment", heading_style))
    if incident.recommendation:
        # split long text into paragraphs
        for line in incident.recommendation.split('\n'):
            if line.strip():
                elements.append(Paragraph(line.strip(), body_style))
                elements.append(Spacer(1, 2*mm))
    else:
        elements.append(Paragraph("No AI assessment has been performed for this incident.", body_style))

    elements.append(Spacer(1, 6*mm))

    # section 3 - impact
    elements.append(Paragraph("3. Impact Assessment", heading_style))

    impact_data = [
        ['Data Categories Affected', incident.affected_data_categories or 'To be determined'],
        ['Estimated Individuals Affected', str(incident.estimated_affected_count) if incident.estimated_affected_count else 'To be determined'],
        ['Likely Consequences', incident.likely_consequences or 'To be determined'],
    ]

    impact_table = Table(impact_data, colWidths=[55*mm, 110*mm])
    impact_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8f9fb')),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#6b7280')),
        ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#374151')),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(impact_table)
    elements.append(Spacer(1, 6*mm))

    # section 4 - remediation
    elements.append(Paragraph("4. Remediation Measures", heading_style))
    if incident.remediation_measures:
        elements.append(Paragraph(incident.remediation_measures, body_style))
    else:
        elements.append(Paragraph("Remediation measures to be documented by the DPO following investigation.", body_style))

    elements.append(Spacer(1, 10*mm))

    # footer
    elements.append(Paragraph("This report was generated by the AI-Powered Data Protection Officer system.", label_style))
    elements.append(Paragraph(f"Generated on {datetime.now().strftime('%d/%m/%Y at %H:%M')}", label_style))

    doc.build(elements)

    return filepath, filename
def generate_ropa_report(records, output_dir=None):
    """generates a data inventory report as a pdf"""
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'reports')

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    filename = f"data_inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(output_dir, filename)

    doc = SimpleDocTemplate(filepath, pagesize=A4,
        topMargin=20*mm, bottomMargin=20*mm,
        leftMargin=20*mm, rightMargin=20*mm)

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'],
        fontSize=18, textColor=colors.HexColor('#1e1b4b'), spaceAfter=12)
    heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'],
        fontSize=13, textColor=colors.HexColor('#1e1b4b'), spaceAfter=8, spaceBefore=16)
    body_style = ParagraphStyle('CustomBody', parent=styles['Normal'],
        fontSize=10, leading=14, textColor=colors.HexColor('#374151'))
    label_style = ParagraphStyle('Label', parent=styles['Normal'],
        fontSize=9, textColor=colors.HexColor('#6b7280'))

    elements = []

    elements.append(Paragraph("DATA INVENTORY REPORT", title_style))
    elements.append(Paragraph("Record of Personal Data Held by the Organisation", label_style))
    elements.append(Spacer(1, 8*mm))

    # summary
    elements.append(Paragraph(f"Total data types recorded: {len(records)}", body_style))
    elements.append(Paragraph(f"Report generated: {datetime.now().strftime('%d/%m/%Y %H:%M')}", body_style))
    elements.append(Spacer(1, 6*mm))

    # table of all data entries
    elements.append(Paragraph("Data Inventory", heading_style))

    table_data = [['Data Type', 'Purpose', 'Legal Basis', 'Access', 'Retention', 'Security']]
    for r in records:
        table_data.append([
            r.data_categories or '',
            r.purpose or '',
            r.lawful_basis or '',
            r.data_recipients or '',
            r.retention_period or '',
            r.security_measures or ''
        ])

    col_widths = [30*mm, 30*mm, 25*mm, 25*mm, 25*mm, 30*mm]
    inventory_table = Table(table_data, colWidths=col_widths, repeatRows=1)
    inventory_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e1b4b')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTSIZE', (0, 0), (-1, 0), 8),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fb')]),
    ]))
    elements.append(inventory_table)

    elements.append(Spacer(1, 10*mm))
    elements.append(Paragraph("This report was generated by the AI-Powered Data Protection Officer system.", label_style))
    elements.append(Paragraph(f"Generated on {datetime.now().strftime('%d/%m/%Y at %H:%M')}", label_style))

    doc.build(elements)
    return filepath, filename