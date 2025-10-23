# generate_pdf_report.py
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

proj = '/home/kali/Desktop/Project'
outpdf = proj + '/incident_report.pdf'

def readfile(path, maxlines=50):
    try:
        with open(path) as f:
            lines = f.readlines()
        return ''.join(lines[:maxlines])
    except:
        return 'No data found.\n'

# Read data
flows = readfile(proj + '/suspicious_flows_classified.csv', 20)
dns = readfile(proj + '/dns_queries.tsv', 30)
enrich = readfile(proj + '/enrichment.txt', 60)

# Create PDF
doc = SimpleDocTemplate(outpdf, pagesize=A4, rightMargin=36,leftMargin=36, topMargin=36,bottomMargin=36)
styles = getSampleStyleSheet()
story = []

story.append(Paragraph("Incident Report — Network Capture Triage", styles['Title']))
story.append(Spacer(1,12))
story.append(Paragraph(f"<b>Generated:</b> {__import__('datetime').datetime.utcnow().isoformat()}Z", styles['Normal']))
story.append(Spacer(1,8))

story.append(Paragraph("<b>Top suspicious flows:</b>", styles['Heading3']))
story.append(Paragraph("<pre>%s</pre>" % flows.replace('&','&amp;'), styles['Code']))
story.append(Spacer(1,8))

story.append(Paragraph("<b>Top DNS queries (sample):</b>", styles['Heading3']))
story.append(Paragraph("<pre>%s</pre>" % dns.replace('&','&amp;'), styles['Code']))
story.append(Spacer(1,8))

story.append(Paragraph("<b>Enrichment (sample):</b>", styles['Heading3']))
story.append(Paragraph("<pre>%s</pre>" % enrich.replace('&','&amp;'), styles['Code']))
story.append(Spacer(1,10))

story.append(Paragraph("<b>Assessment & Next steps:</b>", styles['Heading3']))
story.append(Paragraph("Review top external flows; isolate suspicious hosts; run host-level scans; block IPs/domains; preserve evidence.", styles['Normal']))

doc.build(story)
print(f"Generated {outpdf}")
