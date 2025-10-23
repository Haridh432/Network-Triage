#!/usr/bin/env python3
import subprocess, os

proj = '/home/kali/Desktop/Project'
capture_file = os.path.join(proj, 'capture_auto.pcap')
dst_ips_file = os.path.join(proj, 'dst_ips.txt')
domains_file = os.path.join(proj, 'domains.txt')
enrichment_file = os.path.join(proj, 'enrichment.txt')
flows_file = os.path.join(proj, 'suspicious_flows.csv')
dns_file = os.path.join(proj, 'dns_queries.tsv')
summary_file = os.path.join(proj, 'incident_summary.txt')
pdf_file = os.path.join(proj, 'incident_report.pdf')

# 1. Capture live traffic (10s)
print("Capturing live traffic for 10s...")
subprocess.run(f"sudo timeout 10s tshark -i 1 -w {capture_file}", shell=True)

# 2. Extract destination IPs from HTTP
subprocess.run(f"tshark -r {capture_file} -Y 'http.request' -T fields -e ip.dst | sed '/^$/d' | sort -u > {dst_ips_file}", shell=True)

# 3. Extract domains from DNS
subprocess.run(f"tshark -r {capture_file} -Y 'dns.qry.name' -T fields -e dns.qry.name | sed '/^$/d' | sort -u > {domains_file}", shell=True)

# 4. Create enrichment.txt
with open(enrichment_file, 'w') as ef:
    # IP enrichment
    with open(dst_ips_file) as f:
        for ip in f:
            ip = ip.strip()
            if not ip: continue
            ef.write(f"---- {ip} ----\n")
            dig = subprocess.run(f"dig -x {ip} +short", shell=True, capture_output=True, text=True)
            ef.write(dig.stdout)
            whois_out = subprocess.run(f"whois {ip} | egrep -i 'OrgName|org-name|Country|country|CIDR|NetName'", shell=True, capture_output=True, text=True)
            ef.write(whois_out.stdout)
            ef.write("\n")
    # Domain enrichment
    with open(domains_file) as f:
        for domain in f:
            domain = domain.strip()
            if not domain: continue
            ef.write(f"==== {domain} ====\n")
            whois_out = subprocess.run(f"whois {domain} | egrep -i 'Registrar|Registrant|Creation Date|Expiry|Name Server|Country'", shell=True, capture_output=True, text=True)
            ef.write(whois_out.stdout)
            ef.write("\n")

# 5. Extract suspicious flows
subprocess.run(f"tshark -r {capture_file} -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e _ws.col.Protocol -e frame.len -E header=y -E separator=, > {flows_file}", shell=True)

# 6. Extract DNS queries
subprocess.run(f"tshark -r {capture_file} -Y 'dns.qry.name' -T fields -e frame.time -e ip.src -e dns.qry.name -e dns.flags.response > {dns_file}", shell=True)

# 7. Generate incident summary
with open(summary_file, 'w') as out:
    out.write(f"Incident summary generated: {__import__('datetime').datetime.utcnow().isoformat()}Z\n\n")
    out.write("Top flows:\n")
    subprocess.run(f"head -n 7 {flows_file}", shell=True, stdout=out)
    out.write("\nTop DNS queries:\n")
    subprocess.run(f"awk -F'\\t' '{{print $3}}' {dns_file} | sed '/^$/d' | sort | uniq -c | sort -rn | head -n 10", shell=True, stdout=out)
    out.write("\nEnrichment sample:\n")
    subprocess.run(f"head -n 60 {enrichment_file}", shell=True, stdout=out)
    out.write("\nAssessment: Review top flows and DNS hits; isolate suspicious hosts; scan; block IPs/domains if malicious.\n")

# 8. Generate PDF
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

def readfile(path, maxlines=50):
    try:
        with open(path) as f:
            lines = f.readlines()
        return ''.join(lines[:maxlines])
    except:
        return ''

flows = readfile(flows_file, 20)
dns = readfile(dns_file, 30)
enrich = readfile(enrichment_file, 100)

doc = SimpleDocTemplate(pdf_file, pagesize=A4, rightMargin=36,leftMargin=36, topMargin=36,bottomMargin=36)
styles = getSampleStyleSheet()
story = []

story.append(Paragraph("Incident Report — Automated Capture", styles['Title']))
story.append(Spacer(1,12))
story.append(Paragraph(f"<b>Generated:</b> {__import__('datetime').datetime.utcnow().isoformat()}Z", styles['Normal']))
story.append(Spacer(1,8))

story.append(Paragraph("<b>Top flows (sample):</b>", styles['Heading3']))
story.append(Paragraph("<pre>%s</pre>" % flows.replace('&','&amp;'), styles['Code']))
story.append(Spacer(1,8))

story.append(Paragraph("<b>Top DNS queries (sample):</b>", styles['Heading3']))
story.append(Paragraph("<pre>%s</pre>" % dns.replace('&','&amp;'), styles['Code']))
story.append(Spacer(1,8))

story.append(Paragraph("<b>Enrichment (sample):</b>", styles['Heading3']))
story.append(Paragraph("<pre>%s</pre>" % (enrich[:4000].replace('&','&amp;')), styles['Code']))
story.append(Spacer(1,10))

story.append(Paragraph("<b>Assessment & Next steps:</b> Review flows, isolate hosts, scan, block IPs/domains.", styles['Normal']))

doc.build(story)

print(f"Generated PDF: {pdf_file}")
