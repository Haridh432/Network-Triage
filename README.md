# Network Traffic Triage

## Overview
This project demonstrates a quick network traffic triage workflow using Wireshark/Tshark and Python. It captures packets, aggregates flows, extracts DNS/HTTP activity, enriches IPs/domains, and produces a professional incident report.

The project is designed to be completed in one day, giving a snapshot of suspicious network activity for further investigation.

---

## Files

| File | Description |
|------|-------------|
| `capture.pcap` | Raw network capture (optional small example) |
| `all_packets.csv` | Packet-level details extracted from capture |
| `suspicious_flows.csv` | Aggregated flows by bytes and packet count |
| `suspicious_flows_classified.csv` | Flows labeled as internal/external |
| `http_requests.tsv` | HTTP requests extracted from capture |
| `dns_queries.tsv` | DNS queries extracted from capture |
| `dst_ips.txt` / `domains.txt` | Unique IPs and domains for enrichment |
| `enrichment.txt` | Reverse DNS and WHOIS info for IPs/domains |
| `incident_summary.txt` | Quick text summary of suspicious activity |
| `incident_report.pdf` | One-page professional incident report |
| `collapse_flows.py` | Python script to aggregate flows |
| `classify_flows.py` | Python script to classify internal/external flows |
| `generate_pdf_report.py` | Python script to create PDF report |

---

## How to Run

1. **Capture network traffic** (optional if you have `capture.pcap`):

```bash
sudo tshark -i <interface> -w capture.pcap
