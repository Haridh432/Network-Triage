# collapse_flows.py
import sys, csv
from collections import defaultdict

inp = sys.argv[1] if len(sys.argv)>1 else 'all_packets.csv'
flows = defaultdict(lambda: {'bytes':0,'pkts':0})

def first_nonempty(*vals):
    for v in vals:
        if v:
            return v
    return ''

with open(inp, newline='') as f:
    r = csv.DictReader(f)
    for row in r:
        src = row.get('ip.src','').strip()
        dst = row.get('ip.dst','').strip()
        sport = first_nonempty(row.get('tcp.srcport',''), row.get('udp.srcport',''))
        dport = first_nonempty(row.get('tcp.dstport',''), row.get('udp.dstport',''))
        proto = row.get('_ws.col.Protocol','').strip() or 'IP'
        if not src or not dst:
            continue
        # normalize tuple so opposite direction aggregates separately (optional)
        key = (src, dst, sport, dport, proto)
        try:
            ln = int(row.get('frame.len') or 0)
        except:
            ln = 0
        flows[key]['bytes'] += ln
        flows[key]['pkts'] += 1

# Write CSV
with open('suspicious_flows.csv','w',newline='') as out:
    w = csv.writer(out)
    w.writerow(['src','dst','src_port','dst_port','proto','bytes','pkts'])
    for (src,dst,sport,dport,proto), stats in sorted(flows.items(), key=lambda x: x[1]['bytes'], reverse=True):
        w.writerow([src,dst,sport,dport,proto,stats['bytes'],stats['pkts']])

print('Wrote suspicious_flows.csv')
