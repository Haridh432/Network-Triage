import ipaddress, csv

def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False

with open('suspicious_flows.csv', newline='') as f, open('suspicious_flows_classified.csv', 'w', newline='') as o:
    r = csv.DictReader(f)
    fieldnames = r.fieldnames + ['src_internal','dst_internal']
    w = csv.DictWriter(o, fieldnames=fieldnames)
    w.writeheader()
    for row in r:
        row['src_internal'] = str(is_private(row['src']))
        row['dst_internal'] = str(is_private(row['dst']))
        w.writerow(row)

print("Wrote suspicious_flows_classified.csv")
