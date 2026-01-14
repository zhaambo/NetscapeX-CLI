"""Reporting utilities: CLI summary and JSON output."""
import json
import sys


def write_report(path, results):
    with open(path, 'w') as f:
        json.dump(results, f, indent=2)


def print_summary(results):
    # Print table header
    lines = []
    header = f"{'Flow ID':20} | {'Src':15} | {'Dst':15} | {'Threat Type':20} | {'Confidence':9}"
    sep = '-' * len(header)
    print(header)
    print(sep)

    # for readability, sort by risk score desc
    items = []
    for fid, data in results.items():
        det = data['detections']
        score = det.get('risk_score', 0)
        conf = det.get('confidence', 0)
        # choose a highest-priority threat type for display
        ttype = 'none'
        if det.get('dns_tunnel', {}).get('flag'):
            ttype = 'dns_tunnel'
        elif det.get('beaconing', {}).get('flag'):
            ttype = 'beaconing'
        elif det.get('protocol_anomaly', {}).get('flag'):
            ttype = 'protocol_anomaly'
        elif det.get('ml_prob_encrypted', 0) > 0.8:
            ttype = 'encrypted_like'

        items.append((score, fid, data['features']['src'], data['features']['dst'], ttype, conf))

    for score, fid, src, dst, ttype, conf in sorted(items, key=lambda x: x[0], reverse=True):
        print(f"{fid:20} | {src:15} | {dst:15} | {ttype:20} | {conf:<9}")
