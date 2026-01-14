"""Detect protocol/port mismatches.

Examples: HTTPS (port 443) over UDP, or non-TCP protocols using ports
commonly associated with another protocol.
"""


def detect_protocol_anomaly(flow):
    anomalies = []
    for p in flow['packets']:
        proto = p.get('protocol')
        sport = p.get('sport')
        dport = p.get('dport')

        # Port 443 typically TCP (HTTPS). If seen on UDP, flag it.
        if (sport == 443 or dport == 443) and proto != 'TCP':
            anomalies.append({'type': '443_on_non_tcp', 'pkt': {'sport': sport, 'dport': dport, 'proto': proto}})

        # Port 53 usually DNS over UDP
        if (sport == 53 or dport == 53) and proto != 'UDP':
            anomalies.append({'type': '53_on_non_udp', 'pkt': {'sport': sport, 'dport': dport, 'proto': proto}})

    return {'flag': bool(anomalies), 'anomalies': anomalies}
