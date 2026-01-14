"""PCAP parsing utilities using Scapy.

Extracts lightweight packet metadata without inspecting payloads.
"""
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS, DNSQR


def parse_pcap(path):
    """Read a pcap and return a list of packet metadata dicts.

    Each dict contains: timestamp, src_ip, dst_ip, protocol, packet_size,
    sport, dport, and dns_qname (if present).
    """
    packets = []
    pcap = rdpcap(path)
    for pkt in pcap:
        try:
            ts = float(pkt.time)
        except Exception:
            continue

        src = None
        dst = None
        proto = 'OTHER'
        sport = None
        dport = None
        dns_qname = None

        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            if TCP in pkt:
                proto = 'TCP'
                sport = int(pkt[TCP].sport)
                dport = int(pkt[TCP].dport)
            elif UDP in pkt:
                proto = 'UDP'
                sport = int(pkt[UDP].sport)
                dport = int(pkt[UDP].dport)
        elif IPv6 in pkt:
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
            if TCP in pkt:
                proto = 'TCP'
                sport = int(pkt[TCP].sport)
                dport = int(pkt[TCP].dport)
            elif UDP in pkt:
                proto = 'UDP'
                sport = int(pkt[UDP].sport)
                dport = int(pkt[UDP].dport)

        # DNS query name (if present)
        if DNS in pkt and pkt[DNS].qdcount > 0:
            try:
                q = pkt[DNS].qd
                if isinstance(q, DNSQR):
                    dns_qname = q.qname.decode() if isinstance(q.qname, bytes) else q.qname
            except Exception:
                dns_qname = None

        size = len(pkt)

        if src is None or dst is None:
            # skip non-IP packets
            continue

        packets.append({
            'timestamp': ts,
            'src_ip': src,
            'dst_ip': dst,
            'protocol': proto,
            'packet_size': size,
            'sport': sport,
            'dport': dport,
            'dns_qname': dns_qname,
            'raw': None,
        })

    return packets
