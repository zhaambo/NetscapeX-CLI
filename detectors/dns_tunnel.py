"""DNS tunneling detector using domain entropy heuristics."""
import math


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    probs = [v / len(s) for v in freq.values()]
    return -sum(p * math.log2(p) for p in probs)


def detect_dns_tunneling(flow):
    """Inspect packets in a flow for DNS queries and flag high-entropy long domains.

    flow: {'key':..., 'packets': [...]}
    """
    found = False
    reasons = []
    for p in flow['packets']:
        q = p.get('dns_qname')
        if not q:
            continue
        # normalize
        qstr = q.rstrip('.') if isinstance(q, str) else str(q)
        ent = shannon_entropy(qstr)
        if len(qstr) > 30 and ent > 3.5:
            found = True
            reasons.append({'qname': qstr, 'entropy': ent, 'length': len(qstr)})

    return {'flag': bool(found), 'reasons': reasons}
