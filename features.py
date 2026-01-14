"""Feature extraction for flows.

Compute inter-arrival times, packet size stats, bursts, duration, etc.
"""
import numpy as np


def extract_flow_features(flow_id, flow):
    """Return a dict of features for the given flow.

flow is {'key': (src,dst,proto), 'packets': [...]}
    """
    pkts = flow['packets']
    timestamps = [p['timestamp'] for p in pkts]
    sizes = [p['packet_size'] for p in pkts]

    pkt_count = len(pkts)
    duration = max(timestamps) - min(timestamps) if pkt_count > 1 else 0.0

    if pkt_count > 1:
        iats = np.diff(sorted(timestamps))
        iat_mean = float(np.mean(iats))
        iat_var = float(np.var(iats))
    else:
        iats = np.array([0.0])
        iat_mean = 0.0
        iat_var = 0.0

    pkt_mean = float(np.mean(sizes)) if sizes else 0.0
    pkt_var = float(np.var(sizes)) if sizes else 0.0

    # Simple burst detection: count groups separated by gap > threshold
    gap_thresh = 1.0  # seconds
    bursts = 1
    if pkt_count > 1:
        gaps = [t2 - t1 for t1, t2 in zip(sorted(timestamps)[:-1], sorted(timestamps)[1:])]
        bursts = 1 + sum(1 for g in gaps if g > gap_thresh)

    features = {
        'flow_id': flow_id,
        'src': flow['key'][0],
        'dst': flow['key'][1],
        'protocol': flow['key'][2],
        'pkt_count': pkt_count,
        'duration': float(duration),
        'iat_mean': float(iat_mean),
        'iat_var': float(iat_var),
        'pkt_size_mean': float(pkt_mean),
        'pkt_size_var': float(pkt_var),
        'burst_count': int(bursts),
    }

    return features
