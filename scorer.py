"""Combine detector outputs into a final risk score and confidence.
"""


def score_flow(detections: dict):
    """Return (score 0-100, confidence 0.0-1.0) based on detections.

    detections expected keys: ml_prob_encrypted (0..1), beaconing, dns_tunnel, protocol_anomaly
    """
    ml = float(detections.get('ml_prob_encrypted', 0.0))
    beacon = detections.get('beaconing', {})
    dns = detections.get('dns_tunnel', {})
    proto = detections.get('protocol_anomaly', {})

    beacon_score = float(beacon.get('score', 0.0)) if isinstance(beacon, dict) else (1.0 if beacon else 0.0)
    dns_flag = 1.0 if dns.get('flag') else 0.0
    proto_flag = 1.0 if proto.get('flag') else 0.0

    # Weighted combination
    raw = (ml * 50.0) + (beacon_score * 25.0) + (dns_flag * 15.0) + (proto_flag * 10.0)
    score = max(0.0, min(100.0, raw))

    # Confidence roughly corresponds to how many detectors fired or strong ML prob
    conf_components = [ml, beacon_score, dns_flag, proto_flag]
    confidence = min(1.0, sum(conf_components) / 4.0 + 0.1)

    return float(round(score, 2)), float(round(confidence, 2))
