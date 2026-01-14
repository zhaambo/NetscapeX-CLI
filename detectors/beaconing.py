"""Beaconing detector: finds low-variance periodic small outbound flows."""


def detect_beaconing(features_row):
    """Detect beaconing from features (pandas Series or dict-like).

    Returns dict with 'flag' and 'score'.
    """
    try:
        iat_var = float(features_row.get('iat_var', features_row.get('iat_var', 0)))
        pkt_mean = float(features_row.get('pkt_size_mean', 0))
        pkt_count = int(features_row.get('pkt_count', 0))
        iat_mean = float(features_row.get('iat_mean', 0))
    except Exception:
        return {'flag': False, 'score': 0.0}

    # Heuristic: many small packets, low variance of inter-arrival times
    flag = (pkt_count >= 4) and (pkt_mean < 400) and (iat_var < max(0.5, iat_mean * 0.5))
    score = 0.0
    if flag:
        # stronger score for lower variance
        score = min(1.0, 0.9 * (1.0 / (1.0 + iat_var)))

    return {'flag': bool(flag), 'score': float(score)}
