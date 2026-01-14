"""Flow reconstruction utilities.

Group packets into flows keyed by (src_ip, dst_ip, protocol).
"""
from collections import defaultdict


class FlowManager:
    def __init__(self):
        # flows: key -> list of packet metadata dicts
        self.flows = defaultdict(list)

    def _key(self, pkt):
        return (pkt['src_ip'], pkt['dst_ip'], pkt['protocol'])

    def add_packet(self, pkt):
        key = self._key(pkt)
        self.flows[key].append(pkt)

    def get_flows(self):
        # convert to a dict with string flow ids
        out = {}
        for i, (k, pkts) in enumerate(self.flows.items(), start=1):
            fid = f'flow-{i}'
            out[fid] = {'key': k, 'packets': pkts}
        return out
