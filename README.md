# NetscapeX CLI

NetscapeX is a lightweight Python CLI tool to parse PCAPs, reconstruct flows,
extract traffic features, run simple detectors, and produce a JSON security
report.

Example usage:

```bash
python netscapex.py --pcap sample.pcap --out report.json
```

Requirements: Python 3.10+, install dependencies:

```bash
pip install -r requirements.txt
```

Files created:

- `netscapex.py` - CLI entrypoint
- `parser.py` - PCAP parsing (scapy)
- `flow.py` - Flow reconstruction
- `features.py` - Feature extraction
- `detectors/` - Detection modules
- `scorer.py` - Risk scoring
- `report.py` - JSON output and CLI summary

Notes:
- The ML classifier uses a dummy RandomForest model placeholder and will
  create `model.pkl` if none exists.
- The tool avoids payload inspection; only packet metadata and DNS qname
  (if present in DNS layer) are used.
# NetscapeX-CLI