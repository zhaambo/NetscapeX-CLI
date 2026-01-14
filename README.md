# NetscapeX CLI

NetscapeX is a lightweight, modular Python CLI for basic PCAP analysis and
security-oriented flow inspection. It reconstructs IP flows, extracts
statistical features, runs simple detectors (including a placeholder ML
classifier), and produces a structured JSON report.

Quick start
-----------

Install dependencies (Python 3.10+):

```bash
pip install -r requirements.txt
```

Interactive menu (recommended):

```bash
python netscapex.py
```

Direct analyze (non-interactive):

```bash
python netscapex.py --pcap sample.pcap --out report.json
```

What it does
------------
- Parses PCAPs (Scapy) and extracts packet metadata (timestamp, src/dst IP,
  protocol, packet size). No payload inspection is performed.
- Reconstructs flows using the tuple (src_ip, dst_ip, protocol).
- Extracts features per flow: inter-arrival times, packet size mean/variance,
  burst count, and flow duration.
- Runs detectors:
  - ML traffic classifier (RandomForest placeholder)
  - Beaconing detector (low-variance periodic traffic)
  - DNS tunneling detector (high-entropy domain labels)
  - Protocol anomaly detector (port/protocol mismatches)
- Combines detections into a risk score (0–100) and confidence value.
- Prints a CLI summary table and writes a JSON report with full details.

Project layout
--------------
- `netscapex.py` — CLI entrypoint and interactive menu
- `parser.py` — PCAP parsing utilities (Scapy)
- `flow.py` — Flow reconstruction
- `features.py` — Feature extraction
- `detectors/` — Detector modules and ML placeholder
- `scorer.py` — Risk scoring logic
- `report.py` — JSON output and CLI summary
- `requirements.txt` — Python dependencies

Notes
-----
- The ML classifier will create a small dummy `model.pkl` if none exists.
- The interactive mode shows a typing-style banner and a simple menu for
  running analysis without command-line arguments.
- Handle large PCAPs carefully — this tool is designed for laptops and small
  to medium captures; for very large files consider sampling or using a
  more scalable pipeline.

Example output
--------------
See `sample_output.json` for a minimal example of the JSON report structure.

Contributing
------------
If you'd like enhancements (better detectors, PyShark parsing option, CLI
flags, or tests), open an issue or submit a PR.
