#!/usr/bin/env python3
"""CLI entry for NetscapeX.

Usage:
    python netscapex.py --pcap sample.pcap --out report.json

Prints an ASCII banner, parses the PCAP, reconstructs flows,
extracts features, runs detectors, scores risk, and saves JSON.
"""
import argparse
import logging
import sys
import time
import threading

from parser import parse_pcap
from flow import FlowManager
from features import extract_flow_features
from detectors.ml_classifier import MLClassifier
from detectors.beaconing import detect_beaconing
from detectors.dns_tunnel import detect_dns_tunneling
from detectors.protocol_anomaly import detect_protocol_anomaly
from scorer import score_flow
from report import write_report, print_summary


ASCII_BANNER = r'''
888b    888          888                                                Y88b   d88P 
8888b   888          888                                                 Y88b d88P  
88888b  888          888                                                  Y88o88P   
888Y88b 888  .d88b.  888888 .d8888b   .d8888b  8888b.  88888b.   .d88b.    Y888P    
888 Y88b888 d8P  Y8b 888    88K      d88P"        "88b 888 "88b d8P  Y8b   d888b    
888  Y88888 88888888 888    "Y8888b. 888      .d888888 888  888 88888888  d88888b   
888   Y8888 Y8b.     Y88b.       X88 Y88b.    888  888 888 d88P Y8b.     d88P Y88b  
888    Y888  "Y8888   "Y888  88888P'  "Y8888P "Y888888 88888P"   "Y8888 d88P   Y88b 
                                                       888                          
                                                       888                          
                                                       888                          
>> CYBROSKIS :: NetscapeX :: Beyond Packet Inspection
'''


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%H:%M:%S',
    )


def type_banner(text: str, delay: float = 0.004):
    """Print the ASCII banner with a typing animation."""
    for ch in text:
        print(ch, end='', flush=True)
        time.sleep(delay)
    print()


def run_analysis(pcap_path: str, out_path: str, model_path: str = 'model.pkl'):
    """Run the full analysis pipeline for a given pcap and write report."""
    setup_logging()
    logging.info('Starting analysis: %s -> %s', pcap_path, out_path)

    try:
        packets = parse_pcap(pcap_path)
    except Exception as e:
        logging.error(f'Failed to read PCAP: {e}')
        return False

    fm = FlowManager()
    for pkt in packets:
        fm.add_packet(pkt)

    flows = fm.get_flows()
    logging.info('Reconstructed %d flows', len(flows))

    features_list = []
    for fid, flow in flows.items():
        feats = extract_flow_features(fid, flow)
        features_list.append(feats)

    import pandas as pd

    df = pd.DataFrame(features_list)

    ml = MLClassifier(model_path=model_path)
    probs = ml.predict_proba(df)
    df['ml_prob_encrypted'] = probs

    results = {}
    for i, row in df.iterrows():
        fid = row['flow_id']
        flow = flows[fid]
        det = {
            'ml_prob_encrypted': float(row['ml_prob_encrypted']),
            'beaconing': detect_beaconing(row),
            'dns_tunnel': detect_dns_tunneling(flow),
            'protocol_anomaly': detect_protocol_anomaly(flow),
        }
        score, confidence = score_flow(det)
        det['risk_score'] = score
        det['confidence'] = confidence
        results[fid] = {'features': row.to_dict(), 'detections': det}

    write_report(out_path, results)
    print_summary(results)
    logging.info('Report written to %s', out_path)
    return True


def interactive_menu():
    """Provide a simple menu-driven interface when no CLI args are provided."""
    # Typing banner animation
    type_banner(ASCII_BANNER, delay=0.002)

    menu = (
        "\nNetscapeX - Menu:\n"
        "1) Analyze PCAP file\n"
        "2) Show commands/help\n"
        "3) Exit\n"
        "Enter choice: "
    )

    while True:
        try:
            choice = input(menu).strip()
        except (EOFError, KeyboardInterrupt):
            print('\nExiting.')
            break

        if choice == '1':
            pcap = input('Enter PCAP path: ').strip()
            out = input('Enter output JSON path: ').strip()
            model = input('Optional model path (press enter to skip): ').strip() or 'model.pkl'
            print('\nRunning analysis... (logs will appear below)')
            run_analysis(pcap, out, model)
            print('\nAnalysis complete.')
        elif choice == '2':
            print('\nCommands:')
            print(' - Analyze PCAP: prompts for input/output and runs analysis')
            print(' - Show commands/help: display this help')
            print(' - Exit: quit the program')
        elif choice == '3':
            print('Goodbye.')
            break
        else:
            print('Invalid choice, try again.')


def main():
    # If arguments are provided, behave like before, otherwise show interactive menu
    if len(sys.argv) == 1:
        interactive_menu()
        return

    parser = argparse.ArgumentParser(description='NetscapeX CLI')
    parser.add_argument('--pcap', required=True, help='Input PCAP file')
    parser.add_argument('--out', required=True, help='Output JSON report')
    parser.add_argument('--model', default='model.pkl', help='Optional ML model path')
    args = parser.parse_args()

    # print banner without typing when called with args
    print(ASCII_BANNER)
    run_analysis(args.pcap, args.out, args.model)


if __name__ == '__main__':
    main()
