import argparse
import csv
import hashlib
import json
import subprocess
import sys
import time
from contextlib import closing, nullcontext
from pathlib import Path
import numpy as np
from .features import FEATURES, CSV_FIELDS
from .model import read_windows, load_model, score, train
from .capture import interfaces, live_windows, pcap_windows, tshark_path

def open_csv(path, fields):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open('x', newline='', encoding='utf-8')
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader(); handle.flush()
    return handle, writer

def write_windows(path, windows):
    handle, writer = open_csv(path, CSV_FIELDS)
    count = 0
    with handle, closing(windows):
        for row in windows:
            writer.writerow(row); handle.flush(); count += 1
    if not count:
        raise ValueError('No completed windows were recorded. Choose a longer capture and a new output filename.')
    print(f'Saved {count} complete windows to {path}', flush=True)

def collect(args):
    tshark_path(args.tshark)
    write_windows(args.output, live_windows(args.interface, args.window, args.seconds, args.tshark))

def export_pcap(args):
    tshark_path(args.tshark)
    write_windows(args.output, pcap_windows(args.pcap, args.window, args.tshark))

def training(args):
    if not args.baseline_is_normal:
        raise ValueError('Review the baseline and add --baseline-is-normal only if it represents normal activity.')
    print('Fitting One-Class SVM on the first chronological segment...', flush=True)
    report = train(args.data, args.output, args.nu, args.target_false_alarm, args.gap)
    frozen = subprocess.run([sys.executable, '-m', 'pip', 'freeze'], text=True, capture_output=True)
    if not frozen.returncode:
        (Path(args.output) / 'requirements-frozen.txt').write_text(frozen.stdout, encoding='utf-8')
    print(json.dumps(report, indent=2), flush=True)
    print('Normal holdout alert rate is not attack-detection accuracy.', flush=True)

def decisions(bundle, rows):
    for row in rows:
        if not np.isclose(float(row['window_seconds']), bundle['window_seconds'], rtol=0, atol=1e-6):
            raise ValueError('Window duration differs from the model baseline.')
        started = time.perf_counter()
        value = float(score(bundle, np.asarray([[float(row[name]) for name in FEATURES]]))[0])
        latency = (time.perf_counter() - started)*1000
        yield {**row, 'decision_score': value, 'threshold': bundle['threshold'],
               'anomaly': int(value < bundle['threshold']), 'inference_ms': latency}

def write_decisions(path, bundle, rows, delay=0):
    handle, writer = open_csv(path, [*CSV_FIELDS, 'decision_score', 'threshold', 'anomaly', 'inference_ms'])
    count = alerts = 0
    with handle, (closing(rows) if hasattr(rows, 'close') else nullcontext(rows)):
        for result in decisions(bundle, rows):
            writer.writerow(result); handle.flush()
            count += 1; alerts += result['anomaly']
            state = 'ANOMALI' if result['anomaly'] else 'NORMAL'
            print(f'[{state}] window={count} packets/s={float(result["packets_per_second"]):.1f} '
                  f'bytes/s={float(result["bytes_per_second"]):.0f} '
                  f'score={result["decision_score"]:.4f} '
                  f'threshold={bundle["threshold"]:.4f} '
                  f'inference={result["inference_ms"]:.2f}ms', flush=True)
            if delay:
                time.sleep(delay)
    print(f'{count} windows, {alerts} alerts. Saved {path}. Alerts are not proof of attacks.', flush=True)

def replay(args):
    if args.delay < 0:
        raise ValueError('Delay must be nonnegative.')
    bundle = load_model(args.model)
    rows, _, seconds = read_windows(args.data)
    same = hashlib.sha256(Path(args.data).read_bytes()).hexdigest() == bundle['source_sha256']
    if same:
        print('NOTE: this is the training baseline. Replay demonstrates operation, not independent evaluation.', flush=True)
    if not np.isclose(seconds, bundle['window_seconds'], rtol=0, atol=1e-6):
        raise ValueError('Window duration differs from the model baseline.')
    write_decisions(args.output, bundle, iter(rows), args.delay)

def monitor(args):
    tshark_path(args.tshark)
    bundle = load_model(args.model)
    # Use exactly the window length recorded with the trained model.
    write_decisions(args.output, bundle,
                    live_windows(args.interface, bundle['window_seconds'], args.seconds, args.tshark,
                                 on_window=lambda row: None))

def demo_data(args):
    root = Path(args.output)
    if root.exists() and any(root.iterdir()):
        raise ValueError('Demo folder is not empty. Choose a new folder.')
    root.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(42)
    def make_row(index, unusual=False):
        packet_rate = max(.1, rng.normal(55, 8))
        mean = max(60, rng.normal(600, 55))
        values = [packet_rate, packet_rate*mean, mean, rng.uniform(250, 350),
                  int(rng.integers(8, 18)), int(rng.integers(10, 25)),
                  rng.uniform(.72, .88), 0, rng.uniform(.01, .08)]
        values[7] = 1 - values[6]
        if unusual:
            values[0] *= 12; values[1] *= 12; values[4] *= 20; values[5] *= 20
            values[8] = .7
        return dict(zip(CSV_FIELDS, [1700000000 + index*10, 10, *values]))
    for filename, n, unusual in [('normal.csv', 360, False), ('new_session.csv', 30, True)]:
        handle, writer = open_csv(root / filename, CSV_FIELDS)
        with handle:
            for index in range(n):
                writer.writerow(make_row(index + (400 if unusual else 0), unusual and 10 <= index < 15))
    (root / 'ABOUT.txt').write_text('SYNTHETIC DATA FOR SOFTWARE TESTING ONLY.\n'
        'These records are generated feature vectors, not captured packets or real attacks.\n'
        'Do not report detection accuracy from them.\n', encoding='utf-8')
    print(f'Synthetic feature CSVs created in {root}. No network packets were sent or captured.', flush=True)

def main():
    parser = argparse.ArgumentParser(description='One-Class SVM network novelty detection research prototype')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('interfaces'); p.add_argument('--tshark'); p.set_defaults(handler=lambda a: print(interfaces(a.tshark)))
    p = sub.add_parser('demo-data'); p.add_argument('--output', required=True); p.set_defaults(handler=demo_data)
    for name, handler in [('collect',collect), ('export-pcap',export_pcap), ('monitor',monitor)]:
        p = sub.add_parser(name); p.add_argument('--output', required=True); p.add_argument('--tshark')
        if name == 'export-pcap':
            p.add_argument('--pcap', required=True)
        else:
            p.add_argument('--interface', required=True)
            p.add_argument('--seconds', type=float, default=900)
        if name == 'monitor':
            p.add_argument('--model', required=True)
        else:
            p.add_argument('--window', type=float, default=10)
        p.set_defaults(handler=handler)
    p = sub.add_parser('train')
    p.add_argument('--data', required=True); p.add_argument('--output', required=True)
    p.add_argument('--baseline-is-normal', action='store_true')
    p.add_argument('--nu', type=float, default=.05)
    p.add_argument('--target-false-alarm', type=float, default=.05)
    p.add_argument('--gap', type=int, default=2); p.set_defaults(handler=training)
    p = sub.add_parser('replay')
    p.add_argument('--data', required=True); p.add_argument('--model', required=True)
    p.add_argument('--output', required=True); p.add_argument('--delay', type=float, default=0)
    p.set_defaults(handler=replay)
    args = parser.parse_args()
    try:
        args.handler(args)
    except KeyboardInterrupt:
        parser.exit(130, '\nStopped by Ctrl+C. Completed CSV rows remain saved; partial windows are omitted.\n')
    except (ValueError, FileNotFoundError, FileExistsError, PermissionError, OSError) as error:
        parser.exit(2, f'Error: {error}\n')

if __name__ == '__main__':
    main()
