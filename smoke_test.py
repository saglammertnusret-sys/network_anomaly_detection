"""Test the complete offline path without TShark or actual packet capture."""
import csv
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
def run(*args):
    subprocess.run([sys.executable, '-m', 'network_monitor.cli', *map(str,args)], cwd=ROOT, check=True)

def main():
    with tempfile.TemporaryDirectory(prefix='network-smoke-') as directory:
        directory = Path(directory)
        run('demo-data', '--output', directory / 'data')
        run('train', '--data', directory / 'data' / 'normal.csv', '--output', directory / 'run', '--baseline-is-normal')
        run('replay', '--data', directory / 'data' / 'new_session.csv', '--model', directory / 'run' / 'model.joblib', '--output', directory / 'alerts.csv')
        with (directory / 'alerts.csv').open(newline='') as handle:
            rows = list(csv.DictReader(handle))
        assert len(rows) == 30
        assert any(int(row['anomaly']) for row in rows[10:15]), 'Synthetic novelty did not produce any alert.'
        report = json.loads((directory / 'run' / 'training_report.json').read_text())
        assert report['attack_detection_metrics'] is None
        assert report['split'] == {'train':216, 'calibration':70, 'normal_holdout':70, 'gap_per_boundary':2}
    print('\nSMOKE TEST PASSED. Synthetic alerts have no real attack-detection performance meaning.')

if __name__ == '__main__':
    main()
