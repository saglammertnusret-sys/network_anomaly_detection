import csv
import hashlib
import json
import platform
import time
from pathlib import Path
import joblib
import numpy as np
import sklearn
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM
from .features import FEATURES, CSV_FIELDS

def read_windows(path):
    with Path(path).open(newline='', encoding='utf-8-sig') as handle:
        reader = csv.DictReader(handle)
        if not set(CSV_FIELDS).issubset(reader.fieldnames or []):
            raise ValueError('CSV feature columns are missing. Use collect, demo-data or export-pcap.')
        rows = list(reader)
    if not rows:
        raise ValueError('CSV contains no completed windows.')
    starts, durations, vectors = [], [], []
    for row in rows:
        starts.append(float(row['window_start']))
        durations.append(float(row['window_seconds']))
        vector = [float(row[name]) for name in FEATURES]
        if not np.isfinite(vector).all() or min(vector) < 0:
            raise ValueError('Features must be finite and nonnegative.')
        if any(value > 1 for value in vector[6:]):
            raise ValueError('Protocol fractions must be between zero and one.')
        vectors.append(vector)
    if not np.isfinite(starts).all() or not np.isfinite(durations).all() or min(durations) <= 0:
        raise ValueError('Window metadata must be finite with positive duration.')
    if not np.allclose(durations, durations[0], rtol=0, atol=1e-6):
        raise ValueError('Mixed window durations are not allowed.')
    if any(starts[i] < starts[i-1] + durations[0] - 1e-6 for i in range(1, len(starts))):
        raise ValueError('Windows overlap or are not in chronological order.')
    return rows, np.asarray(vectors), float(durations[0])

def transform(matrix):
    return np.log1p(matrix)

def score(bundle, matrix):
    return bundle['svm'].decision_function(bundle['scaler'].transform(transform(matrix)))

def load_model(path):
    # joblib files must come from this project or another trusted source.
    bundle = joblib.load(path)
    if bundle.get('schema_version') != 1 or bundle.get('features') != FEATURES:
        raise ValueError('Model feature schema is incompatible.')
    if bundle['sklearn_version'] != sklearn.__version__:
        raise ValueError('Model scikit-learn version differs. Use its requirements-frozen.txt or retrain.')
    return bundle

def train(csv_path, output, nu=.05, false_alarm=.05, gap=2):
    rows, matrix, seconds = read_windows(csv_path)
    n = len(rows)
    if n < 60:
        raise ValueError('Collect at least 60 complete windows; 360 or more are preferable.')
    if n > 20000:
        raise ValueError('This prototype supports at most 20000 windows per baseline.')
    if not 0 < nu < 1 or not 0 < false_alarm < .5 or gap < 0:
        raise ValueError('Use 0 < nu < 1, 0 < target-false-alarm < 0.5 and gap >= 0.')
    if any('label' in row and row['label'].upper() not in ('NORMAL', 'BENIGN', '0') for row in rows):
        raise ValueError('Baseline contains non-normal labels. Train only on reviewed normal traffic.')
    a, b = int(n*.6), int(n*.8)
    x_train, x_cal, x_test = matrix[:a], matrix[a+gap:b], matrix[b+gap:]
    if len(x_cal) < 10 or len(x_test) < 10:
        raise ValueError('Calibration or holdout is too small after the temporal gaps.')
    if not np.any(np.ptp(x_train, axis=0) > 0):
        raise ValueError('Training windows have no variation; record representative normal activity.')
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError('Run folder is not empty. Choose a new run folder to keep previous results.')
    output.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    scaler = StandardScaler().fit(transform(x_train))
    svm = OneClassSVM(kernel='rbf', gamma='scale', nu=nu).fit(scaler.transform(transform(x_train)))
    bundle = {'schema_version': 1, 'features': FEATURES, 'window_seconds': seconds,
              'scaler': scaler, 'svm': svm, 'sklearn_version': sklearn.__version__,
              'source_sha256': hashlib.sha256(Path(csv_path).read_bytes()).hexdigest()}
    calibration_scores = score(bundle, x_cal)
    bundle['threshold'] = float(np.quantile(calibration_scores, false_alarm))
    test_scores = score(bundle, x_test)
    elapsed = time.perf_counter() - started
    metadata = {'algorithm': 'OneClassSVM', 'kernel': 'rbf', 'gamma': 'scale', 'nu': nu,
                'window_seconds': seconds, 'features': FEATURES,
                'target_calibration_false_alarm': false_alarm, 'threshold': bundle['threshold'],
                'split': {'train': len(x_train), 'calibration': len(x_cal),
                          'normal_holdout': len(x_test), 'gap_per_boundary': gap},
                'source_sha256': bundle['source_sha256'], 'fit_and_validation_seconds': elapsed,
                'support_vectors': int(svm.support_.size),
                'calibration_alert_rate': float(np.mean(calibration_scores < bundle['threshold'])),
                'normal_holdout_alert_rate': float(np.mean(test_scores < bundle['threshold'])),
                'label_assumption': 'User reviewed this entire capture as normal; not verified by the algorithm.',
                'attack_detection_metrics': None,
                'python': platform.python_version(), 'sklearn': sklearn.__version__,
                'numpy': np.__version__}
    temporary = output / 'model.joblib.tmp'
    joblib.dump(bundle, temporary)
    temporary.replace(output / 'model.joblib')
    (output / 'training_report.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    with (output / 'normal_holdout_scores.csv').open('w', newline='', encoding='utf-8') as handle:
        writer = csv.writer(handle)
        writer.writerow(['window_start', 'decision_score', 'anomaly'])
        for row, value in zip(rows[b+gap:], test_scores):
            writer.writerow([row['window_start'], value, int(value < bundle['threshold'])])
    if len(x_cal) < 100:
        print('NOTE: fewer than 100 calibration windows; the threshold estimate is unstable.', flush=True)
    return metadata
