# Network Traffic Monitoring and Anomaly Detection

A Python prototype that captures visible IP traffic with TShark, summarizes it in time windows and detects deviations from a normal-traffic reference using an RBF One-Class SVM.

**Author:** Mert Nusret Sağlam

## Pipeline

TShark capture or PCAP input → nine features per 10-second window → log1p transformation → StandardScaler fitted on training data → One-Class SVM → calibrated alert score and CSV output.

The features describe packet/byte rates, packet-size statistics, distinct IP/port counts, protocol fractions and SYN fraction. IPv4 and IPv6 are supported. Normal-data training, threshold calibration and normal holdout use chronological splits with gaps. Empty windows are marked `TRAFIK_YOK` separately from anomaly verdicts.

## API-free demo on Windows

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe smoke_test.py
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The smoke test generates artificial feature vectors, trains a model and replays a new artificial session. It requires neither TShark nor live packet capture and does not simulate a real network attack.

## Live monitoring

Install Wireshark/TShark and the appropriate capture driver, then identify the active adapter:

```powershell
.\.venv\Scripts\python.exe -m network_monitor.cli interfaces
```

Collect a representative normal baseline on your own adapter, train a model and monitor new windows. Full commands, capture setup and model-free adapter diagnostics are documented in [README_TR.md](README_TR.md). Interface IDs vary between computers; do not copy an ID without checking it.

## Evaluation and limits

Twelve automated tests and the synthetic end-to-end smoke test passed during development. No attack-detection accuracy, recall or ROC-AUC is claimed: such metrics require separately labeled normal and attack observations. New normal activity can also trigger novelty alerts.

Raspberry Pi deployment and resource use have not been benchmarked. No edge-device performance claim is made. Only load trusted, self-created joblib models. Keep real capture files, baseline data and trained models out of the source repository. See [VALIDATION.md](VALIDATION.md) for the validation record.
