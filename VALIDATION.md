# Validation record

Checked on 2026-10-02 in a Linux CPU environment with Python 3.12.14,
NumPy 2.3.5, scikit-learn 1.8.0 and joblib 1.5.3.

## Passed

- Eight unit/integration checks covering IPv4 and IPv6 parsing, window statistics,
  chronological train/calibration/holdout boundaries, train-only scaler fitting,
  quantile threshold selection, model reload, invalid/overlapping windows,
  contaminated baseline rejection, idle windows, streamed packet processing,
  capture-process errors, and omission of partial PCAP tails.
- End-to-end synthetic feature demo: data generation, SVM fitting, persistence,
  independent synthetic-session replay, console alerts and output CSV.
- Saved run folders are protected against accidental overwrite.

The capture-process tests use controlled subprocess fixtures, not a real TShark
installation. Synthetic records are generated feature vectors; no live packets,
real attacks or attack datasets were used. No detection accuracy, recall or AUC
is established by these checks.

## Requires testing on the user's device

- Windows Python installation and dependency commands.
- Actual TShark/Npcap interface listing and live packet capture.
- Real PCAP decoding by TShark, capture loss and clock/buffering effects.
- Windows Ctrl+C process cleanup, including TShark and its capture child.
- Representative normal reference collection, false alarms in new real sessions,
  and separately labeled normal/attack evaluation.
- Raspberry Pi installation, capture permissions, CPU/RAM use and throughput.

The reconstruction implements a window-based novelty detector. It does not
recover or verify the lost project's original implementation or measurements.
