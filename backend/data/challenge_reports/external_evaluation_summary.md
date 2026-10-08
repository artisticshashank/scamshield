# External Evaluation Summary

## Frozen configuration

- Dataset.csv SHA-256: `d68b3cd0648dcf9c775347416ad1a8995e8a025921fbe3871ca6158d4db3c3a1`
- Model artifact SHA-256: `fda0c7b574ab944e58af3446d8bd806c4e0ae4516c8610373588df454acd7885`
- Domain-grouped split: train 69960, validation 23320, test 23319; seed 42
- Locked thresholds: ML 20, suspicious 30, dangerous 70
- Evaluation timestamp: `2026-10-07T21:12:36.370519+00:00`
- Python: `3.11.9`; packages: `{'numpy': '2.4.0', 'scikit-learn': '1.9.0', 'shap': '0.47.2', 'scipy': '1.17.1'}`

## Source identity

| Benchmark | Rows | Malicious | Benign | SHA-256 |
|---|---:|---:|---:|---|
| PhishVN v3.1.0 Open | 8941 | 5096 | 3845 | `b692882e8ae26b2c0b217c090e92d3a19307a26acbfb3c8c89692db26d409bc9` |
| PhishBench-External D4v v2 | 1000 | 500 | 500 | `df25f4cae492c91cdca83887737a3d1672df71ebe8b581eeac21715a704b869f` |

## Metrics

| Benchmark | Configuration | Accuracy | Precision | Recall | F1 | PR-AUC | ROC-AUC | FPR | FNR | TP | TN | FP | FN |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| PhishVN v3.1.0 Open | ML_ONLY | 58.2821% | 71.7932% | 44.1523% | 54.6780% | 66.9901% | 50.9380% | 22.9909% | 55.8477% | 2250 | 2961 | 884 | 2846 |
| PhishVN v3.1.0 Open | RULE_PLUS_ML | 54.0208% | 78.3535% | 26.7072% | 39.8361% | 66.9599% | 51.0112% | 9.7789% | 73.2928% | 1361 | 3469 | 376 | 3735 |
| PhishVN v3.1.0 Open | FULL_SCAMSHIELD | 54.0208% | 78.3535% | 26.7072% | 39.8361% | 66.9599% | 51.0112% | 9.7789% | 73.2928% | 1361 | 3469 | 376 | 3735 |
| PhishBench-External D4v v2 | ML_ONLY | 71.6000% | 65.0000% | 93.6000% | 76.7213% | 88.9362% | 88.1188% | 50.4000% | 6.4000% | 468 | 248 | 252 | 32 |
| PhishBench-External D4v v2 | RULE_PLUS_ML | 77.3000% | 74.6835% | 82.6000% | 78.4425% | 87.6866% | 86.2264% | 28.0000% | 17.4000% | 413 | 360 | 140 | 87 |
| PhishBench-External D4v v2 | FULL_SCAMSHIELD | 77.3000% | 74.6835% | 82.6000% | 78.4425% | 87.6866% | 86.2264% | 28.0000% | 17.4000% | 413 | 360 | 140 | 87 |

## Overlap and limitations

- PhishVN normalized overlap with Dataset.csv: 10; training partition: 10; validation: 0; test: 0.
- PhishBench normalized overlap with Dataset.csv: 5; training partition: 5; validation: 0; test: 0.
- Cross-source normalized overlap: 41; host overlap: 41.
- External intelligence coverage was 0% because no live provider/DNS/TLS/redirect requests were made.
- These benchmarks provide external evaluation evidence, but overlap and source-level duplicate findings limit claims of strict independence.
- No superiority, zero-day, or production-readiness claim is made.

## Existing Dataset.csv TEST reference

The previously completed locked domain-grouped TEST reference for ML_ONLY at threshold 20 was: accuracy 99.3739%, precision 82.8390%, recall 85.7456%, F1 84.2672%, PR-AUC 91.9341%, ROC-AUC 99.3122%, FPR 0.3543%, FNR 14.2544%, TP 391, TN 22,782, FP 81, FN 65. This is a reference comparison only; no thresholds or production behavior were changed.
