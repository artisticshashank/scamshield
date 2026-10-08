# TEST Evidence-Aware Confirmation

This was a single confirmation experiment on the untouched TEST partition. No production code, weights, thresholds, dataset, or artifact was modified. No retraining or TEST-based tuning was performed.

## Evaluation setup

- Dataset: `C:\Users\SHASHANK\OneDrive\Desktop\3RD-YR-MP\backend\data\Dataset.csv`
- Artifact: `C:\Users\SHASHANK\OneDrive\Desktop\3RD-YR-MP\backend\artifacts\scamshield_domain_grouped_baseline.pkl`
- Dataset SHA-256: `d68b3cd0648dcf9c775347416ad1a8995e8a025921fbe3871ca6158d4db3c3a1`
- Split: domain-grouped
- Seed: `42`
- TRAIN samples: `69,960`
- VALIDATION samples: `23,320`
- TEST samples: `23,319`
- ML-only threshold: `20`
- Fusion threshold: `30`

EVIDENCE_AWARE definition: when no rule evidence is present, the final score equals the ML score unchanged. When rule evidence is present, the final score is the existing equal Rules + ML blend.

## Metrics

| Configuration | Threshold | Precision | Recall | F1 | PR-AUC | ROC-AUC | FPR | FNR | TP | TN | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| CURRENT | 30 | 0.968553 | 0.675439 | 0.795866 | 0.881811 | 0.964164 | 0.000437 | 0.324561 | 308 | 22853 | 10 | 148 |
| EVIDENCE_AWARE | 30 | 0.938619 | 0.804825 | 0.866588 | 0.916623 | 0.988918 | 0.001050 | 0.195175 | 367 | 22839 | 24 | 89 |
| ML_ONLY_REFERENCE | 20 | 0.828390 | 0.857456 | 0.842672 | 0.919341 | 0.993122 | 0.003543 | 0.142544 | 391 | 22782 | 81 | 65 |

## EVIDENCE_AWARE comparison

- CURRENT total malicious misses: **148**
- Additional CURRENT misses that ML-only detected (the requested 83-URL cohort): **83**
- URLs recovered by EVIDENCE_AWARE within that 83-URL cohort: **59**
- CURRENT misses recovered by EVIDENCE_AWARE across all 148 malicious misses: **59**
- ML-only false positives: **81**
- ML-only false positives still suppressed by EVIDENCE_AWARE: **57**
- New false positives versus ML-only: **0**
- New false negatives versus ML-only: **24**
- TEST URLs with rule evidence: **65.7575%**

## Score distributions

| Configuration | Min | Q25 | Median | Mean | Q75 | Max |
|---|---:|---:|---:|---:|---:|---:|
| CURRENT | 0.000814 | 1.200910 | 3.648497 | 3.679878 | 3.813784 | 73.961943 |
| EVIDENCE_AWARE | 0.001627 | 2.401820 | 3.659122 | 4.512503 | 3.857119 | 99.865474 |
| ML_ONLY_REFERENCE | 0.000097 | 0.094857 | 0.353519 | 2.491494 | 1.178447 | 99.865474 |

## Comparison with existing TEST baseline

The existing CURRENT fusion baseline used the same artifact, same domain-grouped TEST partition, and fusion threshold `30`. EVIDENCE_AWARE was evaluated once against that fixed baseline. No threshold was selected after observing these TEST results.

| Metric | CURRENT | EVIDENCE_AWARE | Change (EVIDENCE_AWARE - CURRENT) |
|---|---:|---:|---:|
| Precision | 0.968553 | 0.938619 | -0.029935 |
| Recall | 0.675439 | 0.804825 | +0.129386 |
| F1 | 0.795866 | 0.866588 | +0.070722 |
| PR-AUC | 0.881811 | 0.916623 | +0.034812 |
| ROC-AUC | 0.964164 | 0.988918 | +0.024754 |
| FPR | 0.000437 | 0.001050 | +0.000612 |
| FNR | 0.324561 | 0.195175 | -0.129386 |
| TP | 308 | 367 | +59 |
| TN | 22853 | 22839 | -14 |
| FP | 10 | 24 | +14 |
| FN | 148 | 89 | -59 |

## Comparison with ML-only TEST reference

ML-only uses the unchanged model artifact and threshold `20`. EVIDENCE_AWARE uses fusion threshold `30`.

| Metric | ML-only | EVIDENCE_AWARE |
|---|---:|---:|
| Precision | 0.828390 | 0.938619 |
| Recall | 0.857456 | 0.804825 |
| F1 | 0.842672 | 0.866588 |
| PR-AUC | 0.919341 | 0.916623 |
| ROC-AUC | 0.993122 | 0.988918 |
| FPR | 0.003543 | 0.001050 |
| FNR | 0.142544 | 0.195175 |
| TP | 391 | 367 |
| TN | 22782 | 22839 |
| FP | 81 | 24 |
| FN | 65 | 89 |

## Status

This is a confirmation result only. It does not authorize a production change and does not select another threshold.
