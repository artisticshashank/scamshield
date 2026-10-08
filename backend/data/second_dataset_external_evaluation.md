# PhishBench-External D4v v2 External Evaluation

Evaluation used the frozen artifact and locked thresholds only. No retraining, refitting, threshold search, or live network/external-provider calls were performed. External reputation, domain intelligence, and redirect signals are explicitly unavailable for every record; FULL_SCAMSHIELD therefore has the same measurable score as RULE_PLUS_ML in this run.

## Dataset

- Rows: 1000
- Malicious: 500
- Benign: 500

## ML_ONLY

| Metric | Value |
|---|---:|
| ACCURACY | 71.6000% |
| PRECISION | 65.0000% |
| RECALL | 93.6000% |
| F1 | 76.7213% |
| PR_AUC | 88.9362% |
| ROC_AUC | 88.1188% |
| FPR | 50.4000% |
| FNR | 6.4000% |
| TP | 468 |
| TN | 248 |
| FP | 252 |
| FN | 32 |
| TOTAL | 1000 |
| MALICIOUS_COUNT | 500 |
| BENIGN_COUNT | 500 |
| THRESHOLD | 20.0 |


## RULE_PLUS_ML

| Metric | Value |
|---|---:|
| ACCURACY | 77.3000% |
| PRECISION | 74.6835% |
| RECALL | 82.6000% |
| F1 | 78.4425% |
| PR_AUC | 87.6866% |
| ROC_AUC | 86.2264% |
| FPR | 28.0000% |
| FNR | 17.4000% |
| TP | 413 |
| TN | 360 |
| FP | 140 |
| FN | 87 |
| TOTAL | 1000 |
| MALICIOUS_COUNT | 500 |
| BENIGN_COUNT | 500 |
| THRESHOLD | 30.0 |


## FULL_SCAMSHIELD

| Metric | Value |
|---|---:|
| ACCURACY | 77.3000% |
| PRECISION | 74.6835% |
| RECALL | 82.6000% |
| F1 | 78.4425% |
| PR_AUC | 87.6866% |
| ROC_AUC | 86.2264% |
| FPR | 28.0000% |
| FNR | 17.4000% |
| TP | 413 |
| TN | 360 |
| FP | 140 |
| FN | 87 |
| TOTAL | 1000 |
| MALICIOUS_COUNT | 500 |
| BENIGN_COUNT | 500 |
| THRESHOLD | 30.0 |


## External coverage

All three external components: available 0; unavailable 1000; failed 0; timeout 0; no-result 0; participating in scoring 0.

## Latency

```json
{
  "fusion_local_median_ms": 0.0835999999253545,
  "fusion_local_p95_ms": 0.130599997646641,
  "ml_median_ms": 0.6681499980913941,
  "ml_p95_ms": 0.9872000009636395
}
```

These are local deterministic timings; provider/network latency was not measured because no external requests were made.

## Error analysis

- ML false positives: 252
- ML false negatives: 32
- RULE_PLUS_ML/FULL false positives: 140
- RULE_PLUS_ML/FULL false negatives: 87
- Rules associated with fusion errors: `{'NO_TRIGGERED_RULES': 152, 'URL_NO_HTTPS': 50, 'URL_BRAND_IMPERSONATION': 18, 'URL_SUSPICIOUS_TLD': 4, 'URL_SHORTENER': 2, 'URL_IP_HOST': 1, 'URL_USERINFO_TRICK': 1}`

No production behavior was changed based on these results.
