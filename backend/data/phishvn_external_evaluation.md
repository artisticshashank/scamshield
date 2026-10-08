# PhishVN v3.1.0 Open External Evaluation

Evaluation used the frozen artifact and locked thresholds only. No retraining, refitting, threshold search, or live network/external-provider calls were performed. External reputation, domain intelligence, and redirect signals are explicitly unavailable for every record; FULL_SCAMSHIELD therefore has the same measurable score as RULE_PLUS_ML in this run.

## Dataset

- Rows: 8941
- Malicious: 5096
- Benign: 3845

## ML_ONLY

| Metric | Value |
|---|---:|
| ACCURACY | 58.2821% |
| PRECISION | 71.7932% |
| RECALL | 44.1523% |
| F1 | 54.6780% |
| PR_AUC | 66.9901% |
| ROC_AUC | 50.9380% |
| FPR | 22.9909% |
| FNR | 55.8477% |
| TP | 2250 |
| TN | 2961 |
| FP | 884 |
| FN | 2846 |
| TOTAL | 8941 |
| MALICIOUS_COUNT | 5096 |
| BENIGN_COUNT | 3845 |
| THRESHOLD | 20.0 |


## RULE_PLUS_ML

| Metric | Value |
|---|---:|
| ACCURACY | 54.0208% |
| PRECISION | 78.3535% |
| RECALL | 26.7072% |
| F1 | 39.8361% |
| PR_AUC | 66.9599% |
| ROC_AUC | 51.0112% |
| FPR | 9.7789% |
| FNR | 73.2928% |
| TP | 1361 |
| TN | 3469 |
| FP | 376 |
| FN | 3735 |
| TOTAL | 8941 |
| MALICIOUS_COUNT | 5096 |
| BENIGN_COUNT | 3845 |
| THRESHOLD | 30.0 |


## FULL_SCAMSHIELD

| Metric | Value |
|---|---:|
| ACCURACY | 54.0208% |
| PRECISION | 78.3535% |
| RECALL | 26.7072% |
| F1 | 39.8361% |
| PR_AUC | 66.9599% |
| ROC_AUC | 51.0112% |
| FPR | 9.7789% |
| FNR | 73.2928% |
| TP | 1361 |
| TN | 3469 |
| FP | 376 |
| FN | 3735 |
| TOTAL | 8941 |
| MALICIOUS_COUNT | 5096 |
| BENIGN_COUNT | 3845 |
| THRESHOLD | 30.0 |


## External coverage

All three external components: available 0; unavailable 8941; failed 0; timeout 0; no-result 0; participating in scoring 0.

## Latency

```json
{
  "fusion_local_median_ms": 0.08739999975659885,
  "fusion_local_p95_ms": 0.15020000137155876,
  "ml_median_ms": 0.684200000250712,
  "ml_p95_ms": 1.096500000130618
}
```

These are local deterministic timings; provider/network latency was not measured because no external requests were made.

## Error analysis

- ML false positives: 884
- ML false negatives: 2846
- RULE_PLUS_ML/FULL false positives: 376
- RULE_PLUS_ML/FULL false negatives: 3735
- Rules associated with fusion errors: `{'NO_TRIGGERED_RULES': 4021, 'URL_SUSPICIOUS_TLD': 48, 'URL_BRAND_IMPERSONATION': 24, 'URL_NO_HTTPS': 9, 'URL_PUNYCODE': 7, 'URL_HOMOGLYPH_SIGNAL': 7, 'URL_PAYMENT_KEYWORDS': 3}`

No production behavior was changed based on these results.
