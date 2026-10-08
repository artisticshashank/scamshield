# Final Controlled ScamShield Component Ablation

Read-only evaluation on the untouched domain-grouped TEST partition. No retraining, TEST tuning, live network calls, production changes, artifact changes, or dataset changes occurred.

- TEST: 23,319; seed: 42; SHA-256: `d68b3cd0648dcf9c775347416ad1a8995e8a025921fbe3871ca6158d4db3c3a1`
- Thresholds: ML 20; suspicious 30; dangerous 70
- Reputation/domain/redirect fixture overlap with TEST: 0 URLs; these signals remain explicitly unavailable.

## Complete metrics

| Configuration | Status | Threshold | Precision | Recall | F1 | PR-AUC | ROC-AUC | FPR | FNR | TP | TN | FP | FN | Median ms | P95 ms |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| DOMAIN_INTELLIGENCE_ONLY | UNAVAILABLE | 30 | — | — | — | — | — | — | — | — | — | — | — | 0.0001 | 0.0002 |
| FULL_SCAMSHIELD | partial_unavailable | 30 | 0.938619 | 0.804825 | 0.866588 | 0.916623 | 0.988918 | 0.001050 | 0.195175 | 367 | 22839 | 24 | 89 | 0.0066 | 0.0129 |
| ML_ONLY | available | 20 | 0.828390 | 0.857456 | 0.842672 | 0.919341 | 0.993122 | 0.003543 | 0.142544 | 391 | 22782 | 81 | 65 | 0.0060 | 0.0117 |
| ML_PLUS_DOMAIN | partial_unavailable | 20 | 0.828390 | 0.857456 | 0.842672 | 0.919341 | 0.993122 | 0.003543 | 0.142544 | 391 | 22782 | 81 | 65 | 0.0058 | 0.0096 |
| ML_PLUS_REDIRECT | partial_unavailable | 20 | 0.828390 | 0.857456 | 0.842672 | 0.919341 | 0.993122 | 0.003543 | 0.142544 | 391 | 22782 | 81 | 65 | 0.0062 | 0.0122 |
| ML_PLUS_REPUTATION | partial_unavailable | 20 | 0.828390 | 0.857456 | 0.842672 | 0.919341 | 0.993122 | 0.003543 | 0.142544 | 391 | 22782 | 81 | 65 | 0.0069 | 0.0102 |
| REDIRECT_ONLY | UNAVAILABLE | 30 | — | — | — | — | — | — | — | — | — | — | — | 0.0002 | 0.0002 |
| REPUTATION_ONLY | UNAVAILABLE | 30 | — | — | — | — | — | — | — | — | — | — | — | 0.0001 | 0.0002 |
| RULE_ONLY | available | 30 | 1.000000 | 0.015351 | 0.030238 | 0.101939 | 0.347602 | 0.000000 | 0.984649 | 7 | 22863 | 0 | 449 | 0.0062 | 0.0116 |
| RULE_PLUS_ML | available | 30 | 0.938619 | 0.804825 | 0.866588 | 0.916623 | 0.988918 | 0.001050 | 0.195175 | 367 | 22839 | 24 | 89 | 0.0067 | 0.0148 |
| RULE_PLUS_ML_PLUS_DOMAIN | partial_unavailable | 30 | 0.938619 | 0.804825 | 0.866588 | 0.916623 | 0.988918 | 0.001050 | 0.195175 | 367 | 22839 | 24 | 89 | 0.0068 | 0.0129 |
| RULE_PLUS_ML_PLUS_DOMAIN_PLUS_REDIRECT | partial_unavailable | 30 | 0.938619 | 0.804825 | 0.866588 | 0.916623 | 0.988918 | 0.001050 | 0.195175 | 367 | 22839 | 24 | 89 | 0.0070 | 0.0125 |
| RULE_PLUS_ML_PLUS_REDIRECT | partial_unavailable | 30 | 0.938619 | 0.804825 | 0.866588 | 0.916623 | 0.988918 | 0.001050 | 0.195175 | 367 | 22839 | 24 | 89 | 0.0068 | 0.0128 |
| RULE_PLUS_ML_PLUS_REPUTATION | partial_unavailable | 30 | 0.938619 | 0.804825 | 0.866588 | 0.916623 | 0.988918 | 0.001050 | 0.195175 | 367 | 22839 | 24 | 89 | 0.0068 | 0.0127 |
| RULE_PLUS_ML_PLUS_REPUTATION_PLUS_DOMAIN | partial_unavailable | 30 | 0.938619 | 0.804825 | 0.866588 | 0.916623 | 0.988918 | 0.001050 | 0.195175 | 367 | 22839 | 24 | 89 | 0.0064 | 0.0115 |
| RULE_PLUS_ML_PLUS_REPUTATION_PLUS_REDIRECT | partial_unavailable | 30 | 0.938619 | 0.804825 | 0.866588 | 0.916623 | 0.988918 | 0.001050 | 0.195175 | 367 | 22839 | 24 | 89 | 0.0069 | 0.0119 |
| RULE_PLUS_REPUTATION | partial_unavailable | 30 | 1.000000 | 0.015351 | 0.030238 | 0.101939 | 0.347602 | 0.000000 | 0.984649 | 7 | 22863 | 0 | 449 | 0.0071 | 0.0122 |
| WITHOUT_DOMAIN_INTELLIGENCE | partial_unavailable | 30 | 0.938619 | 0.804825 | 0.866588 | 0.916623 | 0.988918 | 0.001050 | 0.195175 | 367 | 22839 | 24 | 89 | 0.0064 | 0.0118 |
| WITHOUT_ML | partial_unavailable | 30 | 1.000000 | 0.015351 | 0.030238 | 0.101939 | 0.347602 | 0.000000 | 0.984649 | 7 | 22863 | 0 | 449 | 0.0058 | 0.0109 |
| WITHOUT_REDIRECT_ANALYSIS | partial_unavailable | 30 | 0.938619 | 0.804825 | 0.866588 | 0.916623 | 0.988918 | 0.001050 | 0.195175 | 367 | 22839 | 24 | 89 | 0.0068 | 0.0136 |
| WITHOUT_REPUTATION | partial_unavailable | 30 | 0.938619 | 0.804825 | 0.866588 | 0.916623 | 0.988918 | 0.001050 | 0.195175 | 367 | 22839 | 24 | 89 | 0.0074 | 0.0149 |
| WITHOUT_RULES | partial_unavailable | 20 | 0.828390 | 0.857456 | 0.842672 | 0.919341 | 0.993122 | 0.003543 | 0.142544 | 391 | 22782 | 81 | 65 | 0.0054 | 0.0096 |

## Sorted by F1

| Rank | Configuration | Status | Value |
|---:|---|---|---:|
| 1 | FULL_SCAMSHIELD | partial_unavailable | 0.866588 |
| 2 | RULE_PLUS_ML | available | 0.866588 |
| 3 | RULE_PLUS_ML_PLUS_DOMAIN | partial_unavailable | 0.866588 |
| 4 | RULE_PLUS_ML_PLUS_DOMAIN_PLUS_REDIRECT | partial_unavailable | 0.866588 |
| 5 | RULE_PLUS_ML_PLUS_REDIRECT | partial_unavailable | 0.866588 |
| 6 | RULE_PLUS_ML_PLUS_REPUTATION | partial_unavailable | 0.866588 |
| 7 | RULE_PLUS_ML_PLUS_REPUTATION_PLUS_DOMAIN | partial_unavailable | 0.866588 |
| 8 | RULE_PLUS_ML_PLUS_REPUTATION_PLUS_REDIRECT | partial_unavailable | 0.866588 |
| 9 | WITHOUT_DOMAIN_INTELLIGENCE | partial_unavailable | 0.866588 |
| 10 | WITHOUT_REDIRECT_ANALYSIS | partial_unavailable | 0.866588 |
| 11 | WITHOUT_REPUTATION | partial_unavailable | 0.866588 |
| 12 | ML_ONLY | available | 0.842672 |
| 13 | ML_PLUS_DOMAIN | partial_unavailable | 0.842672 |
| 14 | ML_PLUS_REDIRECT | partial_unavailable | 0.842672 |
| 15 | ML_PLUS_REPUTATION | partial_unavailable | 0.842672 |
| 16 | WITHOUT_RULES | partial_unavailable | 0.842672 |
| 17 | RULE_ONLY | available | 0.030238 |
| 18 | RULE_PLUS_REPUTATION | partial_unavailable | 0.030238 |
| 19 | WITHOUT_ML | partial_unavailable | 0.030238 |
| 20 | DOMAIN_INTELLIGENCE_ONLY | unavailable | — |
| 21 | REDIRECT_ONLY | unavailable | — |
| 22 | REPUTATION_ONLY | unavailable | — |

## Sorted by malicious recall

| Rank | Configuration | Status | Value |
|---:|---|---|---:|
| 1 | ML_ONLY | available | 0.857456 |
| 2 | ML_PLUS_DOMAIN | partial_unavailable | 0.857456 |
| 3 | ML_PLUS_REDIRECT | partial_unavailable | 0.857456 |
| 4 | ML_PLUS_REPUTATION | partial_unavailable | 0.857456 |
| 5 | WITHOUT_RULES | partial_unavailable | 0.857456 |
| 6 | FULL_SCAMSHIELD | partial_unavailable | 0.804825 |
| 7 | RULE_PLUS_ML | available | 0.804825 |
| 8 | RULE_PLUS_ML_PLUS_DOMAIN | partial_unavailable | 0.804825 |
| 9 | RULE_PLUS_ML_PLUS_DOMAIN_PLUS_REDIRECT | partial_unavailable | 0.804825 |
| 10 | RULE_PLUS_ML_PLUS_REDIRECT | partial_unavailable | 0.804825 |
| 11 | RULE_PLUS_ML_PLUS_REPUTATION | partial_unavailable | 0.804825 |
| 12 | RULE_PLUS_ML_PLUS_REPUTATION_PLUS_DOMAIN | partial_unavailable | 0.804825 |
| 13 | RULE_PLUS_ML_PLUS_REPUTATION_PLUS_REDIRECT | partial_unavailable | 0.804825 |
| 14 | WITHOUT_DOMAIN_INTELLIGENCE | partial_unavailable | 0.804825 |
| 15 | WITHOUT_REDIRECT_ANALYSIS | partial_unavailable | 0.804825 |
| 16 | WITHOUT_REPUTATION | partial_unavailable | 0.804825 |
| 17 | RULE_ONLY | available | 0.015351 |
| 18 | RULE_PLUS_REPUTATION | partial_unavailable | 0.015351 |
| 19 | WITHOUT_ML | partial_unavailable | 0.015351 |
| 20 | DOMAIN_INTELLIGENCE_ONLY | unavailable | — |
| 21 | REDIRECT_ONLY | unavailable | — |
| 22 | REPUTATION_ONLY | unavailable | — |

## Sorted by lowest FPR

| Rank | Configuration | Status | Value |
|---:|---|---|---:|
| 1 | DOMAIN_INTELLIGENCE_ONLY | unavailable | — |
| 2 | REDIRECT_ONLY | unavailable | — |
| 3 | REPUTATION_ONLY | unavailable | — |
| 4 | ML_ONLY | available | 0.003543 |
| 5 | ML_PLUS_DOMAIN | partial_unavailable | 0.003543 |
| 6 | ML_PLUS_REDIRECT | partial_unavailable | 0.003543 |
| 7 | ML_PLUS_REPUTATION | partial_unavailable | 0.003543 |
| 8 | WITHOUT_RULES | partial_unavailable | 0.003543 |
| 9 | FULL_SCAMSHIELD | partial_unavailable | 0.001050 |
| 10 | RULE_PLUS_ML | available | 0.001050 |
| 11 | RULE_PLUS_ML_PLUS_DOMAIN | partial_unavailable | 0.001050 |
| 12 | RULE_PLUS_ML_PLUS_DOMAIN_PLUS_REDIRECT | partial_unavailable | 0.001050 |
| 13 | RULE_PLUS_ML_PLUS_REDIRECT | partial_unavailable | 0.001050 |
| 14 | RULE_PLUS_ML_PLUS_REPUTATION | partial_unavailable | 0.001050 |
| 15 | RULE_PLUS_ML_PLUS_REPUTATION_PLUS_DOMAIN | partial_unavailable | 0.001050 |
| 16 | RULE_PLUS_ML_PLUS_REPUTATION_PLUS_REDIRECT | partial_unavailable | 0.001050 |
| 17 | WITHOUT_DOMAIN_INTELLIGENCE | partial_unavailable | 0.001050 |
| 18 | WITHOUT_REDIRECT_ANALYSIS | partial_unavailable | 0.001050 |
| 19 | WITHOUT_REPUTATION | partial_unavailable | 0.001050 |
| 20 | RULE_ONLY | available | 0.000000 |
| 21 | RULE_PLUS_REPUTATION | partial_unavailable | 0.000000 |
| 22 | WITHOUT_ML | partial_unavailable | 0.000000 |

## Incremental path

| From | To | Result |
|---|---|---|
| ML_ONLY | RULE_PLUS_ML | Rules changed F1 from 0.842672 to 0.866588, recall from 0.857456 to 0.804825, FPR from 0.003543 to 0.001050, and FN from 65 to 89. |
| RULE_PLUS_ML | + Reputation | Not measurable: reputation fixture unavailable for every TEST URL. |
| + Reputation | + Domain | Not measurable: domain fixture unavailable for every TEST URL. |
| + Domain | FULL_SCAMSHIELD (+ Redirect) | Not measurable: domain and redirect fixtures unavailable for every TEST URL. |

## Leave-one-component-out interpretation

WITHOUT_RULES equals ML-only because only ML is available and uses threshold 20. WITHOUT_ML equals Rules-only because all external signals are unavailable. Removing reputation, domain intelligence, or redirect cannot show a contribution in this run because their fixtures do not overlap TEST.

## Component conclusion

Rules measurably improve precision and reduce FPR versus ML-only, at the cost of recall and additional false negatives under locked EVIDENCE_AWARE fusion. ML is the dominant available predictive component. External intelligence contribution is not measurable in this run, not negative. SHAP remains explanatory-only. No superiority, zero-day detection, or production-readiness claim is made.
