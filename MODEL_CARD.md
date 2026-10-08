# Model Card

## Model

The baseline is a character n-gram TF-IDF vectorizer with analyzer `char`,
range `(3,5)`, lowercase processing, accent stripping, sublinear TF, and
Logistic Regression (`liblinear`, `max_iter=1000`, `random_state=42`).
The frozen artifact is
`backend/artifacts/scamshield_domain_grouped_baseline.pkl`.

## Data and evaluation

`Dataset.csv` contains 116,599 accepted records: 100,000 benign and 16,599
malicious. The frozen domain-grouped split uses seed 42:
69,960 train, 23,320 validation, and 23,319 test records. The dataset SHA-256
is recorded in the evaluation reports.

On the untouched internal TEST partition at ML threshold 20, ML_ONLY achieved
accuracy 99.3739%, precision 82.8390%, recall 85.7456%, F1 84.2672%,
PR-AUC 91.9341%, ROC-AUC 99.3122%, FPR 0.3543%, and FNR 14.2544%
(TP 391, TN 22,782, FP 81, FN 65).

The locked Rules+ML evaluation at fusion threshold 30 achieved F1 86.6588%,
precision 93.8619%, recall 80.4825%, FPR 0.1050%, and FNR 19.5175%.

## External evaluation and limitations

PhishVN strict-clean ML ROC-AUC was 0.508767 and F1 was 0.546780.
PhishBench strict-clean ML ROC-AUC was 0.880242 and F1 was 0.767213.
The diagnosis found substantial distribution shift; leakage filtering had
negligible impact. These results are not claims of universal or zero-day
detection, real-world 99% accuracy, or product superiority.
