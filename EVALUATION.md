# Evaluation

## Internal evaluation

The frozen artifact was evaluated once on the untouched domain-grouped TEST
partition from `Dataset.csv`, with seed 42 and locked thresholds. No TEST
tuning or retraining was performed.

ML_ONLY: accuracy 99.3739%, precision 82.8390%, recall 85.7456%, F1 84.2672%,
PR-AUC 91.9341%, ROC-AUC 99.3122%, FPR 0.3543%, FNR 14.2544%.

Rules+ML under locked EVIDENCE_AWARE fusion: precision 93.8619%, recall
80.4825%, F1 86.6588%, FPR 0.1050%, FNR 19.5175%. Rules improved precision
and reduced false positives while increasing false negatives in this test.

## Controlled ablation

The final ablation used the same TEST records and deterministic offline
fixtures. Fixture URLs had zero overlap with TEST, so reputation, domain, and
redirect contributions were unavailable and no benefit from those components
could be measured in that run. The full result therefore matched the
available Rules+ML result.

## External datasets

Strict leakage-free views excluded exact and normalized overlaps with the
training dataset and frozen partitions. PhishVN strict-clean ML ROC-AUC was
0.508767 and F1 0.546780. PhishBench strict-clean ML ROC-AUC was 0.880242 and
F1 0.767213. Labels and preprocessing were verified. The evidence supports
source/distribution shift, not a single exclusive cause.

External intelligence was fixture-tested offline; live providers were not
used in the controlled ablation.
