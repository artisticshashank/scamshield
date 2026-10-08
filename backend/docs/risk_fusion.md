# Risk Fusion

Risk Fusion combines the scores produced by the local rule engine, the
character n-gram ML classifier, and any available external intelligence.
Configured weights remain unchanged, and unavailable external signals are
excluded from the denominator rather than treated as safe.

## Evidence-aware rule handling

The rule engine returns triggered evidence. An empty evidence list means that
no rule fired; it does **not** mean that the URL received a benign rule score.
Risk Fusion therefore omits the rules channel when the list is empty. This
prevents absence of rule evidence from suppressing the ML score.

When one or more rules fire, the existing weighted blend is used. With only
rules and ML available, the configured `0.30` and `0.30` weights are
availability-normalized and therefore act as an equal blend:

```text
final_score = (rule_score + ml_score) / 2
```

When no rules fire and ML is available:

```text
final_score = ml_score
```

Available reputation, domain-intelligence, and redirect signals continue to
participate through the existing availability-aware weighting. SHAP remains
explanatory-only and is never included in the risk score.
