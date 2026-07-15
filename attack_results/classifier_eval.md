# Injection Classifier Evaluation

Train (augmented): 150 examples | Test (held-out, novel phrasing): 17 examples

## Held-out test set results (the real generalization measure)

| Metric | Keyword baseline | TF-IDF + LogReg classifier |
|---|---|---|
| Precision | 1.00 | 1.00 |
| Recall | 0.42 | 1.00 |
| F1 | 0.59 | 1.00 |
| False positive rate | 0.00 | 0.00 |
| TP / FP / FN / TN | 5/0/7/5 | 12/0/0/5 |

## Per-category recall on held-out test set (novel phrasing per category)

| Category | Keyword baseline | ML classifier |
|---|---|---|
| authority_impersonation | 2/2 | 2/2 |
| direct_override | 0/2 | 2/2 |
| exfiltration_framing | 0/2 | 2/2 |
| indirect_document_injection | 2/2 | 2/2 |
| obfuscation_encoding | 0/2 | 2/2 |
| roleplay_jailbreak | 1/2 | 2/2 |

(sanity check only, not the real metric) ML classifier on TRAIN set: precision=1.00 recall=1.00 -- a high train score with a much lower test score would indicate memorization, not generalization.

## Notes / honest limitations

- Base taxonomy has only 20 hand-authored training examples across 6 techniques + benign; augmentation (politeness/urgency wrapper variation) expands this without adding new techniques or touching the test set. A production system would want far more real examples per category.
- The test set is intentionally adversarial to the classifier: every test query uses a phrasing *pattern* (not just different words) that never appeared in training. This is a harder and more honest test than a random train/test split of similar-sounding sentences would be.
- The held-out test set has only 17 examples (2 per malicious category, a handful of benign). A perfect or near-perfect score on this size of test set is a promising signal, NOT a statistically robust claim -- it should be read as 'the approach looks directionally correct' rather than 'this classifier is proven at production reliability.' A real next step would be generating substantially more held-out examples per category before trusting these numbers at face value.