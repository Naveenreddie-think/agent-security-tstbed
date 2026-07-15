"""
Step 4b (part 2): Train + evaluate an injection classifier.

Compares two approaches, both evaluated on the SAME held-out test set from
attack_taxonomy.py (structurally novel phrasing families the classifier
never saw during training):

  1. Keyword/heuristic baseline -- simple regex for known injection phrases
     ("ignore previous instructions", "DAN", base64-looking strings, etc).
     This is the kind of naive defense many projects stop at.
  2. TF-IDF + Logistic Regression -- an actual trained ML classifier,
     combining word n-grams (catches phrasing) and character n-grams
     (catches spaced-out/obfuscated text like "i-g-n-o-r-e").

WHY BOTH: reporting only the ML classifier's number in isolation proves
nothing. Comparing it against a naive baseline on the SAME held-out set is
what shows whether the extra engineering effort actually bought anything.

HONEST LIMITATION (report this, don't hide it): the raw taxonomy has only
20 training examples. A lightweight, template-based augmentation step
below (varying politeness/urgency wrappers, NOT new attack techniques)
expands this to a usable training size while keeping the test set's
structurally distinct phrasing families completely untouched -- augmentation
never touches the test set, so the generalization test stays honest.

Run: python -m app.train_injection_classifier
Output: attack_results/classifier_eval.md (metrics report)
        models/injection_classifier.pkl (trained model, for reuse)
"""
import json
import pickle
import random
import re
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix
from sklearn.pipeline import FeatureUnion, Pipeline

RESULTS_DIR = Path(__file__).parent.parent / "attack_results"
MODELS_DIR = Path(__file__).parent.parent / "models"
MODELS_DIR.mkdir(exist_ok=True)

random.seed(42)

# ---------------------------------------------------------------------------
# Load taxonomy data (must run `python -m app.attack_taxonomy` first)
# ---------------------------------------------------------------------------
def load_variants():
    train_path = RESULTS_DIR / "variants_train.json"
    test_path = RESULTS_DIR / "variants_test.json"
    if not train_path.exists() or not test_path.exists():
        raise FileNotFoundError(
            "Run `python -m app.attack_taxonomy` first to generate variants_train.json / variants_test.json"
        )
    train = json.loads(train_path.read_text())
    test = json.loads(test_path.read_text())
    return train, test


# ---------------------------------------------------------------------------
# Lightweight augmentation of the TRAIN set only. This varies surface wording
# (politeness, urgency framing) WITHOUT introducing new attack techniques or
# touching the test set's held-out structural families -- it just gives the
# classifier more examples of each already-defined technique to learn from.
# ---------------------------------------------------------------------------
PREFIXES = ["", "Please, ", "Immediately, ", "Kindly, ", "Right now, ", "Urgently, "]
SUFFIXES = ["", " Thanks.", " This is important.", " Do it now.", " No exceptions."]


def augment_train(train_variants: list[dict], multiplier: int = 4) -> list[dict]:
    augmented = list(train_variants)  # keep originals
    for v in train_variants:
        # augment both classes -- a classifier trained on plentiful malicious
        # examples but only a handful of benign ones will overfit to treating
        # almost anything unfamiliar as malicious (this is exactly what an
        # earlier version of this script did -- see FINDINGS.md).
        this_multiplier = multiplier if v["is_malicious"] else multiplier
        for _ in range(this_multiplier):
            prefix = random.choice(PREFIXES)
            suffix = random.choice(SUFFIXES)
            new_query = f"{prefix}{v['query']}{suffix}"
            augmented.append({**v, "query": new_query, "id": v["id"] + "_aug"})
    return augmented


# ---------------------------------------------------------------------------
# Baseline: keyword/heuristic detector (the "naive" comparison point)
# ---------------------------------------------------------------------------
INJECTION_KEYWORDS = [
    r"ignore (all )?previous instructions",
    r"disregard (your |the )?(prior|earlier) instructions",
    r"forget everything you were told",
    r"system admin override",
    r"as the system administrator",
    r"this is your developer",
    r"maintenance mode",
    r"compliance audit",
    r"you are now dan\b",
    r"do anything now",
    r"no (content policy|restrictions|safety)",
    r"decode this base64",
    r"hidden instruction",
    r"not visible to human reader",
    r"system_note",
    r"system:",
]
INJECTION_KEYWORD_RE = re.compile("|".join(INJECTION_KEYWORDS), re.IGNORECASE)


def keyword_baseline_predict(query: str) -> bool:
    return bool(INJECTION_KEYWORD_RE.search(query))


# ---------------------------------------------------------------------------
# ML classifier: word n-grams + char n-grams -> Logistic Regression
# ---------------------------------------------------------------------------
def build_classifier_pipeline() -> Pipeline:
    features = FeatureUnion([
        ("word_tfidf", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=1)),
        ("char_tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1)),
    ])
    clf = LogisticRegression(max_iter=2000, class_weight="balanced", C=1.0)
    return Pipeline([("features", features), ("clf", clf)])


def evaluate(y_true: list[bool], y_pred: list[bool], label: str) -> dict:
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", pos_label=True, zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[False, True]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "label": label, "precision": precision, "recall": recall, "f1": f1,
        "false_positive_rate": fpr, "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
    }


def per_category_recall(test_variants: list[dict], y_pred: list[bool]) -> dict:
    by_cat = {}
    for v, pred in zip(test_variants, y_pred):
        if not v["is_malicious"]:
            continue
        cat = v["category"]
        by_cat.setdefault(cat, {"total": 0, "caught": 0})
        by_cat[cat]["total"] += 1
        if pred:
            by_cat[cat]["caught"] += 1
    return by_cat


def main():
    train_raw, test = load_variants()
    train = augment_train(train_raw, multiplier=4)

    print(f"Raw train examples: {len(train_raw)} -> augmented to: {len(train)}")
    print(f"Held-out test examples (untouched, structurally novel): {len(test)}\n")

    X_train = [v["query"] for v in train]
    y_train = [v["is_malicious"] for v in train]
    X_test = [v["query"] for v in test]
    y_test = [v["is_malicious"] for v in test]

    # --- Baseline: keyword matching ---
    baseline_pred = [keyword_baseline_predict(q) for q in X_test]
    baseline_metrics = evaluate(y_test, baseline_pred, "keyword_baseline")

    # --- ML classifier ---
    pipeline = build_classifier_pipeline()
    pipeline.fit(X_train, y_train)
    ml_pred_test = list(pipeline.predict(X_test))
    ml_metrics = evaluate(y_test, ml_pred_test, "tfidf_logreg_classifier")

    # sanity: also check train-set fit (expect near-perfect, not the real signal)
    ml_pred_train = list(pipeline.predict(X_train))
    ml_train_metrics = evaluate(y_train, ml_pred_train, "tfidf_logreg_on_TRAIN(sanity_only)")

    # per-category breakdown on the held-out test set
    baseline_by_cat = per_category_recall(test, baseline_pred)
    ml_by_cat = per_category_recall(test, ml_pred_test)

    # save the trained model for reuse in the actual defense pipeline later
    with open(MODELS_DIR / "injection_classifier.pkl", "wb") as f:
        pickle.dump(pipeline, f)

    # --- report ---
    lines = [
        "# Injection Classifier Evaluation",
        "",
        f"Train (augmented): {len(train)} examples | Test (held-out, novel phrasing): {len(test)} examples",
        "",
        "## Held-out test set results (the real generalization measure)",
        "",
        "| Metric | Keyword baseline | TF-IDF + LogReg classifier |",
        "|---|---|---|",
        f"| Precision | {baseline_metrics['precision']:.2f} | {ml_metrics['precision']:.2f} |",
        f"| Recall | {baseline_metrics['recall']:.2f} | {ml_metrics['recall']:.2f} |",
        f"| F1 | {baseline_metrics['f1']:.2f} | {ml_metrics['f1']:.2f} |",
        f"| False positive rate | {baseline_metrics['false_positive_rate']:.2f} | {ml_metrics['false_positive_rate']:.2f} |",
        f"| TP / FP / FN / TN | {baseline_metrics['tp']}/{baseline_metrics['fp']}/{baseline_metrics['fn']}/{baseline_metrics['tn']} "
        f"| {ml_metrics['tp']}/{ml_metrics['fp']}/{ml_metrics['fn']}/{ml_metrics['tn']} |",
        "",
        "## Per-category recall on held-out test set (novel phrasing per category)",
        "",
        "| Category | Keyword baseline | ML classifier |",
        "|---|---|---|",
    ]
    for cat in sorted(set(list(baseline_by_cat.keys()) + list(ml_by_cat.keys()))):
        b = baseline_by_cat.get(cat, {"total": 0, "caught": 0})
        m = ml_by_cat.get(cat, {"total": 0, "caught": 0})
        lines.append(f"| {cat} | {b['caught']}/{b['total']} | {m['caught']}/{m['total']} |")

    lines += [
        "",
        f"(sanity check only, not the real metric) ML classifier on TRAIN set: "
        f"precision={ml_train_metrics['precision']:.2f} recall={ml_train_metrics['recall']:.2f} "
        f"-- a high train score with a much lower test score would indicate memorization, not generalization.",
        "",
        "## Notes / honest limitations",
        "",
        "- Base taxonomy has only 20 hand-authored training examples across 6 techniques + benign; "
        "augmentation (politeness/urgency wrapper variation) expands this without adding new techniques "
        "or touching the test set. A production system would want far more real examples per category.",
        "- The test set is intentionally adversarial to the classifier: every test query uses a phrasing "
        "*pattern* (not just different words) that never appeared in training. This is a harder and more "
        "honest test than a random train/test split of similar-sounding sentences would be.",
        f"- The held-out test set has only {len(test)} examples (2 per malicious category, a handful of "
        "benign). A perfect or near-perfect score on this size of test set is a promising signal, NOT a "
        "statistically robust claim -- it should be read as 'the approach looks directionally correct' "
        "rather than 'this classifier is proven at production reliability.' A real next step would be "
        "generating substantially more held-out examples per category before trusting these numbers at face value.",
    ]

    report_path = RESULTS_DIR / "classifier_eval.md"
    report_path.write_text("\n".join(lines))

    print("\n".join(lines))
    print(f"\nSaved report: {report_path}")
    print(f"Saved model: {MODELS_DIR / 'injection_classifier.pkl'}")


if __name__ == "__main__":
    main()