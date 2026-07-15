"""
Step 4c: Defense integration -- wraps the trained classifier (from
train_injection_classifier.py) so it can actually intercept content in the
live agent pipeline, not just sit evaluated-but-unused in a report.

WHERE THIS GETS APPLIED (see agent.py): every piece of TEXT THAT RETURNS
FROM A TOOL CALL (read_file output, web_search output) is classified BEFORE
it's fed back to Claude. This is the key design decision -- the classifier
protects the model from ever seeing the malicious content, rather than
trying to catch the model's response after the fact. This means the defense
works independent of whether the underlying model would have refused on its
own, which is exactly the gap Step 3 identified (Claude's judgment was the
ONLY thing stopping attacks; this gives the system a second, code-level
line of defense that doesn't rely on any particular model's training).

We also classify the user's own query for direct-injection-style attempts,
though tool output scanning is the more novel/valuable half here since
that's what catches INDIRECT injection (content embedded in documents).
"""
import pickle
from pathlib import Path

MODEL_PATH = Path(__file__).parent.parent / "models" / "injection_classifier.pkl"

_pipeline = None  # lazy-loaded singleton


def _get_pipeline():
    global _pipeline
    if _pipeline is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Classifier not found at {MODEL_PATH}. Run "
                "`python -m app.attack_taxonomy` then "
                "`python -m app.train_injection_classifier` first."
            )
        with open(MODEL_PATH, "rb") as f:
            _pipeline = pickle.load(f)
    return _pipeline


def classify(text: str, threshold: float = 0.5) -> dict:
    """
    Returns {"flagged": bool, "score": float} for a piece of text.
    `score` is the model's estimated probability the text is a malicious
    injection attempt (class = True). Threshold is adjustable -- lower it
    to be more aggressive (higher recall, more false positives), raise it
    to be more conservative.
    """
    if not text or not text.strip():
        return {"flagged": False, "score": 0.0}

    pipeline = _get_pipeline()
    proba = pipeline.predict_proba([text])[0]
    classes = list(pipeline.classes_)
    score = float(proba[classes.index(True)]) if True in classes else 0.0
    return {"flagged": score >= threshold, "score": score}


def redact_if_flagged(text: str, source_label: str, threshold: float = 0.5) -> tuple[str, dict]:
    """
    Classifies `text`. If flagged, returns a safe placeholder instead of the
    real content (so the malicious payload never reaches the model), plus
    the classification result for logging/audit. If not flagged, returns the
    original text unchanged.
    """
    result = classify(text, threshold=threshold)
    if result["flagged"]:
        safe_text = (
            f"[CONTENT WITHHELD BY DEFENSE LAYER -- {source_label} was flagged as a "
            f"likely prompt injection attempt (confidence={result['score']:.2f}) and "
            f"has been blocked before reaching the model. Original length: {len(text)} chars.]"
        )
        return safe_text, result
    return text, result