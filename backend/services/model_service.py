"""
backend/services/model_service.py
===================================
Loads phishguard_v1.pkl once at startup.
Exposes predict(url) -> dict with risk_score (0-100), verdict, top_features.
"""

import os
import joblib
import numpy as np
import pandas as pd
from typing import Optional

# ── Paths ──────────────────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH   = os.path.join(BASE_DIR, "models", "phishguard_v1.pkl")
FEATURE_PATH = os.path.join(BASE_DIR, "models", "feature_names.pkl")

# Global — loaded once at startup by FastAPI lifespan
_pipeline      = None
_feature_names = None


def load_model():
    """Call once during app startup."""
    global _pipeline, _feature_names

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Model not found at {MODEL_PATH}. "
            "Run 'python ml/train.py' first."
        )

    _pipeline      = joblib.load(MODEL_PATH)
    _feature_names = joblib.load(FEATURE_PATH)
    print(f"✓ Model loaded: {MODEL_PATH} ({len(_feature_names)} features)")


def get_feature_importances() -> dict:
    """Returns feature importance dict for dashboard explainability."""
    if _pipeline is None:
        return {}
    clf = _pipeline.named_steps["clf"]
    importances = clf.feature_importances_
    return dict(zip(_feature_names, [round(float(v), 6) for v in importances]))


def predict(url: str, features: dict) -> dict:
    """
    Takes a pre-extracted feature dict (from FeatureExtractor.extract()).
    Returns:
      risk_score   : float 0.0–100.0  (plan spec: multiply proba by 100)
      verdict      : "benign" | "suspicious" | "phishing"
      top_features : list of top 5 (feature_name, value, importance) tuples
    """
    if _pipeline is None:
        raise RuntimeError("Model not loaded. Call load_model() at startup.")

    # Build feature vector in exact training order
    row = pd.DataFrame([{k: features.get(k, 0) for k in _feature_names}])

    proba      = _pipeline.predict_proba(row)[0][1]
    risk_score = round(float(proba) * 100, 2)

    # Verdict thresholds per plan spec
    if risk_score < 30:
        verdict = "benign"
    elif risk_score < 70:
        verdict = "suspicious"
    else:
        verdict = "phishing"

    # Top features: multiply feature value (normalised) by importance
    importances = get_feature_importances()
    scored = []
    for fname, imp in importances.items():
        val = features.get(fname, 0)
        scored.append({
            "feature": fname,
            "value": val,
            "importance": imp,
            "contribution": round(float(val) * imp, 6),
        })
    scored.sort(key=lambda x: x["importance"], reverse=True)
    top_features = scored[:10]

    return {
        "risk_score":   risk_score,
        "verdict":      verdict,
        "top_features": top_features,
    }
