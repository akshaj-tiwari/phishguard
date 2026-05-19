"""
backend/services/model_service.py
===================================
Loads the trained model once at startup and exposes predict().

v3.1 changes:
  - Model is CalibratedClassifierCV wrapping a StackingClassifier Pipeline
  - threshold.json stores the optimised decision threshold (not fixed 0.5)
  - Feature importances loaded from pre-computed JSON (fast, avoids digging
    through CalibratedClassifierCV → Pipeline → StackingClassifier → XGB)
"""

import os
import json
import warnings
import joblib
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
warnings.filterwarnings("ignore", category=UserWarning, module="lightgbm")

BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH   = os.path.join(BASE_DIR, "models", "phishguard_v1.pkl")
FEATURE_PATH = os.path.join(BASE_DIR, "models", "feature_names.pkl")
IMP_PATH     = os.path.join(BASE_DIR, "models", "feature_importances.json")
THRESH_PATH  = os.path.join(BASE_DIR, "models", "threshold.json")

_pipeline      = None
_feature_names = None
_importances   = {}
_threshold     = 0.50   # overridden by threshold.json if present


def load_model():
    global _pipeline, _feature_names, _importances, _threshold

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Model not found: {MODEL_PATH}\n"
            "Run: python ml/train.py"
        )

    _pipeline      = joblib.load(MODEL_PATH)
    _feature_names = joblib.load(FEATURE_PATH)

    # Load optimised threshold (saved during training)
    if os.path.exists(THRESH_PATH):
        with open(THRESH_PATH) as f:
            _threshold = float(json.load(f).get("threshold", 0.5))
    else:
        _threshold = 0.50

    # Load pre-computed importances
    if os.path.exists(IMP_PATH):
        with open(IMP_PATH) as f:
            _importances = json.load(f)
    else:
        _importances = _extract_importances_fallback()

    print(f"✓ Model loaded : {MODEL_PATH}  ({len(_feature_names)} features, threshold={_threshold:.2f})")


def _extract_importances_fallback() -> dict:
    """Fallback importance extraction — tries multiple model wrapper patterns."""
    if _pipeline is None:
        return {}
    try:
        # CalibratedClassifierCV → Pipeline → StackingClassifier → XGB
        base  = _pipeline.calibrated_classifiers_[0].estimator
        xgb   = base.named_steps["clf"].estimators_[0]
        imps  = xgb.feature_importances_
        return {n: round(float(v), 6) for n, v in zip(_feature_names or [], imps)}
    except Exception:
        pass
    try:
        # Direct Pipeline → StackingClassifier → XGB (non-calibrated)
        xgb  = _pipeline.named_steps["clf"].estimators_[0]
        imps = xgb.feature_importances_
        return {n: round(float(v), 6) for n, v in zip(_feature_names or [], imps)}
    except Exception:
        pass
    try:
        # Direct Pipeline → single clf (v1/v2 backward compat)
        clf  = _pipeline.named_steps["clf"]
        imps = clf.feature_importances_
        return {n: round(float(v), 6) for n, v in zip(_feature_names or [], imps)}
    except Exception:
        return {}


def get_feature_importances() -> dict:
    return _importances


def predict(url: str, features: dict) -> dict:
    """
    Predicts phishing probability for a URL given pre-extracted features.

    Returns:
      risk_score   : 0.0–100.0
      verdict      : "benign" | "suspicious" | "phishing"
      top_features : top 10 features by importance
    """
    if _pipeline is None:
        raise RuntimeError("Model not loaded. Call load_model() at startup.")

    # Build feature vector in exact training order
    row   = pd.DataFrame([{k: features.get(k, 0) for k in _feature_names}])
    proba = float(_pipeline.predict_proba(row)[0][1])
    risk_score = round(proba * 100, 2)

    # Use optimised threshold (not fixed 0.5) — this is where +1-2% comes from
    if proba >= _threshold:
        verdict = "phishing"
    elif proba >= (_threshold * 0.43):   # scale suspicious band proportionally
        verdict = "suspicious"
    else:
        verdict = "benign"

    # Top features by importance
    scored = [
        {
            "feature":      fname,
            "value":        features.get(fname, 0),
            "importance":   _importances.get(fname, 0.0),
            "contribution": round(features.get(fname, 0) * _importances.get(fname, 0.0), 6),
        }
        for fname in _feature_names
    ]
    scored.sort(key=lambda x: x["importance"], reverse=True)

    return {
        "risk_score":   risk_score,
        "verdict":      verdict,
        "top_features": scored[:10],
    }
