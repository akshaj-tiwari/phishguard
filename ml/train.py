"""
ml/train.py
============
Trains XGBoost phishing classifier — v2, targeting >=95% accuracy.

Changes from v1 (which got 90.22%):
  - FeatureExtractor v2: 40 features (was 26). New: domain_entropy,
    keyword detection, path analysis, vowel_ratio, tld_in_subdomain etc.
  - XGBoost tuned: added min_child_weight, gamma, reg_alpha, reg_lambda
  - Scale_pos_weight: corrects class imbalance in ISCX automatically
  - N_PER_CLASS bumped to 80_000 default (more data = better generalisation)

Datasets:
  - ISCX URL 2016 (Kaggle) — columns: url, type
  - Tranco Top 1M (tranco-list.eu) — NO header, columns: rank, domain

Run:
    cd ml/
    python train.py
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import mlflow
import mlflow.sklearn

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, f1_score, roc_auc_score,
    classification_report, confusion_matrix, roc_curve
)
from xgboost import XGBClassifier

# ── Paths ──────────────────────────────────────────────────────────────────
ML_DIR      = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(ML_DIR, "..", "backend")
MODEL_OUT   = os.path.join(BACKEND_DIR, "models")
PLOTS_OUT   = os.path.join(ML_DIR, "plots")
os.makedirs(MODEL_OUT, exist_ok=True)
os.makedirs(PLOTS_OUT, exist_ok=True)

sys.path.insert(0, BACKEND_DIR)
from services.feature_extractor import FeatureExtractor

# ══════════════════════════════════════════════════════════════════════════
# CONFIG — UPDATE FILENAMES TO MATCH YOUR ml/data/ FOLDER
# Run `dir ml\data` (Windows) or `ls ml/data` (Mac/Linux) to check
# ══════════════════════════════════════════════════════════════════════════

ISCX_CSV   = os.path.join(ML_DIR, "data", "iscx_url_2016.csv")
TRANCO_CSV = os.path.join(ML_DIR, "data", "legit.csv")

# More data = better accuracy. 80k takes ~10 min, 100k takes ~15 min.
N_PER_CLASS = 100_000

MLFLOW_EXP_NAME = "phishguard-xgboost-v2"


# ══════════════════════════════════════════════════════════════════════════
# SECTION 1 — DATASET
# ══════════════════════════════════════════════════════════════════════════

def load_data() -> pd.DataFrame:
    frames_phish = []
    frames_legit = []

    # ── ISCX ───────────────────────────────────────────────────────────────
    if not os.path.exists(ISCX_CSV):
        raise FileNotFoundError(
            f"ISCX not found: {ISCX_CSV}\n"
            f"Update ISCX_CSV at top of this file to match your filename."
        )

    print(f"Loading ISCX: {os.path.basename(ISCX_CSV)}")
    iscx = pd.read_csv(ISCX_CSV).dropna(subset=["url", "type"])
    iscx["url"] = iscx["url"].str.strip()

    iscx_phish = iscx[iscx["type"].str.lower() != "benign"][["url"]].copy()
    iscx_legit = iscx[iscx["type"].str.lower() == "benign"][["url"]].copy()
    iscx_phish["label"] = 1
    iscx_legit["label"] = 0

    print(f"  ISCX phishing : {len(iscx_phish):,}")
    print(f"  ISCX benign   : {len(iscx_legit):,}")
    frames_phish.append(iscx_phish)
    frames_legit.append(iscx_legit)

    # ── Tranco ─────────────────────────────────────────────────────────────
    if not os.path.exists(TRANCO_CSV):
        print(f"WARNING: Tranco not found at {TRANCO_CSV} — using ISCX only")
    else:
        print(f"Loading Tranco: {os.path.basename(TRANCO_CSV)}")
        tranco = pd.read_csv(
            TRANCO_CSV,
            header=None,
            names=["rank", "domain"],
            usecols=["domain"],
        ).dropna()
        tranco["domain"] = tranco["domain"].str.strip()
        tranco["url"]    = "https://" + tranco["domain"]
        tranco["label"]  = 0
        tranco           = tranco[["url", "label"]]
        print(f"  Tranco domains: {len(tranco):,}")
        frames_legit.append(tranco)

    # ── Merge + balance ────────────────────────────────────────────────────
    all_phish = pd.concat(frames_phish).drop_duplicates("url").reset_index(drop=True)
    all_legit = pd.concat(frames_legit).drop_duplicates("url").reset_index(drop=True)

    print(f"\nBefore balance — phishing:{len(all_phish):,}  legit:{len(all_legit):,}")

    n = min(N_PER_CLASS, len(all_phish), len(all_legit))
    df = pd.concat([
        all_phish.sample(n=n, random_state=42),
        all_legit.sample(n=n, random_state=42),
    ]).sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"Final dataset  — {len(df):,} URLs ({n:,} each class)\n")
    return df


# ══════════════════════════════════════════════════════════════════════════
# SECTION 2 — FEATURE EXTRACTION
# ══════════════════════════════════════════════════════════════════════════

def build_features(df: pd.DataFrame, extractor: FeatureExtractor):
    # Disable live DNS/WHOIS for speed — API does it at runtime
    extractor._get_domain_age = lambda domain: -1
    extractor._has_mx_record  = lambda domain: False

    print(f"Extracting features for {len(df):,} URLs...")
    print("(DNS/WHOIS disabled — runs live in the API at inference time)")

    records = []
    errors  = 0
    for i, url in enumerate(df["url"]):
        if i % 5000 == 0 and i > 0:
            print(f"  {i:,} / {len(df):,}  ({i/len(df)*100:.0f}%)")
        try:
            records.append(extractor.extract(str(url)))
        except Exception:
            records.append(extractor._empty_features())
            errors += 1

    if errors:
        print(f"  Skipped {errors} malformed URLs")

    X = pd.DataFrame(records)
    y = df["label"].values
    print(f"Feature matrix: {X.shape[0]:,} rows x {X.shape[1]} features\n")
    return X, y


# ══════════════════════════════════════════════════════════════════════════
# SECTION 3 — TRAINING (tuned hyperparameters)
# ══════════════════════════════════════════════════════════════════════════

def train(X: pd.DataFrame, y: np.ndarray):
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=42
    )
    print(f"Split: train={len(X_train):,}  val={len(X_val):,}  test={len(X_test):,}")

    # ── Tuned XGBoost hyperparameters ──────────────────────────────────────
    #
    # Changes from v1 and why each one helps:
    #
    # n_estimators=500   : more trees = better fit on complex URL patterns
    # max_depth=7        : deeper trees catch more feature interactions
    # min_child_weight=3 : prevents fitting noise (small URL subgroups)
    # gamma=0.1          : minimum gain needed to split — reduces overfitting
    # reg_alpha=0.1      : L1 regularisation — removes irrelevant features
    # reg_lambda=1.5     : L2 regularisation — shrinks large weights
    # subsample=0.8      : row sampling per tree — reduces overfitting
    # colsample_bytree=0.8: feature sampling per tree
    # scale_pos_weight   : handles class imbalance in ISCX automatically
    #                      = count(negative) / count(positive)
    #                      Here it's 1.0 since we balanced, but leave it as
    #                      a safeguard for slight imbalance after dedup.
    #
    n_neg = int((y_train == 0).sum())
    n_pos = int((y_train == 1).sum())
    scale  = round(n_neg / max(n_pos, 1), 2)
    print(f"Class balance: neg={n_neg:,}  pos={n_pos:,}  scale_pos_weight={scale}")

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", XGBClassifier(
            n_estimators      = 500,
            max_depth         = 7,
            learning_rate     = 0.05,      # lower LR + more trees = better
            min_child_weight  = 3,
            gamma             = 0.1,
            reg_alpha         = 0.1,
            reg_lambda        = 1.5,
            subsample         = 0.8,
            colsample_bytree  = 0.8,
            scale_pos_weight  = scale,
            eval_metric       = "logloss",
            random_state      = 42,
            n_jobs            = -1,
        ))
    ])

    mlflow.set_experiment(MLFLOW_EXP_NAME)
    with mlflow.start_run():
        print("\nTraining XGBoost v2 (500 trees, deeper, regularised)...")
        print("This will take ~10-15 minutes on 160k URLs. Go get chai.")
        pipeline.fit(X_train, y_train)

        y_pred  = pipeline.predict(X_test)
        y_prob  = pipeline.predict_proba(X_test)[:, 1]
        acc     = accuracy_score(y_test, y_pred)
        f1      = f1_score(y_test, y_pred)
        auc_roc = roc_auc_score(y_test, y_prob)
        cm      = confusion_matrix(y_test, y_pred)

        mlflow.log_params({
            "n_estimators": 500, "max_depth": 7, "learning_rate": 0.05,
            "min_child_weight": 3, "gamma": 0.1, "reg_alpha": 0.1,
            "reg_lambda": 1.5, "n_per_class": N_PER_CLASS,
            "num_features": X.shape[1],
        })
        mlflow.log_metrics({
            "accuracy": round(acc, 4),
            "f1_score": round(f1, 4),
            "roc_auc":  round(auc_roc, 4),
        })
        mlflow.sklearn.log_model(pipeline, "phishguard_model_v2")

        # ── Results ────────────────────────────────────────────────────────
        print(f"\n{'='*55}")
        print("EVALUATION RESULTS — v2")
        print(f"{'='*55}")
        print(f"Accuracy : {acc*100:.2f}%   (target >= 95%)")
        print(f"F1 Score : {f1:.4f}")
        print(f"AUC-ROC  : {auc_roc:.4f}")
        print(f"\nConfusion Matrix:")
        print(f"  True Neg  (legit  -> legit)    : {cm[0][0]:,}")
        print(f"  False Pos (legit  -> phishing) : {cm[0][1]:,}")
        print(f"  False Neg (phish  -> legit)    : {cm[1][0]:,}")
        print(f"  True Pos  (phish  -> phishing) : {cm[1][1]:,}")
        print(f"\n{classification_report(y_test, y_pred, target_names=['Benign','Phishing'])}")

        if acc >= 0.95:
            print(f"TARGET MET: {acc*100:.2f}% >= 95%")
        else:
            gap = 0.95 - acc
            print(f"Still {gap*100:.2f}% short of target.")
            print("Options: raise N_PER_CLASS to 100_000, or add PhishTank data.")

        _plot_roc(y_test, y_prob, auc_roc)
        _plot_feature_importance(pipeline, list(X.columns))

        metrics = {
            "accuracy":         round(float(acc), 4),
            "f1_score":         round(float(f1), 4),
            "roc_auc":          round(float(auc_roc), 4),
            "confusion_matrix": cm.tolist(),
            "train_size":       len(X_train),
            "val_size":         len(X_val),
            "test_size":        len(X_test),
            "n_per_class":      N_PER_CLASS,
            "num_features":     int(X.shape[1]),
        }
        with open(os.path.join(MODEL_OUT, "metrics.json"), "w") as f:
            json.dump(metrics, f, indent=2)

    return pipeline, X_test, y_test


# ══════════════════════════════════════════════════════════════════════════
# SECTION 4 — SAVE
# ══════════════════════════════════════════════════════════════════════════

def save(pipeline, feature_names: list):
    model_path   = os.path.join(MODEL_OUT, "phishguard_v1.pkl")   # keep same name so API works
    feature_path = os.path.join(MODEL_OUT, "feature_names.pkl")
    joblib.dump(pipeline,      model_path)
    joblib.dump(feature_names, feature_path)
    size_mb = os.path.getsize(model_path) / 1024 / 1024
    print(f"\nModel saved    : {model_path}  ({size_mb:.1f} MB)")
    print(f"Features saved : {feature_path}  ({len(feature_names)} features)")


# ══════════════════════════════════════════════════════════════════════════
# PLOTS
# ══════════════════════════════════════════════════════════════════════════

def _plot_roc(y_test, y_prob, auc_roc):
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    plt.figure(figsize=(7, 5))
    plt.plot(fpr, tpr, color="#185FA5", lw=2, label=f"AUC = {auc_roc:.4f}")
    plt.plot([0, 1], [0, 1], color="#888780", linestyle="--", lw=1)
    plt.xlabel("False Positive Rate"); plt.ylabel("True Positive Rate")
    plt.title("PhishGuard - AUC-ROC Curve (v2)"); plt.legend(loc="lower right")
    plt.tight_layout()
    path = os.path.join(PLOTS_OUT, "roc_curve.png")
    plt.savefig(path, dpi=150); plt.close()
    print(f"ROC curve: {path}")


def _plot_feature_importance(pipeline, feature_names: list):
    clf         = pipeline.named_steps["clf"]
    importances = clf.feature_importances_
    indices     = np.argsort(importances)[-20:]   # top 20 now (more features)
    plt.figure(figsize=(9, 7))
    plt.barh([feature_names[i] for i in indices], importances[indices], color="#185FA5")
    plt.xlabel("Feature importance (gain)")
    plt.title("PhishGuard - Top 20 Feature Importances (v2)"); plt.tight_layout()
    path = os.path.join(PLOTS_OUT, "feature_importance.png")
    plt.savefig(path, dpi=150); plt.close()
    print(f"Feature importance: {path}")


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 55)
    print("PhishGuard ML Training Pipeline — v2")
    print("=" * 55)
    print(f"ISCX   : {ISCX_CSV}")
    print(f"Tranco : {TRANCO_CSV}")
    print(f"N/class: {N_PER_CLASS:,}")
    print(f"Target : >= 95% accuracy")
    print()

    extractor = FeatureExtractor()
    df        = load_data()

    df.to_csv(os.path.join(ML_DIR, "data", "phishguard_dataset.csv"), index=False)
    print(f"Merged dataset -> ml/data/phishguard_dataset.csv")

    X, y          = build_features(df, extractor)
    feature_names = list(X.columns)

    pipeline, X_test, y_test = train(X, y)
    save(pipeline, feature_names)

    print("\n" + "=" * 55)
    print("DONE.")
    print("cd ../backend && uvicorn main:app --reload --port 8000")
    print("=" * 55)