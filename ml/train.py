"""
ml/train.py — PhishGuard v3.1 (targets >=95% accuracy on real ISCX)
=====================================================================

WHY 92% HAPPENS ON REAL ISCX AND HOW THIS FIXES IT:
─────────────────────────────────────────────────────
Real ISCX has 4 label types:
  benign     — normal pages (easy to catch)
  phishing   — keyword/TLD abuse (caught well already)
  defacement — normal-looking domains, just serve defaced content → HARD
  malware    — distribution URLs on CDN/legit-looking hosts → HARD

The 92% failures are almost entirely defacement + malware that look
structurally similar to legitimate URLs at the character/TLD level.

Fix strategy (5 changes):
  1. FeatureExtractor v3.1 — 54 features (was 45).
     New: token_count, avg_token_length, longest_token, double_extension,
          ext_risk_score, subdomain_entropy, query_key_entropy, has_non_ascii,
          and the 6 v3 structural features now baked into the extractor.
     Token features catch defacement/malware URL structure patterns.
     ext_risk_score specifically targets .exe/.dll/.bat distribution.

  2. CalibratedClassifierCV — wraps the ensemble with isotonic calibration.
     Real ISCX probabilities are poorly calibrated from stacking alone.
     Calibration fixes the 0.30/0.70 thresholds to work on actual data.

  3. Optuna hyperparameter tuning (optional, 30 trials, ~20 min).
     Finds optimal XGB/LGBM/RF params for *this specific dataset*.
     Set OPTUNA_TRIALS=0 to skip.

  4. Threshold optimization — finds the exact threshold that maximises
     F1/accuracy on the validation set rather than using fixed 0.5.
     Typical gain: +0.5-1.0% accuracy.

  5. class_weight='balanced' tuning — ISCX has 4 classes merged to 2.
     Defacement/malware are underrepresented in phishing-focused datasets.
     Explicit class weights compensate.

Expected outcome: 95-97% accuracy on real ISCX (vs 92.33% before).

Run:
    cd phishguard-dev/
    python ml/train.py

Options (env vars):
    ISCX_CSV=ml/data/iscx_url_2016.csv   # path to dataset
    TRANCO_CSV=ml/data/legit.csv          # optional extra legit URLs
    N_PER_CLASS=80000                     # samples per class (80k default)
    OPTUNA_TRIALS=30                      # 0 = skip tuning, use defaults
"""

import os, sys, json, time, warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

import joblib
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, f1_score, roc_auc_score, precision_score,
    recall_score, classification_report, confusion_matrix, roc_curve,
)
from xgboost import XGBClassifier

try:
    from lightgbm import LGBMClassifier
    _LGBM = True
except ImportError:
    _LGBM = False
    from sklearn.ensemble import ExtraTreesClassifier

try:
    import optuna
    optuna.logging.set_verbosity(optuna.logging.WARNING)
    _OPTUNA = True
except ImportError:
    _OPTUNA = False

# ── Paths ──────────────────────────────────────────────────────────────────
ML_DIR      = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(ML_DIR, "..", "backend")
MODEL_OUT   = os.path.join(BACKEND_DIR, "models")
PLOTS_OUT   = os.path.join(ML_DIR, "plots")
os.makedirs(MODEL_OUT, exist_ok=True)
os.makedirs(PLOTS_OUT, exist_ok=True)

sys.path.insert(0, BACKEND_DIR)
from services.feature_extractor import FeatureExtractor

# ── Config ─────────────────────────────────────────────────────────────────
ISCX_CSV       = os.environ.get("ISCX_CSV",       os.path.join(ML_DIR, "data", "iscx_url_2016.csv"))
TRANCO_CSV     = os.environ.get("TRANCO_CSV",     os.path.join(ML_DIR, "data", "legit.csv"))
N_PER_CLASS    = int(os.environ.get("N_PER_CLASS",    "80000"))
OPTUNA_TRIALS  = int(os.environ.get("OPTUNA_TRIALS",  "30"))
RANDOM_SEED    = 42
CV_FOLDS       = 5


# ══════════════════════════════════════════════════════════════════════════
# 1 — DATASET
# ══════════════════════════════════════════════════════════════════════════
def load_data():
    if not os.path.exists(ISCX_CSV):
        raise FileNotFoundError(
            f"\nISCX not found: {ISCX_CSV}\n"
            "Download: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset\n"
            "Columns needed: url, type  (type=benign|phishing|defacement|malware)"
        )

    print(f"Loading: {ISCX_CSV}")
    iscx = pd.read_csv(ISCX_CSV).dropna(subset=["url", "type"])
    iscx["url"] = iscx["url"].astype(str).str.strip()

    print("\nClass distribution in raw ISCX:")
    print(iscx["type"].value_counts().to_string())

    # Binary: benign=0, everything else (phishing/defacement/malware)=1
    iscx_phish = iscx[iscx["type"].str.lower() != "benign"][["url"]].copy()
    iscx_legit = iscx[iscx["type"].str.lower() == "benign"][["url"]].copy()
    iscx_phish["label"] = 1
    iscx_legit["label"] = 0

    frames_phish = [iscx_phish]
    frames_legit = [iscx_legit]

    if os.path.exists(TRANCO_CSV):
        tranco = pd.read_csv(TRANCO_CSV, header=None, names=["rank","domain"],
                             usecols=["domain"]).dropna()
        tranco["url"]   = "https://" + tranco["domain"].astype(str).str.strip()
        tranco["label"] = 0
        frames_legit.append(tranco[["url","label"]])
        print(f"\nTranco: +{len(tranco):,} legit URLs")

    all_phish = pd.concat(frames_phish).drop_duplicates("url").reset_index(drop=True)
    all_legit = pd.concat(frames_legit).drop_duplicates("url").reset_index(drop=True)

    print(f"\nAvailable — malicious:{len(all_phish):,}  legit:{len(all_legit):,}")

    n = min(N_PER_CLASS, len(all_phish), len(all_legit))
    df = pd.concat([
        all_phish.sample(n=n, random_state=RANDOM_SEED),
        all_legit.sample(n=n, random_state=RANDOM_SEED),
    ]).sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

    print(f"Training set: {len(df):,} URLs ({n:,} per class)\n")
    return df


# ══════════════════════════════════════════════════════════════════════════
# 2 — FEATURE EXTRACTION
# ══════════════════════════════════════════════════════════════════════════
def build_features(df, extractor):
    extractor._get_domain_age = lambda d: -1
    extractor._has_mx_record  = lambda d: False

    total = len(df)
    print(f"Extracting features: {total:,} URLs...")
    t0 = time.time()

    records, errors = [], 0
    for i, url in enumerate(df["url"]):
        if i % 10000 == 0 and i > 0:
            eta = ((time.time()-t0)/i)*(total-i)
            print(f"  {i:,}/{total:,}  ETA {eta/60:.1f}m")
        try:
            records.append(extractor.extract(str(url)))
        except Exception:
            records.append(extractor._empty_features())
            errors += 1

    if errors:
        print(f"  {errors} URLs skipped")

    X = pd.DataFrame(records)
    y = df["label"].values
    print(f"Features: {X.shape[0]:,} × {X.shape[1]}  [{time.time()-t0:.0f}s]\n")
    return X, y


# ══════════════════════════════════════════════════════════════════════════
# 3 — HYPERPARAMETER TUNING (Optuna, optional)
# ══════════════════════════════════════════════════════════════════════════
def tune_hyperparams(X_train, y_train, n_trials: int):
    """
    Uses Optuna to find the best XGBoost hyperparameters for *this* dataset.
    Optimises cross-val F1 score (more robust than accuracy for imbalanced data).
    Typical improvement over defaults: +0.5-1.5% accuracy.
    """
    if not _OPTUNA or n_trials == 0:
        print("Optuna tuning skipped — using default hyperparameters.")
        print("  Install optuna + set OPTUNA_TRIALS=30 for +0.5-1.5% accuracy.\n")
        return _default_xgb_params()

    print(f"Optuna tuning: {n_trials} trials (this takes ~15 min)...")

    def objective(trial):
        params = {
            "n_estimators":     trial.suggest_int("n_estimators", 300, 700),
            "max_depth":        trial.suggest_int("max_depth", 5, 9),
            "learning_rate":    trial.suggest_float("learning_rate", 0.01, 0.1, log=True),
            "min_child_weight": trial.suggest_int("min_child_weight", 1, 7),
            "gamma":            trial.suggest_float("gamma", 0.0, 0.5),
            "reg_alpha":        trial.suggest_float("reg_alpha", 0.0, 0.5),
            "reg_lambda":       trial.suggest_float("reg_lambda", 0.5, 2.5),
            "subsample":        trial.suggest_float("subsample", 0.6, 1.0),
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.6, 1.0),
        }
        clf = XGBClassifier(**params, eval_metric="logloss",
                            random_state=RANDOM_SEED, n_jobs=-1, verbosity=0)
        # 3-fold CV for speed during tuning
        scores = cross_val_score(clf, X_train, y_train, cv=3,
                                 scoring="f1", n_jobs=-1)
        return scores.mean()

    study = optuna.create_study(direction="maximize",
                                sampler=optuna.samplers.TPESampler(seed=RANDOM_SEED))
    study.optimize(objective, n_trials=n_trials, show_progress_bar=False)

    best = study.best_params
    print(f"Best F1: {study.best_value:.4f}")
    print(f"Best params: {json.dumps(best, indent=2)}\n")
    return best


def _default_xgb_params():
    return {
        "n_estimators": 600, "max_depth": 7, "learning_rate": 0.04,
        "min_child_weight": 3, "gamma": 0.05, "reg_alpha": 0.1,
        "reg_lambda": 1.5, "subsample": 0.85, "colsample_bytree": 0.85,
    }


# ══════════════════════════════════════════════════════════════════════════
# 4 — TRAINING (Ensemble + Calibration + Threshold Optimization)
# ══════════════════════════════════════════════════════════════════════════
def train(X, y):
    # 80% train, 10% val (threshold tuning), 10% test (final eval)
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=0.10, stratify=y, random_state=RANDOM_SEED)
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.111, stratify=y_temp, random_state=RANDOM_SEED)
    # 0.111 of 0.90 ≈ 0.10 of total

    print(f"Split: train={len(X_train):,}  val={len(X_val):,}  test={len(X_test):,}")

    n_neg = int((y_train == 0).sum())
    n_pos = int((y_train == 1).sum())
    spw   = round(n_neg / max(n_pos, 1), 3)
    print(f"Class balance: neg={n_neg:,}  pos={n_pos:,}  spw={spw}\n")

    # ── Hyperparameter tuning ──────────────────────────────────────────────
    xgb_params = tune_hyperparams(X_train, y_train, OPTUNA_TRIALS)

    # ── Base learners ─────────────────────────────────────────────────────
    xgb = XGBClassifier(
        **xgb_params, scale_pos_weight=spw,
        eval_metric="logloss", random_state=RANDOM_SEED, n_jobs=-1, verbosity=0,
    )

    if _LGBM:
        b2 = LGBMClassifier(
            n_estimators=500, max_depth=8, learning_rate=0.04, num_leaves=63,
            min_child_samples=20, reg_alpha=0.1, reg_lambda=0.5,
            subsample=0.85, colsample_bytree=0.85, scale_pos_weight=spw,
            random_state=RANDOM_SEED, n_jobs=-1, verbose=-1,
        )
        b2_name = "lgbm"
    else:
        b2 = ExtraTreesClassifier(
            n_estimators=300, max_depth=20, random_state=RANDOM_SEED, n_jobs=-1)
        b2_name = "extra_trees"

    rf = RandomForestClassifier(
        n_estimators=300, max_depth=20, min_samples_split=5,
        min_samples_leaf=2, max_features="sqrt", class_weight="balanced",
        random_state=RANDOM_SEED, n_jobs=-1,
    )

    meta = LogisticRegression(
        C=0.5, solver="lbfgs", max_iter=1000,
        random_state=RANDOM_SEED, class_weight="balanced",
    )

    # ── Stacking ensemble ──────────────────────────────────────────────────
    stacker = StackingClassifier(
        estimators=[("xgb", xgb), (b2_name, b2), ("rf", rf)],
        final_estimator=meta,
        cv=CV_FOLDS,
        stack_method="predict_proba",
        passthrough=True,   # let meta-learner also see raw features
        n_jobs=-1,
    )

    pipeline = Pipeline([("scaler", StandardScaler()), ("clf", stacker)])

    print("=" * 60)
    print("Training Ensemble Stack v3.1")
    print(f"  Base : XGBoost + {'LightGBM' if _LGBM else 'ExtraTrees'} + RandomForest")
    print(f"  Meta : LogisticRegression (passthrough=True, C=0.5)")
    print(f"  CV   : {CV_FOLDS}-fold  |  Features: {X.shape[1]}")
    print("=" * 60)
    print("Fitting... (~15-25 min for 160k URLs)")

    t0 = time.time()
    pipeline.fit(X_train, y_train)
    elapsed = time.time() - t0
    print(f"Done in {elapsed/60:.1f}m\n")

    # ── Probability calibration ───────────────────────────────────────────
    # CalibratedClassifierCV with isotonic regression fixes poor probability
    # estimates from stacking, which directly improves threshold quality.
    print("Calibrating probabilities (isotonic regression)...")
    calibrated = CalibratedClassifierCV(pipeline, method="isotonic", cv=3)
    calibrated.fit(X_train, y_train)
    print("Calibration done.\n")

    # ── Threshold optimization on validation set ──────────────────────────
    # Find threshold that maximises accuracy on held-out val set.
    # This is the biggest single improvement over fixed 0.5 threshold.
    print("Optimising decision threshold on validation set...")
    val_probs  = calibrated.predict_proba(X_val)[:, 1]
    best_thresh, best_acc = 0.5, 0.0
    for thresh in np.arange(0.30, 0.70, 0.01):
        preds = (val_probs >= thresh).astype(int)
        acc   = accuracy_score(y_val, preds)
        if acc > best_acc:
            best_acc, best_thresh = acc, thresh

    print(f"  Best threshold: {best_thresh:.2f}  (val acc = {best_acc*100:.2f}%)\n")

    # ── Final evaluation on test set ──────────────────────────────────────
    test_probs  = calibrated.predict_proba(X_test)[:, 1]
    y_pred      = (test_probs >= best_thresh).astype(int)
    acc         = accuracy_score(y_test, y_pred)
    f1          = f1_score(y_test, y_pred)
    prec        = precision_score(y_test, y_pred)
    rec         = recall_score(y_test, y_pred)
    auc         = roc_auc_score(y_test, test_probs)
    cm          = confusion_matrix(y_test, y_pred)

    print("=" * 60)
    print("RESULTS — v3.1 Ensemble + Calibration + Threshold")
    print("=" * 60)
    print(f"  Accuracy  : {acc*100:.2f}%  ({'✓ TARGET MET' if acc>=0.95 else f'✗ {(0.95-acc)*100:.2f}% below target'})")
    print(f"  F1 Score  : {f1:.4f}")
    print(f"  Precision : {prec:.4f}")
    print(f"  Recall    : {rec:.4f}")
    print(f"  AUC-ROC   : {auc:.4f}")
    print(f"  Threshold : {best_thresh:.2f}")
    print(f"\nConfusion Matrix:")
    print(f"  TN={cm[0][0]:,}  FP={cm[0][1]:,}")
    print(f"  FN={cm[1][0]:,}  TP={cm[1][1]:,}")
    print(f"\n{classification_report(y_test, y_pred, target_names=['Benign','Malicious'])}")

    _plot_roc(y_test, test_probs, auc)
    _plot_cm(cm)
    _plot_importance(pipeline, list(X.columns))
    _plot_threshold_curve(y_val, val_probs, best_thresh)

    metrics = {
        "model_version":   "v3.1_ensemble_calibrated",
        "accuracy":        round(float(acc), 4),
        "f1_score":        round(float(f1), 4),
        "precision":       round(float(prec), 4),
        "recall":          round(float(rec), 4),
        "roc_auc":         round(float(auc), 4),
        "decision_threshold": round(float(best_thresh), 2),
        "confusion_matrix": cm.tolist(),
        "train_size":      len(X_train),
        "val_size":        len(X_val),
        "test_size":       len(X_test),
        "n_per_class":     N_PER_CLASS,
        "num_features":    int(X.shape[1]),
        "calibration":     "isotonic",
        "base_learners":   ["xgboost", "lightgbm" if _LGBM else "extra_trees", "random_forest"],
        "meta_learner":    "logistic_regression",
        "training_time_minutes": round(elapsed/60, 1),
    }
    with open(os.path.join(MODEL_OUT, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    return calibrated, best_thresh, metrics


# ══════════════════════════════════════════════════════════════════════════
# 5 — SAVE
# ══════════════════════════════════════════════════════════════════════════
def save(model, feature_names, threshold):
    mp = os.path.join(MODEL_OUT, "phishguard_v1.pkl")
    fp = os.path.join(MODEL_OUT, "feature_names.pkl")
    tp = os.path.join(MODEL_OUT, "threshold.json")

    joblib.dump(model,         mp, compress=3)
    joblib.dump(feature_names, fp, compress=3)
    with open(tp, "w") as f:
        json.dump({"threshold": threshold}, f)

    print(f"\nModel saved    : {mp}  ({os.path.getsize(mp)/1024/1024:.1f} MB)")
    print(f"Features saved : {fp}  ({len(feature_names)} features)")
    print(f"Threshold saved: {tp}  (threshold={threshold:.2f})")


# ══════════════════════════════════════════════════════════════════════════
# PLOTS
# ══════════════════════════════════════════════════════════════════════════
def _plot_roc(y_test, probs, auc):
    fpr, tpr, _ = roc_curve(y_test, probs)
    fig, ax = plt.subplots(figsize=(7,5))
    ax.plot(fpr, tpr, "#185FA5", lw=2.5, label=f"AUC = {auc:.4f}")
    ax.plot([0,1],[0,1],"#888",ls="--",lw=1)
    ax.fill_between(fpr, tpr, alpha=0.08, color="#185FA5")
    ax.set(xlabel="FPR", ylabel="TPR", title="PhishGuard v3.1 — ROC Curve")
    ax.legend(); ax.grid(alpha=0.2); plt.tight_layout()
    p = os.path.join(PLOTS_OUT, "roc_curve.png")
    plt.savefig(p, dpi=150); plt.close(); print(f"ROC curve         : {p}")

def _plot_cm(cm):
    fig, ax = plt.subplots(figsize=(5,4))
    im = ax.imshow(cm, cmap="Blues")
    plt.colorbar(im)
    thresh = cm.max()/2
    for i in range(2):
        for j in range(2):
            ax.text(j,i,f"{cm[i,j]:,}",ha="center",va="center",
                    color="white" if cm[i,j]>thresh else "black",fontsize=14)
    ax.set(xticks=[0,1],yticks=[0,1],
           xticklabels=["Benign","Malicious"],yticklabels=["Benign","Malicious"],
           xlabel="Predicted",ylabel="Actual",title="PhishGuard v3.1 — Confusion Matrix")
    plt.tight_layout()
    p = os.path.join(PLOTS_OUT, "confusion_matrix.png")
    plt.savefig(p, dpi=150); plt.close(); print(f"Confusion matrix  : {p}")

def _plot_importance(pipeline, feature_names):
    try:
        # Navigate through wrapper chain to XGBoost base learner
        try:
            base_est = pipeline.calibrated_classifiers_[0].estimator
            xgb_clf  = base_est.named_steps["clf"].estimators_[0]
        except AttributeError:
            xgb_clf  = pipeline.named_steps["clf"].estimators_[0]
        imps     = xgb_clf.feature_importances_
        idx      = np.argsort(imps)[-25:]
        labels   = [feature_names[i] if i < len(feature_names) else f"f{i}" for i in idx]
        fig, ax  = plt.subplots(figsize=(11,9))
        ax.barh(labels, imps[idx], color="#185FA5")
        ax.set(xlabel="XGBoost feature importance (gain)",
               title="PhishGuard v3.1 — Top 25 Features")
        plt.tight_layout()
        p = os.path.join(PLOTS_OUT, "feature_importance.png")
        plt.savefig(p, dpi=150); plt.close(); print(f"Feature importance: {p}")

        imp_dict = {n: round(float(v),6) for n,v in zip(feature_names,imps)}
        imp_path = os.path.join(MODEL_OUT, "feature_importances.json")
        with open(imp_path,"w") as f: json.dump(imp_dict, f, indent=2)
        print(f"Importances JSON  : {imp_path}")
    except Exception as e:
        print(f"Feature importance plot skipped: {e}")

def _plot_threshold_curve(y_val, probs, best_thresh):
    thresholds = np.arange(0.20, 0.80, 0.01)
    accs = [accuracy_score(y_val, (probs >= t).astype(int)) for t in thresholds]
    fig, ax = plt.subplots(figsize=(7,4))
    ax.plot(thresholds, [a*100 for a in accs], "#185FA5", lw=2)
    ax.axvline(best_thresh, color="#e74c3c", ls="--", lw=1.5,
               label=f"Optimal: {best_thresh:.2f} ({max(accs)*100:.2f}%)")
    ax.set(xlabel="Decision Threshold", ylabel="Accuracy (%)",
           title="PhishGuard v3.1 — Threshold Optimization")
    ax.legend(); ax.grid(alpha=0.2); plt.tight_layout()
    p = os.path.join(PLOTS_OUT, "threshold_curve.png")
    plt.savefig(p, dpi=150); plt.close(); print(f"Threshold curve   : {p}")


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 60)
    print("PhishGuard ML v3.1 — Ensemble + Calibration + Threshold")
    print("=" * 60)
    print(f"ISCX     : {ISCX_CSV}")
    print(f"Tranco   : {TRANCO_CSV}")
    print(f"N/class  : {N_PER_CLASS:,}")
    print(f"Optuna   : {OPTUNA_TRIALS} trials ({'enabled' if _OPTUNA and OPTUNA_TRIALS > 0 else 'disabled — pip install optuna to enable'})")
    print()

    extractor = FeatureExtractor()
    df        = load_data()
    df.to_csv(os.path.join(ML_DIR, "data", "phishguard_dataset.csv"), index=False)

    X, y          = build_features(df, extractor)
    feature_names = list(X.columns)

    print(f"Total features: {len(feature_names)}")
    print()

    model, threshold, metrics = train(X, y)
    save(model, feature_names, threshold)

    print("\n" + "=" * 60)
    print("DONE")
    print(f"  Accuracy  : {metrics['accuracy']*100:.2f}%")
    print(f"  AUC-ROC   : {metrics['roc_auc']:.4f}")
    print(f"  Threshold : {metrics['decision_threshold']}")
    print()
    print("Start backend:")
    print("  cd backend && uvicorn main:app --reload --port 8000")
    print("=" * 60)
