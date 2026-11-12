"""
train_v2.py - Deuxieme modele Isolation Forest pour CIC-IDS2017.

Configuration :
- 300 000 lignes maximum depuis CIC-IDS2017
- Split stratifie : 70 % train / 15 % validation / 15 % test
- Entrainement uniquement sur les flux BENIGN du train
- Tous les flux BENIGN du train sont utilises (pas de plafond a 150 000)
- Isolation Forest : 300 arbres, max_samples=512
- Seuil choisi sur validation en maximisant le F1-score
- Evaluation finale sur test, sans regler le modele sur ce jeu

Les fichiers sont enregistres sous des noms V2 dans model/.
Les fichiers V1 ne sont ni modifies ni supprimes.

Installation :
    pip install datasets pandas numpy scikit-learn joblib

Execution :
    python train_v2.py
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from datasets import load_dataset
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


# -------------------------- Configuration --------------------------

ROOT = Path(__file__).resolve().parent
MODEL_DIR = ROOT / "model"
DATASET_NAME = "c01dsnap/CIC-IDS2017"

RANDOM_STATE = 42
N_ESTIMATORS = 300
MAX_SAMPLES = 512

# Fichiers propres a V2 : aucun ecrasement de V1.
MODEL_PATH = MODEL_DIR / "isolation_forest_v2_pipeline.joblib"
FEATURES_PATH = MODEL_DIR / "feature_columns_v2.json"
THRESHOLD_PATH = MODEL_DIR / "threshold_v2.json"
METADATA_PATH = MODEL_DIR / "model_metadata_v2.json"
METRICS_PATH = MODEL_DIR / "evaluation_metrics_v2.json"
CONFUSION_PATH = MODEL_DIR / "confusion_matrix_v2.csv"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-rows", type=int, default=300_000)
    parser.add_argument("--test-size", type=float, default=0.15)
    parser.add_argument("--validation-size", type=float, default=0.15)
    args = parser.parse_args()

    if args.max_rows < 10:
        parser.error("--max-rows doit etre au moins egal a 10.")
    if not 0 < args.test_size < 1 or not 0 < args.validation_size < 1:
        parser.error("Les proportions doivent etre comprises entre 0 et 1.")
    if args.test_size + args.validation_size >= 1:
        parser.error("test-size + validation-size doit etre inferieur a 1.")
    return args


def load_and_clean(max_rows: int) -> pd.DataFrame:
    log.info("Chargement du dataset %s", DATASET_NAME)
    ds = load_dataset(DATASET_NAME)

    if "train" not in ds:
        raise ValueError(f"Split train absent. Splits disponibles : {list(ds.keys())}")

    source = ds["train"]
    n = min(max_rows, len(source))
    log.info("Echantillonnage de %s lignes sur %s", f"{n:,}", f"{len(source):,}")

    df = source.shuffle(seed=RANDOM_STATE).select(range(n)).to_pandas()
    df.columns = df.columns.astype(str).str.strip()

    if "Label" not in df.columns:
        raise ValueError("La colonne Label est introuvable dans le dataset.")

    df = df[df["Label"].notna()].copy()
    df["Label"] = df["Label"].astype(str).str.strip()
    df = df[df["Label"] != ""].drop_duplicates().reset_index(drop=True)

    # Cible d'evaluation uniquement : elle ne sera pas une feature.
    df["target"] = (df["Label"].str.upper() != "BENIGN").astype("int8")

    counts = df["target"].value_counts()
    log.info(
        "Apres nettoyage : %s lignes ; BENIGN=%s ; non-BENIGN=%s",
        f"{len(df):,}",
        f"{int(counts.get(0, 0)):,}",
        f"{int(counts.get(1, 0)):,}",
    )
    if df["target"].nunique() != 2:
        raise ValueError("L'echantillon doit contenir BENIGN et non-BENIGN.")
    return df


def split_data(df, test_size: float, validation_size: float):
    # Premier split : test final.
    train_validation, test = train_test_split(
        df,
        test_size=test_size,
        random_state=RANDOM_STATE,
        stratify=df["target"],
    )

    # La taille validation est exprimee en proportion du dataset total.
    relative_validation_size = validation_size / (1.0 - test_size)
    train, validation = train_test_split(
        train_validation,
        test_size=relative_validation_size,
        random_state=RANDOM_STATE,
        stratify=train_validation["target"],
    )

    log.info(
        "Split : train=%s (%.1f%%), validation=%s (%.1f%%), test=%s (%.1f%%)",
        f"{len(train):,}", 100 * len(train) / len(df),
        f"{len(validation):,}", 100 * len(validation) / len(df),
        f"{len(test):,}", 100 * len(test) / len(df),
    )
    return train, validation, test


def prepare_features(train, validation, test):
    # Isolation Forest n'apprend que les flux normaux du train.
    benign_train = train[train["Label"].str.upper() == "BENIGN"]
    if benign_train.empty:
        raise ValueError("Aucun flux BENIGN disponible dans train.")

    numeric_cols = train.select_dtypes(include=[np.number]).columns.tolist()
    numeric_cols = [c for c in numeric_cols if c != "target"]

    X_benign = benign_train[numeric_cols].replace([np.inf, -np.inf], np.nan)
    non_empty_cols = X_benign.columns[X_benign.notna().any()].tolist()
    X_benign = X_benign[non_empty_cols]

    # Retirer les features constantes sur les exemples normaux d'entrainement.
    features = [
        c for c in X_benign.columns
        if X_benign[c].nunique(dropna=True) > 1
    ]
    if not features:
        raise ValueError("Aucune feature numerique exploitable.")

    # Tous les BENIGN de train sont utilises, sans limite de 150 000.
    X_train = X_benign[features].copy()
    X_val = validation[features].replace([np.inf, -np.inf], np.nan)
    X_test = test[features].replace([np.inf, -np.inf], np.nan)
    y_val = validation["target"].astype(int)
    y_test = test["target"].astype(int)

    log.info("Nombre de features : %d", len(features))
    log.info("Flux BENIGN utilises pour fit : %s", f"{len(X_train):,}")
    log.info("Lignes validation : %s ; anomalies : %s",
             f"{len(X_val):,}", f"{int(y_val.sum()):,}")
    log.info("Lignes test : %s ; anomalies : %s",
             f"{len(X_test):,}", f"{int(y_test.sum()):,}")

    return X_train, X_val, X_test, y_val, y_test, features


def train_model(X_train) -> Pipeline:
    log.info(
        "Entrainement : n_estimators=%d, max_samples=%d",
        N_ESTIMATORS, MAX_SAMPLES,
    )
    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("isolation_forest", IsolationForest(
            n_estimators=N_ESTIMATORS,
            max_samples=MAX_SAMPLES,
            contamination="auto",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )),
    ])
    pipeline.fit(X_train)
    log.info("Entrainement termine.")
    return pipeline


def anomaly_scores(pipeline: Pipeline, X: pd.DataFrame) -> np.ndarray:
    # score_samples faible = observation plus atypique.
    # On inverse le signe : score eleve = plus anomal.
    imputed = pipeline.named_steps["imputer"].transform(X)
    return -pipeline.named_steps["isolation_forest"].score_samples(imputed)


def select_threshold(y_val, scores):
    log.info("Recherche du seuil sur le jeu de validation...")
    precision, recall, thresholds = precision_recall_curve(y_val, scores)

    if len(thresholds) == 0:
        raise ValueError("Impossible de calculer un seuil sur la validation.")

    p = precision[:-1]
    r = recall[:-1]
    denom = p + r
    f1 = np.divide(2 * p * r, denom, out=np.zeros_like(denom), where=denom != 0)

    best = int(np.nanargmax(f1))
    threshold = float(thresholds[best])
    validation_metrics = {
        "precision_attack": float(p[best]),
        "recall_attack": float(r[best]),
        "f1_attack": float(f1[best]),
    }
    log.info("Seuil choisi : %.10f", threshold)
    log.info("Validation : %s", validation_metrics)
    return threshold, validation_metrics


def evaluate(y_true, scores, threshold, label):
    # 0 = normal ; 1 = anomalie.
    predictions = (scores >= threshold).astype(int)

    metrics = {
        "accuracy": float(accuracy_score(y_true, predictions)),
        "precision_attack": float(precision_score(y_true, predictions, zero_division=0)),
        "recall_attack": float(recall_score(y_true, predictions, zero_division=0)),
        "f1_attack": float(f1_score(y_true, predictions, zero_division=0)),
    }
    try:
        metrics["roc_auc"] = float(roc_auc_score(y_true, scores))
        metrics["average_precision"] = float(average_precision_score(y_true, scores))
    except ValueError as exc:
        log.warning("ROC AUC / Average Precision indisponible : %s", exc)

    matrix = confusion_matrix(y_true, predictions, labels=[0, 1])

    print("\\n" + "=" * 65)
    print(f"RESULTATS {label}")
    print("=" * 65)
    print(classification_report(
        y_true, predictions,
        labels=[0, 1],
        target_names=["Normal", "Anomalie"],
        zero_division=0,
    ))
    print("Matrice de confusion :")
    print(matrix)
    print("Metriques :")
    for name, value in metrics.items():
        print(f"  {name}: {value:.4f}")

    return metrics, matrix, predictions


def save_artifacts(
    pipeline, features, threshold, val_metrics, test_metrics,
    test_matrix, n_train, n_validation, n_test,
):
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    # Fichiers V2 distincts : isolation_forest_pipeline.joblib (V1) reste intact.
    joblib.dump(pipeline, MODEL_PATH)

    FEATURES_PATH.write_text(
        json.dumps(features, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    threshold_info = {
        "score_definition": "-IsolationForest.score_samples(imputed_features)",
        "decision_rule": "score >= threshold => anomalie (1), sinon normal (0)",
        "threshold": threshold,
        "selection": "maximum F1-score sur le jeu de validation",
        "validation_metrics_at_threshold": val_metrics,
    }
    THRESHOLD_PATH.write_text(
        json.dumps(threshold_info, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    metrics_info = {"validation": val_metrics, "test": test_metrics}
    METRICS_PATH.write_text(
        json.dumps(metrics_info, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    metadata = {
        "model_version": "V2",
        "model_name": "IsolationForest",
        "dataset": DATASET_NAME,
        "training_strategy": "one_class_training_on_BENIGN_only",
        "split": {"train": 0.70, "validation": 0.15, "test": 0.15},
        "n_train_normal": int(n_train),
        "n_validation": int(n_validation),
        "n_test": int(n_test),
        "n_features": len(features),
        "n_estimators": N_ESTIMATORS,
        "max_samples": MAX_SAMPLES,
        "contamination": "auto",
        "random_state": RANDOM_STATE,
        "threshold": threshold,
        "threshold_selection": "maximum F1-score on validation",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
        "inference_note": (
            "Conserver exactement les features et leur ordre. Appliquer le pipeline "
            "pour l'imputation, calculer -score_samples, puis comparer au seuil."
        ),
    }
    METADATA_PATH.write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    pd.DataFrame(
        test_matrix,
        index=["reel_normal", "reel_anomalie"],
        columns=["predit_normal", "predit_anomalie"],
    ).to_csv(CONFUSION_PATH)

    log.info("Fichiers V2 enregistres dans %s :", MODEL_DIR)
    for path in (
        MODEL_PATH, FEATURES_PATH, THRESHOLD_PATH,
        METADATA_PATH, METRICS_PATH, CONFUSION_PATH,
    ):
        log.info("  %s", path.name)


def verify_saved_model(X_test, threshold):
    loaded = joblib.load(MODEL_PATH)
    loaded_features = json.loads(FEATURES_PATH.read_text(encoding="utf-8"))
    loaded_threshold = json.loads(THRESHOLD_PATH.read_text(encoding="utf-8"))["threshold"]

    sample = X_test[loaded_features].head(5)
    scores = anomaly_scores(loaded, sample)
    labels = ["Anomalie" if s >= loaded_threshold else "Normal" for s in scores]

    if not np.isclose(threshold, loaded_threshold):
        raise RuntimeError("Le seuil recharge ne correspond pas au seuil choisi.")
    log.info("Verification du modele sauvegarde : %s", labels)


def main():
    args = parse_args()
    log.info("========== DEBUT ENTRAINEMENT V2 ==========")
    log.info("Les fichiers V1 seront conserves.")

    df = load_and_clean(args.max_rows)
    train_df, val_df, test_df = split_data(
        df, args.test_size, args.validation_size
    )

    X_train, X_val, X_test, y_val, y_test, features = prepare_features(
        train_df, val_df, test_df
    )

    model = train_model(X_train)

    # Le seuil est selectionne sur validation, jamais sur le test.
    val_scores = anomaly_scores(model, X_val)
    threshold, val_metrics = select_threshold(y_val, val_scores)

    # Une seule evaluation finale sur le jeu test.
    test_scores = anomaly_scores(model, X_test)
    test_metrics, test_matrix, _ = evaluate(
        y_test, test_scores, threshold, "TEST FINAL"
    )

    save_artifacts(
        model, features, threshold, val_metrics, test_metrics,
        test_matrix, len(X_train), len(X_val), len(X_test),
    )
    verify_saved_model(X_test, threshold)

    log.info("========== ENTRAINEMENT V2 TERMINE ==========")
    log.info("Le modele V1 n'a pas ete ecrase.")


if __name__ == "__main__":
    main()
