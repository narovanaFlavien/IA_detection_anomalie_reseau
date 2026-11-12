"""
train_supervised.py
===================

Classification supervisee multi-classes sur CIC-IDS2017.
Le modele predit directement le type de trafic :
BENIGN, DoS Hulk, PortScan, DDoS, FTP-Patator, etc.

Choix initial : ExtraTreesClassifier (Scikit-learn).
Pourquoi pas SVM RBF en premier ?
- CIC-IDS2017 contient beaucoup de lignes et plusieurs classes.
- Un SVM RBF peut devenir tres couteux en temps et en RAM sur 300 000 lignes.
- ExtraTrees gere bien les relations non lineaires, ne necessite pas de normalisation
  et constitue une bonne reference pour un premier classificateur multiclasses.

Installation :
    pip install datasets pandas numpy scikit-learn joblib matplotlib seaborn

Execution :
    python train_supervised.py
    python train_supervised.py --max-rows 300000 --n-estimators 300

Sorties :
    model/supervised_v1_pipeline.joblib
    model/supervised_v1_metadata.json
    model/supervised_v1_metrics.json
    model/supervised_v1_classification_report.csv
    model/supervised_v1_confusion_matrix.csv
    model/supervised_v1_labels.json

Ce script ne modifie pas les fichiers Isolation Forest V1 ou V2.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from datasets import load_dataset
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent
MODEL_DIR = ROOT / "model_supervised"
DATASET_NAME = "c01dsnap/CIC-IDS2017"
RANDOM_STATE = 42

DEFAULT_MAX_ROWS = 300_000
DEFAULT_N_ESTIMATORS = 300

MODEL_PATH = MODEL_DIR / "supervised_v1_pipeline.joblib"
METADATA_PATH = MODEL_DIR / "supervised_v1_metadata.json"
METRICS_PATH = MODEL_DIR / "supervised_v1_metrics.json"
REPORT_PATH = MODEL_DIR / "supervised_v1_classification_report.csv"
CONFUSION_PATH = MODEL_DIR / "supervised_v1_confusion_matrix.csv"
LABELS_PATH = MODEL_DIR / "supervised_v1_labels.json"
FEATURES_PATH = MODEL_DIR / "supervised_v1_features.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("supervised_training")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Classification multi-classes supervisee CIC-IDS2017."
    )
    parser.add_argument("--max-rows", type=int, default=DEFAULT_MAX_ROWS)
    parser.add_argument("--n-estimators", type=int, default=DEFAULT_N_ESTIMATORS)
    parser.add_argument("--test-size", type=float, default=0.20)
    parser.add_argument("--validation-size", type=float, default=0.10)
    args = parser.parse_args()

    if args.max_rows < 100:
        parser.error("--max-rows doit etre au moins egal a 100.")
    if args.n_estimators < 10:
        parser.error("--n-estimators doit etre au moins egal a 10.")
    if not 0 < args.test_size < 1 or not 0 < args.validation_size < 1:
        parser.error("Les proportions doivent etre comprises entre 0 et 1.")
    if args.test_size + args.validation_size >= 1:
        parser.error("test-size + validation-size doit etre inferieur a 1.")
    return args


def normalize_label(value: object) -> str:
    """Nettoie les espaces sans fusionner les differents types d'attaques."""
    return str(value).strip()


def load_stratified_sample(max_rows: int) -> pd.DataFrame:
    """
    Charge le split Hugging Face puis tire un echantillon stratifie.
    La stratification preserve autant que possible la representation de chaque classe,
    contrairement a un tirage aleatoire simple qui peut perdre des attaques rares.
    """
    log.info("Chargement de %s...", DATASET_NAME)
    dataset_dict = load_dataset(DATASET_NAME)

    if "train" not in dataset_dict:
        raise ValueError(
            f"Split 'train' absent. Splits disponibles : {list(dataset_dict.keys())}"
        )

    dataset = dataset_dict["train"]
    if " Label" not in dataset.column_names:
        raise ValueError(
            f"Colonne Label absente. Colonnes : {dataset.column_names}"
        )

    total = len(dataset)
    n_rows = min(max_rows, total)
    log.info("Dataset source : %s lignes", f"{total:,}")
    log.info("Echantillon demande : %s lignes", f"{n_rows:,}")

    # Lire uniquement la colonne cible pour preparer les indices stratifies.
    labels = np.asarray(
        [normalize_label(x) for x in dataset[" Label"]],
        dtype=object,
    )
    indices = np.arange(total)

    if n_rows < total:
        try:
            sampled_indices, _ = train_test_split(
                indices,
                train_size=n_rows,
                random_state=RANDOM_STATE,
                stratify=labels,
            )
        except ValueError as exc:
            raise ValueError(
                "Impossible de faire un echantillonnage stratifie. "
                "Verifiez que chaque classe possede au moins deux exemples "
                "et augmentez --max-rows si necessaire."
            ) from exc
    else:
        sampled_indices = indices

    sampled_indices = np.sort(sampled_indices)
    sampled = dataset.select(sampled_indices.tolist())
    df = sampled.to_pandas()
    log.info("Echantillon charge : %s lignes", f"{len(df):,}")
    return df


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    log.info("Nettoyage des donnees...")
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]

    if "Label" not in df.columns:
        raise ValueError("Colonne Label introuvable.")

    df["Label"] = df["Label"].map(normalize_label)
    df = df[df["Label"].notna() & (df["Label"] != "")].copy()

    before = len(df)
    df = df.drop_duplicates().reset_index(drop=True)
    log.info("Doublons supprimes : %s", f"{before - len(df):,}")

    # Uniformiser les noms des classes, mais garder le nom de l'attaque.
    df["Label"] = df["Label"].replace({
        "Web Attack � Brute Force": "Web Attack - Brute Force",
        "Web Attack � XSS": "Web Attack - XSS",
        "Web Attack � Sql Injection": "Web Attack - Sql Injection",
    })

    log.info("Nombre de classes : %d", df["Label"].nunique())
    log.info("Repartition des classes :\n%s", df["Label"].value_counts().to_string())
    return df


def select_numeric_features(df: pd.DataFrame):
    """
    Retire les identifiants de flux, IP et timestamp, qui risquent de provoquer
    une memorisation du contexte de capture plutot qu'un apprentissage du trafic.
    Les ports et le protocole sont conserves s'ils sont numeriques.
    """
    excluded_exact = {
        "label",
        "target",
        "flow id",
        "source ip",
        "destination ip",
        "src ip",
        "dst ip",
        "timestamp",
    }

    feature_candidates = []
    for col in df.columns:
        normalized = re.sub(r"\s+", " ", col.strip().lower())
        if normalized in excluded_exact:
            continue
        if "timestamp" in normalized or normalized.endswith("_ip"):
            continue

        converted = pd.to_numeric(df[col], errors="coerce")
        if converted.notna().any():
            feature_candidates.append(col)
            df[col] = converted

    if not feature_candidates:
        raise ValueError("Aucune caracteristique numerique exploitable.")

    X = df[feature_candidates].replace([np.inf, -np.inf], np.nan)

    # Retirer les colonnes vides ou constantes sur l'ensemble echantillonne.
    valid_features = [
        col for col in X.columns
        if X[col].notna().any() and X[col].nunique(dropna=True) > 1
    ]
    X = X[valid_features]

    if X.shape[1] == 0:
        raise ValueError("Toutes les caracteristiques sont vides ou constantes.")

    y = df["Label"].astype(str)
    log.info("Caracteristiques numeriques retenues : %d", X.shape[1])
    log.info("Features : %s", valid_features)
    return X, y, valid_features


def split_data(X, y, test_size: float, validation_size: float):
    """
    Split stratifie :
    train = 70 %, validation = 10 %, test = 20 % par defaut.
    Le jeu de validation sert a controler le modele et a choisir les ameliorations.
    Le test est reserve a l'evaluation finale.
    """
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    validation_relative = validation_size / (1.0 - test_size)
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val,
        y_train_val,
        test_size=validation_relative,
        random_state=RANDOM_STATE,
        stratify=y_train_val,
    )

    log.info(
        "Split : train=%s, validation=%s, test=%s",
        f"{len(X_train):,}", f"{len(X_val):,}", f"{len(X_test):,}",
    )
    return X_train, X_val, X_test, y_train, y_val, y_test


def build_model(n_estimators: int) -> Pipeline:
    """
    Pipeline reproductible : imputation mediane + Extra Trees.
    class_weight='balanced' aide les classes moins representees.
    """
    return Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="median")),
        ("classifier", ExtraTreesClassifier(
            n_estimators=n_estimators,
            max_features="sqrt",
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )),
    ])


def evaluate_model(model, X, y, split_name: str, labels: list[str]):
    predictions = model.predict(X)

    accuracy = accuracy_score(y, predictions)
    precision_macro = precision_score(
        y, predictions, average="macro", zero_division=0
    )
    recall_macro = recall_score(
        y, predictions, average="macro", zero_division=0
    )
    f1_macro = f1_score(y, predictions, average="macro", zero_division=0)
    f1_weighted = f1_score(y, predictions, average="weighted", zero_division=0)

    print("\n" + "=" * 72)
    print(f"RESULTATS - {split_name.upper()}")
    print("=" * 72)
    print(f"Accuracy       : {accuracy:.4f}")
    print(f"Precision macro: {precision_macro:.4f}")
    print(f"Recall macro   : {recall_macro:.4f}")
    print(f"F1 macro       : {f1_macro:.4f}")
    print(f"F1 weighted    : {f1_weighted:.4f}")
    print("\nRapport par classe :")
    print(classification_report(
        y,
        predictions,
        labels=labels,
        target_names=labels,
        zero_division=0,
    ))

    metrics = {
        "accuracy": float(accuracy),
        "precision_macro": float(precision_macro),
        "recall_macro": float(recall_macro),
        "f1_macro": float(f1_macro),
        "f1_weighted": float(f1_weighted),
    }
    report = classification_report(
        y,
        predictions,
        labels=labels,
        target_names=labels,
        output_dict=True,
        zero_division=0,
    )
    matrix = confusion_matrix(y, predictions, labels=labels)
    return metrics, report, matrix


def save_artifacts(
    model,
    features,
    labels,
    metrics,
    report,
    matrix,
    n_train,
    n_validation,
    n_test,
    n_estimators,
):
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, MODEL_PATH)
    FEATURES_PATH.write_text(
        json.dumps(features, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    LABELS_PATH.write_text(
        json.dumps(labels, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    METRICS_PATH.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    METADATA_PATH.write_text(
        json.dumps({
            "model_version": "supervised_v1",
            "algorithm": "ExtraTreesClassifier",
            "dataset": DATASET_NAME,
            "task": "multiclass_network_intrusion_classification",
            "target_column": "Label",
            "classes": labels,
            "n_features": len(features),
            "features": features,
            "n_train": n_train,
            "n_validation": n_validation,
            "n_test": n_test,
            "n_estimators": n_estimators,
            "max_features": "sqrt",
            "min_samples_leaf": 2,
            "class_weight": "balanced",
            "random_state": RANDOM_STATE,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
        }, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    pd.DataFrame(report).transpose().to_csv(REPORT_PATH, index=True)
    pd.DataFrame(
        matrix,
        index=[f"reel_{label}" for label in labels],
        columns=[f"predit_{label}" for label in labels],
    ).to_csv(CONFUSION_PATH, index=True)

    log.info("Artefacts sauvegardes dans %s :", MODEL_DIR)
    for path in (
        MODEL_PATH, FEATURES_PATH, LABELS_PATH, METADATA_PATH,
        METRICS_PATH, REPORT_PATH, CONFUSION_PATH,
    ):
        log.info("  - %s", path.name)


def main():
    args = parse_args()
    log.info("========== CLASSIFICATION SUPERVISEE CIC-IDS2017 ==========")
    log.info("Les fichiers Isolation Forest V1/V2 seront conserves.")

    df = load_stratified_sample(args.max_rows)
    df = clean_dataframe(df)

    X, y, features = select_numeric_features(df)

    # Certaines classes tres rares peuvent ne pas permettre une separation fiable.
    counts = y.value_counts()
    rare = counts[counts < 3]
    if not rare.empty:
        raise ValueError(
            "Certaines classes ont moins de 3 exemples apres nettoyage : "
            f"{rare.to_dict()}. Augmentez --max-rows."
        )

    X_train, X_val, X_test, y_train, y_val, y_test = split_data(
        X, y, args.test_size, args.validation_size
    )

    labels = sorted(y.unique().tolist())
    model = build_model(args.n_estimators)

    log.info("Entrainement ExtraTrees sur %s lignes...", f"{len(X_train):,}")
    model.fit(X_train, y_train)
    log.info("Entrainement termine.")

    # Validation : diagnostic avant l'evaluation finale.
    val_metrics, _, _ = evaluate_model(
        model, X_val, y_val, "VALIDATION", labels
    )

    # Test : mesure finale, sans ajustement apres lecture de ces resultats.
    test_metrics, test_report, test_matrix = evaluate_model(
        model, X_test, y_test, "TEST FINAL", labels
    )

    metrics = {"validation": val_metrics, "test": test_metrics}
    save_artifacts(
        model=model,
        features=features,
        labels=labels,
        metrics=metrics,
        report=test_report,
        matrix=test_matrix,
        n_train=len(X_train),
        n_validation=len(X_val),
        n_test=len(X_test),
        n_estimators=args.n_estimators,
    )

    # Petit test de rechargement pour verifier que le fichier est exploitable.
    loaded_model = joblib.load(MODEL_PATH)
    sample_predictions = loaded_model.predict(X_test.head(5))
    log.info("Verification rechargement : %s", sample_predictions.tolist())
    log.info("Classification supervisee terminee.")


if __name__ == "__main__":
    main()
