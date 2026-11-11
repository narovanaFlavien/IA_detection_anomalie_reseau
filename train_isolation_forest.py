"""
Entraînement d'un premier modèle de détection d'anomalies réseau
avec Isolation Forest et le dataset CIC-IDS2017.

Exécution depuis la racine du projet :
    python train.py

Ou avec des paramètres :
    python train.py --max-rows 500000 --max-train-normal 150000 --trees 200

Les artefacts sont enregistrés dans :
    model/
        isolation_forest_pipeline.joblib
        feature_columns.json
        model_metadata.json
        evaluation_metrics.json
        confusion_matrix.csv

Important :
- Le modèle est entraîné uniquement sur les flux BENIGN.
- Les labels servent à sélectionner les données normales et à évaluer
  le modèle ; ils ne sont pas fournis à Isolation Forest.
- Le modèle attend des caractéristiques de flux réseau compatibles
  avec celles de CIC-IDS2017, pas des paquets Scapy bruts.
"""

from __future__ import annotations

import argparse
import json
import logging
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


# ---------------------------------------------------------------------
# Configuration générale
# ---------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent
MODEL_DIR = PROJECT_ROOT / "model"
DATASET_NAME = "c01dsnap/CIC-IDS2017"
RANDOM_STATE = 42

warnings.filterwarnings("ignore", category=FutureWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def parse_arguments() -> argparse.Namespace:
    """Récupère les paramètres éventuellement fournis en ligne de commande."""
    parser = argparse.ArgumentParser(
        description="Entraîner Isolation Forest sur CIC-IDS2017."
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=500_000,
        help="Nombre maximal de lignes échantillonnées depuis le dataset (défaut : 500000).",
    )
    parser.add_argument(
        "--max-train-normal",
        type=int,
        default=150_000,
        help="Nombre maximal de flux BENIGN utilisés pour l'entraînement (défaut : 150000).",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.20,
        help="Proportion réservée au test (défaut : 0.20).",
    )
    parser.add_argument(
        "--trees",
        type=int,
        default=200,
        help="Nombre d'arbres Isolation Forest (défaut : 200).",
    )
    parser.add_argument(
        "--contamination",
        type=str,
        default="auto",
        help='Paramètre contamination (défaut : "auto").',
    )
    return parser.parse_args()


def validate_arguments(args: argparse.Namespace) -> None:
    """Vérifie que les paramètres fournis sont cohérents."""
    if args.max_rows < 2:
        raise ValueError("--max-rows doit être supérieur ou égal à 2.")
    if args.max_train_normal < 1:
        raise ValueError("--max-train-normal doit être supérieur ou égal à 1.")
    if not 0 < args.test_size < 1:
        raise ValueError("--test-size doit être compris entre 0 et 1.")
    if args.trees < 1:
        raise ValueError("--trees doit être supérieur ou égal à 1.")


def load_and_sample_dataset(max_rows: int) -> pd.DataFrame:
    """
    Télécharge CIC-IDS2017, mélange les lignes puis convertit un échantillon
    en DataFrame Pandas pour limiter l'utilisation de la mémoire.
    """
    logger.info("Chargement du dataset Hugging Face : %s", DATASET_NAME)
    dataset_dict = load_dataset(DATASET_NAME)

    if "train" not in dataset_dict:
        raise ValueError(
            "Le dataset ne contient pas de split 'train'. "
            f"Splits disponibles : {list(dataset_dict.keys())}"
        )

    hf_train = dataset_dict["train"]
    number_of_rows = min(max_rows, len(hf_train))

    logger.info("Nombre total de lignes disponibles : %s", f"{len(hf_train):,}")
    logger.info("Échantillonnage de %s lignes...", f"{number_of_rows:,}")

    sampled_dataset = hf_train.shuffle(seed=RANDOM_STATE).select(
        range(number_of_rows)
    )
    dataframe = sampled_dataset.to_pandas()

    logger.info("Échantillon chargé : %s lignes et %s colonnes.", *dataframe.shape)
    return dataframe


def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Nettoie les noms de colonnes, les labels et les doublons."""
    logger.info("Nettoyage des données...")

    df = df.copy()
    df.columns = df.columns.astype(str).str.strip()

    if "Label" not in df.columns:
        raise ValueError(
            "La colonne 'Label' est introuvable. "
            f"Colonnes disponibles : {df.columns.tolist()}"
        )

    # Supprimer les labels réellement manquants avant leur conversion en texte.
    df = df[df["Label"].notna()].copy()
    df["Label"] = df["Label"].astype(str).str.strip()
    df = df[df["Label"] != ""].copy()

    before = len(df)
    df = df.drop_duplicates().reset_index(drop=True)
    logger.info("Doublons supprimés : %s", f"{before - len(df):,}")

    # Cette cible binaire sert uniquement à l'évaluation.
    # Elle ne sera jamais incluse dans les features du modèle.
    df["target"] = (df["Label"].str.upper() != "BENIGN").astype("int8")

    counts = df["target"].value_counts().sort_index()
    logger.info(
        "Flux normaux : %s | Flux non-BENIGN : %s",
        f"{int(counts.get(0, 0)):,}",
        f"{int(counts.get(1, 0)):,}",
    )

    if df["target"].nunique() < 2:
        raise ValueError(
            "L'échantillon doit contenir des flux BENIGN et non-BENIGN "
            "pour effectuer une évaluation stratifiée."
        )

    return df


def split_dataset(
    df: pd.DataFrame,
    test_size: float,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Sépare les données de développement et de test."""
    logger.info("Séparation développement/test...")

    development_df, test_df = train_test_split(
        df,
        test_size=test_size,
        random_state=RANDOM_STATE,
        stratify=df["target"],
    )

    logger.info("Développement : %s lignes", f"{len(development_df):,}")
    logger.info("Test : %s lignes", f"{len(test_df):,}")
    return development_df, test_df


def prepare_features(
    development_df: pd.DataFrame,
    test_df: pd.DataFrame,
    max_train_normal: int,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, list[str]]:
    """
    Construit X_train à partir des flux BENIGN uniquement.
    Conserve les mêmes colonnes et le même ordre pour le jeu de test.
    """
    logger.info("Sélection et préparation des caractéristiques...")

    normal_train_df = development_df[
        development_df["Label"].str.upper() == "BENIGN"
    ].copy()

    if normal_train_df.empty:
        raise ValueError("Aucun flux BENIGN disponible pour entraîner le modèle.")

    numeric_columns = development_df.select_dtypes(
        include=[np.number]
    ).columns.tolist()
    numeric_columns = [column for column in numeric_columns if column != "target"]

    if not numeric_columns:
        raise ValueError("Aucune caractéristique numérique exploitable trouvée.")

    X_normal_raw = normal_train_df[numeric_columns].replace(
        [np.inf, -np.inf], np.nan
    )

    # Supprimer les colonnes entièrement vides dans les données normales.
    non_empty_columns = X_normal_raw.columns[
        X_normal_raw.notna().any()
    ].tolist()
    X_normal_raw = X_normal_raw[non_empty_columns]

    # Supprimer les colonnes constantes : elles n'apportent pas
    # d'information utile pour distinguer les observations.
    feature_columns = [
        column
        for column in X_normal_raw.columns
        if X_normal_raw[column].nunique(dropna=True) > 1
    ]

    if not feature_columns:
        raise ValueError(
            "Aucune feature variable n'a été trouvée après le nettoyage."
        )

    X_normal = X_normal_raw[feature_columns]

    # Échantillonner uniquement les flux normaux pour l'entraînement.
    if len(X_normal) > max_train_normal:
        X_train = X_normal.sample(
            n=max_train_normal,
            random_state=RANDOM_STATE,
        )
    else:
        X_train = X_normal.copy()

    # Le test contient les flux normaux et non-BENIGN.
    # On lui applique exactement les colonnes retenues pour l'entraînement.
    X_test = test_df[feature_columns].replace(
        [np.inf, -np.inf], np.nan
    )
    y_test = test_df["target"].astype(int)

    logger.info("Nombre de features retenues : %s", len(feature_columns))
    logger.info("Flux normaux pour l'entraînement : %s", f"{len(X_train):,}")
    logger.info("Flux dans le jeu de test : %s", f"{len(X_test):,}")

    return X_train, X_test, y_test, feature_columns


def train_model(
    X_train: pd.DataFrame,
    trees: int,
    contamination: str,
) -> Pipeline:
    """Construit le pipeline et entraîne Isolation Forest."""
    logger.info("Entraînement d'Isolation Forest...")

    pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            (
                "isolation_forest",
                IsolationForest(
                    n_estimators=trees,
                    contamination=contamination,
                    random_state=RANDOM_STATE,
                    n_jobs=-1,
                ),
            ),
        ]
    )

    pipeline.fit(X_train)
    logger.info("Entraînement terminé.")
    return pipeline


def evaluate_model(
    model: Pipeline,
    X_test: pd.DataFrame,
    y_test: pd.Series,
) -> tuple[dict[str, float], np.ndarray, np.ndarray]:
    """Évalue le modèle et retourne les métriques, prédictions et scores."""
    logger.info("Évaluation sur le jeu de test...")

    # Isolation Forest renvoie 1 pour normal et -1 pour anomalie.
    raw_predictions = model.predict(X_test)

    # Conversion vers notre convention d'évaluation :
    # 0 = normal ; 1 = anomalie.
    y_pred = np.where(raw_predictions == -1, 1, 0)

    # Un score élevé indique une observation plus atypique.
    anomaly_scores = -model.decision_function(X_test)

    metrics: dict[str, float] = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision_attack": float(
            precision_score(y_test, y_pred, zero_division=0)
        ),
        "recall_attack": float(
            recall_score(y_test, y_pred, zero_division=0)
        ),
        "f1_attack": float(f1_score(y_test, y_pred, zero_division=0)),
    }

    try:
        metrics["roc_auc"] = float(roc_auc_score(y_test, anomaly_scores))
        metrics["average_precision"] = float(
            average_precision_score(y_test, anomaly_scores)
        )
    except ValueError as error:
        logger.warning("Métriques ROC/PR non calculables : %s", error)

    print("\n" + "=" * 65)
    print("RAPPORT DE CLASSIFICATION")
    print("=" * 65)
    print(
        classification_report(
            y_test,
            y_pred,
            labels=[0, 1],
            target_names=["Normal", "Anomalie"],
            zero_division=0,
        )
    )

    print("MÉTRIQUES")
    for name, value in metrics.items():
        print(f"- {name}: {value:.4f}")

    print("\nMATRICE DE CONFUSION")
    print(
        confusion_matrix(y_test, y_pred, labels=[0, 1])
    )

    logger.info("Anomalies détectées : %s", f"{int((y_pred == 1).sum()):,}")
    logger.info("Flux considérés normaux : %s", f"{int((y_pred == 0).sum()):,}")

    return metrics, y_pred, anomaly_scores


def save_artifacts(
    model: Pipeline,
    feature_columns: list[str],
    metrics: dict[str, float],
    X_train: pd.DataFrame,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    y_pred: np.ndarray,
    trees: int,
    contamination: str,
) -> None:
    """Enregistre le modèle et les fichiers utiles dans le dossier model/."""
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    model_path = MODEL_DIR / "isolation_forest_pipeline.joblib"
    features_path = MODEL_DIR / "feature_columns.json"
    metadata_path = MODEL_DIR / "model_metadata.json"
    metrics_path = MODEL_DIR / "evaluation_metrics.json"
    confusion_path = MODEL_DIR / "confusion_matrix.csv"

    logger.info("Enregistrement des artefacts dans : %s", MODEL_DIR)

    # Le pipeline complet contient l'imputation et Isolation Forest.
    joblib.dump(model, model_path)

    with features_path.open("w", encoding="utf-8") as file:
        json.dump(feature_columns, file, ensure_ascii=False, indent=2)

    metadata: dict[str, Any] = {
        "model_name": "IsolationForest",
        "dataset": DATASET_NAME,
        "training_strategy": "unsupervised_one_class_benign_only",
        "normal_label": "BENIGN",
        "anomaly_output": -1,
        "normal_output": 1,
        "evaluation_normal_value": 0,
        "evaluation_anomaly_value": 1,
        "n_features": len(feature_columns),
        "n_train_normal": int(len(X_train)),
        "n_test": int(len(X_test)),
        "n_test_normal": int((y_test == 0).sum()),
        "n_test_anomaly": int((y_test == 1).sum()),
        "n_estimators": trees,
        "contamination": contamination,
        "random_state": RANDOM_STATE,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "metrics": metrics,
    }

    with metadata_path.open("w", encoding="utf-8") as file:
        json.dump(metadata, file, ensure_ascii=False, indent=2)

    with metrics_path.open("w", encoding="utf-8") as file:
        json.dump(metrics, file, ensure_ascii=False, indent=2)

    matrix = confusion_matrix(y_test, y_pred, labels=[0, 1])
    confusion_df = pd.DataFrame(
        matrix,
        index=["reel_normal", "reel_anomalie"],
        columns=["predit_normal", "predit_anomalie"],
    )
    confusion_df.to_csv(confusion_path, index=True)

    logger.info("Artefacts enregistrés :")
    for path in (
        model_path,
        features_path,
        metadata_path,
        metrics_path,
        confusion_path,
    ):
        logger.info("  - %s", path)


def verify_saved_model(
    X_test: pd.DataFrame,
    feature_columns: list[str],
) -> None:
    """Recharge le modèle sauvegardé et effectue une prédiction de contrôle."""
    model_path = MODEL_DIR / "isolation_forest_pipeline.joblib"
    features_path = MODEL_DIR / "feature_columns.json"

    logger.info("Vérification du chargement du modèle sauvegardé...")

    loaded_model = joblib.load(model_path)
    with features_path.open("r", encoding="utf-8") as file:
        loaded_features = json.load(file)

    sample_input = X_test[loaded_features].head(5)
    sample_output = loaded_model.predict(sample_input)

    interpretations = [
        "Anomalie" if prediction == -1 else "Normal"
        for prediction in sample_output
    ]

    logger.info("Prédictions de vérification : %s", interpretations)
    logger.info("Vérification réussie.")


def main() -> None:
    args = parse_arguments()
    validate_arguments(args)

    logger.info("Démarrage de l'entraînement CIC-IDS2017 / Isolation Forest.")

    df = load_and_sample_dataset(args.max_rows)
    df = clean_dataset(df)

    development_df, test_df = split_dataset(
        df,
        test_size=args.test_size,
    )

    X_train, X_test, y_test, feature_columns = prepare_features(
        development_df,
        test_df,
        max_train_normal=args.max_train_normal,
    )

    model = train_model(
        X_train,
        trees=args.trees,
        contamination=args.contamination,
    )

    metrics, y_pred, _ = evaluate_model(
        model,
        X_test,
        y_test,
    )

    save_artifacts(
        model=model,
        feature_columns=feature_columns,
        metrics=metrics,
        X_train=X_train,
        X_test=X_test,
        y_test=y_test,
        y_pred=y_pred,
        trees=args.trees,
        contamination=args.contamination,
    )

    verify_saved_model(X_test, feature_columns)

    logger.info("Processus terminé avec succès.")


if __name__ == "__main__":
    main()
