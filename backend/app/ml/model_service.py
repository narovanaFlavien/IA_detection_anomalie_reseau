
import json
from pathlib import Path

import joblib
import pandas as pd

from app.ml.feature_mapping import map_flow_to_model_features

from app.ml.preprocessing import (
    load_feature_names,
    prepare_input,
)


class ModelService:
    def __init__(
        self,
        model,
        feature_names: list[str],
        labels: list[str],
        metadata: dict,
    ):
        self.model = model
        self.feature_names = feature_names
        self.labels = labels
        self.metadata = metadata

    @classmethod
    def load(
        cls,
        model_path: Path,
        features_path: Path,
        labels_path: Path,
        metadata_path: Path,
    ):
        """
        Charge le pipeline et les fichiers associés.
        Cette méthode est appelée au démarrage de FastAPI.
        """

        # Vérifier la présence des fichiers
        paths = [
            model_path,
            features_path,
            labels_path,
            metadata_path,
        ]

        for path in paths:
            if not path.is_file():
                raise FileNotFoundError(
                    f"Fichier du modèle introuvable : {path}"
                )

        print("Loading Extra Trees model...")

        # Charger le pipeline entraîné
        model = joblib.load(model_path)

        # Charger les caractéristiques
        feature_names = load_feature_names(features_path)

        # Charger les classes
        with open(labels_path, "r", encoding="utf-8") as file:
            labels = json.load(file)

        # Charger les métadonnées
        with open(metadata_path, "r", encoding="utf-8") as file:
            metadata = json.load(file)

        # Vérifications de cohérence
        if len(labels) != 13:
            raise ValueError(
                f"13 classes attendues, {len(labels)} reçues."
            )

        if metadata.get("n_features") != len(feature_names):
            raise ValueError(
                "Incohérence entre les métadonnées et les caractéristiques."
            )

        if hasattr(model, "n_features_in_"):
            if model.n_features_in_ != len(feature_names):
                raise ValueError(
                    "Le nombre de caractéristiques du modèle est incorrect."
                )

        print("Extra Trees model loaded successfully.")

        return cls(
            model=model,
            feature_names=feature_names,
            labels=labels,
            metadata=metadata,
        )

    def predict_one(self, flow: dict) -> dict:
        """
        Reçoit un flow CICFlowMeter brut et effectue
        une classification avec Extra Trees.
        """

        # 1. Convertir les noms CICFlowMeter
        mapped_flow = map_flow_to_model_features(
            flow,
            self.feature_names,
        )

        # 2. Construire le DataFrame dans le bon ordre
        dataframe = prepare_input(
            mapped_flow,
            self.feature_names,
        )

        # 3. Prédiction
        prediction = self.model.predict(dataframe)[0]

        # 4. Confiance
        confidence = None

        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(dataframe)[0]
            confidence = float(max(probabilities))

        return {
            "prediction": str(prediction),
            "confidence": confidence,
            "model_version": self.metadata["model_version"],
        }

