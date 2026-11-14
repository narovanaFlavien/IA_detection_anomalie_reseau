
import json
from pathlib import Path

import pandas as pd


def load_feature_names(features_path: Path) -> list[str]:
    """
    Charge la liste ordonnée des caractéristiques attendues
    par le modèle.
    """
    with open(features_path, "r", encoding="utf-8") as file:
        features = json.load(file)

    if not isinstance(features, list):
        raise ValueError("Le fichier des caractéristiques doit contenir une liste.")

    if len(features) != 70:
        raise ValueError(
            f"70 caractéristiques attendues, {len(features)} reçues."
        )

    return features


def prepare_input(
    flow: dict,
    feature_names: list[str],
) -> pd.DataFrame:
    """
    Transforme un dictionnaire de caractéristiques en DataFrame
    respectant l'ordre attendu par le modèle.
    """

    missing_features = [
        name for name in feature_names
        if name not in flow
    ]

    if missing_features:
        raise ValueError(
            f"Caractéristiques manquantes : {missing_features}"
        )

    # Construire une seule ligne avec les 70 caractéristiques
    data = {
        name: flow[name]
        for name in feature_names
    }

    dataframe = pd.DataFrame(
        [data],
        columns=feature_names,
    )

    # Conversion des valeurs en données numériques
    dataframe = dataframe.apply(
        pd.to_numeric,
        errors="coerce",
    )

    # Remplacer les valeurs infinies par NaN
    dataframe = dataframe.replace(
        [float("inf"), float("-inf")],
        float("nan"),
    )

    return dataframe
