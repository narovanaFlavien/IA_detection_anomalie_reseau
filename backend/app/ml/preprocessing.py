import json
from pathlib import Path

import numpy as np
import pandas as pd


class MissingFeatureError(ValueError):
    """Une caractéristique obligatoire est absente."""


class InvalidFeatureValueError(ValueError):
    """Une caractéristique contient une valeur non numérique."""


def load_feature_names(features_path: Path) -> list[str]:

    with open(features_path, "r", encoding="utf-8") as file:
        features = json.load(file)

    if not isinstance(features, list):
        raise ValueError("Le fichier des caractéristiques doit contenir une liste.")

    if len(features) != 70:
        raise ValueError(
            f"70 caractéristiques attendues, {len(features)} reçues."
        )

    if len(set(features)) != len(features):
        raise ValueError(
            "Le fichier contient des noms de caractéristiques dupliqués."
        )

    return features


def prepare_input(
    mapped_flow: dict,
    feature_names: list[str],
) -> pd.DataFrame:
    """
    Construit un DataFrame contenant exactement les caractéristiques
    attendues par le modèle, dans leur ordre d'entraînement.
    """

    missing = [
        feature
        for feature in feature_names
        if feature not in mapped_flow
    ]

    if missing:
        raise MissingFeatureError(
            f"Caractéristiques manquantes : {missing}"
        )

    values = []

    for feature in feature_names:

        raw_value = mapped_flow[feature]

        # Une valeur absente peut être traitée comme NaN.
        # Le pipeline doit disposer d'un mécanisme d'imputation.
        if raw_value is None or raw_value == "":
            values.append(np.nan)
            continue

        try:
            numeric_value = float(raw_value)
        except (TypeError, ValueError):
            raise InvalidFeatureValueError(
                f"La caractéristique '{feature}' "
                f"contient une valeur non numérique : {raw_value}"
            )

        # Le pipeline peut traiter NaN avec son imputer.
        # On ne transmet pas +inf ou -inf au modèle.
        if not np.isfinite(numeric_value):
            numeric_value = np.nan

        values.append(numeric_value)

    return pd.DataFrame(
        [values],
        columns=feature_names,
    )
