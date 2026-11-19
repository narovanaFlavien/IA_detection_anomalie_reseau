
from app.ml.preprocessing import (
    MissingFeatureError,
)


# Clé : nom de la caractéristique attendu par le modèle
# Valeur : nom de la colonne produite par CICFlowMeter
#
# None signifie que la correspondance n'est pas encore validée.

FEATURE_MAPPING: dict[str, str | None] = {
    "Destination Port": "Dst Port",
    "Flow Duration": "Flow Duration",
    "Total Fwd Packets": "Total Fwd Packet",
    "Total Backward Packets": "Total Bwd packets",
    "Total Length of Fwd Packets": "Total Length of Fwd Packet",
    "Total Length of Bwd Packets": "Total Length of Bwd Packet",
    "Fwd Packet Length Max": "Fwd Packet Length Max",
    "Fwd Packet Length Min": "Fwd Packet Length Min",
    "Fwd Packet Length Mean": "Fwd Packet Length Mean",
    "Fwd Packet Length Std": "Fwd Packet Length Std",
    "Bwd Packet Length Max": "Bwd Packet Length Max",
    "Bwd Packet Length Min": "Bwd Packet Length Min",
    "Bwd Packet Length Mean": "Bwd Packet Length Mean",
    "Bwd Packet Length Std": "Bwd Packet Length Std",
    "Flow Bytes/s": "Flow Bytes/s",
    "Flow Packets/s": "Flow Packets/s",
    "Flow IAT Mean": "Flow IAT Mean",
    "Flow IAT Std": "Flow IAT Std",
    "Flow IAT Max": "Flow IAT Max",
    "Flow IAT Min": "Flow IAT Min",
    "Fwd IAT Total": "Fwd IAT Total",
    "Fwd IAT Mean": "Fwd IAT Mean",
    "Fwd IAT Std": "Fwd IAT Std",
    "Fwd IAT Max": "Fwd IAT Max",
    "Fwd IAT Min": "Fwd IAT Min",
    "Bwd IAT Total": "Bwd IAT Total",
    "Bwd IAT Mean": "Bwd IAT Mean",
    "Bwd IAT Std": "Bwd IAT Std",
    "Bwd IAT Max": "Bwd IAT Max",
    "Bwd IAT Min": "Bwd IAT Min",
    "Fwd PSH Flags": "Fwd PSH Flags",
    "Fwd URG Flags": "Fwd URG Flags",
    "Fwd Header Length": "Fwd Header Length",
    "Bwd Header Length": "Bwd Header Length",
    "Fwd Packets/s": "Fwd Packets/s",
    "Bwd Packets/s": "Bwd Packets/s",
    "Min Packet Length": "Packet Length Min",
    "Max Packet Length": "Packet Length Max",
    "Packet Length Mean": "Packet Length Mean",
    "Packet Length Std": "Packet Length Std",
    "Packet Length Variance": "Packet Length Variance",
    "FIN Flag Count": "FIN Flag Count",
    "SYN Flag Count": "SYN Flag Count",
    "RST Flag Count": "RST Flag Count",
    "PSH Flag Count": "PSH Flag Count",
    "ACK Flag Count": "ACK Flag Count",
    "URG Flag Count": "URG Flag Count",

    # À confirmer : CWE Flag Count et cwr_flag_count
    # ne sont pas considérés équivalents sans preuve.
    "CWE Flag Count": "CWR Flag Count",

    "ECE Flag Count": "ECE Flag Count",
    "Down/Up Ratio": "Down/Up Ratio",
    "Average Packet Size": "Average Packet Size",
    "Avg Fwd Segment Size": "Fwd Segment Size Avg",
    "Avg Bwd Segment Size": "Bwd Segment Size Avg",

    # Alias provisoire : le CSV live ne contient qu'une colonne
    # fwd_header_len. À vérifier avec les données d'entraînement.
    "Fwd Header Length.1": "Fwd Header Length",

    "Subflow Fwd Packets": "Subflow Fwd Packets",
    "Subflow Fwd Bytes": "Subflow Fwd Bytes",
    "Subflow Bwd Packets": "Subflow Bwd Packets",
    "Subflow Bwd Bytes": "Subflow Bwd Bytes",
    "Init_Win_bytes_forward": "FWD Init Win Bytes",
    "Init_Win_bytes_backward": "Bwd Init Win Bytes",
    "act_data_pkt_fwd": "Fwd Act Data Pkts",
    "min_seg_size_forward": "Fwd Seg Size Min",
    "Active Mean": "Active Mean",
    "Active Std": "Active Std",
    "Active Max": "Active Max",
    "Active Min": "Active Min",
    "Idle Mean": "Idle Mean",
    "Idle Std": "Idle Std",
    "Idle Max": "Idle Max",
    "Idle Min": "Idle Min",
}


class MappingConfigurationError(RuntimeError):
    """Une correspondance du mapping n'est pas configurée."""


def map_flow_to_model_features(
    flow: dict,
    feature_names: list[str],
) -> dict:
    """
    Convertit un flow CICFlowMeter vers les noms
    et l'ordre attendus par le modèle.
    """

    unresolved = [
        feature
        for feature in feature_names
        if feature not in FEATURE_MAPPING
        or FEATURE_MAPPING[feature] is None
    ]

    if unresolved:
        raise MappingConfigurationError(
            f"Mapping non confirmé pour : {unresolved}"
        )

    missing_columns = [
        FEATURE_MAPPING[feature]
        for feature in feature_names
        if FEATURE_MAPPING[feature] not in flow
    ]

    if missing_columns:
        raise MissingFeatureError(
            f"Colonnes CICFlowMeter manquantes : {missing_columns}"
        )

    return {
        feature: flow[FEATURE_MAPPING[feature]]
        for feature in feature_names
    }
