
from app.ml.preprocessing import (
    MissingFeatureError,
)


# Clé : nom de la caractéristique attendu par le modèle
# Valeur : nom de la colonne produite par CICFlowMeter
#
# None signifie que la correspondance n'est pas encore validée.

FEATURE_MAPPING: dict[str, str | None] = {
    "Destination Port": "dst_port",
    "Flow Duration": "flow_duration",
    "Total Fwd Packets": "tot_fwd_pkts",
    "Total Backward Packets": "tot_bwd_pkts",
    "Total Length of Fwd Packets": "totlen_fwd_pkts",
    "Total Length of Bwd Packets": "totlen_bwd_pkts",
    "Fwd Packet Length Max": "fwd_pkt_len_max",
    "Fwd Packet Length Min": "fwd_pkt_len_min",
    "Fwd Packet Length Mean": "fwd_pkt_len_mean",
    "Fwd Packet Length Std": "fwd_pkt_len_std",
    "Bwd Packet Length Max": "bwd_pkt_len_max",
    "Bwd Packet Length Min": "bwd_pkt_len_min",
    "Bwd Packet Length Mean": "bwd_pkt_len_mean",
    "Bwd Packet Length Std": "bwd_pkt_len_std",
    "Flow Bytes/s": "flow_byts_s",
    "Flow Packets/s": "flow_pkts_s",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Flow IAT Min": "flow_iat_min",
    "Fwd IAT Total": "fwd_iat_tot",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Fwd IAT Std": "fwd_iat_std",
    "Fwd IAT Max": "fwd_iat_max",
    "Fwd IAT Min": "fwd_iat_min",
    "Bwd IAT Total": "bwd_iat_tot",
    "Bwd IAT Mean": "bwd_iat_mean",
    "Bwd IAT Std": "bwd_iat_std",
    "Bwd IAT Max": "bwd_iat_max",
    "Bwd IAT Min": "bwd_iat_min",
    "Fwd PSH Flags": "fwd_psh_flags",
    "Fwd URG Flags": "fwd_urg_flags",
    "Fwd Header Length": "fwd_header_len",
    "Bwd Header Length": "bwd_header_len",
    "Fwd Packets/s": "fwd_pkts_s",
    "Bwd Packets/s": "bwd_pkts_s",
    "Min Packet Length": "pkt_len_min",
    "Max Packet Length": "pkt_len_max",
    "Packet Length Mean": "pkt_len_mean",
    "Packet Length Std": "pkt_len_std",
    "Packet Length Variance": "pkt_len_var",
    "FIN Flag Count": "fin_flag_cnt",
    "SYN Flag Count": "syn_flag_cnt",
    "RST Flag Count": "rst_flag_cnt",
    "PSH Flag Count": "psh_flag_cnt",
    "ACK Flag Count": "ack_flag_cnt",
    "URG Flag Count": "urg_flag_cnt",

    # À confirmer : CWE Flag Count et cwr_flag_count
    # ne sont pas considérés équivalents sans preuve.
    "CWE Flag Count": "cwr_flag_count",

    "ECE Flag Count": "ece_flag_cnt",
    "Down/Up Ratio": "down_up_ratio",
    "Average Packet Size": "pkt_size_avg",
    "Avg Fwd Segment Size": "fwd_seg_size_avg",
    "Avg Bwd Segment Size": "bwd_seg_size_avg",

    # Alias provisoire : le CSV live ne contient qu'une colonne
    # fwd_header_len. À vérifier avec les données d'entraînement.
    "Fwd Header Length.1": "fwd_header_len",

    "Subflow Fwd Packets": "subflow_fwd_pkts",
    "Subflow Fwd Bytes": "subflow_fwd_byts",
    "Subflow Bwd Packets": "subflow_bwd_pkts",
    "Subflow Bwd Bytes": "subflow_bwd_byts",
    "Init_Win_bytes_forward": "init_fwd_win_byts",
    "Init_Win_bytes_backward": "init_bwd_win_byts",
    "act_data_pkt_fwd": "fwd_act_data_pkts",
    "min_seg_size_forward": "fwd_seg_size_min",
    "Active Mean": "active_mean",
    "Active Std": "active_std",
    "Active Max": "active_max",
    "Active Min": "active_min",
    "Idle Mean": "idle_mean",
    "Idle Std": "idle_std",
    "Idle Max": "idle_max",
    "Idle Min": "idle_min",
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
