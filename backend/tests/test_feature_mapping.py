
import json

import pytest

from app.ml.feature_mapping import (
    FEATURE_MAPPING,
    MappingConfigurationError,
    map_flow_to_model_features,
)


def test_mapping_contains_exact_model_features():

    with open(
        "app/ml/artifacts/supervised_v1_features.json",
        encoding="utf-8",
    ) as file:
        features = json.load(file)

    assert len(features) == 70
    assert list(FEATURE_MAPPING.keys()) == features


def test_header_length_alias_is_explicit():

    assert (
        FEATURE_MAPPING["Fwd Header Length"]
        == "fwd_header_len"
    )

    assert (
        FEATURE_MAPPING["Fwd Header Length.1"]
        == "fwd_header_len"
    )


def test_cwe_mapping_is_not_assumed():

    assert FEATURE_MAPPING["CWE Flag Count"] is not None

    with pytest.raises(MappingConfigurationError):
        map_flow_to_model_features(
            {},
            list(FEATURE_MAPPING.keys()),
        )
