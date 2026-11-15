
from app.core.config import settings
from app.ml.model_service import ModelService


def test_model_prediction():

    service = ModelService.load(
        model_path=settings.MODEL_PATH,
        features_path=settings.FEATURES_PATH,
        labels_path=settings.LABELS_PATH,
        metadata_path=settings.METADATA_PATH,
    )

    # Données artificielles : 70 valeurs nulles
    # Ce test vérifie le fonctionnement technique,
    # pas la qualité de la classification.
    sample_flow = {
        feature: 0
        for feature in service.feature_names
    }

    result = service.predict_one(sample_flow)

    assert result["prediction"] in service.labels
    assert result["model_version"] == "supervised_v1"

    if result["confidence"] is not None:
        assert 0 <= result["confidence"] <= 1
