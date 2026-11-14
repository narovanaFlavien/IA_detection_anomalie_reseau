from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


# Dossier racine du backend
BASE_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    APP_NAME: str = "Network Anomaly Detection API"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    API_V1_PREFIX: str = "/api/v1"

    # Fichiers du modèle IA
    MODEL_PATH: Path = (
        BASE_DIR / "app" / "ml" / "artifacts"
        / "supervised_v1_pipeline.joblib"
    )

    FEATURES_PATH: Path = (
        BASE_DIR / "app" / "ml" / "artifacts"
        / "supervised_v1_features.json"
    )

    LABELS_PATH: Path = (
        BASE_DIR / "app" / "ml" / "artifacts"
        / "supervised_v1_labels.json"
    )

    METADATA_PATH: Path = (
        BASE_DIR / "app" / "ml" / "artifacts"
        / "supervised_v1_metadata.json"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
