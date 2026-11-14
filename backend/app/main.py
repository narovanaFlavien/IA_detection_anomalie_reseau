from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.config import settings
from app.api.v1.router import api_router
from app.ml.model_service import ModelService


@asynccontextmanager
async def lifespan(app: FastAPI):

    print("Starting Network Anomaly Detection API...")

    # Charger le modèle une seule fois au démarrage
    app.state.model_service = ModelService.load(
        model_path=settings.MODEL_PATH,
        features_path=settings.FEATURES_PATH,
        labels_path=settings.LABELS_PATH,
        metadata_path=settings.METADATA_PATH,
    )

    yield

    # Nettoyage à l'arrêt
    app.state.model_service = None

    print("Stopping Network Anomaly Detection API...")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="API for AI-based network traffic anomaly detection",
    lifespan=lifespan,
)

app.include_router(
    api_router,
    prefix=settings.API_V1_PREFIX,
)