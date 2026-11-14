from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.config import settings
from app.api.v1.router import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialisation des ressources au démarrage
    print("Starting Network Anomaly Detection API...")

    yield

    # Nettoyage des ressources à l'arrêt
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