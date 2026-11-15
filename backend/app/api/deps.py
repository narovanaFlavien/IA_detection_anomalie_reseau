
from fastapi import HTTPException, Request

from app.services.flow_service import FlowService


def get_flow_service(request: Request) -> FlowService:

    model_service = getattr(
        request.app.state,
        "model_service",
        None,
    )

    if model_service is None:
        raise HTTPException(
            status_code=503,
            detail="Le modèle IA n'est pas disponible.",
        )

    return FlowService(model_service)
