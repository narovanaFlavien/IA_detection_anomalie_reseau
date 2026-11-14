from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/health")
async def health_check(request: Request):

    model_service = getattr(
        request.app.state,
        "model_service",
        None,
    )

    return {
        "status": "ok",
        "message": "Network Anomaly Detection API is running",
        "model_loaded": model_service is not None,
    }
