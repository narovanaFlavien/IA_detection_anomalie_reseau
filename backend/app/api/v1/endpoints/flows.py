
from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import get_flow_service
from app.ml.feature_mapping import MappingConfigurationError
from app.ml.preprocessing import (
    InvalidFeatureValueError,
    MissingFeatureError,
)
from app.schemas.flow import (
    FlowCreate,
    FlowPredictionResponse,
    FlowBatchCreate,
    FlowBatchResponse,
)
from app.services.flow_service import FlowService


router = APIRouter(prefix="/flows", tags=["Flows"])


def classify_one(
    flow: FlowCreate,
    service: FlowService,
) -> FlowPredictionResponse:

    try:
        return service.predict_flow(flow)

    except MappingConfigurationError as error:
        raise HTTPException(
            status_code=503,
            detail=str(error),
        )

    except (
        MissingFeatureError,
        InvalidFeatureValueError,
    ) as error:
        raise HTTPException(
            status_code=422,
            detail=str(error),
        )


@router.post(
    "",
    response_model=FlowPredictionResponse,
)
def create_flow(
    flow: FlowCreate,
    service: FlowService = Depends(get_flow_service),
):
    return classify_one(flow, service)


@router.post(
    "/batch",
    response_model=FlowBatchResponse,
)
def create_flows_batch(
    payload: FlowBatchCreate,
    service: FlowService = Depends(get_flow_service),
):

    results = []

    for flow in payload.flows:
        result = classify_one(flow, service)
        results.append(result)

    return FlowBatchResponse(
        total=len(results),
        results=results,
    )
