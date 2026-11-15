
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class FlowCreate(BaseModel):
    """
    Structure d'un flow reçu depuis CICFlowMeter.

    Les champs supplémentaires sont autorisés car
    CICFlowMeter produit de nombreuses caractéristiques.
    """

    model_config = ConfigDict(extra="allow")

    src_ip: str | None = None
    dst_ip: str | None = None

    src_port: int | None = None
    dst_port: int | None = None

    protocol: int | None = None
    timestamp: datetime | str | None = None


class FlowPredictionResponse(BaseModel):
    flow_id: UUID

    src_ip: str | None = None
    dst_ip: str | None = None

    src_port: int | None = None
    dst_port: int | None = None

    protocol: int | None = None

    prediction: str
    confidence: float | None = None
    model_version: str


class FlowBatchCreate(BaseModel):
    flows: list[FlowCreate] = Field(
        min_length=1,
        max_length=500,
    )


class FlowBatchResponse(BaseModel):
    total: int
    results: list[FlowPredictionResponse]
