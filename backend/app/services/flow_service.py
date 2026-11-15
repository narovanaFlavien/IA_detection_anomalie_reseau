
from uuid import uuid4

from app.ml.model_service import ModelService
# from tests.test_flows import FakeModelService
from app.schemas.flow import (
    FlowCreate,
    FlowPredictionResponse,
)


class FlowService:

    def __init__(self, model_service: ModelService):
        self.model_service = model_service

    def predict_flow(
        self,
        flow: FlowCreate,
    ) -> FlowPredictionResponse:

        # Convertir le schéma Pydantic en dictionnaire
        flow_data = flow.model_dump()

        # Demander au modèle de classifier le flow
        prediction = self.model_service.predict_one(flow_data)

        # Construire la réponse
        return FlowPredictionResponse(
            flow_id=uuid4(),

            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,

            src_port=flow.src_port,
            dst_port=flow.dst_port,

            protocol=flow.protocol,

            prediction=prediction["prediction"],
            confidence=prediction["confidence"],
            model_version=prediction["model_version"],
        )

    def predict_batch(
        self,
        flows: list[FlowCreate],
    ) -> list[FlowPredictionResponse]:

        results = []

        for flow in flows:
            result = self.predict_flow(flow)
            results.append(result)

        return results
