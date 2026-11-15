
import pytest

from fastapi.testclient import TestClient

from app.main import app
from app.api.deps import get_flow_service
from app.services.flow_service import FlowService


class FakeModelService:

    def predict_one(self, flow: dict) -> dict:
        return {
            "prediction": "BENIGN",
            "confidence": 0.95,
            "model_version": "supervised_v1",
        }


@pytest.fixture
def client():

    app.dependency_overrides[get_flow_service] = (
        lambda: FlowService(FakeModelService())
    )

    # Ne pas entrer dans le contexte lifespan ici :
    # nous voulons éviter de charger le vrai modèle.
    yield TestClient(app)

    app.dependency_overrides.clear()


def sample_flow():

    return {
        "src_ip": "192.168.213.173",
        "dst_ip": "104.18.39.21",
        "src_port": 9182,
        "dst_port": 443,
        "protocol": 6,
        "timestamp": "2026-11-13T22:10:18",
        "flow_duration": 90.516268,
        "tot_fwd_pkts": 135,
        "tot_bwd_pkts": 137,
        "flow_byts_s": 2030.485835,
        "syn_flag_cnt": 0,
    }


def test_create_single_flow(client):

    response = client.post(
        "/api/v1/flows",
        json=sample_flow(),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["prediction"] == "BENIGN"
    assert data["confidence"] == 0.95
    assert data["model_version"] == "supervised_v1"
    assert data["src_ip"] == "192.168.213.173"
    assert "flow_id" in data


def test_create_batch_flows(client):

    payload = {
        "flows": [
            sample_flow(),
            sample_flow(),
        ]
    }

    response = client.post(
        "/api/v1/flows/batch",
        json=payload,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 2
    assert len(data["results"]) == 2

    for result in data["results"]:
        assert result["prediction"] == "BENIGN"
