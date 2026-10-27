import pytest
from fastapi import status
from app.models.all_models import UserRole
from app.core.security import create_access_token


def test_fetch_indicators_queue_unauthenticated(client):
    """Ensures unauthenticated traffic hits boundary locks (NFR-06 compliance)."""
    response = client.get("/api/v1/indicators")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_fetch_indicators_queue_authorized(
    client, mock_soc_analyst, static_threat_dataset
):
    """Validates prioritized data processing arrays for authorized team profiles."""
    # Generate explicit test security token mapping to analyst access roles
    token = create_access_token(data={"sub": mock_soc_analyst.username})
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/api/v1/indicators", headers=headers)

    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    # Confirm structural arrays match values injected by setup fixtures
    assert len(data) >= 2
    assert data[0]["value"] in ["185.220.101.4", "malicious-phishing-domain.top"]
