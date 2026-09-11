from app.edr.config import EDRSettings
from app.edr.service import EDRService


def test_edr_service_uses_mock_provider():
    settings = EDRSettings(provider="mock")
    service = EDRService(settings)

    assert service.authenticate() is True

    alerts = service.fetch_alerts()

    assert len(alerts) == 2
    assert alerts[0]["alert_id"] == "MOCK-001"