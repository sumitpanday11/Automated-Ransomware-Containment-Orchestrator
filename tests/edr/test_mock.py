from app.edr.mock import MockEDRProvider


def test_mock_edr_authentication():
    provider = MockEDRProvider()

    assert provider.authenticate() is True


def test_mock_edr_fetches_alerts():
    provider = MockEDRProvider()

    provider.authenticate()
    alerts = provider.fetch_alerts()

    assert len(alerts) == 2
    assert alerts[0]["alert_id"] == "MOCK-001"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["alert_type"] == "ransomware_behavior"


def test_mock_edr_requires_authentication():
    provider = MockEDRProvider()

    try:
        provider.fetch_alerts()
        assert False, "Expected authentication error"
    except RuntimeError as exc:
        assert str(exc) == "EDR provider is not authenticated"