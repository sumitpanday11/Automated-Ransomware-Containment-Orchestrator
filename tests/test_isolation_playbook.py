import pytest

from app.edr.mock import MockEDRProvider
from app.edr.service import EDRService
from app.response.isolation_playbook import (
    HostIsolationPlaybook,
)
from app.response.decision_engine import ResponseAction


def create_service_with_mock() -> EDRService:
    service = EDRService()
    service.provider = MockEDRProvider()
    return service


def test_mock_edr_isolates_host():
    provider = MockEDRProvider()

    assert provider.authenticate() is True
    assert provider.isolate_host("workstation-01") is True
    assert provider.get_isolation_status("workstation-01") == "isolated"


def test_mock_edr_host_is_not_isolated_initially():
    provider = MockEDRProvider()

    provider.authenticate()

    assert provider.get_isolation_status("workstation-01") == "not_isolated"


def test_isolation_playbook_success():
    service = create_service_with_mock()
    playbook = HostIsolationPlaybook(
        edr_service=service,
        max_retries=3,
    )

    result = playbook.isolate("workstation-01")

    assert result.success is True
    assert result.status == "isolated"
    assert result.attempts == 1
    assert len(result.audit_log) == 1
    assert result.audit_log[0].success is True


def test_isolation_playbook_creates_audit_log():
    service = create_service_with_mock()
    playbook = HostIsolationPlaybook(edr_service=service)

    result = playbook.isolate("server-01")

    entry = result.audit_log[0]

    assert entry.hostname == "server-01"
    assert entry.action == "isolate_host"
    assert entry.attempt == 1
    assert entry.success is True
    assert entry.status == "isolated"


def test_isolation_playbook_retries_after_failure(monkeypatch):
    service = create_service_with_mock()

    attempts = 0

    def failing_then_success(hostname: str) -> bool:
        nonlocal attempts
        attempts += 1

        if attempts < 3:
            return False

        service.provider._isolated_hosts.add(hostname)
        return True

    monkeypatch.setattr(
        service.provider,
        "isolate_host",
        failing_then_success,
    )

    playbook = HostIsolationPlaybook(
        edr_service=service,
        max_retries=3,
    )

    result = playbook.isolate("workstation-01")

    assert result.success is True
    assert result.attempts == 3
    assert len(result.audit_log) == 3


def test_isolation_playbook_stops_after_max_retries(monkeypatch):
    service = create_service_with_mock()

    attempts = 0

    def always_fail(hostname: str) -> bool:
        nonlocal attempts
        attempts += 1
        return False

    monkeypatch.setattr(
        service.provider,
        "isolate_host",
        always_fail,
    )

    playbook = HostIsolationPlaybook(
        edr_service=service,
        max_retries=3,
    )

    result = playbook.isolate("workstation-01")

    assert result.success is False
    assert result.attempts == 3
    assert len(result.audit_log) == 3
    assert all(entry.success is False for entry in result.audit_log)


def test_empty_hostname_is_rejected():
    service = create_service_with_mock()
    playbook = HostIsolationPlaybook(edr_service=service)

    with pytest.raises(ValueError, match="hostname"):
        playbook.isolate("")


def test_invalid_retry_count_is_rejected():
    service = create_service_with_mock()

    with pytest.raises(ValueError, match="max_retries"):
        HostIsolationPlaybook(
            edr_service=service,
            max_retries=0,
        )


def test_isolation_action_name_matches_response_action():
    assert ResponseAction.ISOLATE_HOST.value == "isolate_host"
