from app.forensics.collectors.host import HostEvidenceCollector


def test_host_collector_metadata():
    collector = HostEvidenceCollector()

    assert collector.name == "host_evidence_collector"
    assert collector.evidence_type == "host"


def test_host_collector_collects_all_evidence_categories():
    collector = HostEvidenceCollector()

    evidence = collector.collect("workstation-01")

    assert evidence.collector == "host_evidence_collector"
    assert evidence.evidence_type == "host"
    assert evidence.data["hostname"] == "workstation-01"

    assert "running_processes" in evidence.data
    assert "network_connections" in evidence.data
    assert "logged_in_users" in evidence.data
    assert "file_metadata" in evidence.data
    assert "system_information" in evidence.data
    assert "suspicious_processes" in evidence.data


def test_running_processes_have_expected_fields():
    collector = HostEvidenceCollector()

    evidence = collector.collect("workstation-01")
    processes = evidence.data["running_processes"]

    assert isinstance(processes, list)

    if processes:
        process = processes[0]

        assert "pid" in process
        assert "name" in process
        assert "username" in process
        assert "create_time" in process


def test_network_connections_have_expected_fields():
    collector = HostEvidenceCollector()

    evidence = collector.collect("workstation-01")
    connections = evidence.data["network_connections"]

    assert isinstance(connections, list)

    if connections:
        connection = connections[0]

        assert "family" in connection
        assert "type" in connection
        assert "local_address" in connection
        assert "remote_address" in connection
        assert "status" in connection
        assert "pid" in connection


def test_system_information_is_collected():
    collector = HostEvidenceCollector()

    evidence = collector.collect("workstation-01")
    system_info = evidence.data["system_information"]

    assert system_info["system"]
    assert system_info["release"]
    assert system_info["machine"]
    assert system_info["python_version"]
    assert system_info["cpu_count"] is not None


def test_file_metadata_is_a_list():
    collector = HostEvidenceCollector()

    evidence = collector.collect("workstation-01")

    assert isinstance(evidence.data["file_metadata"], list)


def test_suspicious_process_detection():
    collector = HostEvidenceCollector()

    processes = [
        {
            "pid": 100,
            "name": "powershell.exe",
            "username": "alice",
            "create_time": 1234567890,
            "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "cmdline": ["powershell.exe"],
        },
        {
            "pid": 200,
            "name": "notepad.exe",
            "username": "alice",
            "create_time": 1234567890,
            "exe": r"C:\Windows\System32\notepad.exe",
            "cmdline": ["notepad.exe"],
        },
    ]

    suspicious = collector._identify_suspicious_processes(processes)

    assert len(suspicious) == 1
    assert suspicious[0]["name"] == "powershell.exe"


def test_empty_hostname_is_rejected():
    collector = HostEvidenceCollector()

    try:
        collector.collect("")
        assert False
    except ValueError as exc:
        assert str(exc) == "hostname must not be empty"