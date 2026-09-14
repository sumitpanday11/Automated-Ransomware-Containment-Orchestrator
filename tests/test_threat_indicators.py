from app.edr.threat_indicators import extract_threat_indicators


def test_extract_threat_indicators():
    alert = {
        "hostname": "WIN-TEST-01",
        "source_ip": "192.168.1.50",
        "username": "admin",
        "process_name": "powershell.exe",
        "process_hash": "abc123sha256",
        "file_path": "C:\\Windows\\Temp\\malware.exe",
        "command_line": "powershell.exe -enc malicious",
        "parent_process": "explorer.exe",
        "severity": "high",
        "detection_name": "Suspicious PowerShell Activity",
        "mitre_technique": "T1059.001",
    }

    indicators = extract_threat_indicators(alert)

    assert indicators["hostname"] == "WIN-TEST-01"
    assert indicators["ip"] == "192.168.1.50"
    assert indicators["username"] == "admin"
    assert indicators["process_name"] == "powershell.exe"
    assert indicators["process_hash"] == "abc123sha256"
    assert indicators["file_path"] == "C:\\Windows\\Temp\\malware.exe"
    assert indicators["command_line"] == "powershell.exe -enc malicious"
    assert indicators["parent_process"] == "explorer.exe"
    assert indicators["severity"] == "high"
    assert indicators["detection_name"] == "Suspicious PowerShell Activity"
    assert indicators["mitre_technique"] == "T1059.001"


def test_extract_nested_edr_indicators():
    alert = {
        "host": {
            "hostname": "WIN-ENDPOINT",
            "ip": "10.0.0.25",
        },
        "user": {
            "username": "sumit",
        },
        "process": {
            "name": "cmd.exe",
            "sha256": "hash456",
            "file_path": "C:\\Temp\\test.exe",
            "command_line": "cmd.exe /c whoami",
            "parent_name": "explorer.exe",
        },
        "severity": "critical",
        "detection": {
            "name": "Malicious Command Execution",
            "mitre_technique": "T1059",
        },
    }

    indicators = extract_threat_indicators(alert)

    assert indicators["hostname"] == "WIN-ENDPOINT"
    assert indicators["ip"] == "10.0.0.25"
    assert indicators["username"] == "sumit"
    assert indicators["process_name"] == "cmd.exe"
    assert indicators["process_hash"] == "hash456"
    assert indicators["file_path"] == "C:\\Temp\\test.exe"
    assert indicators["command_line"] == "cmd.exe /c whoami"
    assert indicators["parent_process"] == "explorer.exe"
    assert indicators["severity"] == "critical"
    assert indicators["detection_name"] == "Malicious Command Execution"
    assert indicators["mitre_technique"] == "T1059"
