from typing import Any


def extract_threat_indicators(alert: dict[str, Any]) -> dict[str, Any]:
    process = alert.get("process") or {}
    host = alert.get("host") or {}
    user = alert.get("user") or {}
    detection = alert.get("detection") or {}

    return {
        "hostname": host.get("hostname") or alert.get("hostname"),
        "ip": host.get("ip") or alert.get("source_ip") or alert.get("ip"),
        "username": user.get("username") or alert.get("username"),
        "process_name": process.get("name") or alert.get("process_name"),
        "process_hash": (
            process.get("sha256")
            or process.get("hash")
            or alert.get("process_hash")
        ),
        "file_path": process.get("file_path") or alert.get("file_path"),
        "command_line": process.get("command_line") or alert.get("command_line"),
        "parent_process": (
            process.get("parent_name")
            or process.get("parent_process")
            or alert.get("parent_process")
        ),
        "severity": alert.get("severity"),
        "detection_name": (
            detection.get("name")
            or alert.get("detection_name")
            or alert.get("threat")
        ),
        "mitre_technique": (
            detection.get("mitre_technique")
            or alert.get("mitre_technique")
            or alert.get("mitre")
        ),
    }
