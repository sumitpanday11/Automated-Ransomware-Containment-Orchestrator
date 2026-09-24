import platform
from pathlib import Path
from typing import Any

import psutil

from app.forensics.collector import Evidence, EvidenceCollector, create_evidence


class HostEvidenceCollector(EvidenceCollector):
    """Collect safe, read-only host forensic information."""

    SUSPICIOUS_PROCESS_NAMES = {
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
    }

    @property
    def name(self) -> str:
        return "host_evidence_collector"

    @property
    def evidence_type(self) -> str:
        return "host"

    def collect(self, hostname: str) -> Evidence:
        """Collect safe forensic information from a host."""

        if not hostname.strip():
            raise ValueError("hostname must not be empty")

        processes = self._collect_processes()

        data: dict[str, Any] = {
            "hostname": hostname,
            "running_processes": processes,
            "network_connections": self._collect_network_connections(),
            "logged_in_users": self._collect_logged_in_users(),
            "file_metadata": self._collect_file_metadata(),
            "system_information": self._collect_system_information(),
            "suspicious_processes": self._identify_suspicious_processes(
                processes
            ),
        }

        return create_evidence(
            collector=self.name,
            evidence_type=self.evidence_type,
            data=data,
        )

    def _collect_processes(self) -> list[dict[str, Any]]:
        """Collect basic read-only information about running processes."""

        processes: list[dict[str, Any]] = []

        for process in psutil.process_iter(
            ["pid", "name", "username", "create_time", "exe", "cmdline"]
        ):
            try:
                info = process.info

                processes.append(
                    {
                        "pid": info.get("pid"),
                        "name": info.get("name"),
                        "username": info.get("username"),
                        "create_time": info.get("create_time"),
                        "exe": info.get("exe"),
                        "cmdline": info.get("cmdline"),
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return processes

    def _collect_network_connections(self) -> list[dict[str, Any]]:
        """Collect active network connection metadata."""

        connections: list[dict[str, Any]] = []

        try:
            system_connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            return connections

        for connection in system_connections:
            local_address = None
            remote_address = None

            if connection.laddr:
                local_address = {
                    "ip": connection.laddr.ip,
                    "port": connection.laddr.port,
                }

            if connection.raddr:
                remote_address = {
                    "ip": connection.raddr.ip,
                    "port": connection.raddr.port,
                }

            connections.append(
                {
                    "family": str(connection.family),
                    "type": str(connection.type),
                    "local_address": local_address,
                    "remote_address": remote_address,
                    "status": connection.status,
                    "pid": connection.pid,
                }
            )

        return connections

    def _collect_logged_in_users(self) -> list[dict[str, Any]]:
        """Collect currently logged-in user metadata."""

        users: list[dict[str, Any]] = []

        try:
            logged_in_users = psutil.users()
        except psutil.AccessDenied:
            return users

        for user in logged_in_users:
            users.append(
                {
                    "name": user.name,
                    "terminal": user.terminal,
                    "host": user.host,
                    "started": user.started,
                }
            )

        return users

    def _collect_file_metadata(self) -> list[dict[str, Any]]:
        """Collect metadata for a small set of relevant system files."""

        candidate_paths = [
            Path("C:/Windows/System32/cmd.exe"),
            Path("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"),
        ]

        metadata: list[dict[str, Any]] = []

        for path in candidate_paths:
            try:
                if not path.exists() or not path.is_file():
                    continue

                stat = path.stat()

                metadata.append(
                    {
                        "path": str(path),
                        "size": stat.st_size,
                        "modified_time": stat.st_mtime,
                        "created_time": stat.st_ctime,
                    }
                )
            except (OSError, PermissionError):
                continue

        return metadata

    def _collect_system_information(self) -> dict[str, Any]:
        """Collect basic read-only system information."""

        return {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "cpu_count": psutil.cpu_count(),
            "memory_total": psutil.virtual_memory().total,
        }

    def _identify_suspicious_processes(
        self,
        processes: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Identify processes matching predefined suspicious names."""

        suspicious: list[dict[str, Any]] = []

        for process in processes:
            name = process.get("name")

            if isinstance(name, str) and name.lower() in self.SUSPICIOUS_PROCESS_NAMES:
                suspicious.append(process)

        return suspicious