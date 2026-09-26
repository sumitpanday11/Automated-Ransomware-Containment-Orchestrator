from typing import Any

from app.forensics.memory.adapter import (
    MemoryAcquisitionAdapter,
    MemoryEvidence,
    create_memory_evidence,
)


class MockMemoryAcquisitionAdapter(MemoryAcquisitionAdapter):
    """Safe mock adapter for memory acquisition testing."""

    def __init__(
        self,
        acquisition_tool: str = "mock-memory-acquisition",
        image_reference: str = "evidence/memory/workstation-01.raw",
        image_format: str = "raw",
        metadata: dict[str, Any] | None = None,
        should_fail: bool = False,
    ) -> None:
        self._acquisition_tool = acquisition_tool
        self._image_reference = image_reference
        self._image_format = image_format
        self._metadata = metadata or {
            "analysis_compatible_with": ["Volatility"],
            "acquisition_mode": "mock",
        }
        self._should_fail = should_fail

    @property
    def name(self) -> str:
        return "mock_memory_acquisition"

    @property
    def tool_name(self) -> str:
        return self._acquisition_tool

    def acquire(self, hostname: str) -> MemoryEvidence:
        if not hostname.strip():
            raise ValueError("hostname must not be empty")

        if self._should_fail:
            raise RuntimeError("memory acquisition failed")

        return create_memory_evidence(
            hostname=hostname,
            status="collected",
            acquisition_tool=self.tool_name,
            image_reference=self._image_reference,
            image_format=self._image_format,
            metadata={
                **self._metadata,
                "hostname": hostname,
            },
        )
