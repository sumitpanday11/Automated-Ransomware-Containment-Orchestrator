from dataclasses import dataclass, field
from typing import Any


@dataclass
class DetectionResult:
    detected: bool
    detection_type: str | None = None
    confidence: float = 0.0
    reasons: list[str] = field(default_factory=list)


class RansomwareDetectionEngine:
    """
    Safe ransomware detection engine.

    This engine analyzes synthetic/EDR alert metadata only.
    It does not execute, create, encrypt, modify, or delete files.
    """

    def analyze(self, alert: dict[str, Any]) -> DetectionResult:
        reasons: list[str] = []
        detections: list[tuple[str, float, str]] = []

        if self._is_ransomware_like(alert):
            detections.append(
                (
                    "ransomware_like",
                    0.80,
                    "Alert contains ransomware-like behavior",
                )
            )

        if self._is_mass_file_modification(alert):
            detections.append(
                (
                    "mass_file_modification",
                    0.85,
                    "Mass file modification activity detected",
                )
            )

        if self._is_suspicious_encryption(alert):
            detections.append(
                (
                    "suspicious_encryption",
                    0.90,
                    "Suspicious encryption activity detected",
                )
            )

        if self._is_known_ransomware(alert):
            detections.append(
                (
                    "known_ransomware",
                    0.98,
                    "EDR reported a known ransomware detection",
                )
            )

        if self._is_high_confidence_malicious_process(alert):
            detections.append(
                (
                    "malicious_process",
                    0.92,
                    "High-confidence malicious process detected",
                )
            )

        if not detections:
            return DetectionResult(
                detected=False,
                confidence=0.0,
                reasons=[],
            )

        # Use the strongest detection signal.
        strongest = max(detections, key=lambda item: item[1])

        for _, _, reason in detections:
            reasons.append(reason)

        return DetectionResult(
            detected=True,
            detection_type=strongest[0],
            confidence=strongest[1],
            reasons=reasons,
        )

    @staticmethod
    def _is_ransomware_like(alert: dict[str, Any]) -> bool:
        text = RansomwareDetectionEngine._combined_text(alert)

        keywords = (
            "ransomware",
            "ransom note",
            "file encryption",
            "mass encryption",
            "ransom",
        )

        return any(keyword in text for keyword in keywords)

    @staticmethod
    def _is_mass_file_modification(alert: dict[str, Any]) -> bool:
        activity = str(
            alert.get("activity")
            or alert.get("behavior")
            or alert.get("event_type")
            or ""
        ).lower()

        count = alert.get("modified_file_count")

        if isinstance(count, int) and count >= 100:
            return True

        keywords = (
            "mass file modification",
            "mass file change",
            "mass file rename",
            "mass modification",
        )

        return any(keyword in activity for keyword in keywords)

    @staticmethod
    def _is_suspicious_encryption(alert: dict[str, Any]) -> bool:
        text = RansomwareDetectionEngine._combined_text(alert)

        encryption_keywords = (
            "suspicious encryption",
            "encryption activity",
            "mass encryption",
            "encrypting files",
            "file encryption",
        )

        return any(keyword in text for keyword in encryption_keywords)

    @staticmethod
    def _is_known_ransomware(alert: dict[str, Any]) -> bool:
        detection_name = str(
            alert.get("detection_name")
            or ""
        ).lower()

        return (
            "known ransomware" in detection_name
            or "ransomware detected" in detection_name
        )

    @staticmethod
    def _is_high_confidence_malicious_process(
        alert: dict[str, Any],
    ) -> bool:
        process = str(
            alert.get("process")
            or alert.get("process_name")
            or ""
        ).lower()

        verdict = str(
            alert.get("verdict")
            or alert.get("classification")
            or alert.get("process_verdict")
            or ""
        ).lower()

        confidence = alert.get("confidence")

        malicious = verdict in {
            "malicious",
            "highly malicious",
            "malware",
        }

        high_confidence = (
            isinstance(confidence, (int, float))
            and confidence >= 0.90
        )

        process_present = bool(process)

        return process_present and malicious and high_confidence

    @staticmethod
    def _combined_text(alert: dict[str, Any]) -> str:
        fields = (
            "threat",
            "detection_name",
            "behavior",
            "activity",
            "description",
            "command_line",
            "process",
        )

        return " ".join(
            str(alert.get(field, "")).lower()
            for field in fields
        )