from dataclasses import dataclass
import os


@dataclass(frozen=True)
class S3StorageConfig:
    """Configuration for S3 evidence storage."""

    bucket_name: str
    region: str
    prefix: str = "evidence"

    @classmethod
    def from_environment(cls) -> "S3StorageConfig":
        return cls(
            bucket_name=os.getenv(
                "EVIDENCE_S3_BUCKET",
                "ransomware-evidence",
            ),
            region=os.getenv(
                "AWS_REGION",
                "ap-south-1",
            ),
            prefix=os.getenv(
                "EVIDENCE_S3_PREFIX",
                "evidence",
            ),
        )
