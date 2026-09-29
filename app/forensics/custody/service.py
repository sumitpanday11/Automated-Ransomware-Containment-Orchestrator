from app.forensics.custody.logger import ChainOfCustodyLogger, CustodyEvent


class ChainOfCustodyService:
    def __init__(self, logger: ChainOfCustodyLogger | None = None) -> None:
        self.logger = logger or ChainOfCustodyLogger()

    def log_created(
        self,
        evidence_id: str,
        actor: str,
        evidence_hash: str | None = None,
    ) -> CustodyEvent:
        return self.logger.record(
            actor=actor,
            action="created",
            evidence_id=evidence_id,
            evidence_hash=evidence_hash,
            status="created",
        )

    def log_collected(
        self,
        evidence_id: str,
        actor: str,
        evidence_hash: str | None = None,
    ) -> CustodyEvent:
        return self.logger.record(
            actor=actor,
            action="collected",
            evidence_id=evidence_id,
            evidence_hash=evidence_hash,
            status="collected",
        )

    def log_hashed(
        self,
        evidence_id: str,
        actor: str,
        evidence_hash: str,
    ) -> CustodyEvent:
        return self.logger.record(
            actor=actor,
            action="hashed",
            evidence_id=evidence_id,
            evidence_hash=evidence_hash,
            status="hashed",
        )

    def log_uploaded(
        self,
        evidence_id: str,
        actor: str,
        evidence_hash: str,
    ) -> CustodyEvent:
        return self.logger.record(
            actor=actor,
            action="uploaded",
            evidence_id=evidence_id,
            evidence_hash=evidence_hash,
            status="uploaded",
        )

    def log_accessed(
        self,
        evidence_id: str,
        actor: str,
        evidence_hash: str | None = None,
    ) -> CustodyEvent:
        return self.logger.record(
            actor=actor,
            action="accessed",
            evidence_id=evidence_id,
            evidence_hash=evidence_hash,
            status="accessed",
        )

    def log_analyzed(
        self,
        evidence_id: str,
        actor: str,
        evidence_hash: str | None = None,
    ) -> CustodyEvent:
        return self.logger.record(
            actor=actor,
            action="analyzed",
            evidence_id=evidence_id,
            evidence_hash=evidence_hash,
            status="analyzed",
        )
