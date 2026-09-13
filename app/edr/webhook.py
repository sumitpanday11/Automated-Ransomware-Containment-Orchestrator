import logging
from uuid import uuid4

from fastapi import APIRouter, Header, HTTPException, Request

from app.edr.config import EDRSettings
from app.edr.normalizer import normalize_alert, to_incident

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhook", tags=["EDR Webhook"])


@router.post("/edr")
async def receive_edr_alert(
    request: Request,
    x_edr_api_key: str | None = Header(default=None),
    x_correlation_id: str | None = Header(default=None),
):
    settings = EDRSettings()

    if not settings.api_key or x_edr_api_key != settings.api_key:
        logger.warning("EDR webhook authentication failed")
        raise HTTPException(
            status_code=401,
            detail="Invalid EDR authentication",
        )

    correlation_id = x_correlation_id or str(uuid4())

    try:
        payload = await request.json()
    except Exception:
        logger.warning(
            "Invalid JSON payload correlation_id=%s",
            correlation_id,
        )
        raise HTTPException(
            status_code=422,
            detail="Invalid EDR alert payload",
        )

    provider = request.headers.get("x-edr-provider")

    if not provider:
        raise HTTPException(
            status_code=422,
            detail="X-EDR-Provider header is required",
        )

    try:
        normalized_alert = normalize_alert(payload, provider)
        incident = to_incident(normalized_alert)
    except (ValueError, TypeError):
        logger.warning(
            "EDR alert validation failed provider=%s correlation_id=%s",
            provider,
            correlation_id,
        )
        raise HTTPException(
            status_code=422,
            detail="Invalid EDR alert payload",
        )

    logger.info(
        "EDR alert normalized provider=%s alert_id=%s incident_id=%s "
        "correlation_id=%s",
        provider,
        normalized_alert.alert_id,
        incident.incident_id,
        correlation_id,
    )

    return {
        "status": "accepted",
        "provider": provider,
        "alert_id": str(normalized_alert.alert_id),
        "incident_id": str(incident.incident_id),
        "correlation_id": correlation_id,
        "incident": incident.model_dump(mode="json"),
    }
