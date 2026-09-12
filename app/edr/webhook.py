import logging
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, HTTPException, Request

from app.edr.config import EDRSettings
from app.models.alert import Alert

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
        raise HTTPException(status_code=401, detail="Invalid EDR authentication")

    correlation_id = x_correlation_id or str(uuid4())

    try:
        payload = await request.json()
        alert = Alert.model_validate(payload)
    except Exception:
        logger.warning(
            "Invalid EDR alert payload correlation_id=%s",
            correlation_id,
        )
        raise HTTPException(status_code=422, detail="Invalid EDR alert payload")

    logger.info(
        "EDR alert received alert_id=%s correlation_id=%s",
        alert.alert_id,
        correlation_id,
    )

    return {
        "status": "accepted",
        "alert_id": str(alert.alert_id),
        "correlation_id": correlation_id,
    }
