import logging

from fastapi import FastAPI

from app.config import settings
from app.edr.webhook import router as edr_webhook_router
from app.logging_config import setup_logging

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
)

app.include_router(edr_webhook_router)


@app.on_event("startup")
def startup_event():
    logger.info("Application started successfully")


@app.get("/")
def root():
    logger.info("Root endpoint accessed")
    return {
        "message": "Automated Ransomware Containment Orchestrator",
        "version": settings.app_version,
        "status": "running",
    }


@app.get("/health")
def health():
    logger.info("Health endpoint accessed")
    return {
        "status": "healthy",
        "environment": settings.environment,
    }
