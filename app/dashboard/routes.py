from fastapi import APIRouter

from app.database.database import IncidentDatabase
from app.dashboard.service import DashboardService


router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

database = IncidentDatabase()
service = DashboardService(database)


@router.get("/metrics")
def dashboard_metrics() -> dict:
    return service.get_metrics()


@router.get("/health")
def dashboard_health() -> dict:
    return {
        "status": "healthy",
        "service": "incident-dashboard",
    }