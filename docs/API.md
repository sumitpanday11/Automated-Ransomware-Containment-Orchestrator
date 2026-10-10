# API Documentation

## 1. Overview

The Automated Ransomware Containment Orchestrator is a defensive cybersecurity application built with FastAPI. It supports health monitoring, EDR alert ingestion, incident detection, automated containment, evidence collection, and dashboard metrics.

### Local Base URL

http://127.0.0.1:8000

### Interactive API Documentation

- Swagger UI: http://127.0.0.1:8000/docs
- ReDoc: http://127.0.0.1:8000/redoc

## 2. Health Endpoint

### GET /health

Checks the application's health.

Example:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/health"
```

## 3. EDR Webhook

### POST /webhook/edr

Receives an EDR alert for authentication, validation, normalization, and incident processing.

Headers depend on the configured EDR integration. The current integration uses `x_edr_api_key` for API-key authentication. Check the application configuration for the exact provider and correlation header names.

Example request structure:

```json
{
  "alert_id": "SIM-RANSOM-001",
  "hostname": "LAB-HOST-01",
  "username": "alice",
  "threat": "ransomware",
  "detection_name": "known ransomware",
  "behavior": "mass encryption",
  "modified_file_count": 500
}
```

This is an illustrative payload. The actual accepted fields must be verified against the application's request model and `/docs`.

## 4. Dashboard Endpoints

The project includes a dashboard service for viewing incident and response statistics.

Before using dashboard routes, verify their exact paths and response schemas in the running application's Swagger UI.

## 5. Error Handling

Possible HTTP errors include:

- `401 Unauthorized`: authentication failed.
- `422 Unprocessable Entity`: request validation failed.
- Other status codes depend on the endpoint and its error-handling logic.

Verify actual status codes and response bodies against the running application.

## 6. Security Recommendations

- Keep API keys in environment variables.
- Never commit real credentials.
- Use synthetic alerts for demonstrations.
- Use HTTPS and appropriate access controls in production.
- Restrict access to sensitive incident and forensic evidence data.
- Use mock integrations for safe local testing.

## 7. Endpoint Verification

Start the application using the project's documented setup instructions, then open:

http://127.0.0.1:8000/docs

Use the registered routes and request schemas in Swagger UI as the authoritative reference for the current application version.
