# Automated Ransomware Containment Orchestrator

A defensive cybersecurity automation platform built with Python and FastAPI to demonstrate ransomware-like threat detection, risk assessment, automated incident response, forensic evidence collection, integrity verification, incident tracking, and SOC notification workflows.

## Project Overview

The orchestrator demonstrates the following incident-response lifecycle:

1. Receive an EDR alert.
2. Validate and normalize the alert.
3. Extract threat indicators and evaluate suspicious behavior.
4. Calculate risk and classify incident severity.
5. Select response actions based on configured decision rules.
6. Demonstrate host isolation, user suspension, and session/token revocation.
7. Collect forensic evidence and calculate SHA-256 hashes.
8. Track chain-of-custody events and store incident information.
9. Demonstrate SOC ticket creation and incident notifications.

This is a defensive cybersecurity project. Its end-to-end simulation uses synthetic alerts and mock integrations; it does not execute real ransomware.

## Key Features

- FastAPI REST API and EDR webhook ingestion
- API-key authentication for the EDR webhook
- Alert normalization and threat indicator extraction
- Ransomware-like behavior detection
- Risk scoring and severity classification
- Rule-based response decision engine
- Host isolation and user suspension playbooks
- Session and token revocation workflow
- Host forensic evidence and artifact collection
- Memory acquisition workflow
- SHA-256 evidence integrity verification
- Chain-of-custody tracking
- S3-compatible evidence storage adapter
- SQLite incident and response tracking
- SOC ticketing and incident notification adapters
- Incident dashboard metrics
- Automated tests and end-to-end simulation

## Technology Stack

- Python 3.13
- FastAPI
- Uvicorn
- Pydantic and Pydantic Settings
- SQLite
- pytest
- HTTPX
- Mock EDR, identity, evidence-storage, ticketing, and notification integrations

## Project Structure

```text
Automated-Ransomware-Containment-Orchestrator/
|
|-- app/
|   |-- config.py
|   |-- main.py
|   |-- logging_config.py
|   |-- dashboard/
|   |-- database/
|   |-- detection/
|   |-- edr/
|   |-- forensics/
|   |-- identity/
|   |-- notifications/
|   |-- response/
|   |-- storage/
|   `-- ticketing/
|
|-- tests/
|-- docs/
|   |-- API.md
|   |-- ARCHITECTURE.md
|   |-- PROJECT_REPORT.md
|   `-- SECURITY.md
|
|-- .env.example
|-- .gitignore
|-- requirements.txt
`-- README.md
```

## Prerequisites

- Python 3.13 or a compatible Python version
- PowerShell on Windows
- Git, if cloning the repository

## Installation and Setup

Open PowerShell in the project directory.

### 1. Create a virtual environment

```powershell
python -m venv .venv
```

### 2. Install dependencies

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 3. Configure environment variables

Review `.env.example` for the supported configuration variables. For local development, the project is configured to use the mock EDR provider by default.

Do not commit real API keys, passwords, or other secrets to Git.

## Run the Application

Start the FastAPI application from the project root:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

By default, Uvicorn serves the application at `http://127.0.0.1:8000`.

Useful URLs:

- Root endpoint: `http://127.0.0.1:8000/`
- Health endpoint: `http://127.0.0.1:8000/health`
- Interactive API documentation: `http://127.0.0.1:8000/docs`

Keep the terminal running while testing the application. Press `Ctrl+C` to stop the server.

## Run Tests

From the project root, execute the test suite using the project's virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The command reports passed and failed tests. Run it again before final submission and record the actual result rather than relying on historical results.

## API and Configuration

The application exposes root and health endpoints, an EDR webhook, and dashboard routes. See `docs/API.md` for documented endpoint behavior.

The EDR webhook uses the `x_edr_api_key` authentication header. Consult the API documentation and application configuration for the required settings and request format.

## Security and Safety

- Use synthetic alerts for local demonstrations.
- Mock integrations simulate workflows; they do not prove that external production systems are connected.
- Test real integrations only in authorized, controlled environments.
- Protect credentials and keep secrets out of version control.
- Review `docs/SECURITY.md` for security considerations and known limitations.

## Documentation

- `docs/API.md` - API endpoints, authentication, and request examples
- `docs/ARCHITECTURE.md` - system architecture and incident-response workflow
- `docs/PROJECT_REPORT.md` - project objectives, implementation, testing, and future improvements
- `docs/SECURITY.md` - security controls, safe testing, and limitations

## Limitations

This project demonstrates a defensive response workflow. Actual host isolation, identity actions, evidence acquisition, external ticketing, and notifications depend on the configured implementations and integrations. Mock results must not be interpreted as proof of production deployment or real-world containment.

## Future Improvements

- Integrate with a real EDR platform in an authorized test environment
- Strengthen role-based access control and audit monitoring
- Add production-ready secrets management
- Improve deployment automation and operational monitoring
- Expand integration and security testing

## Disclaimer

This project is intended for defensive cybersecurity education, authorized testing, and incident-response automation research. Do not use it to access or modify systems without permission.

## Demo Commands

Start the app: `.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload`

Check health in a second terminal: `Invoke-RestMethod http://127.0.0.1:8000/health`

Open API docs: http://127.0.0.1:8000/docs

Run tests: `.\.venv\Scripts\python.exe -m pytest -q`

Use mock integrations and synthetic alerts for demonstrations. Do not run destructive activity on real systems.

## Review Preparation

1. What problem does this project solve?
2. Why is FastAPI used?
3. How are EDR alerts received and normalized?
4. How does risk assessment work?
5. How does the decision engine choose containment actions?
6. How are forensic evidence and SHA-256 hashes handled?
7. What does the audit trail record?
8. What is the difference between mock and real integrations?
9. What are the current limitations?
10. How do you run and verify the tests?
