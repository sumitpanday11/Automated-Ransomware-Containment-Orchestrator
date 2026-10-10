# Project Report: Automated Ransomware Containment Orchestrator

## 1. Abstract

The Automated Ransomware Containment Orchestrator is a defensive cybersecurity project developed with Python and FastAPI. It demonstrates how security alerts can be processed, risk-assessed, and used to coordinate incident response actions. The platform also demonstrates evidence collection, integrity verification, incident tracking, ticketing, notifications, and audit logging.

Mock integrations are used for safe local demonstrations where real enterprise infrastructure is unavailable.

## 2. Introduction

Ransomware incidents can disrupt services, compromise data availability, and require rapid coordination between security teams. Manual incident response can delay containment and evidence preservation.

This project explores an automated workflow that connects alert ingestion, detection, risk assessment, response decisions, containment playbooks, evidence handling, and incident tracking.

## 3. Objectives

- Receive and validate simulated EDR alerts.
- Normalize alert data for consistent processing.
- Evaluate suspicious activity and calculate incident risk.
- Select response actions based on risk and decision rules.
- Demonstrate host isolation and identity/session response workflows.
- Collect and track forensic evidence.
- Calculate SHA-256 hashes to support evidence integrity checks.
- Record incidents, response actions, and audit events.
- Demonstrate dashboard metrics, ticketing, and SOC notifications.
- Provide automated tests for important workflows.

## 4. Technology Stack

- **Language:** Python
- **Web framework:** FastAPI
- **Data validation:** Pydantic
- **Testing:** pytest and HTTPX
- **Database:** SQLite
- **API documentation:** OpenAPI, Swagger UI, and ReDoc
- **Integrations:** Configurable adapters, including mock implementations
- **Version control:** Git and GitHub

## 5. System Architecture

The logical workflow is:

EDR or synthetic alert -> API webhook -> authentication and validation -> alert normalization -> detection engine -> risk scoring -> decision engine -> containment playbooks -> evidence collection and integrity verification -> storage and audit tracking -> dashboard, ticketing, and SOC notifications.

The detailed architecture diagram is maintained in `ARCHITECTURE.md`.

## 6. Major Modules

### 6.1 Alert Ingestion

The FastAPI webhook receives EDR alert data and applies configured authentication and validation.

### 6.2 Detection and Risk Assessment

Detection logic evaluates alert characteristics. The risk engine assigns a risk level that informs the response decision.

### 6.3 Decision and Containment

The decision engine selects actions according to configured rules. Demonstrated workflows include host isolation, user suspension, and session/token revocation through the relevant response interfaces.

### 6.4 Evidence Collection

The evidence workflow demonstrates collection of host and forensic artifacts. Available workflows include process and network information, user information, file metadata, and mock memory-acquisition metadata.

### 6.5 Evidence Integrity and Storage

SHA-256 hashes support integrity verification. Storage adapters demonstrate how evidence can be handled by a storage service; mock adapters do not imply that data has been uploaded to a real cloud provider.

### 6.6 Database and Audit Trail

SQLite tracks incidents, response actions, evidence records, and audit events. These records help demonstrate incident lifecycle tracking and accountability.

### 6.7 Dashboard, Ticketing, and Notifications

The project includes dashboard functionality and integrations for ticket creation and SOC notifications. Actual external delivery depends on the configured adapter and environment.

## 7. Testing and Validation

Automated tests cover application endpoints, alert processing, risk assessment, response decisions, containment workflows, evidence handling, database operations, and end-to-end simulation.

The recorded result from the Day 26 end-to-end simulation milestone was **146 tests passed**, with three deprecation warnings.

This result is a historical milestone, not a guarantee of the current test count. Run the full test suite again before final submission and replace this result if the latest outcome differs.

## 8. Security Controls

- API-key authentication for the configured EDR webhook.
- Request validation and alert normalization.
- Risk-based response decisions.
- SHA-256 evidence integrity verification.
- Audit and chain-of-custody event tracking.
- Environment-based configuration for secrets.
- Mock integrations for controlled testing.
- Automated regression and end-to-end tests.

These controls demonstrate defensive design practices; they do not by themselves establish production readiness or regulatory compliance.

## 9. Limitations

- Mock integrations do not perform real endpoint isolation or identity-provider changes.
- Real memory acquisition may require specialized privileges and tools.
- External storage, ticketing, and notifications depend on provider configuration.
- Detection quality depends on the implemented rules and supplied telemetry.
- Production deployment would require additional authentication, authorization, monitoring, resilience, and operational testing.

## 10. Future Improvements

- Integrate with a real EDR platform in an authorized test environment.
- Add role-based access control and stronger service authentication.
- Add durable task queues and retry handling.
- Improve detection rules and threat intelligence enrichment.
- Add deployment automation, containerization, and monitoring.
- Expand integration and failure-recovery testing.
- Add secure evidence retention policies and access auditing.

## 11. Conclusion

The Automated Ransomware Containment Orchestrator demonstrates a modular approach to defensive security automation. It connects alert ingestion, risk assessment, response orchestration, evidence integrity, incident tracking, and SOC workflows in a testable application.

The project is intended for educational and controlled defensive use. Production use would require environment-specific integration, security review, and operational validation.

## 12. Reproducibility

Run the project using the setup instructions in the repository README. Execute the test suite with the project's virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Record the final test output and environment details before submitting the project.
