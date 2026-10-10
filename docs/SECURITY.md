# Security Documentation

## 1. Security Overview

The Automated Ransomware Containment Orchestrator is a defensive cybersecurity project designed to demonstrate automated incident detection, containment, evidence preservation, and incident tracking.

The project uses mock integrations for safe development and testing.

## 2. Authentication and Access Control

- The EDR webhook supports API-key authentication.
- The expected webhook authentication header is `x_edr_api_key`.
- Configure the required EDR credentials through environment variables.
- Never commit real API keys, passwords, access tokens, or other secrets to Git.
- Use `.env.example` as a configuration reference, not as a location for real credentials.

## 3. Detection and Containment

The orchestrator evaluates incoming alerts, calculates incident risk, and selects response actions based on severity.

Demonstrated response actions include:

- Host isolation through the configured response adapter.
- User suspension through the identity integration.
- Session and token revocation.
- Evidence collection and integrity verification.
- Incident tracking, ticketing, and SOC notifications.

Actual external actions depend on the configured integrations. Mock adapters demonstrate workflows without performing real actions on external systems.

## 4. Evidence Integrity and Auditability

- SHA-256 hashes are used to verify evidence integrity.
- Chain-of-custody events record evidence handling activities.
- Incident and response information is stored for investigation and review.
- Evidence storage behavior depends on the configured storage adapter.

A hash can help detect changes to evidence but does not independently prove that the original evidence was authentic.

## 5. Safe Testing

- Automated tests use synthetic alerts and controlled test scenarios.
- The end-to-end ransomware simulation is intended for defensive validation.
- Do not test against systems or accounts without explicit authorization.
- Validate integrations in an isolated test environment before considering production deployment.

## 6. Secrets and Configuration

- Keep `.env` files and credentials out of version control.
- Review `.gitignore` before adding configuration or evidence files.
- Use unique, appropriately scoped credentials for external integrations.
- Rotate any credential that may have been exposed.

## 7. Limitations

- Mock integrations do not establish that a real EDR, identity provider, ticketing system, or notification service is connected.
- Production deployment requires additional authentication, authorization, operational monitoring, and integration-specific testing.
- Automated containment decisions should be reviewed and tested carefully before use in a real environment.
- Evidence collection capabilities depend on host permissions and the configured collection implementation.

## 8. Security Reporting

For suspected vulnerabilities, document the affected component, reproduction steps, potential impact, and a suggested mitigation. Do not include real credentials, personal data, or sensitive production evidence in the report.
