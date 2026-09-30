\# Automated Ransomware Containment \& Incident Response Orchestrator



\## Overview



The Automated Ransomware Containment \& Incident Response Orchestrator is a Python and FastAPI-based cybersecurity project designed to automate the early stages of ransomware incident response.



The system receives security alerts from an Endpoint Detection and Response (EDR) platform, normalizes and validates alerts, extracts threat indicators, evaluates risk, detects ransomware activity, and automatically executes containment actions.



The project also provides forensic evidence collection, memory acquisition, evidence integrity verification, chain of custody, secure evidence storage, and incident tracking.



\## Problem Statement



Ransomware attacks can spread rapidly across endpoints and user accounts. Manual incident response can delay containment and increase the impact of an attack.



This project automates important incident response activities such as:



\* EDR alert ingestion

\* Alert normalization and validation

\* Threat indicator extraction

\* Risk and severity assessment

\* Ransomware detection

\* Automated containment decisions

\* Host isolation

\* User suspension

\* Session and token revocation

\* Forensic evidence collection

\* Evidence integrity verification

\* Chain of custody logging

\* Incident tracking



\## Objectives



\* Automate the initial ransomware incident response workflow.

\* Provide a modular and testable cybersecurity architecture.

\* Integrate EDR alerts through a webhook interface.

\* Identify and prioritize high-risk incidents.

\* Execute automated containment actions.

\* Preserve forensic evidence for investigation.

\* Maintain evidence integrity and chain of custody.

\* Track incident lifecycle and response actions.



\## System Architecture



```text

&#x20;                        EDR ALERT

&#x20;                            |

&#x20;                            v

&#x20;                 +-----------------------+

&#x20;                 |  Webhook Ingestion    |

&#x20;                 | Authentication +      |

&#x20;                 | Correlation ID        |

&#x20;                 +----------+------------+

&#x20;                            |

&#x20;                            v

&#x20;                 +-----------------------+

&#x20;                 | Alert Normalization   |

&#x20;                 | \& Validation          |

&#x20;                 +----------+------------+

&#x20;                            |

&#x20;                            v

&#x20;                 +-----------------------+

&#x20;                 | Threat Indicator      |

&#x20;                 | Extraction            |

&#x20;                 +----------+------------+

&#x20;                            |

&#x20;                            v

&#x20;                 +-----------------------+

&#x20;                 | Risk / Severity       |

&#x20;                 | Engine                |

&#x20;                 +----------+------------+

&#x20;                            |

&#x20;                            v

&#x20;                 +-----------------------+

&#x20;                 | Ransomware Detection  |

&#x20;                 | Engine                |

&#x20;                 +----------+------------+

&#x20;                            |

&#x20;                            v

&#x20;                 +-----------------------+

&#x20;                 | Response Decision     |

&#x20;                 | Engine                |

&#x20;                 +----------+------------+

&#x20;                            |

&#x20;             +--------------+--------------+

&#x20;             |              |              |

&#x20;             v              v              v

&#x20;      Host Isolation   User Suspension   Session /

&#x20;                                         Token Revocation

&#x20;             |              |              |

&#x20;             +--------------+--------------+

&#x20;                            |

&#x20;                            v

&#x20;                 +-----------------------+

&#x20;                 | Forensic Evidence     |

&#x20;                 | Collection            |

&#x20;                 +----------+------------+

&#x20;                            |

&#x20;             +--------------+--------------+

&#x20;             |              |              |

&#x20;             v              v              v

&#x20;      Host Evidence     Artifacts      Memory Evidence

&#x20;             |              |              |

&#x20;             +--------------+--------------+

&#x20;                            |

&#x20;                            v

&#x20;                 +-----------------------+

&#x20;                 | SHA-256 Integrity     |

&#x20;                 | Hashing \& Verification|

&#x20;                 +----------+------------+

&#x20;                            |

&#x20;                            v

&#x20;                 +-----------------------+

&#x20;                 | Chain of Custody      |

&#x20;                 +----------+------------+

&#x20;                            |

&#x20;                   +--------+--------+

&#x20;                   |                 |

&#x20;                   v                 v

&#x20;            S3 Evidence       Incident Database

&#x20;              Storage

```



\## End-to-End Workflow



```text

EDR Alert

&#x20;  ↓

Webhook Authentication

&#x20;  ↓

Alert Normalization

&#x20;  ↓

Threat Indicator Extraction

&#x20;  ↓

Risk / Severity Assessment

&#x20;  ↓

Ransomware Detection

&#x20;  ↓

Response Decision

&#x20;  ↓

Host Isolation

&#x20;  ↓

User Suspension

&#x20;  ↓

Session / Token Revocation

&#x20;  ↓

Incident Containment

&#x20;  ↓

Forensic Evidence Collection

&#x20;  ↓

SHA-256 Integrity Verification

&#x20;  ↓

Chain of Custody

&#x20;  ↓

Evidence Storage

&#x20;  ↓

Incident Tracking

```



\## Core Modules



\### EDR Integration



Location: `app/edr/`



Provides:



\* EDR adapter interface

\* Mock EDR provider

\* EDR configuration

\* Provider factory

\* EDR service

\* Alert normalization

\* Threat indicator extraction

\* Webhook ingestion



\### Incident and Alert Models



Location: `app/models/`



Defines the core incident and alert data structures used throughout the application.



\### Risk and Severity Engine



Location: `app/response/risk\_engine.py`



Evaluates security indicators and assigns incident severity levels:



\* LOW

\* MEDIUM

\* HIGH

\* CRITICAL



\### Ransomware Detection Engine



Location: `app/detection/ransomware\_engine.py`



Analyzes normalized security information and identifies ransomware-related activity.



\### Response Decision Engine



Location: `app/response/decision\_engine.py`



Maps incident severity and detection results to appropriate automated response actions.



\### Host Isolation Playbook



Location: `app/response/isolation\_playbook.py`



Provides:



\* Host isolation

\* Isolation status

\* Failure handling

\* Retry logic

\* Action audit logging



\### User Suspension Playbook



Location: `app/response/user\_suspension\_playbook.py`



Provides automated identity containment through:



\* User lookup

\* Identity authentication

\* User suspension

\* Failure handling

\* Action result tracking



\### Session and Token Revocation



Location: `app/response/session\_revocation\_playbook.py`



Provides automated session and token revocation after a high-risk security incident.



\## Forensic Evidence Collection



The project includes a modular forensic evidence collection framework.



\### Live Response



Location: `app/forensics/`



Provides the base evidence collection architecture.



\### Host Evidence



Location: `app/forensics/collectors/host.py`



Collects relevant host information such as:



\* Running processes

\* Network connections

\* Logged-in users

\* System information

\* File metadata

\* Suspicious process information



\### Forensic Artifacts



Location: `app/forensics/artifacts/`



Provides a KAPE-style conceptual artifact collection workflow for:



\* Event logs

\* Browser artifacts

\* Prefetch-style metadata

\* Startup and persistence indicators

\* Security logs

\* Relevant system artifacts



Actual forensic tooling execution is environment-dependent.



\### Memory Acquisition



Location: `app/forensics/memory/`



Provides:



\* Memory acquisition interface

\* Mock memory acquisition

\* Acquisition workflow

\* Failure handling

\* Memory image metadata

\* Volatility-compatible metadata



\## Evidence Integrity



Location: `app/forensics/integrity/`



The project uses SHA-256 hashing to verify the integrity of forensic evidence.



```text

Evidence

&#x20;  ↓

SHA-256 Hash

&#x20;  ↓

Storage

&#x20;  ↓

Hash Verification

```



\## Chain of Custody



Location: `app/forensics/custody/`



Tracks important evidence lifecycle events:



```text

Created

&#x20; ↓

Collected

&#x20; ↓

Hashed

&#x20; ↓

Uploaded

&#x20; ↓

Accessed

&#x20; ↓

Analyzed

```



\## Evidence Storage



Location: `app/storage/s3/`



Provides an S3-compatible evidence storage abstraction with:



\* Storage configuration

\* Storage adapter

\* Mock S3 storage

\* Evidence upload workflow

\* Metadata tracking

\* Failure handling



Real AWS S3 integration is environment-dependent.



\## Incident Tracking Database



Location: `app/database/`



The project uses SQLite for incident tracking.



The database stores:



\* Incidents

\* Response actions

\* Evidence records

\* Audit logs



\### Incident State Machine



```text

NEW

&#x20;↓

INVESTIGATING

&#x20;↓

CONTAINING

&#x20;↓

CONTAINED

&#x20;↓

EVIDENCE\_COLLECTED

&#x20;↓

RESOLVED

```



\## Project Structure



```text

Automated-Ransomware-Containment-Orchestrator/

│

├── app/

│   ├── database/

│   │   ├── database.py

│   │   ├── repository.py

│   │   └── states.py

│   │

│   ├── detection/

│   │   └── ransomware\_engine.py

│   │

│   ├── edr/

│   │   ├── adapter.py

│   │   ├── config.py

│   │   ├── factory.py

│   │   ├── mock.py

│   │   ├── normalizer.py

│   │   ├── service.py

│   │   ├── threat\_indicators.py

│   │   └── webhook.py

│   │

│   ├── forensics/

│   │   ├── artifacts/

│   │   ├── collectors/

│   │   ├── custody/

│   │   ├── integrity/

│   │   └── memory/

│   │

│   ├── identity/

│   │   ├── adapter.py

│   │   ├── factory.py

│   │   ├── mock.py

│   │   └── service.py

│   │

│   ├── models/

│   │   ├── alert.py

│   │   └── incident.py

│   │

│   ├── response/

│   │   ├── decision\_engine.py

│   │   ├── isolation\_playbook.py

│   │   ├── risk\_engine.py

│   │   ├── session\_revocation\_playbook.py

│   │   └── user\_suspension\_playbook.py

│   │

│   ├── storage/

│   │   └── s3/

│   │

│   ├── config.py

│   ├── logging\_config.py

│   └── main.py

│

├── tests/

│   ├── edr/

│   ├── test\_artifact\_collection.py

│   ├── test\_chain\_of\_custody.py

│   ├── test\_decision\_engine.py

│   ├── test\_end\_to\_end\_containment.py

│   ├── test\_evidence\_integrity.py

│   ├── test\_health.py

│   ├── test\_host\_evidence.py

│   ├── test\_incident\_database.py

│   ├── test\_ingestion\_integration.py

│   ├── test\_isolation\_playbook.py

│   ├── test\_live\_response.py

│   ├── test\_memory\_acquisition.py

│   ├── test\_models.py

│   ├── test\_normalizer.py

│   ├── test\_ransomware\_engine.py

│   ├── test\_risk\_engine.py

│   ├── test\_s3\_evidence\_storage.py

│   ├── test\_session\_revocation\_playbook.py

│   ├── test\_threat\_indicators.py

│   └── test\_user\_suspension\_playbook.py

│

├── .env.example

├── .gitignore

├── requirements.txt

└── README.md

```



\## Technology Stack



\* Python 3.13

\* FastAPI

\* Uvicorn

\* Pydantic

\* Pytest

\* SQLite

\* psutil

\* S3-compatible storage abstraction

\* Git

\* GitHub



\## Security Features



\* EDR webhook authentication

\* Correlation ID tracking

\* Alert validation and normalization

\* Threat indicator extraction

\* Risk-based response

\* Automated containment playbooks

\* Retry and failure handling

\* Forensic evidence collection

\* SHA-256 evidence integrity verification

\* Chain of custody logging

\* Audit logging

\* Mock providers for safe development and testing



\## Development Roadmap



\### Project 2 - Week 1



\*\*Days 1–7\*\*



\* Day 1 — FastAPI foundation and health endpoint

\* Day 2 — Incident and alert models

\* Day 3 — EDR integration

\* Day 4 — Webhook ingestion

\* Day 5 — Alert normalization and validation

\* Day 6 — Threat indicator extraction

\* Day 7 — Ingestion integration testing



\### Project 2 - Week 2



\*\*Days 8–14\*\*



\* Day 8 — Risk and severity engine

\* Day 9 — Ransomware detection engine

\* Day 10 — Automated response decision engine

\* Day 11 — Host isolation playbook

\* Day 12 — Automated user suspension

\* Day 13 — Session and token revocation

\* Day 14 — End-to-end containment testing



\### Project 2 - Week 3



\*\*Days 15–21\*\*



\* Day 15 — Forensic live response framework

\* Day 16 — Host forensic evidence collection

\* Day 17 — Forensic artifact collection

\* Day 18 — Memory acquisition workflow

\* Day 19 — Secure S3 evidence storage

\* Day 20 — Evidence integrity hashing

\* Day 21 — Chain of custody logging



\### Project 2 - Week 4



\*\*Days 22–28\*\*



\* Day 22 — Incident tracking database

\* Days 23–28 — Remaining integration, testing, documentation, and project finalization



\## Testing



Run all tests with:



```powershell

.\\.venv\\Scripts\\python.exe -m pytest -q

```



Current test status:



```text

134 passed

3 warnings

```



\## Installation



```powershell

git clone https://github.com/sumitpanday11/Automated-Ransomware-Containment-Orchestrator.git

cd Automated-Ransomware-Containment-Orchestrator

py -3.13 -m venv .venv

.\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt

Copy-Item .env.example .env

```



\## Running the Application



```powershell

.\\.venv\\Scripts\\python.exe -m uvicorn app.main:app --reload

```



\## Development Approach



The project follows a modular architecture where external systems such as EDR, identity providers, memory acquisition tools, and S3 storage are accessed through adapters or mock implementations.



This allows the project to be developed and tested safely without requiring production security infrastructure.



\## Current Project Status



\*\*Project:\*\* Automated Ransomware Containment \& Incident Response Orchestrator



\*\*Progress:\*\* Day 22 / 28



\*\*Branch:\*\* `main`



\*\*Latest Commit:\*\* `30b8b50`



\*\*Tests:\*\* 134 passed



The core automated containment workflow and major forensic components have been implemented. Incident tracking database functionality is also implemented.



\## Limitations



Some integrations are environment-dependent and currently use mock or abstraction layers for safe development:



\* Production EDR integration

\* Production identity provider

\* Real AWS S3 deployment

\* Actual memory acquisition

\* Environment-specific forensic tools

\* Production SIEM integration



\## Future Enhancements



\* Production EDR integrations

\* Enterprise identity provider integration

\* AWS S3 and IAM integration

\* PostgreSQL-based incident storage

\* SIEM integration

\* Security monitoring dashboards

\* Role-based access control

\* Advanced ransomware detection

\* Metrics and observability

\* Expanded forensic automation



\## Author



\*\*Sumit Panday\*\*



B.Tech CSE — Cyber Security



Organization: Zaalima Development Pvt Ltd



