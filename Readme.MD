# ThreatLens — Cyber Threat Intelligence Dashboard

An enterprise-grade, high-throughput platform for aggregating, normalising, scoring, and operationalising multi-feed Cyber Threat Intelligence (CTI) across a Security Operations Centre (SOC). 

Built to ingest over **50,000 indicators per hour**, ThreatLens handles data formatting differences across public and private feeds, deduplicates incoming vectors into unified canonical shapes, scores their severity metrics, and broadcasts updates via WebSockets in under 5 seconds.

---

## ⚡ Quick Start (Local Single-Command Bring-Up)

The entire production stack is fully containerised and configured to build locally without pre-installing localized database engines or external runtimes.

### Prerequisites
* **Docker Engine** (v20.10.0+)
* **Docker Compose** (v2.0.0+)

### Inception Script
```bash
# 1. Clone the repository
git clone https://github.com
cd threatlens

# 2. Deploy the core stack (PostgreSQL, Redis, Elasticsearch, API Gateway)
docker-compose up --build
```
Once initialized, the services expose the following endpoints:
* **Interactive API Documentation (Swagger/OpenAPI UI):** `http://localhost:8000/docs`
* **CTI Platform API Gateway Engine:** `http://localhost:8000/api/v1`
* **Elasticsearch Search/Analytics Core:** `http://localhost:8000:9200`

---

## 🏗️ System Architecture & Stack Matrix

ThreatLens is constructed using a decoupled, decoupled design profile to ensure that asynchronous feed processing background loops never hinder UI request/response windows.

* **Presentation Layer:** Next.js (React), TypeScript, Tailwind CSS, Recharts, TanStack Query.
* **Application Services:** Python 3.11+, FastAPI (Async worker runtime), Pydantic Data Boundaries.
* **Storage & Indexing Engine:** PostgreSQL (System of Record), Elasticsearch 8.x (Faceted Search Index).
* **Caching & Broker Pipeline:** Redis 7.x (Enrichment Key-Value Cache & Pub/Sub System Messaging).

```text
[ Threat Feeds ] ──> [ Celery Workers ] ──> [ PostgreSQL ] ──> [ Elasticsearch Index ]
                              │
                        (Redis Cache)
                              │
[ Web UI Surface ] <── [ FastAPI WebSockets ] <── [ API Gateway Security Guard ]
```

---

## 🔒 Security Configuration & RBAC Enforcement

The backend applies Role-Based Access Control (RBAC) validations directly at the endpoint framework layers based on **JWT Token States**. Security defaults match the **OWASP Application Security Verification Standard (ASVS)** baseline:

| User Role | Operations Visibility Profile |
| :--- | :--- |
| **Administrator** | Complete ecosystem config, feed onboarding, system auditing, and account lifecycle tools. |
| **Security Engineer** | Interface connector configuration, webhook integrations, system performance matrices. |
| **SOC Analyst** | Live alert queue workflow parsing, on-demand enrichment, incident escalation pipelines. |
| **Executive** | Read-Only posture tracking analytics, automated metric summaries, board reporting. |

---

## 🛠️ Testing Environment Execution

The system establishes an automated verification framework leveraging explicit containment testing wrappers:

```bash
# Execute isolated unit profiles and ORM contract compliance checks
docker-compose exec api pytest app/tests/
```

Quality criteria configurations automatically lock delivery lines if total statement validation coverage values slip underneath an **80% coverage threshold limit**.
