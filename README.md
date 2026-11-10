# Product No. 37: Incident Response Panic Button
> **Automated Cloud Incident Response Playbook for AWS & LocalStack**  
> *Batch 41 & 42 • Team Project*

---

## 🛡️ Overview
* **The Problem:** When an Amazon S3 bucket is accidentally made public or credentials leak, manually navigating the AWS Console to locate the bucket and block public access takes critical minutes.
* **The Solution:** A single-click emergency containment tool that enforces an S3 Public Access Block, alerts the team via Amazon SNS, and produces an audit record in under two seconds.
* **Proof of Lockdown:** Evaluators can directly observe the public S3 URL switch from **HTTP 200 OK (leaking data)** to **HTTP 403 Forbidden (`AccessDenied`)** in real time.

---

## 🌐 Port Architecture & Services

| Port / Address | Service / Purpose | What You Can Inspect Here |
| :--- | :--- | :--- |
| **`http://localhost:8000`** | **Web Console & Dev Server** | Clean containment UI, lockdown trigger, and live public access inspector. |
| **`http://localhost:8000/verify-access`** | **Verification Probe Endpoint** | Returns live JSON indicating whether public access is allowed (200) or denied (403). |
| **`http://localhost:4566`** | **LocalStack Edge Gateway** | Emulates AWS Cloud services (S3, Lambda, API Gateway, SNS, IAM, CloudWatch). |
| **`http://localhost:4566/_localstack/health`** | **LocalStack Healthcheck** | Inspects operational status of all active AWS services. |
| **`4510-4559`** | **LocalStack Service Ports** | Dynamically allocated ports for external AWS service bindings. |

---

## 👥 Team Roles & Responsibilities

| Member Name | Hall Ticket No | Role & Deliverables |
| :--- | :---: | :--- |
| **Ch. Yogi** | `2503A51208` | **Frontend & UI** — Minimalist incident console and live lockdown verification panel. |
| **V. Sri Charan** | `2503A51218` | **Backend & API Orchestration** — API Gateway endpoint routing and verification endpoints. |
| **G. Saketha Vardhan** | `2503A51223` | **Remediation & Incident Automation** — Python 3 & Boto3 Lambda playbook execution. |
| **G. Bala Aditya Reddy** | `2503A51226` | **Cloud Infrastructure & IAM** — LocalStack environment, Docker config, and SNS alert topics. |
| **P. Jashwanth Rao** | `2503A51234` | **Testing & Validation** — Automated test suite and SLA benchmarks. |

---

## 🏗️ Architecture & Verification Flow

```mermaid
sequenceDiagram
    autonumber
    actor Attacker as 🌐 Public / Attacker
    actor SecOps as 👤 SecOps Operator
    participant UI as 🖥️ Console (Port 8000)
    participant Edge as 🚪 LocalStack Gateway (Port 4566)
    participant Lambda as ⚡ Remediation Lambda
    participant S3 as 🪣 Target S3 Bucket
    participant SNS as 📢 SNS Alert Topic

    Note over Attacker,S3: BEFORE LOCKDOWN: Data Exposed
    Attacker->>Edge: GET /confidential-company-data/customer_records_2026.csv
    Edge->>S3: Read object
    S3-->>Attacker: HTTP 200 OK (Customer Data Leaking)

    Note over SecOps,SNS: LOCKDOWN EXECUTION (< 2.0s)
    SecOps->>UI: Clicks "Execute Emergency Lockdown"
    UI->>Edge: POST /panic
    Edge->>Lambda: Invokes Playbook
    Lambda->>S3: put_public_access_block(All 4 flags = True)
    Lambda->>SNS: publish(SEV-1 Lockdown Notice)
    Lambda-->>UI: HTTP 200 OK (Secured)

    Note over Attacker,S3: AFTER LOCKDOWN: Verified Blocked
    Attacker->>Edge: GET /confidential-company-data/customer_records_2026.csv
    Edge->>S3: Blocked by PublicAccessBlock
    S3-->>Attacker: HTTP 403 Forbidden (AccessDenied)
```

---

## 🚀 How to Run & Verify

### Step 1: Start the Development Server
```bash
python3 backend/mock_server.py
```
Open **`http://localhost:8000`** in your browser.

### Step 2: Observe the Exposed State (Before Lockdown)
* Look at the **Lockdown Verification** card at the bottom.
* It shows **`200 OK · Publicly Accessible`** with a preview of the customer records.
* You can also verify via terminal:
  ```bash
  curl -i http://localhost:8000/verify-access
  ```

### Step 3: Trigger Emergency Lockdown
1. Check **Arm trigger to enable emergency lockdown**.
2. Click **Execute Emergency Lockdown**.
3. In under 200ms, the status updates to **`Locked Down (Secured)`**.

### Step 4: Verify Public Access is Denied (After Lockdown)
* The **Lockdown Verification** card automatically updates to **`403 Forbidden · Access Denied`**.
* The response payload immediately switches to `<Code>AccessDenied</Code>`.
* Confirm via terminal:
  ```bash
  curl -i http://localhost:8000/verify-access
  ```
  *(Returns `403 Forbidden` proof)*

---

### Running with Docker LocalStack (Full AWS Stack)
To run against a containerized LocalStack instance on Port 4566:

1. Start LocalStack:
   ```bash
   cd infra
   docker compose up -d
   ```
2. Provision cloud resources:
   ```bash
   ./init_resources.sh
   ```
3. Test unauthenticated access directly against port 4566:
   ```bash
   curl -i http://localhost:4566/confidential-company-data/customer_records_2026.csv
   ```
   *(Returns `403 Forbidden` once the panic button runs)*

---

## 🧪 Automated Tests

Run the test suite:
```bash
python3 -m unittest discover tests
```
Output:
```text
....
----------------------------------------------------------------------
Ran 4 tests in 0.013s

OK
```
