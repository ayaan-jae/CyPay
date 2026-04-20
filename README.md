# CyPay Core: Zero-Trust Financial Identity Shield

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3+-lightgrey.svg)](https://flask.palletsprojects.com/)
[![Stripe API](https://img.shields.io/badge/Stripe-Payment_Integration-indigo.svg)](https://stripe.com)
[![Security](https://img.shields.io/badge/Security-AES--256--GCM%20%7C%20HMAC-Success.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#)

CyPay is a next-generation peer-to-peer campus payment system built entirely on the principle of **Continuous Identity and Zero Trust**. Replacing traditional static passwords, CyPay utilizes facial biometric verification combined with real-time threat-scoring to authenticate and authorize financial transactions dynamically.

The entire backend and security apparatus—including the Risk Engine, Intrusion Detection System (IDS), Forensic Chain, and routing logic—is engineered inside a highly secure, monolithic Flask execution file backed by an immutable SQLite ledger.

---

## ✦ Core Features

### 1. Biometric Authentication (Passwordless)
Accounts are tied directly to facial encodings generated via OpenCV and `face_recognition` models. Static passwords, which are easily breached or shared, do not exist in this ecosystem.

### 2. Live Risk Engine & Adaptive Response
Every transaction generates a real-time risk score `R [0,100]` derived from velocity limits, geometric location algorithms, and session context. The system automatically steps up authentication (e.g., forcing a biometric re-scan) or locks the session via its Adaptive Response logic if critical threat thresholds are breached.

### 3. Intrusion Detection System (IDS)
An active anomaly detection matrix mapped directly to the **MITRE ATT&CK** framework. The system actively monitors for brute-force facial scans, rapid velocity transfers, and IP anomalies, automatically freezing funds when Critical rules trigger.

### 4. Forensic Audit Ledger (Immutable)
All system actions, authentications, risk assessments, and financial transfers are appended to an immutable audit ledger secured by HMAC-SHA512 cryptographic chaining. Logs cannot be tampered with or deleted without breaking the chain validation.

### 5. Stripe API Integration
CyPay integrates securely with the Stripe Checkout API. Users adding funds to their ledger are redirected to a secure Stripe portal. Webhooks/callback success loops mathematically verify the transaction status before crediting the internal database, ensuring zero double-spend or spoofed fund injections.

### 6. Modern 3D Interface
The frontend features a bleeding-edge, highly responsive aesthetic built over an interactive Vanta.js 3D WebGL globe. It utilizes precise CSS filtering and translucency gradients to provide a clean, technical HUD interface.

---

## ✦ Local Development & Quickstart

To run CyPay securely on your local machine, ensure you have Python 3.12+ installed and a working webcam.

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/cypay.git
cd cypay
```

### 2. Configure Virtual Environment & Dependencies
```bash
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Environment Variables & Stripe Initialization
CyPay utilizes `python-dotenv` to ensure secrets are never hardcoded. 
Copy the provided example file to create your local environment file:

```bash
cp .env.example .env
```

Open `.env` in your text editor and configure your secrets:
- **STRIPE_SECRET_KEY**: Your Stripe Test API Secret Key (`sk_test_...`).
- **CYPAY_MASTER_KEY**: A 64-character hex string representing AES 256 keys.
- **FLASK_SECRET_KEY**: Your secure session signing key.

### 4. Run the Engine
```bash
python cypay_core.py
```
CyPay will automatically generate `instance/cypay.db`, apply all SQLAlchemy schemas, and initialize the Zero-Trust environment on `http://localhost:5000`.

---

<details>
<summary><b>▸ Deep Dive: Security Threat Modeling (STRIDE / MITRE)</b> (Click to expand)</summary>

### Threat Modeling via STRIDE
- **Spoofing**: Mitigated by facial biometric encoding requirement at every high-level transaction step.
- **Tampering**: Blocked by AES-256-GCM encryption on database payloads and the HMAC-SHA512 Forensic Chain.
- **Repudiation**: Prevented by strict logging of IP, biometric verification state, and session tokens mapped to immutable logs.
- **Information Disclosure**: API route hardening and failure sanitization ensures verbose database errors are never exposed to clients.
- **Denial of Service**: IP rate limiting triggers IDS Rule-013, isolating the offending vector.
- **Elevation of Privilege**: Role-based access control enforces strict context boundary mapping across transfer boundaries.

### MITRE ATT&CK Mappings
The CyPay internal IDS system continuously monitors the execution environment for designated MITRE behaviors:
- `T1110` (Brute Force): Detected dynamically upon sequential biometric failures.
- `T1190` (Credential Stuffing): Tracked via distributed origin patterns against single accounts.
- `T1550` (Network Service Scanning): Identified through malformed transfer payload injections.
- `T1078` (Valid Accounts): Checked against behavioral anomalies and unexpected transaction velocities.

</details>

<details>
<summary><b>▸ Deep Dive: Algorithmic Risk Engine Weights</b> (Click to expand)</summary>

The Risk Engine scores `R` bounded between `[0,100]` for every transaction, utilizing weighted multi-signal logic:

- **W(bio)**: Biometric Confidence (Weight: 40%) - Degrades exponentially based on face match Euclidean distance variations over time.
- **W(beh)**: Behavioral (Weight: 25%) - Time-to-click, input rapidity, session lifespan anomalies.
- **W(dev)**: Device Context (Weight: 15%) - UA strings, IP proximity, and trusted device tokens.
- **W(vel)**: Velocity (Weight: 15%) - Volumetric frequency of transactions in `T-minus 60 seconds`.
- **W(geo)**: Location Constraint (Weight: 5%) - Geofence restrictions to campus perimeters.

</details>

<details>
<summary><b>▸ System Architecture and Data Storage</b> (Click to expand)</summary>

CyPay abandons legacy relational coupling for a ledger-centric append-only architecture:
- `User`: Stores balances, names, SRNs, and raw NumPy facial encodings.
- `Transaction`: Double-entry accounting log for debit/credit balancing against external APIs (Stripe).
- `IDSAlert`: Dynamic security dashboard table for live SOC monitoring.
- `ForensicLog`: The strict append-only audit backbone linking identity directly to system action contexts.

</details>

---

## ✦ License & Usage Restrictions
This system is provided under the **MIT License**.

> **Note:** The current CyPay core serves as an implementation schema and advanced proof-of-concept for Zero-Trust principles within isolated perimeters. Active physical liveness detection (anti-spoofing) is recommended as a secondary extension before deploying CyPay in unmonitored production environments.
