# CyPay Core: Zero-Trust Financial Identity Shield

**Technology Stack:**
- Python 3.12+
- Flask 2.3+
- Stripe API
- Security: AES-256-GCM + HMAC-SHA512
- License: MIT

## Overview

CyPay is a next-generation peer-to-peer campus payment system built on the principle of **Continuous Identity and Zero Trust**. Rather than relying on traditional static passwords, CyPay utilizes facial biometric verification combined with real-time threat-scoring to authenticate and authorize financial transactions dynamically.

The entire backend and security apparatus—including the Risk Engine, Intrusion Detection System (IDS), Forensic Chain, and routing logic—is engineered inside a monolithic Flask application backed by an immutable SQLite ledger. Every transaction is cryptographically chained and auditable.

---

## Core Features

### 1. Biometric Authentication (Passwordless)
Accounts are tied directly to facial encodings generated via OpenCV and the `face_recognition` library. Static passwords are eliminated entirely, removing a major attack surface. Each transaction requires facial verification, ensuring only authorized users can access funds.

### 2. Live Risk Engine with Adaptive Response
Every transaction generates a real-time risk score (0-100) derived from:
- Velocity limits (transaction frequency in 60-second windows)
- Geolocation algorithms (campus perimeter validation)
- Session behavioral patterns (time-to-click, input rapidity)
- Device context (IP proximity, user agent fingerprinting)
- Biometric confidence (facial match Euclidean distance)

If critical thresholds are exceeded, the system automatically triggers step-up authentication or session lockout.

### 3. Intrusion Detection System (IDS)
The IDS continuously monitors the system for anomalous behavior mapped to the MITRE ATT&CK framework. It detects and responds to:
- Brute-force facial scan attempts
- Rapid velocity transfers (potential fraud)
- IP anomalies (impossible travel, geographic inconsistencies)
- Credential stuffing patterns
- Malformed API requests

When critical rules trigger, funds are automatically frozen pending review.

### 4. Forensic Audit Ledger (Immutable)
All system actions—authentications, risk assessments, transfers, and errors—are appended to an immutable audit ledger. Each entry is secured with HMAC-SHA512 cryptographic chaining, making tampering immediately detectable. This provides forensic traceability and compliance auditability.

### 5. Stripe API Integration
CyPay integrates securely with the Stripe Checkout API for fund additions. Users are redirected to a Stripe portal, and webhook callbacks verify transaction completion before crediting the internal ledger. This eliminates double-spend and spoofed fund injection vulnerabilities.

### 6. Responsive Web Interface
The frontend provides a modern, responsive UI with 3D visualization (Vanta.js WebGL globe) and precise CSS rendering for a clean, technical interface.

---

## Local Development Setup

## Local Development Setup

### Requirements
- Python 3.12 or higher
- Working webcam (for biometric enrollment and authentication)
- pip (Python package manager)

### Installation Steps

**1. Clone the Repository**
```bash
git clone https://github.com/ayaaan-sec/CyPay.git
cd CyPay
```

**2. Create and Activate Virtual Environment**
```bash
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
```

**3. Install Dependencies**
```bash
pip install -r requirements.txt
```

**4. Configure Environment Variables**
CyPay uses environment variables for secrets management. Copy the example file:

```bash
cp .env.example .env
```

Edit `.env` with your configuration:
```
STRIPE_SECRET_KEY=sk_test_...
CYPAY_MASTER_KEY=<64-character hex string for AES-256>
FLASK_SECRET_KEY=<secure random string for session signing>
```

**5. Run the Application**
```bash
python cypay_core.py
```

CyPay will:
- Initialize the SQLite database at `instance/cypay.db`
- Apply all SQLAlchemy schemas
- Start the Flask server on `http://localhost:5000`

---

## Architecture and Design

### System Architecture
CyPay uses a ledger-centric, append-only architecture rather than traditional relational databases:

- **User Table**: Stores account balances, user identifiers (SRN), names, and raw NumPy facial encodings
- **Transaction Table**: Double-entry accounting log for all debits and credits, balanced against Stripe API responses
- **IDSAlert Table**: Real-time security dashboard for SOC monitoring and threat response
- **ForensicLog Table**: Immutable append-only audit ledger linking every action to user identity and context

### Risk Engine Algorithm
The Risk Engine evaluates each transaction on a 0-100 scale using weighted multi-signal analysis:

| Signal | Weight | Description |
|--------|--------|-------------|
| Biometric Confidence (W_bio) | 40% | Facial match quality; degrades with Euclidean distance variance |
| Behavioral (W_beh) | 25% | Time-to-click, input velocity, session patterns |
| Device Context (W_dev) | 15% | User agent, IP proximity, trusted device tokens |
| Velocity (W_vel) | 15% | Transaction frequency within 60-second windows |
| Geolocation (W_geo) | 5% | Campus perimeter validation |

Scores above configured thresholds trigger adaptive authentication (re-scan requirement) or session lockout.

### Security Threat Mitigation

**STRIDE Framework Coverage:**
- **Spoofing**: Mitigated by mandatory facial biometric verification on all high-value transactions
- **Tampering**: AES-256-GCM encryption on database fields + HMAC-SHA512 chain validation on forensic logs
- **Repudiation**: IP logging, biometric state tracking, and immutable audit trail
- **Information Disclosure**: Error message sanitization prevents database schema leakage; API hardening
- **Denial of Service**: IP-based rate limiting triggers IDS Rule-013 to isolate malicious sources
- **Elevation of Privilege**: Role-based access control with strict context boundary enforcement

**MITRE ATT&CK Mappings:**
- `T1110` (Brute Force): Detected on sequential biometric verification failures
- `T1078` (Valid Accounts): Monitored via behavioral anomalies and velocity thresholds
- `T1550` (Network Service Scanning): Identified through malformed API payloads
- `T1190` (Credential Stuffing): Tracked via distributed origin patterns against single accounts

---

## API Usage

### Authentication Endpoints
- `POST /register` - Biometric enrollment with facial capture
- `POST /login` - Facial verification and session creation
- `POST /face_auth` - Transaction-level facial re-authentication

### Transaction Endpoints
- `GET /dashboard` - View account balance and transaction history
- `POST /transfer` - Initiate peer-to-peer transfer (requires facial verification)
- `POST /add_funds` - Redirect to Stripe for fund addition

### Security Endpoints
- `GET /security` - View security settings and device trust list
- `POST /security/trust_device` - Mark current device as trusted

---

## Database Schema

The application uses SQLite with the following core tables:

```
users
├── id (Primary Key)
├── name
├── email
├── password_hash
├── facial_encoding (NumPy array, serialized)
├── balance
└── created_at

transactions
├── id (Primary Key)
├── sender_id (Foreign Key)
├── receiver_id (Foreign Key)
├── amount
├── risk_score
├── status (pending, completed, failed)
└── timestamp

forensic_logs
├── id (Primary Key)
├── user_id
├── action (login, transfer, verification, etc.)
├── risk_score
├── ip_address
├── hmac_chain (Previous log HMAC for chain validation)
└── timestamp

ids_alerts
├── id (Primary Key)
├── user_id
├── rule_id
├── severity (low, medium, critical)
├── description
└── timestamp
```

---

## Security Considerations

### Current Implementation
- AES-256-GCM encryption for sensitive database fields
- HMAC-SHA512 cryptographic chaining for audit logs
- Facial biometric verification (no passwords)
- Real-time risk scoring and adaptive authentication
- IDS monitoring with MITRE ATT&CK coverage

### Recommended Future Enhancements
- Active liveness detection (anti-spoofing) for biometric verification
- Hardware security module (HSM) integration for key management
- Multi-signature authorization for high-value transfers
- Rate limiting per IP, per user, and per device
- Integration with external anomaly detection services
- Penetration testing and red team exercises

---

## Development Guidelines

### Code Organization
- `cypay_core.py` - Main application file containing all Flask routes, database models, and security logic
- `templates/` - HTML templates for UI
- `static/css/` - CSS stylesheets
- `instance/` - Runtime data (database, logs)

### Testing
Run the application with test data:
```bash
python cypay_core.py
```

Then navigate through the UI to test:
1. User enrollment with biometric capture
2. Login with facial verification
3. Transfer initiation and risk scoring
4. Security dashboard

For detailed testing procedures, see `TESTING.md`.

---

## License and Attribution

CyPay Core is provided under the **MIT License**. See the [LICENSE](LICENSE) file for full details.

Copyright (c) 2025 Ayaan Jaffar (https://github.com/ayaaan-sec)

### Important Disclaimer

The current CyPay implementation serves as an advanced proof-of-concept for Zero-Trust security principles in isolated environments. 

**Before production deployment**, the following security enhancements are strongly recommended:

1. **Liveness Detection**: Implement active anti-spoofing checks to prevent facial authentication bypass via static images or videos
2. **Code Audit**: Conduct professional security penetration testing and code review
3. **Compliance Review**: Validate compliance with relevant financial regulations (PCI-DSS, etc.)
4. **Monitoring**: Deploy comprehensive logging, alerting, and real-time incident response capabilities
5. **Key Management**: Integrate with Hardware Security Modules (HSM) or key management services

Use this implementation as a reference for zero-trust architecture patterns, not as production-ready code without additional hardening.

---

## Contributing

Contributions are welcome. Please ensure code follows security best practices and includes appropriate test coverage.

## Support

For questions or issues, please open an issue on GitHub or contact the author at https://github.com/ayaaan-sec
