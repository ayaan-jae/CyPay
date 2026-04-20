# Testing Guide

This document walks through how to manually test every feature in CampusPay. Start the server before running any tests.

## Starting the Server

```bash
cd c4mpu5_p4y
source venv/bin/activate
python cypay_core.py
```

The server runs on `http://localhost:5000`. The SQLite database is created automatically on first run.

---

## 1. Landing Page

**URL:** `http://localhost:5000/`

**What to verify:**
- The page loads with the hero section ("Continuous Identity. Zero Trust.")
- Six feature cards are displayed (Identity Engine, Risk Engine, Behavioral Biometrics, IDS Rule Engine, Red Team Simulator, Cryptography Layer)
- The navbar shows "Login" and "Register" links when not logged in
- Clicking "Get Started" navigates to `/register`
- Clicking "Sign In" navigates to `/login`

---

## 2. User Registration

**URL:** `http://localhost:5000/register`

**What to verify:**
- The form has four fields: Full Name, Date of Birth, Sex (dropdown), and SRN
- All fields are required (try submitting with empty fields -- the browser should block it)

**Test case -- successful registration:**
1. Fill in: Name = "Test User", DOB = any date, Sex = "Male", SRN = "TEST001"
2. Click "Continue to Face Enrollment"
3. You should be redirected to `/enroll/<user_id>`

**Test case -- duplicate SRN:**
1. Register with SRN = "TEST001" again
2. You should see a flash message: "SRN already registered"
3. You stay on the registration page

---

## 3. Face Enrollment

**URL:** `http://localhost:5000/enroll/<user_id>` (you are redirected here after registration)

**What to verify:**
- The page shows the user's name and SRN
- A camera preview box is displayed with corner markers and a scanning line animation
- The status text reads "Position your face in the frame"

**Test case -- successful enrollment:**
1. Allow camera access when prompted by the browser
2. Position your face clearly in the frame (good lighting, face fully visible)
3. Click "Capture & Enroll"
4. Status should change to "Processing..." then show a success message
5. After about 1.5 seconds you are redirected to `/login`

**Test case -- no face detected:**
1. Cover the camera or point it at a blank wall
2. Click "Capture & Enroll"
3. Status should show an error: "No face detected. Try better lighting."

**Test case -- camera denied:**
1. Deny camera access when the browser prompts
2. Status text should change to "Camera access denied"

---

## 4. Login (SRN Entry)

**URL:** `http://localhost:5000/login`

**What to verify:**
- A single field for SRN with a "Verify Identity" button
- A link to the registration page at the bottom

**Test case -- valid SRN:**
1. Enter the SRN you registered with (e.g., "TEST001")
2. Click "Verify Identity"
3. You should be redirected to `/face_auth`

**Test case -- invalid SRN:**
1. Enter a SRN that does not exist (e.g., "FAKE999")
2. Click "Verify Identity"
3. You should see a flash message: "Invalid SRN"
4. You stay on the login page

---

## 5. Face Authentication

**URL:** `http://localhost:5000/face_auth` (you are redirected here from login)

**What to verify:**
- The page shows the user's name and SRN
- Camera preview with scanning animation is displayed
- Status text reads "Look directly at the camera"

**Test case -- successful authentication:**
1. Make sure you are the same person who enrolled
2. Allow camera access
3. Click "Verify Identity"
4. If the face matches (confidence >= 60%), you see a success message with the confidence percentage
5. After about 1.2 seconds you are redirected to `/dashboard`

**Test case -- face mismatch:**
1. Have a different person attempt to authenticate, or cover the camera partially
2. Click "Verify Identity"
3. You should see an error with the confidence percentage: "Face mismatch (Confidence: XX%)"

**Test case -- no face in frame:**
1. Point the camera at a blank surface
2. Click "Verify Identity"
3. You should see: "No face detected"

**Test case -- brute force detection (IDS-001):**
1. Fail authentication 3 times within 60 seconds (use wrong faces or cover camera)
2. On the 3rd failure, the IDS brute-force rule fires
3. Go to the Security dashboard after logging in (or check the database) -- there should be an IDS alert with rule ID "IDS-001" and severity "CRITICAL"
4. A forensic log entry should exist with MITRE TTP "T1110.004"

---

## 6. Dashboard

**URL:** `http://localhost:5000/dashboard` (requires login)

**What to verify:**
- Welcome message with the user's name
- SRN displayed with a green session active indicator
- Four stat cards: Balance, Risk Score, Threat Level, Adaptive Response
- "Add Funds" form with an amount input and button
- Transaction History table (empty on first login, shows "No transactions yet")
- Forensic Log table showing recent events for this user

**Test case -- access without login:**
1. Log out or clear your session
2. Try visiting `http://localhost:5000/dashboard` directly
3. You should be redirected to `/login`

---

## 7. Add Funds

**Location:** Dashboard page, "Add Funds" section

**Test case -- valid amount:**
1. Enter amount: 1000
2. Click "Add Funds"
3. You should see a flash message: "1000.00 added successfully"
4. Balance stat card updates to show the new balance
5. A new entry appears in the Transaction History: "Funds added", +1000.00

**Test case -- zero or negative amount:**
1. Enter amount: 0 or -100
2. Click "Add Funds"
3. You should see a flash message: "Invalid amount"

---

## 8. Fund Transfer

**URL:** `http://localhost:5000/transfer` (requires login)

**Prerequisites:** You need at least two registered users. Register a second user with a different SRN (e.g., "TEST002") and enroll their face.

**What to verify:**
- The page shows the sender's current balance
- Two fields: Recipient SRN and Amount
- A note about risk scoring at the bottom

**Test case -- successful transfer:**
1. Make sure the sender has funds (add some via the dashboard first)
2. Enter recipient SRN: "TEST002"
3. Enter amount: 100
4. Click "Transfer Securely"
5. You should see a flash message: "100.00 sent to [recipient name] (TEST002)"
6. You are redirected to the dashboard
7. Balance is reduced by 100
8. Transaction History shows the debit entry

**Test case -- transfer to yourself:**
1. Enter your own SRN as the recipient
2. Click "Transfer Securely"
3. You should see: "Cannot transfer to yourself"

**Test case -- invalid recipient:**
1. Enter a SRN that does not exist
2. Click "Transfer Securely"
3. You should see: "Recipient SRN not found"

**Test case -- insufficient balance:**
1. Try to transfer more than your current balance
2. Click "Transfer Securely"
3. You should see: "Invalid amount or insufficient balance"

---

## 9. Security Dashboard

**URL:** `http://localhost:5000/security` (requires login)

**What to verify:**
- Header shows "Security Operations Center" with the number of active IDS rules
- IDS Rule Engine section lists all 10 rules with their triggers, responses, and severity badges
- Live IDS Alerts section shows any alerts that have been triggered (or "No active alerts -- all clear")
- Forensic Audit Ledger table shows all logged events across all users with: timestamp, event type, user ID, IP, risk score, risk level, MITRE TTP, IDS rule, and response
- Registered Identities table shows all users with their SRN, balance, biometric enrollment status, and creation date

**Test case -- after brute force:**
1. Trigger the brute-force test from section 5 above
2. Visit the Security dashboard
3. The "Live IDS Alerts" section should show at least one alert with rule ID "IDS-001" and the attacker's IP
4. The Forensic Audit Ledger should contain entries with event type "IDS_TRIGGER" and MITRE TTP "T1110.004"

---

## 10. Logout

**URL:** `http://localhost:5000/logout`

**What to verify:**
1. Click "Logout" in the navbar
2. You should be redirected to the landing page
3. The navbar should now show "Login" and "Register" instead of "Dashboard", "Transfer", "Security", and "Logout"
4. Trying to visit `/dashboard`, `/transfer`, or `/security` should redirect you to `/login`
5. A forensic log entry is created for the logout event

---

## 11. Risk Engine Verification

The risk score is visible on the dashboard. Since the current implementation adds a small random jitter to the baseline score, the risk score and threat level will vary slightly on each page load.

**What to verify:**
- The risk score is a number between 0 and 100
- The threat level badge matches the score:
  - 0--30 = LOW (green)
  - 31--59 = MEDIUM (amber)
  - 60--84 = HIGH (red)
  - 85--100 = CRITICAL (bright red)
- The Adaptive Response label shows the corresponding decision (ALLOW, CHALLENGE, STEP-UP AUTH, or CRITICAL)
- Refresh the dashboard a few times -- the score should fluctuate slightly around the baseline (default baseline is 15.0)

---

## 12. Forensic Chain Integrity

The forensic log uses HMAC-SHA512 chain hashing. You can verify this through the database.

**Steps:**
1. After performing several actions (register, login, transfer, logout), open the SQLite database:
   ```bash
   sqlite3 instance/cypay.db
   ```
2. Query the forensic logs:
   ```sql
   SELECT log_id, event_type, risk_score, chain_hash FROM forensic_log ORDER BY timestamp_utc;
   ```
3. Every row should have a non-null `chain_hash` value (128-character hex string)
4. Each hash should be different from the previous one
5. The `immutable` column should be `1` (true) for all entries

---

## 13. API Endpoint

**URL:** `http://localhost:5000/api/risk/<user_id>`

**Test case:**
1. Find a valid user ID (check the Registered Identities table on the Security dashboard, or query the database)
2. Open `http://localhost:5000/api/risk/1` in a browser or with curl:
   ```bash
   curl http://localhost:5000/api/risk/1
   ```
3. You should receive a JSON response like:
   ```json
   {
     "score": 14.2,
     "level": "LOW",
     "color": "#5cb85c",
     "response": {
       "decision": "ALLOW",
       "detail": "Session continues normally"
     }
   }
   ```

**Test case -- invalid user ID:**
1. Try `http://localhost:5000/api/risk/9999`
2. You should get a 404 response

---

## 14. Responsive Layout

**What to verify:**
1. Open the app in a desktop browser -- the layout should use multi-column grids
2. Open browser developer tools and toggle device emulation (mobile view)
3. The landing page hero text should shrink
4. The stats grid on the dashboard should collapse to 2 columns
5. The security dashboard grid should collapse to a single column
6. The navbar should remain functional at narrow widths

---

## Quick Smoke Test Checklist

Run through this checklist to verify the core flow end-to-end:

```
[ ] Server starts without errors
[ ] Landing page loads at http://localhost:5000
[ ] Register user with SRN "SMOKE01"
[ ] Face enrollment captures and stores encoding
[ ] Login with SRN "SMOKE01" redirects to face auth
[ ] Face auth succeeds and redirects to dashboard
[ ] Dashboard shows balance, risk score, threat level
[ ] Add 500 funds -- balance updates
[ ] Register a second user with SRN "SMOKE02"
[ ] Log back in as SMOKE01
[ ] Transfer 100 to SMOKE02 -- balance decreases
[ ] Security dashboard shows forensic logs for all actions
[ ] Logout redirects to landing page
[ ] Cannot access dashboard after logout
```
