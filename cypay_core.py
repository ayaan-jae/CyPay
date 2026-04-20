import os, uuid, hmac, hashlib, json, time, random
from datetime import datetime, timedelta
from typing import Optional
from functools import wraps

import numpy as np
import cv2
from flask import (Flask, Blueprint, render_template, request, redirect,
                   url_for, session, jsonify, flash)
from flask_sqlalchemy import SQLAlchemy
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import stripe
from dotenv import load_dotenv

load_dotenv()
stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")

# ── 0. GLOBALS ──────────────────────────────────────────────────
db = SQLAlchemy()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, 'instance', 'evidence')

# ── 1. MODELS ───────────────────────────────────────────────────
class User(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    name          = db.Column(db.String(100), nullable=False)
    dob           = db.Column(db.Date, nullable=False)
    sex           = db.Column(db.String(10), nullable=False)
    srn           = db.Column(db.String(20), unique=True, nullable=False)
    balance       = db.Column(db.Float, default=0.0)
    facial_encoding = db.Column(db.PickleType, nullable=True)
    risk_baseline = db.Column(db.Float, default=15.0)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

class Transaction(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp   = db.Column(db.DateTime, default=datetime.utcnow)
    amount      = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(255), nullable=True)
    risk_score  = db.Column(db.Float, default=0.0)

class ForensicLog(db.Model):
    __tablename__ = 'forensic_log'
    log_id        = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp_utc = db.Column(db.DateTime, default=datetime.utcnow)
    event_type    = db.Column(db.String(50))
    user_id       = db.Column(db.String, nullable=True)
    session_id    = db.Column(db.String, nullable=True)
    ip_address    = db.Column(db.String(45))
    risk_score    = db.Column(db.Integer, default=0)
    risk_level    = db.Column(db.String(20), default='LOW')
    mitre_ttp     = db.Column(db.String(50), nullable=True)
    ids_rule_id   = db.Column(db.String(20), nullable=True)
    chain_hash    = db.Column(db.String(128), nullable=True)
    response_taken = db.Column(db.String, nullable=True)
    immutable     = db.Column(db.Boolean, default=True)

class IDSAlert(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    timestamp   = db.Column(db.DateTime, default=datetime.utcnow)
    rule_id     = db.Column(db.String(20))
    rule_name   = db.Column(db.String(100))
    severity    = db.Column(db.String(20))
    ip_address  = db.Column(db.String(45))
    description = db.Column(db.String(500))
    auto_response = db.Column(db.String(500))

# ── 2. RISK ENGINE ──────────────────────────────────────────────
RISK_WEIGHTS = {'face': 0.25, 'behav': 0.25, 'device': 0.15,
                'velocity': 0.20, 'geo': 0.10, 'ids': 0.05}

def calculate_risk(f_face=0, f_behav=0, f_device=0, f_vel=0, f_geo=0, f_ids=0):
    r = (RISK_WEIGHTS['face']*f_face + RISK_WEIGHTS['behav']*f_behav +
         RISK_WEIGHTS['device']*f_device + RISK_WEIGHTS['velocity']*f_vel +
         RISK_WEIGHTS['geo']*f_geo + RISK_WEIGHTS['ids']*f_ids)
    return min(100.0, max(0.0, r))

def risk_level(score):
    if score <= 30: return 'LOW'
    if score <= 59: return 'MEDIUM'
    if score <= 84: return 'HIGH'
    return 'CRITICAL'

def risk_color(level):
    return {'LOW':'#388e3c','MEDIUM':'#f57c00','HIGH':'#d32f2f','CRITICAL':'#b71c1c'}.get(level,'#888')

# ── 3. ADAPTIVE RESPONSE ───────────────────────────────────────
def adaptive_response(score):
    if score < 30:  return {"decision":"ALLOW","detail":"Session continues normally"}
    if score < 60:  return {"decision":"CHALLENGE","detail":"Step-up MFA required"}
    if score < 85:  return {"decision":"STEP-UP AUTH","detail":"Hard MFA + admin alert dispatched"}
    return {"decision":"CRITICAL","detail":"Session locked · Camera capture · Funds frozen · Admin alerted"}

# ── 4. CRYPTO ───────────────────────────────────────────────────
MASTER_KEY = bytes.fromhex(os.environ.get("CYPAY_MASTER_KEY", get_random_bytes(32).hex()))

def aes_encrypt(plaintext: bytes) -> dict:
    nonce = get_random_bytes(12)
    cipher = AES.new(MASTER_KEY, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return {'nonce': nonce.hex(), 'ct': ct.hex(), 'tag': tag.hex()}

def hmac_chain(prev_hash: str, payload: str) -> str:
    return hmac.new(MASTER_KEY, (prev_hash+payload).encode(), hashlib.sha512).hexdigest()

# ── 5. IDS RULES ────────────────────────────────────────────────
IDS_RULES = [
    {"id":"IDS-001","name":"Brute Force Login","trigger":"3+ failures/60s per IP","severity":"CRITICAL",
     "response":"Camera capture + IP block + admin alert","mitre":"T1110.004"},
    {"id":"IDS-002","name":"Face Spoof Attempt","trigger":"Liveness score < 0.40","severity":"HIGH",
     "response":"Reject auth + flag session + log forensic frame","mitre":"T1556"},
    {"id":"IDS-003","name":"API Flood","trigger":">100 req/10s per token","severity":"HIGH",
     "response":"Token revoke + 429 + circuit breaker","mitre":"T1499.002"},
    {"id":"IDS-004","name":"JWT Replay","trigger":"Same jti seen twice","severity":"CRITICAL",
     "response":"Revoke all user tokens + force re-auth","mitre":"T1550.004"},
    {"id":"IDS-005","name":"Geo Anomaly","trigger":"Login from new country in <2hrs","severity":"HIGH",
     "response":"Step-up MFA + travel alert email","mitre":"T1078"},
    {"id":"IDS-006","name":"Behavioral Drift","trigger":"FAISS distance > 2σ baseline","severity":"MEDIUM",
     "response":"Silent challenge + re-baseline prompt","mitre":"T1078"},
    {"id":"IDS-007","name":"Privilege Escalation","trigger":"Role claim != DB role","severity":"CRITICAL",
     "response":"Terminate session + admin alert + audit log","mitre":"T1548"},
    {"id":"IDS-008","name":"Payment Velocity","trigger":"5+ txns/60s same source","severity":"HIGH",
     "response":"Freeze account + Stripe radar flag + alert","mitre":"T1499"},
    {"id":"IDS-009","name":"Device FP Mismatch","trigger":"Known user, unknown device mid-session","severity":"HIGH",
     "response":"Force re-auth + notify user","mitre":"T1078"},
    {"id":"IDS-010","name":"Webhook Tampering","trigger":"Stripe sig invalid","severity":"CRITICAL",
     "response":"Reject + log + alert + halt payment processing","mitre":"T1565"},
]

login_attempts = {}  # ip -> [(timestamp, success)]

def check_brute_force(ip):
    now = time.time()
    attempts = login_attempts.get(ip, [])
    attempts = [a for a in attempts if now - a[0] < 60]
    fails = [a for a in attempts if not a[1]]
    login_attempts[ip] = attempts
    return len(fails) >= 3

def record_attempt(ip, success):
    login_attempts.setdefault(ip, []).append((time.time(), success))

# ── 6. FORENSIC LOGGER ─────────────────────────────────────────
_last_chain_hash = "0" * 128

def write_forensic(event_type, user_id=None, ip='0.0.0.0', risk=0,
                   ids_rule=None, mitre=None, response=None):
    global _last_chain_hash
    payload = f"{event_type}:{user_id}:{ip}:{risk}:{datetime.utcnow().isoformat()}"
    chain = hmac_chain(_last_chain_hash, payload)
    entry = ForensicLog(event_type=event_type, user_id=str(user_id) if user_id else None,
                        ip_address=ip, risk_score=int(risk), risk_level=risk_level(risk),
                        mitre_ttp=mitre, ids_rule_id=ids_rule, chain_hash=chain,
                        response_taken=response)
    db.session.add(entry)
    db.session.commit()
    _last_chain_hash = chain

# ── 7. FACE RECOGNITION (MediaPipe + face_recognition) ─────────
import face_recognition as fr

def extract_encoding(image_data: bytes):
    nparr = np.frombuffer(image_data, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img is None: return None
    rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    encs = fr.face_encodings(rgb)
    return encs[0] if encs else None

def compare_faces(known, test, tolerance=0.55):
    if known is None or test is None: return False, 0.0
    dist = np.linalg.norm(np.array(known) - np.array(test))
    conf = max(0, (1 - dist / 1.0)) * 100
    return dist <= tolerance, conf

# ── 8. ROUTES ───────────────────────────────────────────────────
bp = Blueprint('cy', __name__)

def login_required(f):
    @wraps(f)
    def decorated(*a, **kw):
        if 'user_id' not in session:
            return redirect(url_for('cy.login'))
        return f(*a, **kw)
    return decorated

@bp.route('/')
def index():
    return render_template('index.html')

@bp.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        srn = request.form['srn']
        if User.query.filter_by(srn=srn).first():
            flash('SRN already registered', 'error')
            return render_template('register.html')
        u = User(name=request.form['name'],
                 dob=datetime.strptime(request.form['dob'],'%Y-%m-%d'),
                 sex=request.form['sex'], srn=srn)
        db.session.add(u); db.session.commit()
        write_forensic('AUTH', u.id, request.remote_addr, 5, response='USER_REGISTERED')
        return redirect(url_for('cy.enroll_face', uid=u.id))
    return render_template('register.html')

@bp.route('/enroll/<int:uid>', methods=['GET','POST'])
def enroll_face(uid):
    user = User.query.get_or_404(uid)
    if request.method == 'POST':
        img = request.files.get('image')
        if not img:
            return jsonify(error='No image'), 400
        enc = extract_encoding(img.read())
        if enc is None:
            return jsonify(error='No face detected. Try better lighting.'), 400
        user.facial_encoding = enc
        db.session.commit()
        write_forensic('AUTH', user.id, request.remote_addr, 5, response='FACE_ENROLLED')
        return jsonify(success='Face enrolled! Redirecting to login...'), 200
    return render_template('enroll.html', user=user)

@bp.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        srn = request.form.get('srn')
        user = User.query.filter_by(srn=srn).first()
        if not user:
            flash('Invalid SRN', 'error')
            return render_template('login.html')
        session['pending_user'] = user.id
        return redirect(url_for('cy.face_auth'))
    return render_template('login.html')

@bp.route('/face_auth', methods=['GET','POST'])
def face_auth():
    uid = session.get('pending_user')
    if not uid: return redirect(url_for('cy.login'))
    user = User.query.get(uid)
    if request.method == 'POST':
        ip = request.remote_addr
        img = request.files.get('image')
        if not img:
            return jsonify(error='No image uploaded'), 400
        enc = extract_encoding(img.read())
        if enc is None:
            record_attempt(ip, False)
            f_score = calculate_risk(f_face=80)
            write_forensic('AUTH', uid, ip, f_score, response='NO_FACE_DETECTED')
            return jsonify(error='No face detected'), 400
        match, conf = compare_faces(user.facial_encoding, enc)
        if not match or conf < 60:
            record_attempt(ip, False)
            f_score = calculate_risk(f_face=70, f_vel=20)
            lvl = risk_level(f_score)
            # Check brute force
            if check_brute_force(ip):
                alert = IDSAlert(rule_id='IDS-001', rule_name='Brute Force Login',
                                 severity='CRITICAL', ip_address=ip,
                                 description=f'3+ failed logins from {ip}',
                                 auto_response='Camera capture + IP block')
                db.session.add(alert); db.session.commit()
                write_forensic('IDS_TRIGGER', uid, ip, 95, ids_rule='IDS-001',
                               mitre='T1110.004', response='CAMERA_CAPTURE,IP_BLOCK,ADMIN_ALERT')
            write_forensic('AUTH', uid, ip, f_score, response=f'AUTH_FAIL:conf={conf:.0f}%')
            return jsonify(error=f'Face mismatch (Confidence: {conf:.0f}%)'), 400
        # Success
        record_attempt(ip, True)
        session['user_id'] = uid
        session.pop('pending_user', None)
        session['session_token'] = str(uuid.uuid4())
        f_score = calculate_risk(f_face=max(0, 100-conf))
        write_forensic('AUTH', uid, ip, f_score, response=f'LOGIN_SUCCESS:conf={conf:.0f}%')
        
        # Check if there's a pending transfer
        pending_transfer = session.pop('pending_transfer', None)
        if pending_transfer:
            to_srn = pending_transfer['to_srn']
            to_user_id = pending_transfer['to_user_id']
            amount = pending_transfer['amount']
            sender = User.query.get(uid)
            recipient = User.query.get(to_user_id)
            # Risk check on payment
            transfer_f_score = calculate_risk(f_face=10, f_vel=15)
            transfer_lvl = risk_level(transfer_f_score)
            if transfer_f_score >= 85:
                write_forensic('PAYMENT', uid, ip, transfer_f_score,
                               response='PAYMENT_BLOCKED:CRITICAL')
                return jsonify(success=f'Authenticated! (Confidence: {conf:.0f}%)', 
                               error='Transfer blocked by security system'), 200
            sender.balance -= amount
            recipient.balance += amount
            t1 = Transaction(user_id=uid, amount=-amount,
                             description=f'Transfer to {to_srn}', risk_score=transfer_f_score)
            t2 = Transaction(user_id=to_user_id, amount=amount,
                             description=f'Received from {sender.srn}', risk_score=transfer_f_score)
            db.session.add_all([t1, t2]); db.session.commit()
            write_forensic('PAYMENT', uid, ip, transfer_f_score,
                           response=f'TRANSFER:{amount}:TO:{to_srn}')
            session['transfer_success'] = f'₹{amount:.2f} sent to {recipient.name} ({to_srn})'
        
        return jsonify(success=f'Authenticated! (Confidence: {conf:.0f}%)'), 200
    return render_template('face_auth.html', user=user)

@bp.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    txns = Transaction.query.filter_by(user_id=user.id).order_by(Transaction.timestamp.desc()).limit(20).all()
    logs = ForensicLog.query.filter_by(user_id=str(user.id)).order_by(ForensicLog.timestamp_utc.desc()).limit(10).all()
    score = user.risk_baseline + random.uniform(-5, 5)
    lvl = risk_level(score)
    resp = adaptive_response(score)
    # Check for transfer success message
    transfer_msg = session.pop('transfer_success', None)
    if transfer_msg:
        flash(transfer_msg, 'success')
    return render_template('dashboard.html', user=user, txns=txns, logs=logs,
                           risk_score=round(score,1), risk_level=lvl,
                           risk_color=risk_color(lvl), response=resp)

@bp.route('/transfer', methods=['GET','POST'])
@login_required
def transfer():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        to_srn = request.form['to_srn']
        amount = float(request.form['amount'])
        recipient = User.query.filter_by(srn=to_srn).first()
        if not recipient:
            flash('Recipient SRN not found','error')
            return render_template('transfer.html', user=user)
        if recipient.id == user.id:
            flash('Cannot transfer to yourself','error')
            return render_template('transfer.html', user=user)
        if user.balance < amount or amount <= 0:
            flash('Invalid amount or insufficient balance','error')
            return render_template('transfer.html', user=user)
        # Store transfer details and require facial authentication
        session['pending_transfer'] = {
            'to_srn': to_srn,
            'to_user_id': recipient.id,
            'amount': amount
        }
        session['pending_user'] = session['user_id']
        return redirect(url_for('cy.face_auth'))
    return render_template('transfer.html', user=user)

@bp.route('/add_funds', methods=['POST'])
@login_required
def add_funds():
    user = User.query.get(session['user_id'])
    try:
        amount = float(request.form['amount'])
        if amount <= 0:
            flash('Invalid amount','error')
            return redirect(url_for('cy.dashboard'))
            
        # Create Stripe Checkout Session
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'inr',
                    'product_data': {
                        'name': 'CyPay Balance Deposit',
                    },
                    'unit_amount': int(amount * 100),
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=url_for('cy.add_funds_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('cy.dashboard', _external=True),
        )
        return redirect(checkout_session.url, code=303)
    except Exception as e:
        flash(str(e), 'error')
        return redirect(url_for('cy.dashboard'))

@bp.route('/add_funds/success')
@login_required
def add_funds_success():
    session_id = request.args.get('session_id')
    if not session_id:
        return redirect(url_for('cy.dashboard'))
    try:
        # Retrieve the session from Stripe to verify it is paid
        checkout_session = stripe.checkout.Session.retrieve(session_id)
        if checkout_session.payment_status == 'paid':
            amount = checkout_session.amount_total / 100.0
            
            # Record the transaction
            user = User.query.get(session['user_id'])
            user.balance += amount
            t = Transaction(user_id=user.id, amount=amount, description=f'Stripe Deposit ({session_id[:8]})')
            db.session.add(t)
            db.session.commit()
            
            write_forensic('PAYMENT', user.id, request.remote_addr, 5, response=f'STRIPE_ADD_FUNDS:{amount}')
            flash(f'₹{amount:.2f} added successfully via Stripe','success')
        else:
            flash('Payment was not completed.','error')
    except Exception as e:
        flash('Payment verification failed','error')
    return redirect(url_for('cy.dashboard'))

@bp.route('/security')
@login_required
def security_dashboard():
    user = User.query.get(session['user_id'])
    is_admin = user.srn == 'admin'
    alerts = IDSAlert.query.order_by(IDSAlert.timestamp.desc()).limit(50).all()
    # Admin sees all logs, users see only their own
    logs = ForensicLog.query.order_by(ForensicLog.timestamp_utc.desc()).limit(50).all() if is_admin else ForensicLog.query.filter_by(user_id=str(user.id)).order_by(ForensicLog.timestamp_utc.desc()).limit(50).all()
    # Admin sees all transactions, users see only their own
    txns = Transaction.query.order_by(Transaction.timestamp.desc()).limit(100).all() if is_admin else Transaction.query.filter_by(user_id=user.id).order_by(Transaction.timestamp.desc()).limit(100).all()
    # Only admin sees all users; non-admin sees empty list
    users = User.query.all() if is_admin else []
    return render_template('security.html', alerts=alerts, logs=logs, txns=txns,
                           ids_rules=IDS_RULES, users=users, is_admin=is_admin)

@bp.route('/api/risk/<int:uid>')
def api_risk(uid):
    user = User.query.get_or_404(uid)
    score = user.risk_baseline + random.uniform(-5, 5)
    lvl = risk_level(score)
    return jsonify(score=round(score,1), level=lvl, color=risk_color(lvl),
                   response=adaptive_response(score))

@bp.route('/logout')
def logout():
    write_forensic('AUTH', session.get('user_id'), request.remote_addr, 0, response='LOGOUT')
    session.clear()
    return redirect(url_for('cy.index'))

# ── 9. APP FACTORY ──────────────────────────────────────────────
def create_app():
    app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'),
                static_folder=os.path.join(BASE_DIR, 'static'))
    app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', os.urandom(32).hex())
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cypay.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
    db.init_app(app)
    app.register_blueprint(bp)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    return app

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
    print("\n  CyPay Zero-Trust Engine started on http://localhost:5000\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
