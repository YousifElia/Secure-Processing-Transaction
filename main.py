from fastapi import FastAPI, HTTPException, Depends, Header, status
from pydantic import BaseModel, Field
from typing import Optional, Dict
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import sqlite3
import uuid

# --- CONFIGURATION ---
SECRET_KEY = "ripple_secret_key_demo"  # In real life, keep this safe!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(title="Ripple-Ready Payment API", description="Simulates a secure payment gateway.")

# --- SECURITY & AUTH ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = "Bearer"  # Simplified for this demo

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(authorization: str = Header(...)):
    """ dependency to protect endpoints """
    try:
        scheme, token = authorization.split()
        if scheme.lower() != 'bearer': raise HTTPException(status_code=401, detail="Invalid scheme")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# --- DATABASE (SQLite) ---
# We use SQLite so you have a real "persistence layer" as claimed on the resume.
def init_db():
    conn = sqlite3.connect('payments.db')
    c = conn.cursor()
    # Table for transactions
    c.execute('''CREATE TABLE IF NOT EXISTS transactions
                 (id TEXT PRIMARY KEY, amount REAL, status TEXT, 
                  card_last4 TEXT, fraud_score REAL, idempotency_key TEXT)''')
    conn.commit()
    conn.close()

init_db()

# --- MODELS ---
class PaymentRequest(BaseModel):
    card_number: str = Field(..., min_length=16, max_length=16)
    expiry: str
    cvv: str
    amount: float
    currency: str = "USD"
    merchant_id: str

class CaptureRequest(BaseModel):
    transaction_id: str

# --- CORE LOGIC ---

def run_fraud_check(card_number: str, amount: float) -> float:
    """Simulates a fraud engine. Returns a score 0-100."""
    score = 0
    if amount > 5000: score += 50  # High amount risk
    if card_number.startswith("1111"): score += 100  # Blacklisted BIN simulation
    return score

@app.post("/token")
def login():
    """Get a JWT token (Simulates logging in as a merchant)"""
    # In a real app, you'd check username/password here.
    access_token = create_access_token(data={"sub": "merchant_123"})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/payments/authorize")
def authorize_payment(
    req: PaymentRequest, 
    idempotency_key: str = Header(None),
    user: str = Depends(verify_token)
):
    """
    Step 1: Authorization. Checks funds and fraud, but doesn't take money yet.
    Demonstrates: Idempotency, Fraud Detection, Data Persistence.
    """
    conn = sqlite3.connect('payments.db')
    c = conn.cursor()

    # 1. Idempotency Check (Prevent double charging)
    if idempotency_key:
        c.execute("SELECT * FROM transactions WHERE idempotency_key=?", (idempotency_key,))
        existing = c.fetchone()
        if existing:
            return {"status": "success", "transaction_id": existing[0], "message": "Idempotent Replay"}

    # 2. Fraud Detection
    fraud_score = run_fraud_check(req.card_number, req.amount)
    if fraud_score >= 80:
        raise HTTPException(status_code=403, detail="Transaction blocked: High Fraud Risk")

    # 3. Create Transaction
    tx_id = str(uuid.uuid4())
    status_text = "AUTHORIZED"
    
    c.execute("INSERT INTO transactions VALUES (?, ?, ?, ?, ?, ?)", 
              (tx_id, req.amount, status_text, req.card_number[-4:], fraud_score, idempotency_key))
    conn.commit()
    conn.close()

    return {
        "transaction_id": tx_id,
        "status": status_text, 
        "amount_authorized": req.amount,
        "fraud_risk_score": fraud_score
    }

@app.post("/payments/capture")
def capture_payment(
    req: CaptureRequest,
    user: str = Depends(verify_token)
):
    """
    Step 2: Capture. Finalizes the money movement.
    Demonstrates: State Management (Authorized -> Captured).
    """
    conn = sqlite3.connect('payments.db')
    c = conn.cursor()
    
    # Check current state
    c.execute("SELECT status, amount FROM transactions WHERE id=?", (req.transaction_id,))
    row = c.fetchone()
    
    if not row:
        raise HTTPException(status_code=404, detail="Transaction not found")
    
    current_status = row[0]
    
    if current_status != "AUTHORIZED":
        raise HTTPException(status_code=400, detail=f"Cannot capture. Current status: {current_status}")

    # Update State
    c.execute("UPDATE transactions SET status='CAPTURED' WHERE id=?", (req.transaction_id,))
    conn.commit()
    conn.close()

    return {"transaction_id": req.transaction_id, "status": "CAPTURED", "message": "Funds settled"}

@app.post("/payments/refund")
def refund_payment(req: CaptureRequest, user: str = Depends(verify_token)):
    conn = sqlite3.connect('payments.db')
    c = conn.cursor()
    c.execute("UPDATE transactions SET status='REFUNDED' WHERE id=?", (req.transaction_id,))
    conn.commit()
    return {"transaction_id": req.transaction_id, "status": "REFUNDED"}
