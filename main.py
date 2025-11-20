import os
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User, Session, Deposit, Loan, Message, AuditLog, Settings

app = FastAPI(title="Community Savings API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# Helpers

def oid(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")


def get_settings() -> Settings:
    s = db["settings"].find_one({})
    if not s:
        settings = Settings().model_dump()
        settings["created_at"] = datetime.now(timezone.utc)
        db["settings"].insert_one(settings)
        s = settings
    return Settings(**{k: v for k, v in s.items() if k in Settings.model_fields})


def hash_password(password: str, salt: Optional[str] = None):
    import hashlib, secrets
    if not salt:
        salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return h, salt


def verify_password(password: str, salt: str, password_hash: str) -> bool:
    import hashlib
    return hashlib.sha256((salt + password).encode()).hexdigest() == password_hash


# Pydantic models for requests/responses (no passwords in responses)
class SignUpRequest(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    role: str  # 'member' or 'admin'


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class AuthResponse(BaseModel):
    token: str
    user_id: str
    full_name: str
    role: str
    avatar_url: Optional[str] = None


# Authentication Endpoints
@app.post("/auth/signup", response_model=AuthResponse)
def signup(payload: SignUpRequest):
    role = payload.role.lower()
    if role not in ["member", "admin"]:
        raise HTTPException(status_code=400, detail="Invalid role")

    existing = db["user"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    if role == "admin":
        admin_count = db["user"].count_documents({"role": "admin"})
        if admin_count >= 3:
            raise HTTPException(status_code=403, detail="Admin limit reached (3)")

    password_hash, salt = hash_password(payload.password)
    user = User(
        full_name=payload.full_name,
        email=payload.email,
        password_hash=password_hash,
        password_salt=salt,
        role=role,
        avatar_url=None,
        is_active=True,
    )
    uid = create_document("user", user)

    token = os.urandom(24).hex()
    create_document("session", Session(user_id=uid, token=token, created_at=datetime.now(timezone.utc)))
    return AuthResponse(token=token, user_id=uid, full_name=user.full_name, role=user.role)


@app.post("/auth/login", response_model=AuthResponse)
def login(payload: LoginRequest):
    u = db["user"].find_one({"email": payload.email})
    if not u:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(payload.password, u.get("password_salt"), u.get("password_hash")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = os.urandom(24).hex()
    create_document("session", Session(user_id=str(u["_id"]), token=token, created_at=datetime.now(timezone.utc)))
    return AuthResponse(token=token, user_id=str(u["_id"]), full_name=u.get("full_name"), role=u.get("role", "member"), avatar_url=u.get("avatar_url"))


# Dependency to get current user by token

def get_current_user(token: str = Depends(oauth2_scheme)):
    s = db["session"].find_one({"token": token})
    if not s:
        raise HTTPException(status_code=401, detail="Invalid token")
    u = db["user"].find_one({"_id": oid(s["user_id"]) if isinstance(s["user_id"], str) else s["user_id"]})
    if not u:
        raise HTTPException(status_code=401, detail="User not found")
    return u


# Dashboard metrics
@app.get("/dashboard/overview")
def dashboard_overview(current=Depends(get_current_user)):
    total_deposits = db["deposit"].aggregate([
        {"$match": {"status": {"$in": ["approved", "pending"]}}},
        {"$group": {"_id": None, "sum": {"$sum": "$amount"}}}
    ])
    total_savings = db["deposit"].aggregate([
        {"$match": {"status": "approved"}},
        {"$group": {"_id": None, "sum": {"$sum": "$amount"}}}
    ])
    active_loans_count = db["loan"].count_documents({"status": {"$in": ["approved"]}})
    annual_cash_out = db["loan"].aggregate([
        {"$match": {"status": "repaid"}},
        {"$group": {"_id": None, "sum": {"$sum": "$total_payable"}}}
    ])

    def agg_sum(cursor):
        try:
            doc = list(cursor)
            return (doc[0]["sum"] if doc else 0) or 0
        except Exception:
            return 0

    return {
        "total_balance": agg_sum(total_deposits) - agg_sum(annual_cash_out),
        "total_savings": agg_sum(total_savings),
        "active_loans": active_loans_count,
        "annual_cash_out": agg_sum(annual_cash_out)
    }


# Deposit Management
@app.get("/deposits")
def list_deposits(current=Depends(get_current_user)):
    items = get_documents("deposit", {})
    for it in items:
        it["_id"] = str(it["_id"])
    return items


@app.post("/deposits/upload")
async def upload_deposit(
    amount: float = Form(...),
    note: Optional[str] = Form(None),
    file: UploadFile = File(None),
    current=Depends(get_current_user)
):
    proof_path = None
    if file is not None:
        uploads_dir = "uploads"
        os.makedirs(uploads_dir, exist_ok=True)
        filename = f"{datetime.now(timezone.utc).timestamp()}_{file.filename}"
        filepath = os.path.join(uploads_dir, filename)
        with open(filepath, "wb") as f:
            f.write(await file.read())
        proof_path = f"/files/{filename}"

    dep = Deposit(user_id=str(current["_id"]), amount=amount, proof_path=proof_path, note=note, status="pending")
    did = create_document("deposit", dep)
    create_document("auditlog", AuditLog(actor_id=str(current["_id"]), action="deposit_created", details={"deposit_id": did}, created_at=datetime.now(timezone.utc)))
    return {"id": did, "status": "pending"}


@app.post("/deposits/{deposit_id}/status")
def update_deposit_status(deposit_id: str, status: str, current=Depends(get_current_user)):
    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    if status not in ["approved", "rejected"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    res = db["deposit"].update_one({"_id": oid(deposit_id)}, {"$set": {"status": status, "updated_at": datetime.now(timezone.utc)}})
    if not res.matched_count:
        raise HTTPException(status_code=404, detail="Deposit not found")
    create_document("auditlog", AuditLog(actor_id=str(current["_id"]), action="deposit_status", details={"deposit_id": deposit_id, "status": status}, created_at=datetime.now(timezone.utc)))
    return {"ok": True}


# Loans Management
@app.get("/loans")
def my_loans(current=Depends(get_current_user)):
    q = {"user_id": str(current["_id"]) }
    items = get_documents("loan", q)
    for it in items:
        it["_id"] = str(it["_id"])
    return items


@app.get("/loans/admin/active")
def admin_active_loans(current=Depends(get_current_user)):
    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    items = get_documents("loan", {"status": "approved"})
    for it in items:
        it["_id"] = str(it["_id"])
    return items


@app.get("/loans/admin/pending")
def admin_pending_loans(current=Depends(get_current_user)):
    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    items = get_documents("loan", {"status": "pending"})
    for it in items:
        it["_id"] = str(it["_id"])
    return items


def compute_interest(amount: float, settings: Settings) -> tuple[float, float]:
    rate = settings.interest_base if amount <= 100 else settings.interest_high
    interest_amount = round(amount * rate, 2)
    total_payable = round(amount + interest_amount, 2)
    return interest_amount, total_payable


class LoanApplyRequest(BaseModel):
    amount: float


@app.post("/loans/apply")
def apply_loan(payload: LoanApplyRequest, current=Depends(get_current_user)):
    settings = get_settings()
    active_loans_count = db["loan"].count_documents({"status": "approved"})
    if active_loans_count >= settings.max_active_loans_members:
        raise HTTPException(status_code=403, detail="Maximum active loans reached")

    interest_amount, total_payable = compute_interest(payload.amount, settings)
    loan = Loan(user_id=str(current["_id"]), amount=payload.amount, interest_rate=(settings.interest_base if payload.amount <= 100 else settings.interest_high), interest_amount=interest_amount, total_payable=total_payable, status="pending")
    lid = create_document("loan", loan)
    create_document("auditlog", AuditLog(actor_id=str(current["_id"]), action="loan_applied", details={"loan_id": lid, "amount": payload.amount}, created_at=datetime.now(timezone.utc)))
    return {"id": lid, "status": "pending"}


@app.post("/loans/{loan_id}/decision")
def loan_decision(loan_id: str, decision: str, current=Depends(get_current_user)):
    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    if decision not in ["approved", "rejected"]:
        raise HTTPException(status_code=400, detail="Invalid decision")
    update = {"status": decision, "updated_at": datetime.now(timezone.utc)}
    if decision == "approved":
        update["approved_by"] = str(current["_id"]) 
        update["approved_at"] = datetime.now(timezone.utc)
    res = db["loan"].update_one({"_id": oid(loan_id)}, {"$set": update})
    if not res.matched_count:
        raise HTTPException(status_code=404, detail="Loan not found")
    create_document("auditlog", AuditLog(actor_id=str(current["_id"]), action="loan_decision", details={"loan_id": loan_id, "decision": decision}, created_at=datetime.now(timezone.utc)))
    return {"ok": True}


# Simple Messaging (polling-based to keep stack minimal)
class SendMessageRequest(BaseModel):
    receiver_id: str
    content: str


@app.get("/messages")
def list_messages(peer_id: str, current=Depends(get_current_user)):
    uid = str(current["_id"])
    items = get_documents("message", {"$or": [{"sender_id": uid, "receiver_id": peer_id}, {"sender_id": peer_id, "receiver_id": uid}]})
    for it in items:
        it["_id"] = str(it["_id"]) 
    # attach sender details for convenience
    for it in items:
        sender = db["user"].find_one({"_id": oid(it["sender_id"])}) if ObjectId.is_valid(it["sender_id"]) else db["user"].find_one({"_id": oid(it["sender_id"])})
        if sender:
            it["sender"] = {"full_name": sender.get("full_name"), "avatar_url": sender.get("avatar_url")}
    return items


@app.post("/messages/send")
def send_message(payload: SendMessageRequest, current=Depends(get_current_user)):
    msg = Message(sender_id=str(current["_id"]), receiver_id=payload.receiver_id, content=payload.content, sent_at=datetime.now(timezone.utc))
    mid = create_document("message", msg)
    return {"id": mid}


# Audit Dashboard
@app.get("/audit")
def audit_logs(current=Depends(get_current_user)):
    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    items = get_documents("auditlog", {})
    for it in items:
        it["_id"] = str(it["_id"])
    return items


# Annual Report (basic summary; PDF generation would be client-side for now)
@app.get("/reports/annual")
def annual_report(year: int, current=Depends(get_current_user)):
    start = datetime(year, 1, 1, tzinfo=timezone.utc)
    end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    deposits_sum = list(db["deposit"].aggregate([
        {"$match": {"status": "approved", "created_at": {"$gte": start, "$lt": end}}},
        {"$group": {"_id": None, "sum": {"$sum": "$amount"}}}
    ]))
    loans_sum = list(db["loan"].aggregate([
        {"$match": {"approved_at": {"$gte": start, "$lt": end}, "status": {"$in": ["approved", "repaid"]}}},
        {"$group": {"_id": None, "sum": {"$sum": "$total_payable"}}}
    ]))
    stats = {
        "total_deposits": deposits_sum[0]["sum"] if deposits_sum else 0,
        "loan_performance": loans_sum[0]["sum"] if loans_sum else 0,
    }
    return stats


# Admin Panel Utilities
class UpdateRatesRequest(BaseModel):
    interest_base: float
    interest_high: float


@app.post("/admin/settings/rates")
def update_rates(payload: UpdateRatesRequest, current=Depends(get_current_user)):
    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    db["settings"].update_one({}, {"$set": {"interest_base": payload.interest_base, "interest_high": payload.interest_high}}, upsert=True)
    return {"ok": True}


@app.get("/admin/users")
def admin_users(current=Depends(get_current_user)):
    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    users = get_documents("user", {})
    for u in users:
        u["_id"] = str(u["_id"]) 
        u.pop("password_hash", None)
        u.pop("password_salt", None)
    return users


@app.delete("/admin/users/{user_id}")
def delete_user(user_id: str, current=Depends(get_current_user)):
    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    res = db["user"].delete_one({"_id": oid(user_id)})
    if not res.deleted_count:
        raise HTTPException(status_code=404, detail="User not found")
    create_document("auditlog", AuditLog(actor_id=str(current["_id"]), action="user_deleted", details={"user_id": user_id}, created_at=datetime.now(timezone.utc)))
    return {"ok": True}


@app.get("/")
def root():
    return {"name": "Community Savings API", "ok": True}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            collections = db.list_collection_names()
            response["collections"] = collections[:10]
            response["database"] = "✅ Connected & Working"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    import os as _os
    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
