from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, field_validator
from passlib.context import CryptContext
from jose import jwt, JWTError
from pymongo import MongoClient
from bson import ObjectId
from bson.errors import InvalidId
from datetime import datetime, timedelta
from dotenv import load_dotenv
from pathlib import Path
import os
import re
import random
import smtplib
from email.mime.text import MIMEText
import joblib

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60 * 24

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

client = MongoClient(MONGO_URI)
db = client["phishguard"]
users_collection = db["users"]
scans_collection = db["scans"]
resets_collection = db["password_resets"]
deleted_users_collection = db["deleted_users"]
deleted_scans_collection = db["deleted_scans"]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

app = FastAPI(title="PhishGuard", description="AI-powered phishing and social engineering detector", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
model = joblib.load(BASE_DIR / "phishing_model.pkl")
vectorizer = joblib.load(BASE_DIR / "vectorizer.pkl")


def is_gmail(email: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@gmail\.com$', email))


def mask_email(email: str) -> str:
    try:
        local, domain = email.split("@")
    except ValueError:
        return email
    if len(local) <= 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def validate_gmail(cls, v):
        if not is_gmail(v):
            raise ValueError("Only @gmail.com addresses are allowed")
        return v

    @field_validator("password")
    @classmethod
    def validate_password_length(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Username cannot be empty")
        if len(v) < 3:
            raise ValueError("Username must be at least 3 characters")
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError("Username can only contain letters, numbers, and underscores")
        return v


class LoginRequest(BaseModel):
    name: str
    password: str


class EmailRequest(BaseModel):
    text: str


class ForgotPasswordRequest(BaseModel):
    name: str


class ResetPasswordRequest(BaseModel):
    name: str
    code: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password_length(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


def hash_password(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def create_token(user_id):
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {"sub": user_id, "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def send_email(to_email, subject, body):
    if not EMAIL_USER or not EMAIL_PASSWORD:
        raise HTTPException(status_code=500, detail="Email service not configured")
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_USER
    msg["To"] = to_email
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_USER, to_email, msg.as_string())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not send email: {str(e)}")


def get_red_flags(text):
    flags = []
    text_lower = text.lower()
    urgent_words = ['urgent', 'immediately', 'act now', 'verify', 'suspended', 'locked', 'expire', 'click here', 'limited time']
    found_urgent = [word for word in urgent_words if word in text_lower]
    if found_urgent:
        flags.append("Urgency/pressure language detected: " + ", ".join(found_urgent))
    if re.search(r'http[s]?://|www\.', text_lower):
        flags.append("Contains a link - verify destination before clicking")
    money_words = ['won', 'prize', 'free', 'claim', 'lottery', 'reward', 'gift card']
    found_money = [word for word in money_words if word in text_lower]
    if found_money:
        flags.append("Suspicious reward/prize language: " + ", ".join(found_money))
    credential_words = ['password', 'ssn', 'social security', 'credit card', 'bank account', 'pin number']
    found_cred = [word for word in credential_words if word in text_lower]
    if found_cred:
        flags.append("Requests sensitive information: " + ", ".join(found_cred))
    if not flags:
        flags.append("No obvious red-flag keywords detected - flagged mainly by learned text patterns")
    return flags


@app.post("/signup")
def signup(request: SignupRequest):
    existing_email = users_collection.find_one({"email": request.email})
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    existing_name = users_collection.find_one({"name": request.name})
    if existing_name:
        raise HTTPException(status_code=400, detail="Username already taken")

    hashed_pw = hash_password(request.password)
    user_doc = {
        "name": request.name,
        "email": request.email,
        "password": hashed_pw,
        "created_at": datetime.utcnow()
    }
    result = users_collection.insert_one(user_doc)
    user_id = str(result.inserted_id)
    token = create_token(user_id)
    return {"message": "Signup successful", "token": token}


@app.post("/login")
def login(request: LoginRequest):
    user = users_collection.find_one({"name": request.name})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not verify_password(request.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    user_id = str(user["_id"])
    token = create_token(user_id)
    return {"message": "Login successful", "token": token}


@app.get("/me")
def get_me(user_id: str = Depends(get_current_user)):
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
    except InvalidId:
        raise HTTPException(status_code=400, detail="Invalid user id")
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"name": user.get("name", ""), "email": user["email"]}


@app.post("/forgot-password")
def forgot_password(request: ForgotPasswordRequest):
    user = users_collection.find_one({"name": request.name})
    if not user:
        raise HTTPException(status_code=404, detail="No account found with that username")
    return {"masked_email": mask_email(user["email"])}


@app.post("/forgot-password/send")
def send_forgot_code(request: ForgotPasswordRequest):
    user = users_collection.find_one({"name": request.name})
    if not user:
        raise HTTPException(status_code=404, detail="No account found with that username")

    code = str(random.randint(100000, 999999))
    resets_collection.delete_many({"name": request.name})
    resets_collection.insert_one({
        "name": request.name,
        "email": user["email"],
        "code": code,
        "expires_at": datetime.utcnow() + timedelta(minutes=15),
        "created_at": datetime.utcnow()
    })

    send_email(
        user["email"],
        "PhishGuard Password Reset Code",
        f"Your PhishGuard password reset code is: {code}\n\nThis code expires in 15 minutes."
    )

    return {"message": "Code sent", "masked_email": mask_email(user["email"])}


@app.post("/reset-password")
def reset_password(request: ResetPasswordRequest):
    reset_doc = resets_collection.find_one({"name": request.name, "code": request.code})
    if not reset_doc:
        raise HTTPException(status_code=400, detail="Invalid or expired code")
    if reset_doc["expires_at"] < datetime.utcnow():
        resets_collection.delete_one({"_id": reset_doc["_id"]})
        raise HTTPException(status_code=400, detail="Code has expired")

    hashed_pw = hash_password(request.new_password)
    users_collection.update_one(
        {"name": request.name},
        {"$set": {"password": hashed_pw}}
    )
    resets_collection.delete_one({"_id": reset_doc["_id"]})
    return {"message": "Password reset successful"}


@app.post("/predict")
def predict(request: EmailRequest, user_id: str = Depends(get_current_user)):
    vec = vectorizer.transform([request.text])
    prediction = model.predict(vec)[0]
    probability = model.predict_proba(vec)[0]
    label = "Phishing Email" if prediction == 1 else "Safe Email"
    confidence = float(probability[prediction] * 100)
    red_flags = get_red_flags(request.text)
    scan_doc = {
        "user_id": user_id,
        "email_text": request.text,
        "prediction": label,
        "confidence": round(confidence, 2),
        "red_flags": red_flags,
        "scanned_at": datetime.utcnow()
    }
    scans_collection.insert_one(scan_doc)
    return {
        "prediction": label,
        "confidence": round(confidence, 2),
        "red_flags": red_flags
    }


@app.get("/history")
def get_history(user_id: str = Depends(get_current_user)):
    scans = list(scans_collection.find({"user_id": user_id}).sort("scanned_at", -1))
    for scan in scans:
        scan["_id"] = str(scan["_id"])
    return {"history": scans}


@app.delete("/history")
def clear_history(user_id: str = Depends(get_current_user)):
    scans = list(scans_collection.find({"user_id": user_id}))
    for scan in scans:
        scan["deleted_at"] = datetime.utcnow()
        deleted_scans_collection.insert_one(scan)
    result = scans_collection.delete_many({"user_id": user_id})
    return {"message": f"Deleted {result.deleted_count} scan(s)"}


@app.delete("/history/{scan_id}")
def delete_one_scan(scan_id: str, user_id: str = Depends(get_current_user)):
    try:
        oid = ObjectId(scan_id)
    except InvalidId:
        raise HTTPException(status_code=400, detail="Invalid scan id")
    scan = scans_collection.find_one({"_id": oid, "user_id": user_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan["deleted_at"] = datetime.utcnow()
    deleted_scans_collection.insert_one(scan)
    scans_collection.delete_one({"_id": oid})
    return {"message": "Scan deleted"}


@app.delete("/account")
def delete_account(user_id: str = Depends(get_current_user)):
    try:
        oid = ObjectId(user_id)
    except InvalidId:
        raise HTTPException(status_code=400, detail="Invalid user id")

    user = users_collection.find_one({"_id": oid})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    scans = list(scans_collection.find({"user_id": user_id}))
    for scan in scans:
        scan["deleted_at"] = datetime.utcnow()
        deleted_scans_collection.insert_one(scan)
    scans_collection.delete_many({"user_id": user_id})

    user["deleted_at"] = datetime.utcnow()
    deleted_users_collection.insert_one(user)
    users_collection.delete_one({"_id": oid})

    return {"message": "Account and all associated data deleted"}
