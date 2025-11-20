"""
Database Schemas for Community Savings

Each Pydantic model represents a MongoDB collection.
Collection name is the lowercase of the class name.
"""
from typing import Optional, List
from pydantic import BaseModel, Field, EmailStr, ConfigDict
from datetime import datetime


class User(BaseModel):
    model_config = ConfigDict(extra='ignore')
    full_name: str
    email: EmailStr
    password_hash: str
    password_salt: str
    role: str = Field('member', description="'member' or 'admin'")
    avatar_url: Optional[str] = None
    is_active: bool = True


class Session(BaseModel):
    model_config = ConfigDict(extra='ignore')
    user_id: str
    token: str
    created_at: datetime


class Deposit(BaseModel):
    model_config = ConfigDict(extra='ignore')
    user_id: str
    amount: float = Field(..., ge=0)
    status: str = Field('pending', description="pending|approved|rejected")
    proof_path: Optional[str] = None
    note: Optional[str] = None


class Loan(BaseModel):
    model_config = ConfigDict(extra='ignore')
    user_id: str
    amount: float = Field(..., gt=0)
    interest_rate: float = Field(..., gt=0)
    interest_amount: float = Field(..., ge=0)
    total_payable: float = Field(..., ge=0)
    status: str = Field('pending', description="pending|approved|rejected|repaid")
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None


class Message(BaseModel):
    model_config = ConfigDict(extra='ignore')
    sender_id: str
    receiver_id: str
    content: str
    sent_at: datetime


class AuditLog(BaseModel):
    model_config = ConfigDict(extra='ignore')
    actor_id: Optional[str] = None
    action: str
    details: dict = Field(default_factory=dict)
    created_at: datetime
    level: str = Field('info', description="info|warning|error|security")


class Settings(BaseModel):
    model_config = ConfigDict(extra='ignore')
    interest_base: float = 0.10  # 10% up to 100 RWF
    interest_high: float = 0.20  # 20% above 100 RWF
    max_active_loans_members: int = 30
