from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta, timezone
from typing import Optional
# ----------------------------
# Modelos
# ----------------------------
class RegisterIn(BaseModel):
    email: EmailStr
    password: str
    # Campos del médico
    nombres: str
    apellidos: str
    tipo_doc: str
    doc: str
    especialidades: str

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserOut(BaseModel):
    id: str
    email: EmailStr
    rol_id: int
    created_at: datetime

class MedicoOut(BaseModel):
    id: int
    user_id: str
    nombres: str
    apellidos: str
    tipo_doc: str
    doc: str
    especialidades: str
    created_at: datetime

class UserMedicoUpdateIn(BaseModel):
    # Campos de usuario
    email: Optional[EmailStr] = None
    rol_id: Optional[int] = None
    password: Optional[str] = None
    # Campos de médico
    nombres: Optional[str] = None
    apellidos: Optional[str] = None
    tipo_doc: Optional[str] = None
    doc: Optional[str] = None
    especialidades: Optional[str] = None

class UserMedicoUpdateOut(BaseModel):
    usuario: UserOut
    medico: MedicoOut

class SearchResult(BaseModel):
    usuario: UserOut
    medico: MedicoOut
    encontrado_por: str  # "email" o "documento"