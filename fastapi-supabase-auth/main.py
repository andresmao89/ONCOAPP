import os
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import jwt
from dotenv import load_dotenv
from supabase import create_client, Client

# ----------------------------
# Config
# ----------------------------
load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
JWT_SECRET = os.getenv("JWT_SECRET", "mi_jwt_secret_muy_seguro_123456789")
JWT_ALG = os.getenv("JWT_ALG", "HS256")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

# Verificar configuración de Supabase
if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    print("❌ ERROR: Faltan las credenciales de Supabase")
    print("📝 Crea un archivo .env con las siguientes variables:")
    print("   SUPABASE_URL=https://tu-proyecto-id.supabase.co")
    print("   SUPABASE_SERVICE_ROLE_KEY=tu_service_role_key_real")
    print("   JWT_SECRET=tu_jwt_secret_seguro")
    print()
    print("🔗 Obtén tus credenciales en: https://supabase.com/dashboard")
    raise RuntimeError("Faltan SUPABASE_URL o SUPABASE_SERVICE_ROLE_KEY en .env")

# Inicializar Supabase
try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    print("✅ Conexión a Supabase establecida correctamente")
except Exception as e:
    print(f"❌ Error al conectar con Supabase: {e}")
    print("🔍 Verifica que las credenciales sean correctas")
    raise RuntimeError(f"No se pudo conectar con Supabase: {e}")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="Auth API – FastAPI + Supabase", version="1.0.0")

security = HTTPBearer()

# ----------------------------
# Modelos
# ----------------------------
class RegisterIn(BaseModel):
    email: EmailStr
    password: str

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserOut(BaseModel):
    id: str
    email: EmailStr
    created_at: datetime

# ----------------------------
# Utilidades
# ----------------------------

def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(sub: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {"sub": sub, "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security))-> UserOut:
    token = credentials.credentials
    # Decodificar token
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expirado")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No se pudo validar el token")

    # Buscar email por email en Supabase
    res = supabase.table("users").select("id,email,created_at").eq("email", email).single().execute()
    if res.data is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="email no encontrado")

    return UserOut(**res.data)

# ----------------------------
# Endpoints
# ----------------------------



@app.post("/register", response_model=UserOut, status_code=201)
def register(body: RegisterIn):
    # ¿Existe ya?
    existing = (
        supabase.table("users")
        .select("id")
        .eq("email", body.email.lower())
        .limit(1)
        .execute()
    )
    if existing.data and len(existing.data) > 0:
        raise HTTPException(status_code=409, detail="El email ya está registrado")

    # Crear (insert) -> algunos clientes no soportan .select() encadenado aquí
    hashed = hash_password(body.password)
    to_insert = {
        "email": body.email.lower(),
        "password_hash": hashed,
    }
    ins = supabase.table("users").insert(to_insert).execute()
    if getattr(ins, "error", None):
        raise HTTPException(status_code=500, detail=f"Error creando usuario: {ins.error}")

    # Recuperar el registro recién creado
    sel = (
        supabase.table("users")
        .select("id,email,created_at")
        .eq("email", body.email.lower())
        .limit(1)
        .execute()
    )
    row = sel.data[0] if sel.data else None
    if not row:
        raise HTTPException(status_code=500, detail="Usuario creado pero no recuperado")

    return row

@app.post("/login", response_model=TokenOut)
def login(body: LoginIn):
    res = supabase.table("users").select("email,password_hash").eq("email", body.email.lower()).limit(1).execute()
    row = (res.data[0] if res.data else None)
    if not row or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    token = create_access_token(sub=row["email"])
    return TokenOut(access_token=token)


@app.get("/me", response_model=UserOut)
async def me(current: UserOut = Depends(get_current_user)):
    return current

# ----------------------------
# Configuración del servidor
# ----------------------------
if __name__ == "__main__":
    import uvicorn
    import socket
    
    # Función para encontrar un puerto disponible
    def find_free_port(start_port=8000):
        for port in range(start_port, start_port + 100):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('localhost', port))
                    return port
            except OSError:
                continue
        raise RuntimeError("No se encontró un puerto disponible")
    
    # Buscar puerto disponible
    port = find_free_port()
    print(f"🚀 Iniciando servidor en puerto {port}")
    print(f"📱 Accede a: http://localhost:{port}")
    print(f"📚 Documentación: http://localhost:{port}/docs")
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=True,
        log_level="info"
    )
