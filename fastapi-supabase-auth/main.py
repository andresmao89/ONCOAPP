import os
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import unquote

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

from models import RegisterIn, LoginIn, TokenOut, UserOut, MedicoOut, UserMedicoUpdateIn, UserMedicoUpdateOut, SearchResult

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
    res = supabase.table("users").select("id,email,rol_id,created_at").eq("email", email).execute()
    if not res.data or len(res.data) == 0:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="email no encontrado")

    return UserOut(**res.data[0])


async def get_admin_user(current_user: UserOut = Depends(get_current_user)) -> UserOut:
    """
    Verifica que el usuario actual tenga rol de administrador (rol_id = 2)
    """
    if current_user.rol_id != 2:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Acceso denegado. Se requiere rol de administrador"
        )
    return current_user

# ----------------------------
# Endpoints
# ----------------------------



@app.post("/register", response_model=dict, status_code=201)
def register(body: RegisterIn):
    # ¿Existe ya el usuario?
    existing = (
        supabase.table("users")
        .select("id")
        .eq("email", body.email.lower())
        .limit(1)
        .execute()
    )
    if existing.data and len(existing.data) > 0:
        raise HTTPException(status_code=409, detail="El email ya está registrado")

    # Crear usuario
    hashed = hash_password(body.password)
    user_to_insert = {
        "email": body.email.lower(),
        "password_hash": hashed,
        "rol_id": 1,  # Por defecto, rol de médico
    }
    user_ins = supabase.table("users").insert(user_to_insert).execute()
    if getattr(user_ins, "error", None):
        raise HTTPException(status_code=500, detail=f"Error creando usuario: {user_ins.error}")

    # Recuperar el usuario recién creado
    user_sel = (
        supabase.table("users")
        .select("id,email,rol_id,created_at")
        .eq("email", body.email.lower())
        .limit(1)
        .execute()
    )
    user_row = user_sel.data[0] if user_sel.data else None
    if not user_row:
        raise HTTPException(status_code=500, detail="Usuario creado pero no recuperado")

    # Crear médico asociado al usuario
    medico_to_insert = {
        "user_id": user_row["id"],
        "nombres": body.nombres,
        "apellidos": body.apellidos,
        "tipo_doc": body.tipo_doc,
        "doc": body.doc,
        "especialidades": body.especialidades,
    }
    medico_ins = supabase.table("medicos").insert(medico_to_insert).execute()
    if getattr(medico_ins, "error", None):
        # Si falla la inserción del médico, eliminar el usuario creado
        supabase.table("users").delete().eq("id", user_row["id"]).execute()
        raise HTTPException(status_code=500, detail=f"Error creando médico: {medico_ins.error}")

    # Recuperar el médico recién creado
    medico_sel = (
        supabase.table("medicos")
        .select("id,user_id,nombres,apellidos,tipo_doc,doc,especialidades,created_at")
        .eq("user_id", user_row["id"])
        .limit(1)
        .execute()
    )
    medico_row = medico_sel.data[0] if medico_sel.data else None
    if not medico_row:
        raise HTTPException(status_code=500, detail="Médico creado pero no recuperado")

    return {
        "usuario": user_row,
        "medico": medico_row
    }

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
# Endpoints de Administración (solo rol_id = 2)
# ----------------------------

@app.put("/admin/user-medico/{user_id}", response_model=UserMedicoUpdateOut)
async def update_user_medico(
    user_id: str,
    update_data: UserMedicoUpdateIn,
    admin: UserOut = Depends(get_admin_user)
):
    """
    Actualizar datos de usuario y médico en una sola operación (solo administradores)
    """
    # Verificar que el usuario existe
    existing_user = supabase.table("users").select("id").eq("id", user_id).execute()
    if not existing_user.data:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    # Verificar que el médico existe
    existing_medico = supabase.table("medicos").select("id").eq("user_id", user_id).execute()
    if not existing_medico.data:
        raise HTTPException(status_code=404, detail="Médico no encontrado para este usuario")
    
    # Preparar datos para actualizar usuario
    user_update = {}
    if update_data.email is not None:
        user_update["email"] = update_data.email.lower()
    if update_data.rol_id is not None:
        user_update["rol_id"] = update_data.rol_id
    if update_data.password is not None:
        user_update["password_hash"] = hash_password(update_data.password)
    
    # Preparar datos para actualizar médico
    medico_update = {}
    if update_data.nombres is not None:
        medico_update["nombres"] = update_data.nombres
    if update_data.apellidos is not None:
        medico_update["apellidos"] = update_data.apellidos
    if update_data.tipo_doc is not None:
        medico_update["tipo_doc"] = update_data.tipo_doc
    if update_data.doc is not None:
        medico_update["doc"] = update_data.doc
    if update_data.especialidades is not None:
        medico_update["especialidades"] = update_data.especialidades
    
    # Verificar que hay al menos un campo para actualizar
    if not user_update and not medico_update:
        raise HTTPException(status_code=400, detail="No hay datos para actualizar")
    
    # Actualizar usuario si hay datos
    if user_update:
        user_result = supabase.table("users").update(user_update).eq("id", user_id).execute()
        if getattr(user_result, "error", None):
            raise HTTPException(status_code=500, detail=f"Error actualizando usuario: {user_result.error}")
    
    # Actualizar médico si hay datos
    if medico_update:
        medico_result = supabase.table("medicos").update(medico_update).eq("user_id", user_id).execute()
        if getattr(medico_result, "error", None):
            raise HTTPException(status_code=500, detail=f"Error actualizando médico: {medico_result.error}")
    
    # Recuperar datos actualizados
    updated_user = supabase.table("users").select("id,email,rol_id,created_at").eq("id", user_id).execute()
    if not updated_user.data or len(updated_user.data) == 0:
        raise HTTPException(status_code=500, detail="Error recuperando usuario actualizado")
    
    updated_medico = supabase.table("medicos").select("id,user_id,nombres,apellidos,tipo_doc,doc,especialidades,created_at").eq("user_id", user_id).execute()
    if not updated_medico.data or len(updated_medico.data) == 0:
        raise HTTPException(status_code=500, detail="Error recuperando médico actualizado")
    
    return UserMedicoUpdateOut(
        usuario=UserOut(**updated_user.data[0]),
        medico=MedicoOut(**updated_medico.data[0])
    )


@app.get("/admin/user-medico/{user_id}", response_model=UserMedicoUpdateOut)
async def get_user_medico(
    user_id: str,
    admin: UserOut = Depends(get_admin_user)
):
    """
    Obtener información completa de usuario y médico (solo administradores)
    """
    # Obtener usuario
    user_result = supabase.table("users").select("id,email,rol_id,created_at").eq("id", user_id).execute()
    if not user_result.data or len(user_result.data) == 0:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    # Obtener médico
    medico_result = supabase.table("medicos").select("id,user_id,nombres,apellidos,tipo_doc,doc,especialidades,created_at").eq("user_id", user_id).execute()
    if not medico_result.data or len(medico_result.data) == 0:
        raise HTTPException(status_code=404, detail="Médico no encontrado para este usuario")
    
    return UserMedicoUpdateOut(
        usuario=UserOut(**user_result.data[0]),
        medico=MedicoOut(**medico_result.data[0])
    )


@app.get("/admin/users", response_model=list[UserOut])
async def list_users(admin: UserOut = Depends(get_admin_user)):
    """
    Listar todos los usuarios (solo administradores)
    """
    result = supabase.table("users").select("id,email,rol_id,created_at").execute()
    if getattr(result, "error", None):
        raise HTTPException(status_code=500, detail=f"Error listando usuarios: {result.error}")
    
    return [UserOut(**user) for user in result.data]


@app.get("/admin/medicos", response_model=list[MedicoOut])
async def list_medicos(admin: UserOut = Depends(get_admin_user)):
    """
    Listar todos los médicos (solo administradores)
    """
    result = supabase.table("medicos").select("id,user_id,nombres,apellidos,tipo_doc,doc,especialidades,created_at").execute()
    if getattr(result, "error", None):
        raise HTTPException(status_code=500, detail=f"Error listando médicos: {result.error}")
    
    return [MedicoOut(**medico) for medico in result.data]

# ----------------------------
# Endpoint de Búsqueda
# ----------------------------

@app.get("/search", response_model=SearchResult)
async def search_user_medico(
    email: Optional[str] = None,
    tipo_doc: Optional[str] = None,
    doc: Optional[str] = None,
    admin: UserOut = Depends(get_admin_user)
):
    """
    Buscar usuario y médico por email o por documento (solo administradores)
    
    Parámetros:
    - email: Buscar por email del usuario
    - tipo_doc + doc: Buscar por tipo y número de documento del médico
    
    Ejemplos:
    - /search?email=usuario@ejemplo.com
    - /search?tipo_doc=CC&doc=12345678
    """
    # Validar que se proporcione al menos un criterio de búsqueda
    if not email and not (tipo_doc and doc):
        raise HTTPException(
            status_code=400, 
            detail="Debe proporcionar email O (tipo_doc + doc) para buscar"
        )
    
    # Búsqueda por email
    if email:
        # Decodificar el email (convierte %40 a @)
        decoded_email = unquote(email).lower()
        
        print(f"Decoded email: {decoded_email}")
        
        # Buscar usuario por email
        user_result = supabase.table("users").select("id,email,rol_id,created_at").eq("email", decoded_email).execute()
        if not user_result.data or len(user_result.data) == 0:
            raise HTTPException(status_code=404, detail=f"Usuario con email '{decoded_email}' no encontrado")
        
        user_data = user_result.data[0]
        
        print(f"User data: {user_data}")
        print(f"User id: {user_data['id']}")
        # Buscar médico asociado
        medico_result = supabase.table("medicos").select("id,user_id,nombres,apellidos,tipo_doc,doc,especialidades,created_at").eq("user_id", user_data["id"]).execute()
        if not medico_result.data or len(medico_result.data) == 0:
            raise HTTPException(status_code=404, detail=f"Médico no encontrado para el usuario con email '{decoded_email}'")
        
        medico_data = medico_result.data[0]
        
        return SearchResult(
            usuario=UserOut(**user_data),
            medico=MedicoOut(**medico_data),
            encontrado_por="email"
        )
    
    # Búsqueda por documento
    elif tipo_doc and doc:
        # Buscar médico por documento
        medico_result = supabase.table("medicos").select("id,user_id,nombres,apellidos,tipo_doc,doc,especialidades,created_at").eq("tipo_doc", tipo_doc).eq("doc", doc).execute()
        if not medico_result.data or len(medico_result.data) == 0:
            raise HTTPException(status_code=404, detail=f"Médico con documento {tipo_doc} {doc} no encontrado")
        
        medico_data = medico_result.data[0]
        
        # Buscar usuario asociado
        user_result = supabase.table("users").select("id,email,rol_id,created_at").eq("id", medico_data["user_id"]).execute()
        if not user_result.data or len(user_result.data) == 0:
            raise HTTPException(status_code=404, detail=f"Usuario no encontrado para el médico con documento {tipo_doc} {doc}")
        
        user_data = user_result.data[0]
        
        return SearchResult(
            usuario=UserOut(**user_data),
            medico=MedicoOut(**medico_data),
            encontrado_por="documento"
        )


@app.get("/search/flexible", response_model=list[SearchResult])
async def search_flexible(
    q: str,
    admin: UserOut = Depends(get_admin_user)
):
    """
    Búsqueda flexible que busca en email, nombres, apellidos y documento (solo administradores)
    
    Parámetros:
    - q: Término de búsqueda (busca en email, nombres, apellidos, documento)
    
    Ejemplo:
    - /search/flexible?q=Juan
    - /search/flexible?q=12345678
    - /search/flexible?q=usuario@ejemplo.com
    """
    results = []
    
    # Decodificar el término de búsqueda
    decoded_q = unquote(q)
    
    # Buscar por email
    user_by_email = supabase.table("users").select("id,email,rol_id,created_at").like("email", f"%{decoded_q}%").execute()
    for user in user_by_email.data:
        medico = supabase.table("medicos").select("id,user_id,nombres,apellidos,tipo_doc,doc,especialidades,created_at").eq("user_id", user["id"]).execute()
        if medico.data and len(medico.data) > 0:
            results.append(SearchResult(
                usuario=UserOut(**user),
                medico=MedicoOut(**medico.data[0]),
                encontrado_por="email"
            ))
    
    # Buscar por nombres o apellidos (hacer dos búsquedas separadas)
    medicos_by_nombres = supabase.table("medicos").select("id,user_id,nombres,apellidos,tipo_doc,doc,especialidades,created_at").like("nombres", f"%{decoded_q}%").execute()
    medicos_by_apellidos = supabase.table("medicos").select("id,user_id,nombres,apellidos,tipo_doc,doc,especialidades,created_at").like("apellidos", f"%{decoded_q}%").execute()
    
    # Combinar resultados y eliminar duplicados
    medicos_by_name = medicos_by_nombres.data + medicos_by_apellidos.data
    # Eliminar duplicados basado en el ID
    seen_ids = set()
    medicos_by_name = [medico for medico in medicos_by_name if medico["id"] not in seen_ids and not seen_ids.add(medico["id"])]
    for medico in medicos_by_name:
        # Verificar que no esté ya en los resultados
        if not any(r.medico.id == medico["id"] for r in results):
            user = supabase.table("users").select("id,email,rol_id,created_at").eq("id", medico["user_id"]).execute()
            if user.data and len(user.data) > 0:
                results.append(SearchResult(
                    usuario=UserOut(**user.data[0]),
                    medico=MedicoOut(**medico),
                    encontrado_por="nombre"
                ))
    
    # Buscar por documento
    medicos_by_doc = supabase.table("medicos").select("id,user_id,nombres,apellidos,tipo_doc,doc,especialidades,created_at").like("doc", f"%{decoded_q}%").execute()
    for medico in medicos_by_doc.data:
        # Verificar que no esté ya en los resultados
        if not any(r.medico.id == medico["id"] for r in results):
            user = supabase.table("users").select("id,email,rol_id,created_at").eq("id", medico["user_id"]).execute()
            if user.data and len(user.data) > 0:
                results.append(SearchResult(
                    usuario=UserOut(**user.data[0]),
                    medico=MedicoOut(**medico),
                    encontrado_por="documento"
                ))
    
    if not results:
        raise HTTPException(status_code=404, detail=f"No se encontraron resultados para '{decoded_q}'")
    
    return results

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
