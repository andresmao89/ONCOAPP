# FastAPI + Supabase Auth API

API de autenticación construida con FastAPI y Supabase.

## ?? Solución al Error de Puerto

El error `[WinError 10013]` indica que el puerto está siendo usado por otro proceso. He implementado una solución automática que:

1. **Busca automáticamente un puerto disponible** comenzando desde el 8000
2. **Maneja errores de permisos** de socket
3. **Proporciona mensajes informativos** sobre el estado del servidor

## ?? Instalación

1. **Instalar dependencias:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Crear archivo .env:**
   ```env
   SUPABASE_URL=tu_supabase_url_aqui
   SUPABASE_SERVICE_ROLE_KEY=tu_service_role_key_aqui
   JWT_SECRET=tu_jwt_secret_muy_seguro_aqui
   JWT_ALG=HS256
   JWT_EXPIRE_MINUTES=60
   ```

## ????? Ejecución

### Opción 1: Modo Producción (Con Supabase) - RECOMENDADO
```bash
# Windows
start_prod.bat

# O manualmente
python run_server.py
```

### Opción 2: Ejecutar directamente
```bash
python main.py
```

### Opción 3: Usar uvicorn directamente
```bash
uvicorn main:app --reload --port 8001
```

## ?? Características Implementadas

- ? **Manejo automático de puertos** - Encuentra puertos disponibles automáticamente
- ? **Modo producción** - Conecta directamente con Supabase
- ? **Validación de email** - Usa `EmailStr` de Pydantic para validar emails
- ? **Autenticación JWT** - Tokens seguros con expiración configurable
- ? **Integración con Supabase** - Base de datos en la nube (opcional)
- ? **Hashing de contraseñas** - Usando bcrypt para seguridad
- ? **Documentación automática** - Swagger UI en `/docs`
- ? **Manejo de errores mejorado** - Mensajes informativos y soluciones

## ?? Endpoints

- `GET /health` - Verificar estado del servidor
- `POST /register` - Registrar nuevo usuario
- `POST /login` - Iniciar sesión
- `GET /me` - Obtener información del usuario actual

## ??? Solución de Problemas

### Error de Puerto
Si sigues teniendo problemas de puerto:

1. **Cierra otros servidores** que puedan estar usando el puerto
2. **Ejecuta como administrador** si es necesario
3. **Usa un puerto específico:**
   ```bash
   uvicorn main:app --reload --port 8001
   ```

### Error de Dependencias
```bash
pip install --upgrade -r requirements.txt
```

### Error de Variables de Entorno
Asegúrate de que el archivo `.env` existe y tiene todas las variables necesarias.

## ?? URLs de Acceso

Una vez iniciado el servidor, podrás acceder a:
- **API**: `http://localhost:PUERTO`
- **Documentación**: `http://localhost:PUERTO/docs`
- **ReDoc**: `http://localhost:PUERTO/redoc`
