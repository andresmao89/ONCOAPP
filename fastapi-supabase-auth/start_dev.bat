@echo off
echo ???  Iniciando servidor en modo desarrollo...
echo.
echo ?? Configurando variables de entorno...
set DEVELOPMENT_MODE=true
set SUPABASE_URL=https://tu-proyecto.supabase.co
set SUPABASE_SERVICE_ROLE_KEY=tu_service_role_key_aqui
echo.
echo ?? Iniciando servidor...
python run_server.py
pause
