#!/usr/bin/env python3
"""
Script para iniciar el servidor FastAPI con manejo automático de puertos
"""
import uvicorn
import socket
import sys
import os

def find_free_port(start_port=8000, max_attempts=100):
    """
    Encuentra un puerto disponible comenzando desde start_port
    """
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('localhost', port))
                return port
        except OSError:
            continue
    
    # Si no encuentra puerto, intentar con puertos del sistema
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('localhost', 0))
            return s.getsockname()[1]
    except OSError:
        raise RuntimeError("No se pudo encontrar ningún puerto disponible")

def main():
    try:
        # Verificar que existe el archivo .env
        if not os.path.exists('.env'):
            print("❌ ERROR: No se encontró el archivo .env")
            print("📝 Crea un archivo .env con las siguientes variables:")
            print("   SUPABASE_URL=https://tu-proyecto-id.supabase.co")
            print("   SUPABASE_SERVICE_ROLE_KEY=tu_service_role_key_real")
            print("   JWT_SECRET=tu_jwt_secret_seguro")
            print()
            print("🔗 Obtén tus credenciales en: https://supabase.com/dashboard")
            sys.exit(1)
        
        # Buscar puerto disponible
        port = find_free_port()
        
        print("🚀 Iniciando servidor FastAPI en modo PRODUCCIÓN...")
        print("🔗 Conectando con Supabase...")
        print(f"📱 URL: http://localhost:{port}")
        print(f"📚 Documentación: http://localhost:{port}/docs")
        print(f"🔧 Admin: http://localhost:{port}/redoc")
        print("⏹️  Presiona Ctrl+C para detener el servidor")
        print("-" * 50)
        
        # Iniciar servidor
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=port,
            reload=True,
            log_level="info",
            access_log=True
        )
        
    except KeyboardInterrupt:
        print("\n🛑 Servidor detenido por el usuario")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error al iniciar el servidor: {e}")
        print("\n🔍 Verifica tu configuración de Supabase:")
        print("   1. Archivo .env existe y tiene las credenciales correctas")
        print("   2. URL de Supabase es válida")
        print("   3. Service Role Key es correcta")
        print("   4. Tabla 'users' existe en tu base de datos")
        sys.exit(1)

if __name__ == "__main__":
    main()
