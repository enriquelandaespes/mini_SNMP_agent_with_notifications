#!/usr/bin/env python3
"""
comprobacion_paquetes.py - Verifica e instala las dependencias del proyecto.

Comprueba las librerías de Python y las herramientas externas.
Ofrece instalar las librerías de Python faltantes.
"""

import importlib.metadata
import subprocess
import sys

# Versión exacta de pysnmp que queremos
PYSNMP_VERSION_REQUERIDA = "7.1.4"

# Lista de librerías de Python a comprobar
LIBRERIAS_PYTHON = {
    "pysnmp": PYSNMP_VERSION_REQUERIDA,
    "psutil": None,  # None significa que solo comprobamos si existe
    "keyboard": None,
}

# Lista de herramientas externas (del PATH) a comprobar
HERRAMIENTAS_EXTERNAS = [
    ("snmpget", "-V"), # Usamos -V para comprobar la versión de net-snmp
]

def print_header(title):
    """Imprime un encabezado de sección bonito"""
    print(f"\n{'='*60}")
    print(f" {title.upper()} ")
    print(f"{'='*60}")

def prompt_to_install(lib_name, version=None):
    """
    Pide al usuario que instale una librería faltante o con versión incorrecta.
    Devuelve True si la instalación fue exitosa, False en caso contrario.
    """
    if version:
        install_cmd_str = f"{lib_name}=={version}"
        pretty_name = f"{lib_name} (versión {version})"
    else:
        install_cmd_str = lib_name
        pretty_name = lib_name

    # Preguntar al usuario
    respuesta = input(f"  > ¿Deseas instalar {pretty_name} ahora? (y/n): ").strip().lower()
    
    if respuesta in ['y', 's', 'yes', 'si']:
        print(f"    ... Instalando {install_cmd_str}...")
        
        # Usar sys.executable es más robusto que 'pip' a secas
        # Se asegura de que se usa el pip del intérprete de Python actual
        cmd = [sys.executable, "-m", "pip", "install", install_cmd_str]
        
        try:
            # Ejecutar el comando de instalación
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f"    ✓ Instalación completada.")
            return True
        except subprocess.CalledProcessError as e:
            # Pip devolvió un error
            print(f"    ✗ ERROR durante la instalación:")
            print("--- INICIO SALIDA DE PIP ---")
            print(e.stderr)
            print("--- FIN SALIDA DE PIP ---")
            return False
        except Exception as e:
            print(f"    ✗ ERROR inesperado al ejecutar pip: {e}")
            return False
    else:
        # El usuario ha decidido no instalar
        print(f"    ... Instalación omitida por el usuario.")
        return False

def comprobar_librerias_python():
    """
    Verifica las librerías de Python. Si falta alguna o la versión
    es incorrecta, ofrece instalarla.
    """
    print_header("Comprobando Librerías de Python")
    
    # Comprobamos que estamos en una versión de Python >= 3.8
    if sys.version_info < (3, 8):
        print("  ✗ Python:         VERSIÓN INCORRECTA")
        print("                  Se requiere Python 3.8 o superior.")
        return False
    else:
        print(f"  ✓ Python:         Encontrado (Versión {sys.version_info.major}.{sys.version_info.minor})")
        
    all_ok = True
    
    for lib, version_requerida in LIBRERIAS_PYTHON.items():
        try:
            # 1. Comprobar si existe
            version_encontrada = importlib.metadata.version(lib)
            
            # 2. Comprobar si la versión es la correcta (si se requiere)
            if version_requerida and version_encontrada != version_requerida:
                print(f"  ✗ {lib:<15} VERSIÓN INCORRECTA (Encontrada: {version_encontrada}, Requerida: {version_requerida})")
                # Si es incorrecta, intentar instalar la versión correcta
                if not prompt_to_install(lib, version_requerida):
                    all_ok = False # La instalación falló o el usuario la omitió
            else:
                # Existe y la versión es correcta (o no se requiere una específica)
                print(f"  ✓ {lib:<15} Encontrado (Versión {version_encontrada})")
        
        except importlib.metadata.PackageNotFoundError:
            # 3. La librería no existe
            print(f"  ✗ {lib:<15} NO ENCONTRADO")
            # Intentar instalarla
            if not prompt_to_install(lib, version_requerida):
                all_ok = False # La instalación falló o el usuario la omitió
        
        except Exception as e:
            print(f"  ? {lib:<15} Error al comprobar: {e}")
            all_ok = False
            
    return all_ok

def comprobar_herramientas_externas():
    """Verifica que las herramientas externas (net-snmp) están en el PATH."""
    print_header("Comprobando Herramientas Externas (para test.py)")
    all_ok = True
    
    for tool, args in HERRAMIENTAS_EXTERNAS:
        try:
            cmd = f"{tool} {args}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            
            output = result.stdout + result.stderr
            
            if "NET-SNMP" in output:
                print(f"  ✓ {tool} (NET-SNMP): Encontrado")
            else:
                print(f"  ✗ {tool}: Comando encontrado, pero no parece ser NET-SNMP.")
                print(f"    (Salida: {output.splitlines()[0]})")
                all_ok = False
                
        except Exception as e:
            print(f"  ✗ {tool}: NO ENCONTRADO")
            print(f"    (Error: El comando no se encuentra en el PATH del sistema)")
            all_ok = False
            
    return all_ok

def main():
    print_header("INICIANDO COMPROBACIÓN INTERACTIVA DE DEPENDENCIAS")
    
    python_ok = comprobar_librerias_python()
    tools_ok = comprobar_herramientas_externas()
    
    # --- Resumen Final ---
    print_header("RESUMEN")
    
    if python_ok and tools_ok:
        print("🎉 ¡PERFECTO! Todas las dependencias están instaladas correctamente.")
        print("   Puedes ejecutar el agente y el script de test.")
    else:
        print("⚠️  FALTAN DEPENDENCIAS. Revisa los errores (✗) de arriba.")
        
        if not python_ok:
            print("\n   - No se pudieron instalar o verificar todas las librerías de Python.")
            print("     (Vuelve a ejecutar este script para intentarlo de nuevo)")
            
        if not tools_ok:
            print("\n   - Faltan las herramientas externas (net-snmp).")
            print("     Recuerda que estas debes instalarlas manualmente:")
            print("     1. Descarga e instala 'net-snmp' para Windows.")
            print("     2. Añade la carpeta 'bin' (ej. C:\\Program Files\\net-snmp\\bin) a tu variable de entorno PATH.")
            print("     3. REINICIA tu terminal (y VSCode) después de cambiar el PATH.")

if __name__ == "__main__":
    main()