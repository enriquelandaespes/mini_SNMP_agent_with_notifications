#!/usr/bin/env python3
"""
test_agent_interactivo.py - Script de prueba INTERACTIVO para el mini agente SNMP
Prueba GET, GETNEXT, SET, WALK y restaura los valores originales al finalizar.
"""

import subprocess
import time
import sys
import os

# --- Configuración Global ---
AGENT_IP = "127.0.0.1"  # IP por defecto, se preguntará al usuario
COMMUNITY_RO = "public"
COMMUNITY_RW = "private"
BASE_OID = "1.3.6.1.4.1.28308.1"

# Object OIDs
OID_MANAGER = f"{BASE_OID}.1.1.0"
OID_EMAIL = f"{BASE_OID}.1.2.0"
OID_CPU_USAGE = f"{BASE_OID}.1.3.0"
OID_CPU_THRESHOLD = f"{BASE_OID}.1.4.0"
# ------------------------------

def print_header(title):
    """Imprime un encabezado de sección bonito"""
    print(f"\n{'='*60}")
    print(f" {title.upper()} ")
    print(f"{'='*60}")

def pause_for_next_test(test_name):
    """Espera a que el usuario pulse ENTER para continuar"""
    print(f"\n--- Preparado para el Test: {test_name} ---")
    print("Presiona ENTER para continuar...")
    input()

def run_snmp_command(cmd):
    """Ejecuta un comando SNMP y devuelve el resultado"""
    try:
        # Usamos shell=True para ejecutar comandos de texto como "snmpget -v2c..."
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=10,
            encoding='utf-8',
            errors='ignore'
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Timeout: La IP del agente no responde"
    except Exception as e:
        return False, "", str(e)

def get_snmp_value(oid):
    """Función helper para obtener solo el valor de un OID"""
    cmd = f"snmpget -v2c -c {COMMUNITY_RO} {AGENT_IP} {oid}"
    success, output, error = run_snmp_command(cmd)
    
    if success and output and "=" in output:
        try:
            # El valor está después del primer ':' o '='
            # Ej: MY-MIB::manager.0 = STRING: "manager"
            # Ej: MY-MIB::cpuThreshold.0 = INTEGER: 80
            value_part = output.split(":", 1)[1].strip()
            
            # Quita las comillas si es un STRING
            if value_part.startswith('"') and value_part.endswith('"'):
                value_part = value_part[1:-1]
            
            return value_part
        except Exception as e:
            print(f"  (Error parseando valor: {e})")
            return None
    elif "No Such Object" in output:
        print(f"  (Error: El OID {oid} no existe en el agente)")
        return None
    else:
        print(f"  (Error obteniendo valor: {error})")
        return None

def check_snmp_tools():
    """Check if snmpget is available"""
    print_header("Verificando herramientas SNMP")
    
    SNMPGET = "C:\\usr\\bin\\snmpget.exe"  # <-- Ruta completa
    cmd = [SNMPGET, "-v2c", "-c", "public", AGENT_IP, f"{BASE_OID}.1.0"]
    success, output, error = run_snmp_command(cmd)
    
    if success or "NET-SNMP" in output or "NET-SNMP" in error:
        print("  ✓ net-snmp encontrado")
        return True
    else:
        print("  ✗ net-snmp NO encontrado")
        print("\n  Instala net-snmp para Windows desde:")
        print("  http://www.net-snmp.org/download.html")
        print("\n  O añade la ruta de net-snmp a PATH")
        return False

def test_get_operations():
    """Test 1: Operaciones GET básicas"""
    print_header("TEST 1: Operaciones GET básicas")
    
    tests = [
        ("Manager", OID_MANAGER),
        ("Manager Email", OID_EMAIL),
        ("CPU Usage", OID_CPU_USAGE),
        ("CPU Threshold", OID_CPU_THRESHOLD)
    ]
    
    passed = 0
    for name, oid in tests:
        cmd = f"snmpget -v2c -c {COMMUNITY_RO} {AGENT_IP} {oid}"
        success, output, error = run_snmp_command(cmd)
        
        if success and output and "No Such" not in output:
            print(f"  ✓ {name}: {output}")
            passed += 1
        else:
            print(f"  ✗ {name}: FALLO")
            if error:
                print(f"    Error: {error}")
    
    print(f"\n  Resultado: {passed}/{len(tests)} tests pasados")
    return passed == len(tests)

def test_getnext_operations():
    """Test 2: Operaciones GETNEXT"""
    print_header("TEST 2: Operaciones GETNEXT (Walk manual)")
    
    current_oid = BASE_OID
    objects_found = []
    
    for i in range(5): # Hacemos 5 saltos
        cmd = f"snmpgetnext -v2c -c {COMMUNITY_RO} {AGENT_IP} {current_oid}"
        success, output, error = run_snmp_command(cmd)
        
        if success and output and "End of MIB" not in output:
            # Extrae el OID de la respuesta para el siguiente salto
            try:
                current_oid = output.split("=")[0].strip().split()[-1]
                print(f"  ✓ Paso {i+1}: {output}")
                objects_found.append(output)
            except Exception:
                print(f"  ✗ Fallo al parsear la respuesta de GETNEXT: {output}")
                break
        else:
            print(f"  ℹ Fin del MIB en paso {i+1}")
            break
    print(f"\n  Objetos encontrados: {len(objects_found)} incluyendo el END of MIB")
    return len(objects_found) >= 4

def test_set_operations():
    """Test 3: Operaciones SET (Escritura)"""
    print_header("TEST 3: Operaciones SET")
    
    new_manager = "Enrique"
    new_email = "871135@unizar.es"
    new_threshold = "4" # Usamos string, el tipo 'i' lo convierte

    tests = [
        ("Manager name", OID_MANAGER, "s", new_manager),
        ("Manager email", OID_EMAIL, "s", new_email),
        ("CPU Threshold", OID_CPU_THRESHOLD, "i", new_threshold)
    ]
    
    passed = 0
    for name, oid, snmp_type, value in tests:
        # 1. Operación SET
        cmd_set = f"snmpset -v2c -c {COMMUNITY_RW} {AGENT_IP} {oid} {snmp_type} \"{value}\""
        success, output, error = run_snmp_command(cmd_set)
        
        if success and output:
            # 2. Verificar con GET
            cmd_get = f"snmpget -v2c -c {COMMUNITY_RO} {AGENT_IP} {oid}"
            success_get, output_get, _ = run_snmp_command(cmd_get)
            
            if success_get and value in output_get:
                print(f"  ✓ {name}: Modificado y verificado = {value}")
                passed += 1
            else:
                print(f"  ⚠ {name}: SET OK pero verificación falló. Respuesta: {output_get}")
        else:
            print(f"  ✗ {name}: FALLO al hacer SET")
            if error:
                print(f"    Error: {error}")
    
    print(f"\n  Resultado: {passed}/{len(tests)} tests pasados")
    return passed == len(tests)

def test_walk_operation():
    """Test 4: WALK del subárbol completo"""
    print_header("TEST 4: SNMP WALK del subárbol")
    
    cmd = f"snmpwalk -v2c -c {COMMUNITY_RO} {AGENT_IP} {BASE_OID}"
    success, output, error = run_snmp_command(cmd)
    
    if success and output:
        lines = output.strip().split('\n')
        print(f"  ✓ WALK exitoso: {len(lines)} objetos encontrados")
        for line in lines:
            print(f"    {line}")
        return len(lines) >= 4
    else:
        print(f"  ✗ WALK falló")
        if error:
            print(f"    Error: {error}")
        return False

def test_negative_cases():
    """Test 5: Casos negativos (errores esperados)"""
    print_header("TEST 5: Casos negativos (errores esperados)")
    passed = 0

    # 1. Intentar escribir en objeto Read-Only (cpuUsage)
    cmd_ro = f"snmpset -v2c -c {COMMUNITY_RW} {AGENT_IP} {OID_CPU_USAGE} i 50"
    success_ro, output_ro, error_ro = run_snmp_command(cmd_ro)
    
    if not success_ro or "Error" in error_ro or "notWritable" in output_ro or "noAccess" in output_ro:
        print(f"  ✓ Escritura a objeto READ-ONLY (cpuUsage) bloqueada correctamente")
        passed += 1
    else:
        print(f"  ✗ FALLO: Se ha permitido escribir en un objeto Read-Only (cpuUsage)")

    # 2. Intentar escribir con comunidad Read-Only (public)
    cmd_comm = f"snmpset -v2c -c {COMMUNITY_RO} {AGENT_IP} {OID_CPU_THRESHOLD} i 60"
    success_comm, output_comm, error_comm = run_snmp_command(cmd_comm)
    
    if not success_comm or "Error" in error_comm or "notWritable" in output_comm or "noAccess" in output_comm:
        print(f"  ✓ Escritura con comunidad READ-ONLY (public) bloqueada correctamente")
        passed += 1
    else:
        print(f"  ✗ FALLO: Se ha permitido escribir con la comunidad 'public'")

    print(f"\n  Resultado: {passed}/2 tests pasados")
    return passed == 2

def test_cpu_monitoring():
    """Test 6: Monitoreo de CPU"""
    print_header("TEST 6: Monitoreo de CPU (en tiempo real)")
    
    print("  Leyendo CPU 3 veces (intervalo de 5 segundos)...")
    
    valores = []
    for i in range(3):
        valor = get_snmp_value(OID_CPU_USAGE)
        if valor is not None:
            print(f"  Lectura {i+1}: {valor}%")
            valores.append(valor)
        else:
            print(f"  Lectura {i+1}: FALLO")
            
        if i < 2:
            time.sleep(5)
    
    if len(valores) == 3:
        print(f"  ✓ Monitoreo activo completado")
        return True
    else:
        print(f"  ✗ Fallo en el monitoreo")
        return False

def revert_changes(manager, email, threshold):
    """Restaura los valores originales del agente"""
    print_header("REVIRTIENDO CAMBIOS a los valores originales")
    
    if manager is None or email is None or threshold is None:
        print("  ✗ No se pudo revertir (valores originales no se guardaron).")
        print("  Reinicia el agente manualmente para restaurar valores.")
        return

    # Revertir Manager (string)
    cmd_man = f"snmpset -v2c -c {COMMUNITY_RW} {AGENT_IP} {OID_MANAGER} s \"{manager}\""
    success, out, _ = run_snmp_command(cmd_man)
    print(f"  {'✓' if success else '✗'} Revertido Manager a: {manager}")

    # Revertir Email (string)
    cmd_email = f"snmpset -v2c -c {COMMUNITY_RW} {AGENT_IP} {OID_EMAIL} s \"{email}\""
    success, out, _ = run_snmp_command(cmd_email)
    print(f"  {'✓' if success else '✗'} Revertido Email a: {email}")

    # Revertir Threshold (integer)
    cmd_thr = f"snmpset -v2c -c {COMMUNITY_RW} {AGENT_IP} {OID_CPU_THRESHOLD} i {threshold}"
    success, out, _ = run_snmp_command(cmd_thr)
    print(f"  {'✓' if success else '✗'} Revertido Threshold a: {threshold}")

def main():
    """Ejecuta todos los tests de forma interactiva"""
    global AGENT_IP # Declaramos que modificaremos la variable global
    
    print(f"\n╔{'═'*58}╗")
    print(f"║ SUITE DE PRUEBAS INTERACTIVA - MINI AGENTE SNMP        ║")
    print(f"╚{'═'*58}╝")
    
    # --- 1. Pedir la IP ---
    print(f"\n--- Configuración del Agente ---")
    default_ip = "127.0.0.1"
    new_ip = input(f"Introduce la IP del agente (o ENTER para {default_ip}): ")
    if new_ip.strip():
        AGENT_IP = new_ip.strip()
    else:
        AGENT_IP = default_ip
    print(f"  ✓ Usando IP del agente: {AGENT_IP}")

    # --- 2. Comprobar Herramientas ---
    if not check_snmp_tools():
        print("\n⚠ IMPORTANTE: Revisa el error de net-snmp.")
        sys.exit(1)
    
    print(f"\n⚠ IMPORTANTE: Asegúrate de que el agente está corriendo en {AGENT_IP}:")
    print(f"  python mini_agent.py")
    
    # --- 3. Guardar Valores Originales ---
    print_header("Guardando estado original del agente (para revertir)")
    original_manager = get_snmp_value(OID_MANAGER)
    original_email = get_snmp_value(OID_EMAIL)
    original_threshold = get_snmp_value(OID_CPU_THRESHOLD)
    
    if original_manager is None or original_email is None or original_threshold is None:
        print("  ✗ No se pudo obtener el estado original. El 'revert' al final fallará.")
        print("  Asegúrate de que el agente esté corriendo y la IP sea correcta.")
        input("Presiona ENTER para salir...")
        sys.exit(1)
    else:
        print(f"  ✓ Guardado Manager: {original_manager}")
        print(f"  ✓ Guardado Email: {original_email}")
        print(f"  ✓ Guardado Threshold: {original_threshold}")

    # --- 4. Ejecutar Tests Interactivamente ---
    results = []
    
    pause_for_next_test("GET Operations")
    results.append(("GET Operations", test_get_operations()))
    
    pause_for_next_test("GETNEXT Operations")
    results.append(("GETNEXT Operations", test_getnext_operations()))
    
    pause_for_next_test("SET Operations (modificará valores)")
    results.append(("SET Operations", test_set_operations()))
    
    pause_for_next_test("WALK Operation")
    results.append(("WALK Operation", test_walk_operation()))
    
    pause_for_next_test("Negative Tests (errores esperados)")
    results.append(("Negative Tests", test_negative_cases()))
    
    pause_for_next_test("CPU Monitoring (durará 15 seg)")
    results.append(("CPU Monitoring", test_cpu_monitoring()))
    
    # --- 5. Resumen ---
    print_header("RESUMEN DE RESULTADOS")
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASADO" if result else "✗ FALLADO"
        print(f"  {status}: {test_name}")
    
    print(f"\n  Total: {passed}/{total} tests pasados")
    
    if passed == total:
        print(f"\n  🎉 ¡Todos los tests pasados!")
    else:
        print(f"\n  ⚠ Revisa los tests fallidos arriba")
    
    # --- 6. Revertir Cambios ---
    revert_changes(original_manager, original_email, original_threshold)
    
    print(f"\nPresiona ENTER para salir...")
    input()

if __name__ == "__main__":
    main()