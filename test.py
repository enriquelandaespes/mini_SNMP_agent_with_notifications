#!/usr/bin/env python3
"""
test_agent.py - Windows-compatible test script for mini SNMP agent
Tests all SNMP operations: GET, GETNEXT, SET, WALK
Compatible with net-snmp on Windows
"""

import subprocess
import time
import sys
import os

# Test configuration
AGENT_IP = "127.0.0.1"
COMMUNITY_RO = "public"
COMMUNITY_RW = "private"
BASE_OID = "1.3.6.1.4.1.28308.1"

# Object OIDs
OID_MANAGER = f"{BASE_OID}.1.0"
OID_EMAIL = f"{BASE_OID}.2.0"
OID_CPU_USAGE = f"{BASE_OID}.3.0"
OID_CPU_THRESHOLD = f"{BASE_OID}.4.0"

def print_header(title):
    """Print section header"""
    print(f"\n{'='*60}")
    print(f"{title}")
    print(f"{'='*60}")

def run_snmp_command(cmd):
    """Execute SNMP command and return output"""
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Timeout"
    except Exception as e:
        return False, "", str(e)

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
    """Test 1: Basic GET operations"""
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
    """Test 2: GETNEXT operations"""
    print_header("TEST 2: Operaciones GETNEXT")
    
    current_oid = BASE_OID
    objects_found = []
    
    for i in range(5):
        cmd = f"snmpgetnext -v2c -c {COMMUNITY_RO} {AGENT_IP} {current_oid}"
        success, output, error = run_snmp_command(cmd)
        
        if success and output and "End of MIB" not in output:
            print(f"  ✓ Paso {i+1}: {output}")
            objects_found.append(output)
            # Extract next OID
            if "=" in output:
                parts = output.split("=")[0].strip()
                current_oid = parts.split()[-1] if " " in parts else parts
        else:
            print(f"  ℹ Fin del MIB en paso {i+1}")
            break
    
    print(f"\n  Resultado: {len(objects_found)} objetos encontrados")
    return len(objects_found) >= 4

def test_set_operations():
    """Test 3: SET operations"""
    print_header("TEST 3: Operaciones SET")
    
    tests = [
        ("Manager name", OID_MANAGER, "s", "TestManager"),
        ("Manager email", OID_EMAIL, "s", "test@example.com"),
        ("CPU Threshold", OID_CPU_THRESHOLD, "i", "75")
    ]
    
    passed = 0
    for name, oid, snmp_type, value in tests:
        # SET operation
        cmd_set = f"snmpset -v2c -c {COMMUNITY_RW} {AGENT_IP} {oid} {snmp_type} {value}"
        success, output, error = run_snmp_command(cmd_set)
        
        if success and output:
            # Verify with GET
            cmd_get = f"snmpget -v2c -c {COMMUNITY_RO} {AGENT_IP} {oid}"
            success_get, output_get, _ = run_snmp_command(cmd_get)
            
            if success_get and value in output_get:
                print(f"  ✓ {name}: Modificado y verificado = {value}")
                passed += 1
            else:
                print(f"  ⚠ {name}: SET OK pero verificación falló")
        else:
            print(f"  ✗ {name}: FALLO")
            if error:
                print(f"    Error: {error}")
    
    print(f"\n  Resultado: {passed}/{len(tests)} tests pasados")
    return passed == len(tests)

def test_walk_operation():
    """Test 4: WALK entire subtree"""
    print_header("TEST 4: SNMP WALK del subárbol")
    
    cmd = f"snmpwalk -v2c -c {COMMUNITY_RO} {AGENT_IP} {BASE_OID}"
    success, output, error = run_snmp_command(cmd)
    
    if success and output:
        lines = output.strip().split('\n')
        print(f"  ✓ WALK exitoso: {len(lines)} objetos")
        for line in lines:
            print(f"    {line}")
        return len(lines) >= 4
    else:
        print(f"  ✗ WALK falló")
        if error:
            print(f"    Error: {error}")
        return False

def test_negative_cases():
    """Test 5: Negative tests"""
    print_header("TEST 5: Casos negativos (errores esperados)")
    
    # Try to write to read-only cpuUsage
    cmd = f"snmpset -v2c -c {COMMUNITY_RW} {AGENT_IP} {OID_CPU_USAGE} i 50"
    success, output, error = run_snmp_command(cmd)
    
    if not success or "Error" in error or "notWritable" in output:
        print(f"  ✓ Escritura a objeto READ-ONLY bloqueada correctamente")
        return True
    else:
        print(f"  ✗ Debería haber rechazado escritura a cpuUsage")
        return False

def test_cpu_monitoring():
    """Test 6: CPU monitoring"""
    print_header("TEST 6: Monitoreo de CPU")
    
    print("  Leyendo CPU 3 veces (15 segundos)...")
    
    for i in range(3):
        cmd = f"snmpget -v2c -c {COMMUNITY_RO} {AGENT_IP} {OID_CPU_USAGE}"
        success, output, _ = run_snmp_command(cmd)
        
        if success:
            print(f"  Lectura {i+1}: {output}")
        
        if i < 2:
            time.sleep(5)
    
    print(f"  ✓ Monitoreo activo (verifica que los valores cambien)")
    return True

def main():
    """Run all tests"""
    print(f"\n╔{'═'*58}╗")
    print(f"║ SUITE DE PRUEBAS - MINI AGENTE SNMP                     ║")
    print(f"╚{'═'*58}╝")
    
    if not check_snmp_tools():
        print("\n⚠ IMPORTANTE: Instala net-snmp o añádelo al PATH")
        sys.exit(1)
    
    print(f"\n⚠ IMPORTANTE: Asegúrate de que el agente está corriendo:")
    print(f"  python mini_agent.py")
    print(f"\nPresiona ENTER para continuar...")
    input()
    
    # Run tests
    results = []
    results.append(("GET Operations", test_get_operations()))
    results.append(("GETNEXT Operations", test_getnext_operations()))
    results.append(("SET Operations", test_set_operations()))
    results.append(("WALK Operation", test_walk_operation()))
    results.append(("Negative Tests", test_negative_cases()))
    results.append(("CPU Monitoring", test_cpu_monitoring()))
    
    # Summary
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
    
    print(f"\nPresiona ENTER para salir...")
    input()

if __name__ == "__main__":
    main()
