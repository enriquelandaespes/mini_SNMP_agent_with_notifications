"""
Mini SNMP Agent with JSON MIB storage, CPU monitoring, traps, and email notifications.
This agent works on pysnmp 7.1.4
"""

import json
import os
import time
import threading
import smtplib
import keyboard
import psutil
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, ntforg, context
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.proto.api import v2c
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText as MIMETextPart


# Constantes iniciales
JSON_FILE = "mib_state.json"
AGENT_START = time.time()

# Configuración de Gmail para envío de correos(Es el que envía a el correo del manager)
GMAIL_USER = "fakeunizar@gmail.com"  
GMAIL_PASSWORD = "ldwb lraj msnw smoo"  


# JSONStore maneja la MIB almacenada en un archivo JSON, guardando y cargando el estado de las variables.
class JsonStore:
    def __init__(self, filepath): # Constructor de la clase JsonStore
        self.filepath = filepath # Ruta al archivo JSON
        self.model = self.load() # Cargar modelo desde JSON
        self.oid_map = self.build_oid_map() # Mapeo OID a nombres de variables
        self.sorted_oids = sorted(self.oid_map.keys()) # OIDs ordenados para get-next
        self.snmpEngine = None  # Se establecerá desde main()
    
    def load(self): # Cargar el modelo desde el archivo JSON o usar valores predeterminados
        if os.path.exists(self.filepath):
            with open(self.filepath, 'r') as f:
                return json.load(f)
        
        return { # Modelo por defecto si no existe el archivo JSON
            "baseoid": "1.3.6.1.4.1.28308.1",
            "scalars": {
                "manager": {"oid": "1.3.6.1.4.1.28308.1.1.0", "type": "DisplayString", 
                           "access": "read-write", "value": "manager"},
                "managerEmail": {"oid": "1.3.6.1.4.1.28308.1.2.0", "type": "DisplayString",
                                "access": "read-write", "value": "871135@unizar.es"},
                "cpuUsage": {"oid": "1.3.6.1.4.1.28308.1.3.0", "type": "Integer32",
                            "access": "read-only", "value": 10},
                "cpuThreshold": {"oid": "1.3.6.1.4.1.28308.1.4.0", "type": "Integer32",
                                "access": "read-write", "value": 80}
            }
        }
    
    def save(self, data=None): # Funcion para guardar el modelo en el archivo JSON
        with open(self.filepath, 'w') as f:
            json.dump(data or self.model, f, indent=2)
    
    def build_oid_map(self): # Construir un mapeo de OID a nombres de variables
        return {tuple(int(x) for x in obj["oid"].split('.')): key 
                for key, obj in self.model["scalars"].items()}
    
    def get_exact(self, oid): # Obtener el valor exacto para un OID dado
        nombre_objeto = self.oid_map.get(oid)
        if not nombre_objeto:
            return False, v2c.NoSuchObject() # v2c es para usar pysnmp
        obj = self.model["scalars"][nombre_objeto]
        val = v2c.OctetString(str(obj["value"]).encode('utf-8')) if obj["type"] == "DisplayString" else v2c.Integer(obj["value"])
        return True, val
    
    def get_next(self, oid): # Obtener el siguiente OID y su valor
        for candidate in self.sorted_oids:
            if candidate > oid:
                return True, candidate, self.get_exact(candidate)[1] # get_exact devuelve (ok, val) entonces usamos [1] para obtener val
        return False, None, None
    
    def validate_set(self, oid_tuple, snmp_val, stateReference=None, contextName=''): # Validar una operación SET
        """
        Validación completa que incluye:
        1. Verificación de permisos de comunidad
        2. Existencia del OID
        3. Permisos de acceso del objeto (read-only vs read-write)
        4. Tipo de dato correcto
        """
        # 1. VERIFICAR PERMISOS DE COMUNIDAD
        community = 'unknown'
        
        if self.snmpEngine and stateReference:
            try: # Intentamos extraer la comunidad dependiendo de la version de SNMP (v1, v2c, v3)
                # Guardamos el contexto de ejecución para acceder a la comunidad con securityName
                cache = self.snmpEngine.observer.getExecutionContext('rfc3412.receiveMessage:request')
                if cache and 'securityName' in cache:
                    securityName = cache['securityName'] 
                    # securityName es un objeto SnmpAdminString, extraer el valor
                    if hasattr(securityName, 'prettyPrint'):
                        community = securityName.prettyPrint()
                    else:    # Guardamos el valor de la comunidad directamente
                        community = str(securityName)
                    
                    print(f"   🔍 Comunidad detectada: '{community}'")
                
                # Si no ha encontrado antes la comunidad lo intentamos con communityName
                if community == 'unknown' and 'communityName' in cache:
                    communityName = cache.get('communityName', b'')
                    community = communityName.decode('utf-8') if communityName else 'unknown'
                    print(f"   🔍 Comunidad (communityName): '{community}'")
            
            except Exception as e:
                print(f"   ⚠️  Error extrayendo comunidad: {e}")
        
        print(f"   🔑 Comunidad FINAL: '{community}'")
        
        # Verificar si la comunidad tiene permisos de escritura
        readonly_communities = ['public', 'public-area']
        
        if community in readonly_communities:
            print(f"   🔒 BLOQUEADO: Comunidad '{community}' es de solo lectura")
            return 16, 1  # authorizationError
        
        if community == 'unknown':
            # CRÍTICO: Denegar si no podemos verificar la comunidad
            print(f"   🔒 BLOQUEADO: No se pudo verificar comunidad, denegando por seguridad")
            return 16, 1  # Error: authorizationError
        
        print(f"   ✅ PERMITIDO: Comunidad '{community}' autorizada para escritura") # Si no es publica y existe permitimos escritura (privada)
        
        # 2. Verificar que el OID existe
        key = self.oid_map.get(oid_tuple)
        if not key:
            return 18, 1 # Error: El OID es valido pero no existe en la MIB del agente
        
        obj = self.model["scalars"][key] # Como el OID es valido obtenemos el objeto
        
        # 3. Verificar permisos de acceso del objeto
        if obj["access"] == "read-only":
            return 17, 1 # Error: notWritable
        
        # 4. Verificar tipo de dato
        if obj["type"] == "DisplayString" and not isinstance(snmp_val, v2c.OctetString):
            return 7, 1 # Error: wrongType
        if obj["type"] == "Integer32" and not isinstance(snmp_val, v2c.Integer):
            return 7, 1 # Error: wrongType
        
        return 0, 0 # Sin error
        
    def commit_set(self, oid, snmp_val): # Aplicar el cambio para una operación SET validada
        key = self.oid_map[oid]
        old_value = self.model["scalars"][key]["value"]
        new_value = str(snmp_val) if self.model["scalars"][key]["type"] == "DisplayString" else int(snmp_val)
        self.model["scalars"][key]["value"] = new_value
        self.save() # Guardar cambios en el archivo JSON
        return old_value, new_value
    
    def set_cpu_usage_internal(self, cpu_value): # Actualizar internamente el valor de uso de CPU
        self.model["scalars"]["cpuUsage"]["value"] = cpu_value
        self.save() # Guardar cambios en el archivo JSON

def oid_to_string(oid): # Convierte la tupla/objeto OID en texto legible
    if hasattr(oid, 'prettyPrint'):
        return oid.prettyPrint()
    return '.'.join(str(x) for x in oid)

def get_timestamp(): # Obtener timestamp
    return time.strftime('%Y-%m-%d %H:%M:%S')

# Cada clase maneja un tipo de operación SNMP (GET, GETNEXT, SET) e interactúa con JsonStore haciendo un override de handleMgmtOperation
class JsonGet(cmdrsp.GetCommandResponder):
    def __init__(self, snmpEngine, snmpContext, store): # Constructor de la clase JsonGet
        super().__init__(snmpEngine, snmpContext)
        self.store = store
    
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU): # Manejar una operación GET (override)
        req = v2c.apiPDU.getVarBinds(PDU) # Obtener los VarBinds de la solicitud
        
        print(f"\n{'='*70}")
        print(f"📥 GET REQUEST recibida [{get_timestamp()}]")
        print(f"{'='*70}")
        
        rsp = [] # Respuesta inicial vacía
        for oid, _ in req:
            oid_str = oid_to_string(oid)
            ok, val = self.store.get_exact(tuple(oid))
            
            if ok: # Si se encontró el OID
                key = self.store.oid_map.get(tuple(oid), "unknown") # Obtener el nombre de la variable
                value_str = str(val) if hasattr(val, '__str__') else repr(val) # Convertir valor a string 
                print(f"   OID: {oid_str}")
                print(f"   Variable: {key}")
                print(f"   Valor: {value_str}")
                print(f"   ✅ Encontrado")
            else:
                print(f"   OID: {oid_str}")
                print(f"   ❌ No existe (NoSuchObject)")
            
            rsp.append((oid, val)) # Construir la respuesta
        
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU) # Enviar la respuesta
        
        print(f"   📤 Respuesta enviada correctamente")
        print(f"{'='*70}\n")

class JsonGetNext(cmdrsp.NextCommandResponder): 
    def __init__(self, snmpEngine, snmpContext, store): # Constructor de la clase JsonGetNext
        super().__init__(snmpEngine, snmpContext)
        self.store = store
    
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU): # Manejar una operación GETNEXT (override)
        req = v2c.apiPDU.getVarBinds(PDU) # Obtener los VarBinds de la solicitud
        
        print(f"\n{'='*70}")
        print(f"📥 GETNEXT REQUEST recibida [{get_timestamp()}]")
        print(f"{'='*70}")
        
        rsp = [] # Respuesta inicial vacía
        for oid, _ in req:
            oid_str = oid_to_string(oid)
            ok, next_oid, val = self.store.get_next(tuple(oid)) # Obtener el siguiente OID
            
            print(f"   OID solicitado: {oid_str}")
            
            if ok: # Si se encontró un siguiente OID
                next_oid_str = oid_to_string(next_oid)
                key = self.store.oid_map.get(next_oid, "unknown")
                value_str = str(val) if hasattr(val, '__str__') else repr(val) # Convertir valor a string
                print(f"   ➡️  Siguiente OID: {next_oid_str}")
                print(f"   Variable: {key}")
                print(f"   Valor: {value_str}")
                print(f"   ✅ Encontrado")
                rsp.append((v2c.ObjectIdentifier(next_oid), val)) # Construir la respuesta
            else:
                print(f"   ❌ No hay más OIDs (EndOfMibView)")
                rsp.append((oid, v2c.EndOfMibView())) # Responder con EndOfMibView si no hay siguiente OID
        
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU) # Enviar la respuesta
        
        print(f"   📤 Respuesta enviada correctamente")
        print(f"{'='*70}\n")

class JsonSet(cmdrsp.SetCommandResponder):
    def __init__(self, snmpEngine, snmpContext, store): # Constructor de la clase JsonSet
        super().__init__(snmpEngine, snmpContext)
        self.store = store
    
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU): # Manejar una operación SET (override)
        req = v2c.apiPDU.getVarBinds(PDU) # Obtener los VarBinds de la solicitud
        
        print(f"\n{'='*70}")
        print(f"📥 SET REQUEST recibida [{get_timestamp()}]")
        print(f"{'='*70}")
        
        # Validate all OIDs first
        for idx, (oid, val) in enumerate(req, start=1): # Validar todos los OIDs primero
            oid_str = oid_to_string(oid)
            key = self.store.oid_map.get(tuple(oid), "unknown") # Obtener el nombre de la variable
            
            # Pasar stateReference para que validate_set pueda verificar comunidad
            errStatus, _ = self.store.validate_set(tuple(oid), val, stateReference, contextName)
            
            print(f"   OID: {oid_str}")
            print(f"   Variable: {key}")
            print(f"   Nuevo valor: {val}")
            
            if errStatus: # Si hay un error, enviar respuesta de error inmediatamente
                if errStatus == 16:
                    print(f"   ❌ ERROR: Sin autorización (authorizationError)")
                elif errStatus == 17:
                    print(f"   ❌ ERROR: Variable de solo lectura (notWritable)")
                elif errStatus == 7:
                    print(f"   ❌ ERROR: Tipo incorrecto (wrongType)")
                else:
                    print(f"   ❌ ERROR: Código {errStatus}")
                
                rspPDU = v2c.apiPDU.getResponse(PDU) # Construir PDU de respuesta
                v2c.apiPDU.setErrorStatus(rspPDU, errStatus)
                v2c.apiPDU.setVarBinds(rspPDU, req)
                self.sendPdu(snmpEngine, stateReference, rspPDU) # Enviar la respuesta de error
                print(f"   📤 Respuesta de error enviada")
                print(f"{'='*70}\n")
                return
        
        # Si todos los OIDs son válidos, aplicar los cambios
        print(f"\n   ✅ Validación exitosa, aplicando cambios...")
        
        for oid, val in req: # Aplicar los cambios
            oid_str = oid_to_string(oid)
            key = self.store.oid_map.get(tuple(oid), "unknown")
            old_value, new_value = self.store.commit_set(tuple(oid), val) # Aplicar el cambio
            print(f"   📝 {key}: {old_value} → {new_value}")
        
        rsp = [(oid, self.store.get_exact(tuple(oid))[1]) for oid, _ in req] # Construir la respuesta con los nuevos valores
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU) # Enviar la respuesta
        
        print(f"   📤 Respuesta enviada correctamente")
        print(f"   💾 Cambios guardados en {JSON_FILE}")
        print(f"{'='*70}\n")

def send_trap(snmpEngine, store): # Enviar una TRAP SNMP y un email cuando se supera el umbral de CPU
    ntfOrg = ntforg.NotificationOriginator() 
    cpu_val = store.model["scalars"]["cpuUsage"]["value"]
    threshold_val = store.model["scalars"]["cpuThreshold"]["value"]
    email_val = store.model["scalars"]["managerEmail"]["value"]
    
    print(f"\n{'='*70}")
    print(f"📡 ENVIANDO TRAP [{get_timestamp()}]")
    print(f"{'='*70}")
    print(f"   Razón: CPU {cpu_val}% > Umbral {threshold_val}%")
    print(f"   Email destino: {email_val}")
    
    varBinds = [
        (v2c.ObjectIdentifier((1,3,6,1,2,1,1,3,0)), v2c.TimeTicks(int((time.time()-AGENT_START)*100))),
        (v2c.ObjectIdentifier((1,3,6,1,6,3,1,1,1,4,1,0)), v2c.ObjectIdentifier((1,3,6,1,4,1,28308,2,1))),
        (v2c.ObjectIdentifier((1,3,6,1,4,1,28308,1,3,0)), v2c.Integer(cpu_val)),
        (v2c.ObjectIdentifier((1,3,6,1,4,1,28308,1,4,0)), v2c.Integer(threshold_val)),
        (v2c.ObjectIdentifier((1,3,6,1,4,1,28308,1,2,0)), v2c.OctetString(email_val.encode('utf-8')))
    ] # VarBinds de la TRAP
    
    try: # Enviar la TRAP
        ntfOrg.sendVarBinds(snmpEngine, 'trap-target', None, '', varBinds) # Enviar TRAP al destino configurado
        print(f"   ✅ TRAP enviada exitosamente")
    except Exception as e:
        print(f"   ❌ Error enviando TRAP: {e}")
    
    print(f"{'='*70}\n")
    
    send_email(email_val, cpu_val, threshold_val) # Llama a la funcion de enviar email de alerta

def send_email(to_addr, cpu_val, threshold_val): # Enviar un email de alerta cuando se supera el umbral de CPU
    print(f"{'='*70}")
    print(f"📧 ENVIANDO EMAIL [{get_timestamp()}]")
    print(f"{'='*70}")
    print(f"   De: {GMAIL_USER}")
    print(f"   Para: {to_addr}")
    print(f"   Asunto: ⚠️ Alerta CPU: {cpu_val}%")
    
    try: # Construir el cuerpo del email en HTML y texto plano
        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            padding: 20px;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background-color: white;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #ff6b6b 0%, #ff4757 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 28px;
        }}
        .content {{
            padding: 30px;
        }}
        .metric {{
            background-color: #f8f9fa;
            border-left: 4px solid #ff4757;
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
        }}
        .metric-value {{
            font-size: 36px;
            font-weight: bold;
            color: #ff4757;
            margin: 10px 0;
        }}
        .metric-label {{
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .warning-box {{
            background-color: #fff3cd;
            border: 2px solid #ffc107;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            text-align: center;
        }}
        .footer {{
            background-color: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 12px;
            border-top: 1px solid #dee2e6;
        }}
        .icon {{
            font-size: 48px;
            margin-bottom: 10px;
        }}
        .timestamp {{
            color: #999;
            font-size: 12px;
            margin-top: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="icon">⚠️</div>
            <h1>ALERTA DE CPU</h1>
            <p>Sistema de Monitoreo SNMP</p>
        </div>
        
        <div class="content">
            <div class="warning-box">
                <div style="font-size: 24px; margin-bottom: 10px;">🚨 UMBRAL SUPERADO 🚨</div>
                <p style="margin: 5px 0; font-size: 16px;">
                    El uso de CPU ha excedido el límite configurado
                </p>
            </div>
            
            <div class="metric">
                <div class="metric-label">💻 Uso de CPU Actual</div>
                <div class="metric-value">{cpu_val}%</div>
            </div>
            
            <div class="metric">
                <div class="metric-label">📊 Umbral Configurado</div>
                <div class="metric-value">{threshold_val}%</div>
            </div>
            
            <div class="metric">
                <div class="metric-label">🕐 Fecha y Hora</div>
                <div style="font-size: 18px; font-weight: bold; color: #333; margin-top: 10px;">
                    {time.strftime('%d/%m/%Y - %H:%M:%S')}
                </div>
            </div>
            
            <div style="margin-top: 30px; padding: 20px; background-color: #e3f2fd; border-radius: 8px; border-left: 4px solid #2196f3;">
                <div style="font-size: 16px; color: #1976d2; font-weight: bold; margin-bottom: 10px;">
                    ℹ️ Información
                </div>
                <p style="margin: 5px 0; color: #555;">
                    Esta alerta se genera automáticamente cuando el uso de CPU supera el umbral definido.
                </p>
                <p style="margin: 5px 0; color: #555;">
                    <strong>Acción recomendada:</strong> Verificar procesos y servicios que puedan estar consumiendo recursos excesivos.
                </p>
            </div>
        </div>
        
        <div class="footer">
            <p style="margin: 5px 0;">🖥️ Mini SNMP Agent - Network Management</p>
            <p style="margin: 5px 0;">📧 Notificación automática del sistema</p>
            <div class="timestamp">
                Agente OID: 1.3.6.1.4.1.28308
            </div>
        </div>
    </div>
</body>
</html>
"""
        
        text_body = f"""
╔══════════════════════════════════════════════════════════╗
║                  ⚠️  ALERTA DE CPU  ⚠️                   ║
╚══════════════════════════════════════════════════════════╝

🚨 UMBRAL SUPERADO 🚨

El uso de CPU ha excedido el límite configurado.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💻 Uso de CPU Actual
   ╰─► {cpu_val}%

📊 Umbral Configurado
   ╰─► {threshold_val}%

🕐 Fecha y Hora
   ╰─► {time.strftime('%d/%m/%Y - %H:%M:%S')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ℹ️  INFORMACIÓN

Esta alerta se genera automáticamente cuando el uso de CPU
supera el umbral definido.

⚡ Acción recomendada:
   Verificar procesos y servicios que puedan estar
   consumiendo recursos excesivos.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🖥️  Mini SNMP Agent - Network Management
📧 Notificación automática del sistema
🆔 Agente OID: 1.3.6.1.4.1.28308

══════════════════════════════════════════════════════════
"""
        
        msg = MIMEMultipart('alternative') # Crear mensaje para rellenar
        msg['Subject'] = f'⚠️ Alerta CPU: {cpu_val}% (Umbral: {threshold_val}%)'
        msg['From'] = GMAIL_USER
        msg['To'] = to_addr
        
        part1 = MIMETextPart(text_body, 'plain', 'utf-8')
        msg.attach(part1)
        
        part2 = MIMETextPart(html_body, 'html', 'utf-8')
        msg.attach(part2)
        
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=10) as smtp: # Enviar el email vía Gmail SMTP con la contraseña de aplicación
            smtp.login(GMAIL_USER, GMAIL_PASSWORD)
            smtp.send_message(msg)
        
        print(f"   ✅ Email enviado exitosamente vía Gmail")
        print(f"   📨 Formato: HTML + texto plano")
    except Exception as e:
        print(f"   ❌ Error al enviar email: {e}")
    
    print(f"{'='*70}\n")

def cpu_sampler(store, snmpEngine, stop_event): # Hilo para muestrear el uso de CPU y enviar alertas
    psutil.cpu_percent(interval=None) # Obtenemos un valor inicial usando a psutil
    last_over = False
    show_output = False
    
    print(f"\n{'='*70}")
    print(f"🖥️  MONITOR DE CPU INICIADO [{get_timestamp()}]")
    print(f"{'='*70}")
    print(f"   Pulsa 'r' para mostrar/ocultar salida por pantalla")
    print(f"   Intervalo de muestreo: 5 segundos (siempre activo)")
    print(f"   Archivo de estado: {JSON_FILE}")
    print(f"{'='*70}\n")
    
    def toggle_output(): # Función para alternar la salida por pantalla al presionar 'r'
        nonlocal show_output
        show_output = not show_output
        estado = "VISIBLE" if show_output else "OCULTA"
        print(f"\n[{get_timestamp()}] Salida por pantalla: {estado}\n")
    
    keyboard.add_hotkey('r', toggle_output) # Registrar la tecla 'r' para alternar la salida
    
    while not stop_event.is_set(): # Bucle principal del muestreador de CPU
        time.sleep(5)
        
        # Siempre muestrea y actualiza
        cpu = max(0, min(100, round(psutil.cpu_percent(interval=None)))) # Obtener uso de CPU entre 0 y 100%
        store.set_cpu_usage_internal(cpu)
        threshold = store.model["scalars"]["cpuThreshold"]["value"]
        over = cpu > threshold # Verificar si se supera el umbral
        
        # Solo muestra si show_output está activo (alternado con 'r')
        if show_output:
            status_icon = '⚠️ SUPERADO' if over else '✅ OK'
            print(f"[{get_timestamp()}] 🖥️  CPU: {cpu}% | Umbral: {threshold}% | {status_icon}")
        
        if over and not last_over: # Solo se envia alerta solo cuando se supera el umbral no cada vez que detecta que está por encima
            if show_output:
                print(f"\n⚠️⚠️⚠️  ALERTA: Umbral de CPU superado! ⚠️⚠️⚠️\n")
            send_trap(snmpEngine, store)
        
        last_over = over # Actualizar estado de sobrepaso
    
    keyboard.unhook_all() # Limpiar hotkeys al detener el hilo


def main(): # Función principal para iniciar el agente SNMP
    store = JsonStore(JSON_FILE) # Crear instancia de JsonStore
    snmpEngine = engine.SnmpEngine() # Crear motor SNMP
    snmpContext = context.SnmpContext(snmpEngine) # Crear contexto SNMP
    
    # Configurar referencia al snmpEngine en el store para VACM
    store.snmpEngine = snmpEngine
    
    config.addTransport(
        snmpEngine, 
        udp.domainName, 
        udp.UdpTransport().openServerMode(('0.0.0.0', 161)) # Escucha en todas las interfaces por el puerto 161
    ) # Configurar transporte UDP para SNMP
    
    # Configurar comunidades SNMPv1/v2c
    config.addV1System(snmpEngine, 'public-area', 'public') 
    config.addV1System(snmpEngine, 'private-area', 'private') 
    
    for secModel in (1, 2): # Para cada comunidad, configurar VACM
        config.addVacmUser(snmpEngine, secModel, 'public-area', 'noAuthNoPriv', readSubTree=(1,3,6,1), writeSubTree=())
        config.addVacmUser(snmpEngine, secModel, 'private-area', 'noAuthNoPriv', readSubTree=(1,3,6,1), writeSubTree=(1,3,6,1))
    
    config.addTargetParams(snmpEngine, 'trap-target', 'public-area', 'noAuthNoPriv', 1) # Configurar destino de TRAP
    config.addTargetAddr(snmpEngine, 'trap-target', udp.domainName, ('127.0.0.1', 162), 'trap-target', tagList='trap') # Enviar TRAPs al localhost:162
    config.addNotificationTarget(snmpEngine, 'trap-target', 'trap-target', 'trap') # Configurar notificación de TRAP
    
    # Configurar manejadores para operaciones SNMP
    JsonGet(snmpEngine, snmpContext, store) 
    JsonGetNext(snmpEngine, snmpContext, store)
    JsonSet(snmpEngine, snmpContext, store)
    
    print("\n" + "="*70)
    print("🚀 AGENTE SNMP INICIADO")
    print("="*70)
    print(f"   Puerto: UDP/161")
    print(f"   Comunidad lectura: public")
    print(f"   Comunidad escritura: private")
    print(f"   OID base: {store.model['baseoid']}")
    print(f"   Archivo JSON: {JSON_FILE}")
    print(f"   Inicio: {get_timestamp()}")
    print("="*70)
    print("\n📋 OIDs disponibles:")
    print("-" * 70)
    for key, obj in store.model["scalars"].items():
        access = "RO" if obj["access"] == "read-only" else "RW"
        print(f"   [{access}] {obj['oid']:<35} {key:<20} = {obj['value']}")
    print("="*70)
    print("\n⚡ Presiona Ctrl+C para detener el agente")
    print("="*70 + "\n")
    
    stop_event = threading.Event() # Evento para detener el Agente con el ctrl+c
    
    cpu_thread = threading.Thread(target=cpu_sampler, args=(store, snmpEngine, stop_event)) # Hilo para muestrear CPU
    cpu_thread.daemon = True # Hilo de fondo. No bloquea la salida del programa
    cpu_thread.start() # Iniciar hilo de muestreo de CPU
    
    snmpEngine.transportDispatcher.jobStarted(1) # Iniciar el despachador SNMP
    
    try:
        snmpEngine.transportDispatcher.runDispatcher() # Ejecutar el despachador SNMP es el que escucha y atiende las peticiones
    except KeyboardInterrupt:
        print(f"\n\n{'='*70}")
        print("🛑 APAGANDO AGENTE")
        print("="*70)
        stop_event.set()
        cpu_thread.join(timeout=2)
        store.save()
        print(f"   💾 Estado guardado en {JSON_FILE}")
        print(f"   🕐 Hora de cierre: {get_timestamp()}")
        print("="*70)
        print("\n👋 Agente detenido correctamente\n")
    finally:
        snmpEngine.transportDispatcher.closeDispatcher() # Cerrar el despachador SNMP

if __name__ == '__main__':
    main()