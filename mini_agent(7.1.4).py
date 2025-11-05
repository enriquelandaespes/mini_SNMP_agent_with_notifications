"""
Mini SNMP Agent with JSON MIB storage, CPU monitoring, traps, and email notifications.
This agent works on pysnmp 7.1.4
"""


import json
import os
import time
import threading
import smtplib
from email.mime.text import MIMEText
import psutil
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, ntforg, context
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.proto.api import v2c
from pysnmp.proto import rfc3411  # Para consultar VACM
from pysnmp.proto import api


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
            "baseoid": "1.3.6.1.4.1.28308.1.1",
            "scalars": {
                "manager": {"oid": "1.3.6.1.4.1.28308.1.1.1.0", "type": "DisplayString", 
                           "access": "read-write", "value": "manager"},
                "managerEmail": {"oid": "1.3.6.1.4.1.28308.1.1.2.0", "type": "DisplayString",
                                "access": "read-write", "value": "871135@unizar.es"},
                "cpuUsage": {"oid": "1.3.6.1.4.1.28308.1.1.3.0", "type": "Integer32",
                            "access": "read-only", "value": 10},
                "cpuThreshold": {"oid": "1.3.6.1.4.1.28308.1.1.4.0", "type": "Integer32",
                                "access": "read-write", "value": 80}
            }
        }
    
    def save(self, data=None):
        with open(self.filepath, 'w') as f:
            json.dump(data or self.model, f, indent=2)
    
    def build_oid_map(self):
        return {tuple(int(x) for x in obj["oid"].split('.')): key 
                for key, obj in self.model["scalars"].items()}
    
    def get_exact(self, oid_tuple):
        key = self.oid_map.get(oid_tuple)
        if not key:
            return False, v2c.NoSuchObject()
        obj = self.model["scalars"][key]
        val = v2c.OctetString(str(obj["value"]).encode('utf-8')) if obj["type"] == "DisplayString" else v2c.Integer(obj["value"])
        return True, val
    
    def get_next(self, oid_tuple):
        for candidate in self.sorted_oids:
            if candidate > oid_tuple:
                return True, candidate, self.get_exact(candidate)[1]
        return False, None, None
    
    def validate_set(self, oid_tuple, snmp_val, stateReference=None, contextName=''):
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
            try:
                # En PySNMP 7.x, stateReference es un int, buscar en observer
                cache = self.snmpEngine.observer.getExecutionContext('rfc3412.receiveMessage:request')
                
                if cache and 'securityName' in cache:
                    securityName = cache['securityName']
                    
                    # securityName es un objeto SnmpAdminString, extraer el valor
                    if hasattr(securityName, 'prettyPrint'):
                        community = securityName.prettyPrint()
                    elif hasattr(securityName, '__str__'):
                        community = str(securityName)
                    else:
                        # Último recurso: acceder directamente al payload
                        community = str(securityName)
                    
                    print(f"   🔍 Comunidad detectada: '{community}'")
                
                # También intentar con communityName directamente
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
            return 16, 1  # authorizationError
        
        print(f"   ✅ PERMITIDO: Comunidad '{community}' autorizada para escritura")
        
        # 2. Verificar que el OID existe
        key = self.oid_map.get(oid_tuple)
        if not key:
            return 18, 1
        
        obj = self.model["scalars"][key]
        
        # 3. Verificar permisos de acceso del objeto
        if obj["access"] == "read-only":
            return 17, 1
        
        # 4. Verificar tipo de dato
        if obj["type"] == "DisplayString" and not isinstance(snmp_val, v2c.OctetString):
            return 7, 1
        if obj["type"] == "Integer32" and not isinstance(snmp_val, v2c.Integer):
            return 7, 1
        
        return 0, 0
        
    def commit_set(self, oid_tuple, snmp_val):
        key = self.oid_map[oid_tuple]
        old_value = self.model["scalars"][key]["value"]
        new_value = str(snmp_val) if self.model["scalars"][key]["type"] == "DisplayString" else int(snmp_val)
        self.model["scalars"][key]["value"] = new_value
        self.save()
        return old_value, new_value
    
    def set_cpu_usage_internal(self, cpu_value):
        self.model["scalars"]["cpuUsage"]["value"] = cpu_value
        self.save()



def oid_to_string(oid):
    """Convert OID tuple/object to readable string"""
    if hasattr(oid, 'prettyPrint'):
        return oid.prettyPrint()
    return '.'.join(str(x) for x in oid)



def get_timestamp():
    """Get formatted timestamp"""
    return time.strftime('%Y-%m-%d %H:%M:%S')



# JSON responders - handle SNMP operations with detailed logging
class JsonGet(cmdrsp.GetCommandResponder):
    def __init__(self, snmpEngine, snmpContext, store):
        super().__init__(snmpEngine, snmpContext)
        self.store = store
    
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        req = v2c.apiPDU.getVarBinds(PDU)
        
        print(f"\n{'='*70}")
        print(f"📥 GET REQUEST recibida [{get_timestamp()}]")
        print(f"{'='*70}")
        
        rsp = []
        for oid, _ in req:
            oid_str = oid_to_string(oid)
            ok, val = self.store.get_exact(tuple(oid))
            
            if ok:
                key = self.store.oid_map.get(tuple(oid), "unknown")
                value_str = str(val) if hasattr(val, '__str__') else repr(val)
                print(f"   OID: {oid_str}")
                print(f"   Variable: {key}")
                print(f"   Valor: {value_str}")
                print(f"   ✅ Encontrado")
            else:
                print(f"   OID: {oid_str}")
                print(f"   ❌ No existe (NoSuchObject)")
            
            rsp.append((oid, val))
        
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)
        
        print(f"   📤 Respuesta enviada correctamente")
        print(f"{'='*70}\n")



class JsonGetNext(cmdrsp.NextCommandResponder):
    def __init__(self, snmpEngine, snmpContext, store):
        super().__init__(snmpEngine, snmpContext)
        self.store = store
    
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        req = v2c.apiPDU.getVarBinds(PDU)
        
        print(f"\n{'='*70}")
        print(f"📥 GETNEXT REQUEST recibida [{get_timestamp()}]")
        print(f"{'='*70}")
        
        rsp = []
        for oid, _ in req:
            oid_str = oid_to_string(oid)
            ok, next_oid, val = self.store.get_next(tuple(oid))
            
            print(f"   OID solicitado: {oid_str}")
            
            if ok:
                next_oid_str = oid_to_string(next_oid)
                key = self.store.oid_map.get(next_oid, "unknown")
                value_str = str(val) if hasattr(val, '__str__') else repr(val)
                print(f"   ➡️  Siguiente OID: {next_oid_str}")
                print(f"   Variable: {key}")
                print(f"   Valor: {value_str}")
                print(f"   ✅ Encontrado")
                rsp.append((v2c.ObjectIdentifier(next_oid), val))
            else:
                print(f"   ❌ No hay más OIDs (EndOfMibView)")
                rsp.append((oid, v2c.EndOfMibView()))
        
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)
        
        print(f"   📤 Respuesta enviada correctamente")
        print(f"{'='*70}\n")



class JsonSet(cmdrsp.SetCommandResponder):
    def __init__(self, snmpEngine, snmpContext, store):
        super().__init__(snmpEngine, snmpContext)
        self.store = store
    
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        req = v2c.apiPDU.getVarBinds(PDU)
        
        print(f"\n{'='*70}")
        print(f"📥 SET REQUEST recibida [{get_timestamp()}]")
        print(f"{'='*70}")
        
        # Validate all OIDs first
        for idx, (oid, val) in enumerate(req, start=1):
            oid_str = oid_to_string(oid)
            key = self.store.oid_map.get(tuple(oid), "unknown")
            
            # Pasar stateReference para que validate_set pueda verificar comunidad
            errStatus, _ = self.store.validate_set(tuple(oid), val, stateReference, contextName)
            
            print(f"   OID: {oid_str}")
            print(f"   Variable: {key}")
            print(f"   Nuevo valor: {val}")
            
            if errStatus:
                if errStatus == 16:
                    print(f"   ❌ ERROR: Sin autorización (authorizationError)")
                elif errStatus == 17:
                    print(f"   ❌ ERROR: Variable de solo lectura (notWritable)")
                elif errStatus == 7:
                    print(f"   ❌ ERROR: Tipo incorrecto (wrongType)")
                else:
                    print(f"   ❌ ERROR: Código {errStatus}")
                
                rspPDU = v2c.apiPDU.getResponse(PDU)
                v2c.apiPDU.setErrorStatus(rspPDU, errStatus)
                v2c.apiPDU.setVarBinds(rspPDU, req)
                self.sendPdu(snmpEngine, stateReference, rspPDU)
                print(f"   📤 Respuesta de error enviada")
                print(f"{'='*70}\n")
                return
        
        # If all validated, commit changes
        print(f"\n   ✅ Validación exitosa, aplicando cambios...")
        
        for oid, val in req:
            oid_str = oid_to_string(oid)
            key = self.store.oid_map.get(tuple(oid), "unknown")
            old_value, new_value = self.store.commit_set(tuple(oid), val)
            print(f"   📝 {key}: {old_value} → {new_value}")
        
        rsp = [(oid, self.store.get_exact(tuple(oid))[1]) for oid, _ in req]
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)
        
        print(f"   📤 Respuesta enviada correctamente")
        print(f"   💾 Cambios guardados en {JSON_FILE}")
        print(f"{'='*70}\n")



def send_trap(snmpEngine, store):
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
        (v2c.ObjectIdentifier((1,3,6,1,4,1,28308,1,1,3,0)), v2c.Integer(cpu_val)),
        (v2c.ObjectIdentifier((1,3,6,1,4,1,28308,1,1,4,0)), v2c.Integer(threshold_val)),
        (v2c.ObjectIdentifier((1,3,6,1,4,1,28308,1,1,2,0)), v2c.OctetString(email_val.encode('utf-8')))
    ]
    
    try:
        ntfOrg.sendVarBinds(snmpEngine, 'trap-target', None, '', varBinds)
        print(f"   ✅ TRAP enviada exitosamente")
    except Exception as e:
        print(f"   ❌ Error enviando TRAP: {e}")
    
    print(f"{'='*70}\n")
    
    send_email(email_val, cpu_val, threshold_val)



def send_email(to_addr, cpu_val, threshold_val):
    print(f"{'='*70}")
    print(f"📧 ENVIANDO EMAIL [{get_timestamp()}]")
    print(f"{'='*70}")
    print(f"   De: {GMAIL_USER}")
    print(f"   Para: {to_addr}")
    print(f"   Asunto: ⚠️ Alerta CPU: {cpu_val}%")
    
    try:
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
                Agente OID: 1.3.6.1.4.1.28308.1
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
🆔 Agente OID: 1.3.6.1.4.1.28308.1

══════════════════════════════════════════════════════════
"""
        
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText as MIMETextPart
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'⚠️ Alerta CPU: {cpu_val}% (Umbral: {threshold_val}%)'
        msg['From'] = GMAIL_USER
        msg['To'] = to_addr
        
        part1 = MIMETextPart(text_body, 'plain', 'utf-8')
        msg.attach(part1)
        
        part2 = MIMETextPart(html_body, 'html', 'utf-8')
        msg.attach(part2)
        
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=10) as smtp:
            smtp.login(GMAIL_USER, GMAIL_PASSWORD)
            smtp.send_message(msg)
        
        print(f"   ✅ Email enviado exitosamente vía Gmail")
        print(f"   📨 Formato: HTML + texto plano")
    except Exception as e:
        print(f"   ❌ Error al enviar email: {e}")
    
    print(f"{'='*70}\n")




def cpu_sampler(store, snmpEngine, stop_event):
    psutil.cpu_percent(interval=None)
    last_over = False
    
    print(f"\n{'='*70}")
    print(f"🖥️  MONITOR DE CPU INICIADO [{get_timestamp()}]")
    print(f"{'='*70}")
    print(f"   Intervalo de muestreo: 5 segundos")
    print(f"   Archivo de estado: {JSON_FILE}")
    print(f"{'='*70}\n")
    
    while not stop_event.is_set():
        time.sleep(5)
        cpu = max(0, min(100, round(psutil.cpu_percent(interval=None))))
        store.set_cpu_usage_internal(cpu)
        threshold = store.model["scalars"]["cpuThreshold"]["value"]
        over = cpu > threshold
        
        status_icon = '⚠️ SUPERADO' if over else '✅ OK'
        print(f"[{get_timestamp()}] 🖥️  CPU: {cpu}% | Umbral: {threshold}% | {status_icon}")
        
        if over and not last_over:
            print(f"\n⚠️⚠️⚠️  ALERTA: Umbral de CPU superado! ⚠️⚠️⚠️\n")
            send_trap(snmpEngine, store)
        
        last_over = over



def main():
    store = JsonStore(JSON_FILE)
    snmpEngine = engine.SnmpEngine()
    snmpContext = context.SnmpContext(snmpEngine)
    
    # Configurar referencia al snmpEngine en el store para VACM
    store.snmpEngine = snmpEngine
    
    config.addTransport(
        snmpEngine, 
        udp.domainName, 
        udp.UdpTransport().openServerMode(('0.0.0.0', 161))
    )
    
    config.addV1System(snmpEngine, 'public-area', 'public')
    config.addV1System(snmpEngine, 'private-area', 'private')
    
    for secModel in (1, 2):
        config.addVacmUser(snmpEngine, secModel, 'public-area', 'noAuthNoPriv', readSubTree=(1,3,6,1), writeSubTree=())
        config.addVacmUser(snmpEngine, secModel, 'private-area', 'noAuthNoPriv', readSubTree=(1,3,6,1), writeSubTree=(1,3,6,1))
    
    config.addTargetParams(snmpEngine, 'trap-target', 'public-area', 'noAuthNoPriv', 1)
    config.addTargetAddr(snmpEngine, 'trap-target', udp.domainName, ('127.0.0.1', 162), 'trap-target', tagList='trap')
    config.addNotificationTarget(snmpEngine, 'trap-target', 'trap-target', 'trap')
    
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
    
    stop_event = threading.Event()
    
    cpu_thread = threading.Thread(target=cpu_sampler, args=(store, snmpEngine, stop_event))
    cpu_thread.daemon = True
    cpu_thread.start()
    
    snmpEngine.transportDispatcher.jobStarted(1)
    
    try:
        snmpEngine.transportDispatcher.runDispatcher()
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
        snmpEngine.transportDispatcher.closeDispatcher()



if __name__ == '__main__':
    main()

