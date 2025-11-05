#!/usr/bin/env python3
"""
mini_agent.py - SNMP Agent with JSON storage and notifications
Compatible with PySNMP 7.1.4 - WORKING VERSION
Student project for Network Management course
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
import sys
# Config constants
JSON_FILE = "mib_state.json"
AGENT_START = time.time()

# Gmail SMTP configuration
GMAIL_USER = "fakeunizar@gmail.com"  
GMAIL_PASSWORD = "ldwb lraj msnw smoo"  

# JSON Store class - maintains MIB data
class JsonStore:
    def __init__(self, filepath):
        self.filepath = filepath
        self.model = self.load()
        self.oid_map = self.build_oid_map()
        self.sorted_oids = sorted(self.oid_map.keys())
    
    def load(self):
        if os.path.exists(self.filepath):
            with open(self.filepath, 'r') as f:
                return json.load(f)
        
        return {
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
    
    def validate_set(self, oid_tuple, snmp_val):
        key = self.oid_map.get(oid_tuple)
        if not key or self.model["scalars"][key]["access"] == "read-only":
            return 17, 1
        if self.model["scalars"][key]["type"] == "DisplayString" and not isinstance(snmp_val, v2c.OctetString):
            return 7, 1
        if self.model["scalars"][key]["type"] == "Integer32" and not isinstance(snmp_val, v2c.Integer):
            return 7, 1
        return 0, 0
    
    def commit_set(self, oid_tuple, snmp_val):
        key = self.oid_map[oid_tuple]
        self.model["scalars"][key]["value"] = str(snmp_val) if self.model["scalars"][key]["type"] == "DisplayString" else int(snmp_val)
        self.save()
    
    def set_cpu_usage_internal(self, cpu_value):
        self.model["scalars"]["cpuUsage"]["value"] = cpu_value
        self.save()


# JSON responders - handle SNMP operations (FIXED for PySNMP 7.x)
class JsonGet(cmdrsp.GetCommandResponder):
    def __init__(self, snmpEngine, snmpContext, store):
        super().__init__(snmpEngine, snmpContext)
        self.store = store
    
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        req = v2c.apiPDU.getVarBinds(PDU)
        rsp = [(oid, self.store.get_exact(tuple(oid))[1]) for oid, _ in req]
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)


class JsonGetNext(cmdrsp.NextCommandResponder):
    def __init__(self, snmpEngine, snmpContext, store):
        super().__init__(snmpEngine, snmpContext)
        self.store = store
    
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        req = v2c.apiPDU.getVarBinds(PDU)
        rsp = []
        for oid, _ in req:
            ok, next_oid, val = self.store.get_next(tuple(oid))
            rsp.append((v2c.ObjectIdentifier(next_oid), val) if ok else (oid, v2c.EndOfMibView()))
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)


class JsonSet(cmdrsp.SetCommandResponder):
    def __init__(self, snmpEngine, snmpContext, store):
        super().__init__(snmpEngine, snmpContext)
        self.store = store
    
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        req = v2c.apiPDU.getVarBinds(PDU)
        for idx, (oid, val) in enumerate(req, start=1):
            errStatus, _ = self.store.validate_set(tuple(oid), val)
            if errStatus:
                rspPDU = v2c.apiPDU.getResponse(PDU)
                v2c.apiPDU.setErrorStatus(rspPDU, errStatus)
                v2c.apiPDU.setVarBinds(rspPDU, req)
                self.sendPdu(snmpEngine, stateReference, rspPDU)
                return
        for oid, val in req:
            self.store.commit_set(tuple(oid), val)
        rsp = [(oid, self.store.get_exact(tuple(oid))[1]) for oid, _ in req]
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)


def send_trap(snmpEngine, store):
    ntfOrg = ntforg.NotificationOriginator()
    cpu_val = store.model["scalars"]["cpuUsage"]["value"]
    threshold_val = store.model["scalars"]["cpuThreshold"]["value"]
    email_val = store.model["scalars"]["managerEmail"]["value"]
    
    varBinds = [
        (v2c.ObjectIdentifier((1,3,6,1,2,1,1,3,0)), v2c.TimeTicks(int((time.time()-AGENT_START)*100))),
        (v2c.ObjectIdentifier((1,3,6,1,6,3,1,1,4,1,0)), v2c.ObjectIdentifier((1,3,6,1,4,1,28308,2,1))),
        (v2c.ObjectIdentifier((1,3,6,1,4,1,28308,1,3,0)), v2c.Integer(cpu_val)),
        (v2c.ObjectIdentifier((1,3,6,1,4,1,28308,1,4,0)), v2c.Integer(threshold_val)),
        (v2c.ObjectIdentifier((1,3,6,1,4,1,28308,1,2,0)), v2c.OctetString(email_val.encode('utf-8')))
    ]
    ntfOrg.sendVarBinds(snmpEngine, 'trap-target', None, '', varBinds)
    print(f"📡 TRAP enviada: CPU {cpu_val}% > umbral {threshold_val}%")
    send_email(email_val, cpu_val, threshold_val)


def send_email(to_addr, cpu_val, threshold_val):
    try:
        msg = MIMEText(f"Alerta de CPU!\n\nCPU actual: {cpu_val}%\nUmbral: {threshold_val}%\nHora: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        msg['Subject'] = f'Alerta CPU: {cpu_val}%'
        msg['From'] = GMAIL_USER
        msg['To'] = to_addr
        
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=10) as smtp:
            smtp.login(GMAIL_USER, GMAIL_PASSWORD)
            smtp.send_message(msg)
        
        print(f"✉️  Email enviado a {to_addr} vía Gmail")
    except Exception as e:
        print(f"❌ Error al enviar email: {e}")


def cpu_sampler(store, snmpEngine, stop_event):
    psutil.cpu_percent(interval=None)
    last_over = False
    while not stop_event.is_set():
        time.sleep(5)
        cpu = max(0, min(100, round(psutil.cpu_percent(interval=None))))
        store.set_cpu_usage_internal(cpu)
        threshold = store.model["scalars"]["cpuThreshold"]["value"]
        over = cpu > threshold
        if over and not last_over:
            send_trap(snmpEngine, store)
        last_over = over
        print(f"🖥️  CPU: {cpu}% | Umbral: {threshold}% | {'⚠️ SUPERADO' if over else '✅ OK'}")


def main():
    store = JsonStore(JSON_FILE)
    snmpEngine = engine.SnmpEngine()
    snmpContext = context.SnmpContext(snmpEngine)
    
    # Setup transport
    config.addTransport(
        snmpEngine, 
        udp.domainName, 
        udp.UdpTransport().openServerMode(('0.0.0.0', 161))
    )
    
    # Setup communities
    config.addV1System(snmpEngine, 'public-area', 'public')
    config.addV1System(snmpEngine, 'private-area', 'private')
    
    # Setup VACM
    for secModel in (1, 2):
        config.addVacmUser(snmpEngine, secModel, 'public-area', 'noAuthNoPriv', readSubTree=(1,3,6,1))
        config.addVacmUser(snmpEngine, secModel, 'private-area', 'noAuthNoPriv', readSubTree=(1,3,6,1), writeSubTree=(1,3,6,1))
    
    # Setup trap target
    config.addTargetParams(snmpEngine, 'trap-target', 'public-area', 'noAuthNoPriv', 1)
    config.addTargetAddr(snmpEngine, 'trap-target', udp.domainName, ('127.0.0.1', 162), 'trap-target', tagList='trap')
    config.addNotificationTarget(snmpEngine, 'trap-target', 'trap-target', 'trap')
    
    # Register custom responders
    JsonGet(snmpEngine, snmpContext, store)
    JsonGetNext(snmpEngine, snmpContext, store)
    JsonSet(snmpEngine, snmpContext, store)
    
    print("="*60)
    print("🚀 Agente SNMP ejecutándose en puerto UDP/161")
    print("🔑 Comunidades: public (RO), private (RW)")
    print(f"🆔 OID base: {store.model['baseoid']}")
    print("📊 Muestreo de CPU cada 5 segundos")
    print("📧 Emails vía Gmail SMTP")
    print("⚡ Presiona Ctrl+C para detener")
    print("="*60)
    
    stop_event = threading.Event()
    
    # Start CPU monitor
    cpu_thread = threading.Thread(target=cpu_sampler, args=(store, snmpEngine, stop_event))
    cpu_thread.daemon = True
    cpu_thread.start()
    
    # Start dispatcher
    snmpEngine.transportDispatcher.jobStarted(1)
    
    try:
        snmpEngine.transportDispatcher.runDispatcher()
    except KeyboardInterrupt:
        print("\n\n🛑 Apagando agente...")
        stop_event.set()
        cpu_thread.join(timeout=2)
        store.save()
        print("💾 Estado guardado en mib_state.json")
    finally:
        snmpEngine.transportDispatcher.closeDispatcher()


if __name__ == '__main__':
    main()
