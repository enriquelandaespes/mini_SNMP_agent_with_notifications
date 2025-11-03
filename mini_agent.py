#!/usr/bin/env python3
"""
mini_agent.py - SNMP Agent FUNCIONAL con todas las versiones de pysnmp
"""

import json
import os
import time
import asyncio
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

import psutil
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, ntforg, context
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.proto.api import v2c
from pysnmp import debug

# ==================== Configuration ====================
JSON_FILE = "mib_state.json"
AGENT_START = time.time()
SMTP_SERVER = "localhost"
SMTP_PORT = 1025

# ==================== JSON Store ====================
class JsonStore:
    def __init__(self, filepath):
        self.filepath = filepath
        self.model = self._load()
        self.oid_map = self._build_oid_map()
        self.sorted_oids = sorted(self.oid_map.keys())
    
    def _load(self):
        if os.path.exists(self.filepath):
            with open(self.filepath, 'r') as f:
                return json.load(f)
        
        default = {
            "baseoid": "1.3.6.1.4.1.28308.1",
            "scalars": {
                "manager": {
                    "oid": "1.3.6.1.4.1.28308.1.1.0",
                    "type": "DisplayString",
                    "access": "read-write",
                    "minlen": 1,
                    "maxlen": 255,
                    "value": "manager"
                },
                "managerEmail": {
                    "oid": "1.3.6.1.4.1.28308.1.2.0",
                    "type": "DisplayString",
                    "access": "read-write",
                    "minlen": 4,
                    "maxlen": 255,
                    "value": "fakeunizar@gmail.com"
                },
                "cpuUsage": {
                    "oid": "1.3.6.1.4.1.28308.1.3.0",
                    "type": "Integer32",
                    "access": "read-only",
                    "minval": 0,
                    "maxval": 100,
                    "value": 10
                },
                "cpuThreshold": {
                    "oid": "1.3.6.1.4.1.28308.1.4.0",
                    "type": "Integer32",
                    "access": "read-write",
                    "minval": 0,
                    "maxval": 100,
                    "value": 80
                }
            }
        }
        self._save(default)
        return default
    
    def _save(self, data=None):
        if data is None:
            data = self.model
        with open(self.filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _build_oid_map(self):
        oid_map = {}
        for key, obj in self.model["scalars"].items():
            oid_tuple = tuple(int(x) for x in obj["oid"].split('.'))
            oid_map[oid_tuple] = key
        return oid_map
    
    def get_exact(self, oid_tuple):
        key = self.oid_map.get(oid_tuple)
        if key is None:
            return False, v2c.NoSuchObject()
        obj = self.model["scalars"][key]
        return True, self._to_snmp(obj["type"], obj["value"])
    
    def get_next(self, oid_tuple):
        for candidate in self.sorted_oids:
            if candidate > oid_tuple:
                key = self.oid_map[candidate]
                obj = self.model["scalars"][key]
                return True, candidate, self._to_snmp(obj["type"], obj["value"])
        return False, None, None
    
    def validate_set(self, oid_tuple, snmp_val):
        key = self.oid_map.get(oid_tuple)
        if key is None:
            return 6, 1
        
        obj = self.model["scalars"][key]
        
        if obj["access"] == "read-only":
            return 17, 1
        
        if obj["type"] == "DisplayString":
            if not isinstance(snmp_val, v2c.OctetString):
                return 7, 1
            try:
                value = str(snmp_val)
            except:
                value = bytes(snmp_val).decode('utf-8', errors='replace')
            if len(value) < obj.get("minlen", 0) or len(value) > obj.get("maxlen", 255):
                return 10, 1
        
        elif obj["type"] == "Integer32":
            if not isinstance(snmp_val, v2c.Integer):
                return 7, 1
            value = int(snmp_val)
            if value < obj.get("minval", 0) or value > obj.get("maxval", 2147483647):
                return 10, 1
        
        return 0, 0
    
    def commit_set(self, oid_tuple, snmp_val):
        key = self.oid_map[oid_tuple]
        obj = self.model["scalars"][key]
        
        if obj["type"] == "DisplayString":
            try:
                obj["value"] = str(snmp_val)
            except:
                obj["value"] = bytes(snmp_val).decode('utf-8', errors='replace')
        elif obj["type"] == "Integer32":
            obj["value"] = int(snmp_val)
        
        self._save()
    
    def set_cpu_usage_internal(self, cpu_value):
        self.model["scalars"]["cpuUsage"]["value"] = cpu_value
        self._save()
    
    def _to_snmp(self, snmp_type, value):
        if snmp_type == "DisplayString":
            return v2c.OctetString(str(value).encode('utf-8'))
        elif snmp_type == "Integer32":
            return v2c.Integer(int(value))
        return v2c.Null()


# ==================== Command Responders ====================
class JsonGet(cmdrsp.GetCommandResponder):
    def __init__(self, snmpEngine, snmpContext, store):
        cmdrsp.GetCommandResponder.__init__(self, snmpEngine, snmpContext)
        self.store = store
    
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acInfo):
        req = v2c.apiPDU.getVarBinds(PDU)
        rsp = []
        
        for oid, _ in req:
            found, value = self.store.get_exact(tuple(oid))
            rsp.append((oid, value))
        
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)


class JsonGetNext(cmdrsp.NextCommandResponder):
    def __init__(self, snmpEngine, snmpContext, store):
        cmdrsp.NextCommandResponder.__init__(self, snmpEngine, snmpContext)
        self.store = store
    
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acInfo):
        req = v2c.apiPDU.getVarBinds(PDU)
        rsp = []
        
        for oid, _ in req:
            ok, next_oid, val = self.store.get_next(tuple(oid))
            if ok:
                rsp.append((v2c.ObjectIdentifier(next_oid), val))
            else:
                rsp.append((oid, v2c.EndOfMibView()))
        
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)


class JsonSet(cmdrsp.SetCommandResponder):
    def __init__(self, snmpEngine, snmpContext, store):
        cmdrsp.SetCommandResponder.__init__(self, snmpEngine, snmpContext)
        self.store = store
    
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acInfo):
        req = v2c.apiPDU.getVarBinds(PDU)
        
        for idx, (oid, val) in enumerate(req, start=1):
            errStatus, _ = self.store.validate_set(tuple(oid), val)
            if errStatus != 0:
                rspPDU = v2c.apiPDU.getResponse(PDU)
                v2c.apiPDU.setErrorStatus(rspPDU, errStatus)
                v2c.apiPDU.setErrorIndex(rspPDU, idx)
                v2c.apiPDU.setVarBinds(rspPDU, req)
                self.sendPdu(snmpEngine, stateReference, rspPDU)
                return
        
        for oid, val in req:
            self.store.commit_set(tuple(oid), val)
        
        rsp = []
        for oid, _ in req:
            found, value = self.store.get_exact(tuple(oid))
            rsp.append((oid, value))
        
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)


# ==================== Trap Sender ====================
def send_trap(snmpEngine, store):
    ntfOrg = ntforg.NotificationOriginator()
    
    cpu_val = store.model["scalars"]["cpuUsage"]["value"]
    threshold_val = store.model["scalars"]["cpuThreshold"]["value"]
    email_val = store.model["scalars"]["managerEmail"]["value"]
    
    uptime_ticks = int((time.time() - AGENT_START) * 100)
    
    varBinds = [
        (v2c.ObjectIdentifier((1,3,6,1,2,1,1,3,0)), v2c.TimeTicks(uptime_ticks)),
        (v2c.ObjectIdentifier((1,3,6,1,6,3,1,1,4,1,0)), v2c.ObjectIdentifier((1,3,6,1,4,1,28308,2,1))),
        (v2c.ObjectIdentifier((1,3,6,1,4,1,28308,1,3,0)), v2c.Integer(cpu_val)),
        (v2c.ObjectIdentifier((1,3,6,1,4,1,28308,1,4,0)), v2c.Integer(threshold_val)),
        (v2c.ObjectIdentifier((1,3,6,1,4,1,28308,1,2,0)), v2c.OctetString(email_val.encode('utf-8')))
    ]
    
    ntfOrg.sendVarBinds(snmpEngine, 'trap-target', None, '', varBinds)
    
    print(f"[TRAP] CPU {cpu_val}% > threshold {threshold_val}%")
    send_email(email_val, cpu_val, threshold_val)


def send_email(to_addr, cpu_val, threshold_val):
    try:
        msg = MIMEText(
            f"CPU Usage Alert!\n\n"
            f"Current CPU: {cpu_val}%\n"
            f"Threshold: {threshold_val}%\n"
            f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        msg['Subject'] = f'CPU Alert: {cpu_val}%'
        msg['From'] = 'snmp-agent@localhost'
        msg['To'] = to_addr
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=5) as smtp:
            smtp.send_message(msg)
        
        print(f"[EMAIL] Sent to {to_addr}")
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")


# ==================== CPU Sampler ====================
async def cpu_sampler(store, snmpEngine):
    psutil.cpu_percent(interval=None)
    last_over = False
    
    while True:
        await asyncio.sleep(5)
        
        cpu = round(psutil.cpu_percent(interval=None))
        cpu = max(0, min(100, cpu))
        
        store.set_cpu_usage_internal(cpu)
        
        threshold = int(store.model["scalars"]["cpuThreshold"]["value"])
        over = cpu > threshold
        
        if over and not last_over:
            send_trap(snmpEngine, store)
        
        last_over = over
        print(f"[CPU] {cpu}% (threshold: {threshold}%)")


# ==================== Main ====================
def main():
    store = JsonStore(JSON_FILE)
    snmpEngine = engine.SnmpEngine()
    
    # Create context FIRST
    snmpContext = context.SnmpContext(snmpEngine)
    
    # Transport
    config.addTransport(
        snmpEngine,
        udp.domainName,
        udp.UdpTransport().openServerMode(('0.0.0.0', 161))
    )
    
    # Communities
    config.addV1System(snmpEngine, 'public-area', 'public')
    config.addV1System(snmpEngine, 'private-area', 'private')
    
    # VACM
    for secModel in (1, 2):
        config.addVacmUser(
            snmpEngine, secModel, 'public-area', 'noAuthNoPriv',
            readSubTree=(1,3,6,1)
        )
        config.addVacmUser(
            snmpEngine, secModel, 'private-area', 'noAuthNoPriv',
            readSubTree=(1,3,6,1),
            writeSubTree=(1,3,6,1)
        )
    
    # Trap target
    config.addTargetParams(snmpEngine, 'trap-target', 'public-area', 'noAuthNoPriv', 1)
    config.addTargetAddr(
        snmpEngine, 'trap-target',
        udp.domainName, ('127.0.0.1', 162),
        'trap-target'
    )
    config.addNotificationTarget(
        snmpEngine, 'trap-target', 'trap-target', 'trap'
    )
    
    # Responders - CON snmpContext creado ANTES
    JsonGet(snmpEngine, snmpContext, store)
    JsonGetNext(snmpEngine, snmpContext, store)
    JsonSet(snmpEngine, snmpContext, store)
    
    print("=" * 50)
    print("SNMP Agent running on UDP/161")
    print(f"Communities: public (RO), private (RW)")
    print(f"Base OID: {store.model['baseoid']}")
    print("=" * 50)
    
    # CPU monitor
    loop = asyncio.get_event_loop()
    loop.create_task(cpu_sampler(store, snmpEngine))
    
    # Run dispatcher
    snmpEngine.transportDispatcher.jobStarted(1)
    
    try:
        snmpEngine.transportDispatcher.runDispatcher()
    except KeyboardInterrupt:
        print("\nShutdown...")
    finally:
        snmpEngine.transportDispatcher.closeDispatcher()


if __name__ == '__main__':
    main()
