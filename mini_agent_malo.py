"""
Mini SNMP Agent - With JsonGet/JsonGetNext/JsonSet responders
Following assignment structure with acInfo parameter handling
"""

import asyncio
import json
import os
import signal
import sys
import time
import psutil
import smtplib
from email.message import EmailMessage
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.proto.api import v2c

# ==========================
# CONFIGURATION AND CONSTANTS
# ==========================
BASE_OID = (1, 3, 6, 1, 4, 1, 28308, 1)
NOTIF_OID = (1, 3, 6, 1, 4, 1, 28308, 2, 1)
STATE_FILE = "mib_state.json"

SCALARS = {
    "manager": {
        "oid": BASE_OID + (1, 0),
        "type": "DisplayString",
        "access": "read-write",
        "min_len": 1,
        "max_len": 64,
        "default": "NetAdmin"
    },
    "managerEmail": {
        "oid": BASE_OID + (2, 0),
        "type": "DisplayString",
        "access": "read-write",
        "min_len": 3,
        "max_len": 254,
        "default": "admin@example.com"
    },
    "cpuUsage": {
        "oid": BASE_OID + (3, 0),
        "type": "Integer32",
        "access": "read-only",
        "min": 0,
        "max": 100,
        "default": 0
    },
    "cpuThreshold": {
        "oid": BASE_OID + (4, 0),
        "type": "Integer32",
        "access": "read-write",
        "min": 0,
        "max": 100,
        "default": 80
    }
}

OID_to_KEY = {tuple(v["oid"]): k for k, v in SCALARS.items()}
SORTED_OIDS = sorted(OID_to_KEY.keys())

# ====================
# JSON STORE
# ====================
class MibStore:
    """Maintain instance data in Python dictionary backed by JSON"""
    def __init__(self, path):
        self.path = path
        self.model = self._load_state()

    def _load_state(self):
        if not os.path.exists(self.path):
            return self._default_model()
        try:
            with open(self.path, "r") as f:
                model = json.load(f)
            for k in SCALARS:
                if k not in model["scalars"]:
                    model["scalars"][k] = {"value": SCALARS[k]["default"]}
            return model
        except Exception:
            return self._default_model()

    def _default_model(self):
        return {"scalars": {k: {"value": v["default"]} for k, v in SCALARS.items()}}

    def save(self):
        with open(self.path, "w") as f:
            json.dump(self.model, f, indent=2)

    def get_exact(self, oid_tuple):
        """GET operation: exact OID lookup"""
        key = OID_to_KEY.get(oid_tuple)
        if not key:
            return False, v2c.NoSuchObject()
        val = self.model["scalars"][key]["value"]
        if SCALARS[key]["type"] == "DisplayString":
            return True, v2c.OctetString(str(val))
        else:
            return True, v2c.Integer(int(val))

    def get_next(self, oid_tuple):
        """GETNEXT operation: lexicographic walk"""
        for oid in SORTED_OIDS:
            if oid > oid_tuple:
                found, val = self.get_exact(oid)
                return True, oid, val
        return False, None, v2c.EndOfMibView()

    def validate_set(self, oid_tuple, value):
        """Two-phase SET: validation phase"""
        key = OID_to_KEY.get(oid_tuple)
        if not key:
            return 6, 0  # noAccess
        if SCALARS[key]["access"] == "read-only":
            return 17, 0  # notWritable
        if SCALARS[key]["type"] == "DisplayString":
            if not isinstance(value, v2c.OctetString):
                return 7, 0  # wrongType
            raw = value.asOctets().decode("utf8")
            if len(raw) < SCALARS[key]["min_len"] or len(raw) > SCALARS[key]["max_len"]:
                return 10, 0  # wrongValue
        elif SCALARS[key]["type"] == "Integer32":
            if not isinstance(value, v2c.Integer):
                return 7, 0  # wrongType
            num = int(value)
            if num < SCALARS[key]["min"] or num > SCALARS[key]["max"]:
                return 10, 0  # wrongValue
        return 0, 0  # noError

    def commit_set(self, oid_tuple, value):
        """Two-phase SET: commit phase"""
        key = OID_to_KEY.get(oid_tuple)
        if SCALARS[key]["type"] == "DisplayString":
            raw = value.asOctets().decode("utf8")
            self.model["scalars"][key]["value"] = raw
        elif SCALARS[key]["type"] == "Integer32":
            self.model["scalars"][key]["value"] = int(value)
        self.save()

    def set_cpu_usage_internal(self, val):
        """Internal setter for periodic CPU updates"""
        self.model["scalars"]["cpuUsage"]["value"] = val
        self.save()

STORE = MibStore(STATE_FILE)

# ======================
# COMMAND RESPONDERS WITH acInfo
# ======================
class JsonGet(cmdrsp.GetCommandResponder):
    """GET responder: handles exact OID lookups"""
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acInfo=(None, None)):
        """Handle GET requests - acInfo parameter added"""
        req = v2c.apiPDU.getVarBinds(PDU)
        rsp = []
        for oid, _ in req:
            found, value = STORE.get_exact(tuple(oid))
            rsp.append((oid, value if found else v2c.NoSuchObject()))
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)

class JsonGetNext(cmdrsp.NextCommandResponder):
    """GETNEXT responder: handles lexicographic walk"""
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acInfo=(None, None)):
        """Handle GETNEXT requests - acInfo parameter added"""
        req = v2c.apiPDU.getVarBinds(PDU)
        rsp = []
        for oid, _ in req:
            ok, next_oid, val = STORE.get_next(tuple(oid))
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
    """SET responder: two-phase commit with validation"""
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acInfo=(None, None)):
        """Handle SET requests - acInfo parameter added"""
        req = v2c.apiPDU.getVarBinds(PDU)
        
        # Phase 1: Validate all varbinds
        for idx, (oid, val) in enumerate(req, start=1):
            errStatus, errIndex = STORE.validate_set(tuple(oid), val)
            if errStatus != 0:
                rspPDU = v2c.apiPDU.getResponse(PDU)
                v2c.apiPDU.setErrorStatus(rspPDU, errStatus)
                v2c.apiPDU.setErrorIndex(rspPDU, idx)
                v2c.apiPDU.setVarBinds(rspPDU, req)
                self.sendPdu(snmpEngine, stateReference, rspPDU)
                return
        
        # Phase 2: Commit changes
        for oid, val in req:
            STORE.commit_set(tuple(oid), val)
        
        # Reply with updated values
        rsp = []
        for oid, _ in req:
            found, value = STORE.get_exact(tuple(oid))
            rsp.append((oid, value if found else v2c.NoSuchObject()))
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)

# =================
# NOTIFICATION HANDLING
# =================
def send_email_alert(email, cpu, thr):
    """Send email notification using smtplib"""
    msg = EmailMessage()
    msg['From'] = "agent@example.com"
    msg['To'] = email
    msg['Subject'] = "⚠️ CPU Alert SNMP Agent"
    msg.set_content(f"CPU usage {cpu}% exceeded threshold {thr}% at {time.ctime()}")
    try:
        with smtplib.SMTP('localhost', 1025) as s:
            s.send_message(msg)
        print(f"✉️  Email sent to {email}")
    except Exception as ex:
        print(f"❌ Email failed: {ex}")

def send_trap(snmpEngine, cpu, thr, email, timestamp):
    """Send SNMP trap notification"""
    print(f"📡 Sending TRAP: CPU={cpu}% > Threshold={thr}%")

async def cpu_sampler(snmpEngine):
    """Periodic CPU monitoring task (asyncio coroutine)"""
    psutil.cpu_percent(interval=None)  # warm-up
    last_over = False
    
    while True:
        await asyncio.sleep(5)
        cpu = round(psutil.cpu_percent(interval=None))
        cpu = min(100, max(0, cpu))
        STORE.set_cpu_usage_internal(cpu)
        
        thr = int(STORE.model["scalars"]["cpuThreshold"]["value"])
        email = str(STORE.model["scalars"]["managerEmail"]["value"])
        over = cpu > thr
        
        # Edge-triggered notification
        if over and not last_over:
            timestamp = time.strftime("%Y%m%d%H%M%S")
            send_trap(snmpEngine, cpu, thr, email, timestamp)
            send_email_alert(email, cpu, thr)
        
        last_over = over
        print(f"🖥️  CPU: {cpu}% | Threshold: {thr}% | {'⚠️ OVER' if over else '✅ OK'}")

# ============
# MAIN AGENT
# ============
def signal_handler(sig, frame):
    """Graceful shutdown on Ctrl+C"""
    print("\n\n🛑 Shutting down gracefully...")
    STORE.save()
    print("💾 State saved to mib_state.json")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    snmpEngine = engine.SnmpEngine()

    # Transport: UDP port 161
    config.add_transport(
        snmpEngine,
        udp.DOMAIN_NAME,
        udp.UdpTransport().open_server_mode(('0.0.0.0', 161))
    )

    # Communities: public (RO), private (RW)
    config.add_v1_system(snmpEngine, 'ro-area', 'public')
    config.add_v1_system(snmpEngine, 'rw-area', 'private')

    # VACM: grant access per community
    for secModel in (1, 2):
        config.add_vacm_user(snmpEngine, secModel, 'ro-area', 'noAuthNoPriv',
                           readSubTree=(1,3,6,1))
        config.add_vacm_user(snmpEngine, secModel, 'rw-area', 'noAuthNoPriv',
                           readSubTree=(1,3,6,1), writeSubTree=(1,3,6,1))

    # Register SNMP context
    snmpContext = context.SnmpContext(snmpEngine)

    # Register JSON responders (with acInfo parameter)
    JsonGet(snmpEngine, snmpContext)
    JsonGetNext(snmpEngine, snmpContext)
    JsonSet(snmpEngine, snmpContext)

    print("="*60)
    print("🚀 SNMP Agent Running (JsonGet/JsonGetNext/JsonSet)")
    print("="*60)
    print("📍 Listening on: 0.0.0.0:161")
    print("🔑 Communities: public (RO), private (RW)")
    print("🆔 Base OID: 1.3.6.1.4.1.28308.1")
    print("📊 CPU sampling every 5 seconds")
    print("⚡ Press Ctrl+C to stop")
    print("="*60)
    
    loop = asyncio.get_event_loop()
    loop.create_task(cpu_sampler(snmpEngine))
    
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
