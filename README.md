# Mini Agente SNMP de Monitorización de CPU

Este proyecto implementa un agente SNMP v2c personalizado en Python utilizando la librería `pysnmp`. El agente monitoriza el uso de la CPU, expone esta información mediante una MIB propia y, si se sobrepasa el umbral configurado, genera dos notificaciones: un SNMP Trap y un correo electrónico de alerta. La configuración y estado del agente persisten en un archivo JSON.

---

## 📋 Características Principales

- **MIB Personalizada:** Expone la MIB `MYAGENT-MIB` con prefijo OID `1.3.6.1.4.1.28308`.
- **Monitorización de CPU en tiempo real** empleando `psutil`.
- **Operaciones SNMP:** Soporta `GET`, `GETNEXT`, y `SET` con control de acceso `public` (lectura) y `private` (escritura).
- **Notificaciones Dual:** SNMP Trap y Alertas por Email al superar el umbral de CPU.
- **Persistencia:** Estado guardado en `mib_state.json` para sobrevivir reinicios.
- **Scripts auxiliares:** Comprobación de dependencias (`Comprobacion_paquetes.py`) y test interactivo (`test.py`).

---

## 📁 Estructura de la MIB

### Diagrama conceptual de la jerarquía MIB

```
iso(1)
  └── org(3)
       └── dod(6)
            └── internet(1)
                 └── private(4)
                      └── enterprises(1)
                           └── 28308 [MYAGENT-MIB]
                                ├── myAgentObjects(1)
                                │    ├── manager(1) = RW DisplayString
                                │    ├── managerEmail(2) = RW DisplayString
                                │    ├── cpuUsage(3) = RO Integer32 (%)
                                │    └── cpuThreshold(4) = RW Integer32 (%)
                                └── myAgentNotifications(2)
                                     └── cpuOverThresholdNotification(1)
```

---

## 🗂️ Objetos Gestionados

| Objeto             | OID                          | Acceso       | Descripción                         | Tipo             |
|--------------------|------------------------------|--------------|-------------------------------------|------------------|
| manager            | 1.3.6.1.4.1.28308.1.1.0      | read-write   | Nombre del administrador            | DisplayString    |
| managerEmail       | 1.3.6.1.4.1.28308.1.2.0      | read-write   | Email para notificaciones           | DisplayString    |
| cpuUsage           | 1.3.6.1.4.1.28308.1.3.0      | read-only    | Uso actual de CPU (%)               | Integer32[0-100] |
| cpuThreshold       | 1.3.6.1.4.1.28308.1.4.0      | read-write   | Umbral de CPU para alerta (%)       | Integer32[0-100] |

**Notificación SNMP:**
- **cpuOverThresholdNotification**: OID `1.3.6.1.4.1.28308.2.1`
  - Se dispara cuando `cpuUsage` supera `cpuThreshold`
  - Incluye varBinds: `cpuUsage`, `cpuThreshold`, `managerEmail`, timestamp

---

## 🚀 Instalación y Configuración

### 1. Requisitos

- **Python 3.8 o superior**
- **Dependencias Python:**
  - `pysnmp==7.1.4`
  - `psutil`
  - `keyboard`
- **Herramientas externas:** Net-SNMP (`snmpget`, `snmpset`, `snmpwalk`)
- **Cuenta Gmail con contraseña de aplicación**

### 2. Instalación de Dependencias

Ejecuta el script de comprobación e instalación:

```bash
python Comprobacion_paquetes.py
```

El script:
- Verifica la versión de Python (≥ 3.8)
- Instala/actualiza las librerías necesarias
- Verifica que Net-SNMP esté disponible en el PATH

### 3. Configuración del Correo

Edita el archivo `mini_agent(7.1.4).py` y localiza las constantes:

```python
# Configuración de Gmail para envío de correos
GMAIL_USER = "tu-correo@gmail.com"
GMAIL_PASSWORD = "tu-contraseña-de-aplicacion"
```

**Nota importante:** La contraseña debe ser una "Contraseña de Aplicación" generada desde tu cuenta Google (Settings > Security), no tu contraseña habitual de inicio de sesión.

---

## ⚡ Uso Básico

### Terminal 1: Arrancar el Agente

```bash
python "mini_agent(7.1.4).py"
```

Verás una salida similar a:

```
======================================================================
🚀 AGENTE SNMP INICIADO
======================================================================
   Puerto: UDP/161
   Comunidad lectura: public
   Comunidad escritura: private
   OID base: 1.3.6.1.4.1.28308.1
   Archivo JSON: mib_state.json
======================================================================
🖥️  MONITOR DE CPU INICIADO [2025-11-14 23:10:00]
======================================================================
   Pulsa 'r' para mostrar/ocultar salida por pantalla
```

**Tecla 'r':** Muestra/oculta el log en tiempo real del monitor de CPU.

### Terminal 2: Ejecutar Tests

```bash
python test.py
```

El script guía interactivamente a través de:
- Configuración de la IP del agente
- Guardado del estado actual
- Pruebas GET, GETNEXT, SET
- Tests negativos (acceso denegado, tipos inválidos)
- Monitorización de CPU
- Disparador de notificaciones
- Restauración del estado original

---

## 🧪 Pruebas Manuales con Net-SNMP

### Operaciones Básicas

**Lectura de CPU actual:**
```bash
snmpget -v2c -c public 127.0.0.1 1.3.6.1.4.1.28308.1.3.0
```

**Establecer nuevo umbral (80%):**
```bash
snmpset -v2c -c private 127.0.0.1 1.3.6.1.4.1.28308.1.4.0 i 80
```

**Recorrer todos los objetos:**
```bash
snmpwalk -v2c -c public 127.0.0.1 1.3.6.1.4.1.28308.1
```

**Cambiar nombre del administrador:**
```bash
snmpset -v2c -c private 127.0.0.1 1.3.6.1.4.1.28308.1.1.0 s "John Doe"
```

### Tests Negativos (Esperados que Fallen)

**Intentar escribir sobre cpuUsage (lectura):**
```bash
snmpset -v2c -c private 127.0.0.1 1.3.6.1.4.1.28308.1.3.0 i 50
# Error: notWritable
```

**Intentar escribir con comunidad pública:**
```bash
snmpset -v2c -c public 127.0.0.1 1.3.6.1.4.1.28308.1.4.0 i 80
# Error: noAccess
```

**Tipo de dato incorrecto:**
```bash
snmpset -v2c -c private 127.0.0.1 1.3.6.1.4.1.28308.1.4.0 s "text"
# Error: wrongType
```

---

## 📦 Archivos del Proyecto

| Archivo                  | Descripción                                                          |
|--------------------------|----------------------------------------------------------------------|
| mini_agent(7.1.4).py     | Script principal del agente SNMP (servidor, monitor, notificaciones) |
| MYAGENT-MIB.txt          | Definición SMIv2 de la MIB personalizada                             |
| mib_uml.wsd              | Diagrama UML PlantUML de la jerarquía MIB                            |
| mib_state.json           | Archivo de persistencia: estado y configuración del agente           |
| Comprobacion_paquetes.py | Script de instalación y verificación de dependencias                 |
| test.py                  | Suite interactiva de pruebas SNMP del agente                         |
| USO_IA.md                | Documentación del proceso de desarrollo asistido por IA              |
| README.md                | Este archivo                                                         |

---

## 💡 Detalles Técnicos Importantes

### Validación y Control de Acceso

- **Comunidad `public`**: Solo lectura (GET, GETNEXT, WALK)
- **Comunidad `private`**: Lectura y escritura (GET, SET)
- **Objetos read-only**: `cpuUsage` no puede modificarse
- **Validación de tipos**: Los valores deben coincidir con el tipo SMIv2 definido
- **Rango válido**: CPU y umbral deben estar entre 0 y 100

### Persistencia de Estado

El archivo `mib_state.json` almacena:
```json
{
  "manager": "System Administrator",
  "managerEmail": "admin@example.com",
  "cpuThreshold": 75
}
```

Estos valores se recuperan al reiniciar el agente. El `cpuUsage` es *siempre* medido en tiempo real y no se persiste.

### Mecanismo de Notificaciones

1. El agente monitoriza CPU cada 5 segundos
2. Si `cpuUsage > cpuThreshold`:
   - Envía **SNMP Trap** al gestor
   - Envía **Email** a `managerEmail`
   - Registra el evento
3. La notificación es *edge-triggered*: solo se envía al cruzar el umbral, no continuamente

---

## 📚 Referencias y Recursos

- [RFC 2578 – Structure of Management Information Version 2 (SMIv2)](https://datatracker.ietf.org/doc/html/rfc2578)
- [RFC 3416 – Version 2 of the Protocol Operations for SNMP](https://datatracker.ietf.org/doc/html/rfc3416)
- [pysnmp Official Documentation](https://docs.lextudio.com/pysnmp/v6.2.0/)
- [psutil Documentation](https://psutil.readthedocs.io/en/latest/)
- [Python asyncio Tutorial](https://realpython.com/async-io-python/)
- [Python smtplib Guide](https://realpython.com/python-send-email/)
- [Net-SNMP Tools](https://www.net-snmp.org/)

---

## 🔧 Solución de Problemas

### El agente no inicia

- Verifica que el puerto 161 no esté en uso: `netstat -tlnp | grep 161`
- Confirma que tienes permisos para puertos < 1024 (en Linux, usa `sudo`)

### Net-SNMP commands no encontrados

- Instala Net-SNMP: `apt-get install snmp` (Debian/Ubuntu) o `brew install net-snmp` (macOS)
- Verifica que esté en el PATH: `which snmpget`

### Correos no enviados

- Valida credenciales de Gmail
- Comprueba que tienes activada la autenticación de apps: https://myaccount.google.com/apppasswords
- Prueba con `telnet smtp.gmail.com 587` para verificar conectividad

### MIB no carga en snmpwalk

- Instala la MIB: `snmpwalk -m +MYAGENT-MIB -v2c -c public 127.0.0.1 MYAGENT-MIB::manager`
- O especifica el OID directamente: `snmpwalk -v2c -c public 127.0.0.1 1.3.6.1.4.1.28308`

---

## 👨‍💻 Recomendaciones de Desarrollo

1. **Prueba frecuentemente** con la suite `test.py` tras cambios
2. **Valida la MIB** con herramientas como `smilint` antes de distribuir
3. **Usa commits pequeños** y descriptivos en control de versiones
4. **Documenta cambios** en un archivo CHANGELOG
5. **Prueba credenciales** con MailHog (SMTP local) antes de usar Gmail real

---

## 📄 Licencia

Proyecto desarrollado con fines educativos para demostrar conceptos de SNMP, MIB, notificaciones y programación de agentes de red.

---

**Última actualización:** Noviembre 2025  
**Versión:** 1.0