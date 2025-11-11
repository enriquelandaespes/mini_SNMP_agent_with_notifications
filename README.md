# mini_SNMP_agent_with_notifications

Este repositorio contiene la implementación de un agente SNMP v2c personalizado para la asignatura de Gestión de Red. El agente monitoriza el uso de la CPU en tiempo real, expone objetos MIB personalizados y envía notificaciones (SNMP Traps y correos HTML) cuando se supera un umbral de CPU configurable.

El proyecto está implementado en Python 3 usando `pysnmp` (v7.1.4), `psutil` y `threading`.

## 🚀 Características Principales

* **Agente SNMP v2c:** Implementa un agente completo que responde a peticiones SNMP.
* **MIB Personalizada:** Expone 4 objetos escalares (`manager`, `managerEmail`, `cpuUsage`, `cpuThreshold`).
* **Soporte `GET`/`GETNEXT`/`SET`:** Permite la lectura de todos los objetos y la escritura de los objetos configurables.
* **Seguridad VACM + Lógica:** Implementa una "Defensa en Profundidad". El VACM (Puerta 1) está configurado para bloquear escrituras de la comunidad `public`. Además, el `JsonSet` (Puerta 2) valida manualmente la comunidad para asegurar que `public` nunca pueda escribir.
* **Monitor de CPU Real:** Un hilo (`threading`) separado usa `psutil` para monitorizar el uso real de la CPU cada 5 segundos.
* **Persistencia JSON:** El estado del agente (manager, email, umbral) se guarda en `mib_state.json` y se recarga al reiniciar.
* **Notificaciones Avanzadas:**
    * **SNMP Traps:** Envía un `cpuOverThresholdNotification` al destino `127.0.0.1:162`.
    * **Emails HTML:** Envía un correo de alerta con formato HTML (ver `send_email` en el código) al `managerEmail` configurado.
* **Scripts de Soporte:**
    * `comprobacion_paquetes.py`: Un script interactivo que verifica e instala las dependencias correctas (`pysnmp==7.1.4`).
    * `test.py`: Una suite de pruebas interactiva para validar todo el agente.

## 📂 Ficheros del Repositorio

* `mini_agent(7.1.4).py`: El script principal del agente SNMP.
* `test.py`: El script de prueba interactivo.
* `comprobacion_paquetes.py`: El script de comprobación de dependencias.
* `MYAGENT-MIB.txt`: El fichero de definición de la MIB (SMIv2).
* `mib_state.json`: Fichero de datos autogenerado por el agente.

---

## ⚙️ 1. Instalación y Configuración

Sigue estos pasos para poner en marcha el proyecto.

### Paso 1: Entorno Virtual (Recomendado)

Para evitar conflictos, usa un entorno virtual.

```bash
# 1. Crea el entorno
python -m venv venv

# 2. Actívalo
# En Windows (PowerShell)
.\venv\Scripts\Activate.ps1
# En macOS/Linux
source venv/bin/activate