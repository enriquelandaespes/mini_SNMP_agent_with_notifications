# Uso de la IA en el Proyecto Mini Agente SNMP

## 📋 Índice
1. [Pregunta Inicial](#pregunta-inicial)
2. [Primera Versión Generada por IA](#primera-versión-generada-por-ia)
3. [Fallos Identificados en la Versión Inicial](#fallos-identificados-en-la-versión-inicial)
4. [Problemas con PySnmp](#problemas-con-pysnmp)
5. [Proceso Iterativo de Depuración](#proceso-iterativo-de-depuración)
6. [Consultas y Diagnósticos de Errores](#consultas-y-diagnósticos-de-errores)
7. [Evolución y Refinamiento](#evolución-y-refinamiento)
8. [Resultado Final](#resultado-final)

---

## Pregunta Inicial

El proyecto comenzó cuando planteaste por primera vez los requisitos para diseñar e implementar un **agente SNMP personalizado** que fuera capaz de:

- Exponer objetos de gestión a través del protocolo SNMP
- Enviar **traps SNMP** cuando el uso de CPU excediera un umbral definido
- Enviar **notificaciones por email** al administrador cuando se superara el umbral
- Implementar un modelo de datos compatible con **SMIv2** (Structure of Management Information versión 2)
- Soportar operaciones SNMP básicas: **GET**, **SET** y **GETNEXT**
- Persistir datos en JSON para sobrevivir reinicios del agente
- Usar asincronía con `asyncio` para monitoreo de CPU sin bloquear peticiones SNMP

**La IA interpretó estos requisitos correctamente** y proporcionó una propuesta inicial de:

- Arquitectura del sistema dividida en componentes lógicos
- Estructura de la MIB en formato SMIv2 válido
- Diseño del agente Python con pysnmp
- Estrategia de pruebas automatizadas
- Recomendaciones de commits y versionado en Git

---

## Primera Versión Generada por IA

La IA generó **tres documentos principales** como base del trabajo:

### 1. **MYAGENT-MIB.txt** (Módulo MIB en SMIv2)

La IA creó una MIB completa que definía:

```smi
- Objetos escalares:
  • manager (DisplayString, RW, 1..64 caracteres)
  • managerEmail (DisplayString, RW, 3..128 caracteres)
  • cpuUsage (Integer32, RO, 0..100 %)
  • cpuThreshold (Integer32, RW, 0..100 %)

- Notificación:
  • cpuOverThresholdNotification
    - Variables: cpuUsage, cpuThreshold, managerEmail, dateAndTime
    - Se dispara cuando: cpuUsage > cpuThreshold

- OIDs basados en experimental:
  • 1.3.6.1.3.9999.x (o tu enterprise number)
```

**Características de la MIB generada:**

- Sintaxis SMIv2 válida según RFC 2578
- Jerarquía OID correcta
- Descripciones detalladas en inglés
- Tipos de datos apropiados (DisplayString, Integer32)
- Definición de conformance groups

### 2. **mini_agent.py** (Código Principal)

La IA proporcionó aproximadamente **600 líneas de código Python** con:

```python
# Componentes principales:
- MibStore: Clase para gestionar persistencia en JSON
- GetRequestHandler: Responde a peticiones GET SNMP
- GetNextRequestHandler: Implementa navegación GETNEXT
- SetRequestHandler: Procesa cambios SET con validaciones
- CpuSampler: Tarea asíncrona que muestrea CPU cada 5 segundos
- NotificationManager: Envía traps SNMP y emails
- VacmAccessControl: Control de acceso por comunidades
- SnmpAgent: Clase principal que orquesta todo
```

**Características iniciales del código:**

- Uso de `asyncio` para concurrencia
- Integración con `pysnmp` para operaciones SNMP
- Manejo de JSON para persistencia
- Control de acceso SNMP (comunidades public/private)
- Logging con niveles configurables
- Validaciones de tipos y rangos

### 3. **GUIA_COMPLETA.md** (Documentación y Recursos)

La IA generó una guía exhaustiva con:

- Instalación paso a paso del entorno
- Explicación detallada de cada componente
- Suite de pruebas (GET, SET, GETNEXT, WALK)
- Plan de commits Git recomendado
- Troubleshooting inicial
- 100+ recursos organizados por tema

---

## Fallos Identificados en la Versión Inicial

Al ejecutar el código generado inicialmente, **surgieron varios problemas**:

### Error 1: Sincronización entre asyncio y pysnmp

```
Error: Event loop is already running
Traceback: Event loop conflict between pysnmp callbacks and asyncio
```

**Causa:** La primera versión utilizaba el event loop de asyncio de manera incompatible con los callbacks síncronos de pysnmp. El motor SNMP intentaba usar su propio event loop, conflictando con el de asyncio.

**Problema conceptual:** 
- pysnmp tiene su propio mecanismo de I/O que no siempre es compatible con asyncio
- Los responders de SNMP se ejecutan en contexto de callbacks, no en corrutinas
- Llamar directamente a `await` desde los callbacks causaba deadlocks

### Error 2: Acceso a objetos MIB no inicializados

```
KeyError: 'OID 1.3.6.1.3.9999.1.1.0 not found in MibStore'
```

**Causa:** El mapeo entre OIDs y atributos de la clase MibStore no estaba correctamente vinculado. Los objetos se definían en el JSON pero no se registraban adecuadamente en el diccionario de mapeos.

### Error 3: Permisos en operaciones SET sobre objetos RO

```
SNMPGetSetError: Attempted write to read-only object cpuUsage
```

**Problema:** Las validaciones de lectura/escritura no se aplicaban correctamente. El código permitía SET sobre `cpuUsage` que debería ser solo lectura (RO).

### Error 4: Bloqueo de operaciones SNMP

```
TimeoutError: SNMP request timed out - agent appears unresponsive
```

**Causa:** La tarea de `CpuSampler` usaba `time.sleep()` (bloqueante) en lugar de `asyncio.sleep()`, congestionando el event loop.

---

## Problemas con PySnmp

La integración con `pysnmp` presentó desafíos específicos que requirieron **consultas adicionales a la IA**:

### Problema 1: Versión y compatibilidad

```
Error: No module named 'pysnmp.smi'
ModuleNotFoundError: pysnmp v6.x cambió la API
```

**Contexto:** pysnmp tiene dos versiones principales:
- **v4.x** (legacy): API antigua, deprecated
- **v5.x+** (actual): API rediseñada, incompatible hacia atrás

La IA aconsejó usar:
```bash
pip install pysnmp>=5.0  # O la más reciente estable
```

### Problema 2: Configuración del engine SNMP

```python
# Versión inicial incorrecta:
snmpEngine = SnmpEngine()  # Sin configuración explícita

# La IA sugirió:
snmpEngine = SnmpEngine()
config.addV1System(snmpEngine, 'public', 'public')  # Comunidades
config.addV2cSystem(snmpEngine, 'public', 'public')
config.addTargetParams(...)
config.addTransport(...)
```

### Problema 3: Handlers de respuesta asincronos

```python
# La IA indicó que los responders deben ser síncronos:
def handleGetRequest(cbCtx, implName, implVars):
    # No se puede usar await aquí
    # Pero sí se puede usar asyncio.run_coroutine_threadsafe()
    # para delegar a corrutinas
    pass
```

---

## Proceso Iterativo de Depuración

A medida que identificaste cada error, consultaste a la IA de forma **iterativa y progresiva**:

### Iteración 1: Error del Event Loop

**Tu pregunta:** "El programa se cuelga cuando arranca el agente. Dice que hay un conflicto de event loop."

**La IA respondió con:**
1. Explicación del problema (asyncio vs pysnmp event loops)
2. Alternativas de solución:
   - Usar `asyncio.run_coroutine_threadsafe()` para delegar tareas
   - Separar el event loop de SNMP del de asyncio
   - Usar threading para aislar componentes
3. Código ejemplo de la solución preferida

**Resultado:** Cambio arquitectónico: el CPU sampler usa threads internos de pysnmp en lugar de asyncio puro.

### Iteración 2: Mapeo de OIDs

**Tu pregunta:** "Cuando hago snmpget al OID, dice que no existe. Pero el JSON tiene los datos."

**La IA respondió con:**
1. Análisis del mapeo OID ↔ atributo en MibStore
2. Cómo registrar correctamente los objetos en el SNMP engine
3. Verificación con comandos de debug

**Resultado:** Implementación de un diccionario bidireccional de OIDs con inicialización explícita.

### Iteración 3: Control de acceso VACM

**Tu pregunta:** "Puedo hacer SET sobre cpuUsage con cualquier comunidad, pero debería ser RO."

**La IA respondió con:**
1. Explicación del VACM (View-based Access Control Model)
2. Cómo configurar view acceso per objeto
3. Restricciones por comunidad

**Resultado:** Implementación correcta de ACLs que valida:
```python
if not self.vacm.canWrite(community, oid):
    raise SNMPWriteNotPermittedError()
```

### Iteración 4: Bloqueo del event loop

**Tu pregunta:** "Los snmpget funcionan pero son lentos. Y de repente dejan de responder."

**La IA diagnosticó:**
- `time.sleep()` bloqueante en CPU sampler
- Cambio a `asyncio.sleep()` o threading con periodos cortos

**Resultado:** Refactorización para usar threading interno con `time.time()` y checks no bloqueantes.

---

## Consultas y Diagnósticos de Errores

Durante el desarrollo, realizaste **múltiples consultas sobre errores específicos**:

### Consulta sobre Email

```
Error: smtplib.SMTPAuthenticationError
```

**Tu pregunta:** "El email no se envía. SMTP fallando."

**La IA sugirió:**
1. Verificar configuración SMTP (host, puerto, credenciales)
2. Usar MailHog en local para testing sin credenciales reales
3. Formato correcto del mensaje (headers, encoding)
4. Manejo de excepciones con reintentos

**Código sugerido:**
```python
try:
    smtplib.SMTP(host).sendmail(...)
except SMTPException as e:
    logger.error(f"Email failed: {e}")
    # Retry logic
```

### Consulta sobre Persistencia

```
Error: JSON corrupted after agent crash
```

**Tu pregunta:** "Los datos se pierden si el agente se mata. ¿Cómo garantizar persistencia?"

**La IA propuso:**
1. Escritura atómica: escribir a archivo temporal, luego rename
2. Sincronización frecuente (no solo al salir)
3. Backup automático de versiones anteriores
4. Validación de JSON al cargar

**Código:**
```python
def save_atomic(self, data):
    with open(f"{self.path}.tmp", 'w') as f:
        json.dump(data, f)
    os.rename(f"{self.path}.tmp", self.path)  # Atomic
```

### Consulta sobre Testing

```
Error: SNMP operations inconsistent between local and remote
```

**Tu pregunta:** "¿Cómo hago pruebas exhaustivas?"

**La IA creó:**
- Script `test_agent.sh` con suite completa
- Pruebas positivas (operaciones exitosas)
- Pruebas negativas (errores esperados)
- Pruebas de edge cases (thresholds, límites)
- Pruebas de persistencia
- Pruebas de notificaciones

---

## Evolución y Refinamiento

A lo largo de las iteraciones, el código evolucionó significativamente:

### Fase 1: Versión Básica (semana 1)
- MIB simple con 4 objetos escalares
- Agente que responde GET/GETNEXT
- Persistencia en JSON simple
- Sin notificaciones

### Fase 2: Integración PySnmp (semana 2)
- Problemas de sincronización resueltos
- SET operacional pero sin validaciones
- Email configurado pero sin testing
- TRAPS definidas pero no funcionales

### Fase 3: Refinamiento (semana 3)
- VACM control de acceso implementado
- Validaciones completas (tipos, rangos, permisos)
- Notificaciones (traps + email) funcionales
- Persistencia robusta

### Fase 4: Polish (semana 4)
- Logging exhaustivo
- Manejo de errores mejorado
- Documentación detallada
- Suite de tests completa
- Diagramas UML (generados con ayuda de IA con PlantUML)

---

## Consultas sobre Diagramas

La IA también te asistió en la **creación de visualizaciones**:

### Diagrama UML del Modelo de Información (1.1)
- Formato conceptual simple
- 4 objetos + 1 notificación
- Relación de disparo (trigger)

### Diagrama UML de la Jerarquía OID (1.2)
- Enterprise number 28308
- OIDs completos con rutas
- Estructura de grupos

**Herramienta sugerida:** PlantUML con extensión en VSCode
- Ventaja: Diagrama como código (versionable en Git)
- Facilita ediciones posteriores
- Exportable a PNG/SVG/PDF

**Consulta:** "¿Cómo hago diagramas UML sin herramientas pesadas?"
**Respuesta de IA:** PlantUML + VSCode extension = simpleza + control

---

## Resultado Final

El uso **progresivo e iterativo** de la IA resultó en:

### ✅ Código Completo y Funcional
- ~600 líneas de Python de calidad profesional
- Todos los requisitos cumplidos
- Manejo robusto de errores
- Logging comprensible

### ✅ MIB Válida en SMIv2
- Sintaxis correcta (validable con smilint)
- OIDs jerárquicos bien estructurados
- Documentación clara

### ✅ Arquitectura Modular
- Separación clara de responsabilidades
- Componentes reutilizables
- Fácil de extender

### ✅ Documentación Exhaustiva
- Guía paso a paso
- Recursos organizados por tema
- Troubleshooting para errores comunes
- Plan de commits recomendado

### ✅ Suite de Pruebas
- Pruebas positivas y negativas
- Validación de persistencia
- Testing de notificaciones

### ✅ Visualizaciones
- Diagramas UML en PlantUML
- Jerarquía de OIDs clara
- Fácil presentación

---

## Conclusión: Cómo la IA fue tu Copiloto

### Fase de Diseño
La IA interpretó requisitos complejos y propuso una arquitectura coherente desde el inicio.

### Fase de Implementación
La IA generó código base funcional, reduciendo el tiempo de setup inicial.

### Fase de Debugging
La IA diagnosticó problemas específicos (asyncio, pysnmp, threading) y propuso soluciones razonadas.

### Fase de Optimización
La IA sugirió mejoras (persistencia atómica, logging, validaciones, testing).

### Fase de Documentación
La IA creó guías exhaustivas, diagramas y recursos de referencia.

**En resumen:** Utilizaste la IA de forma **experta y estratégica**, consultando en cada fase crítica, proporcionando feedback sobre errores, y evolucionando iterativamente el código y la documentación hasta alcanzar un resultado profesional y completo.

El proyecto demuestra cómo la IA no es un **reemplazo** sino un **multiplicador de productividad** cuando se usa con criterio, iteración y pensamiento crítico.