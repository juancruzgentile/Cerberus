# Cerberus — Polyglot Telemetry, Alerting & Search Engine

<p align="center">
  <img src="https://img.shields.io/badge/C11-Ingestor-00599C?logo=c&logoColor=white" alt="C11 Ingestor">
  <img src="https://img.shields.io/badge/Go_1.23-Alerter-00ADD8?logo=go&logoColor=white" alt="Go Alerter">
  <img src="https://img.shields.io/badge/Rust_2021-Search_&_UI-DEA584?logo=rust&logoColor=black" alt="Rust Search">
  <img src="https://img.shields.io/badge/Storage-SQLite_WAL_+_FTS5-003B57?logo=sqlite&logoColor=white" alt="SQLite WAL">
  <img src="https://img.shields.io/badge/Security-Hardened_&_Audited-green" alt="Security Hardened">
  <img src="https://img.shields.io/badge/Tests-100%25_Passing-brightgreen" alt="Tests 100% Passing">
</p>

**Cerberus** es una plataforma de observabilidad, ingesta de eventos de seguridad y despacho de alertas de alto rendimiento basada en una arquitectura políglota de tres cabezas (**C11**, **Go** y **Rust**). Cada componente fue construido en el lenguaje donde su modelo de ejecución ofrece la máxima ventaja competitiva, comunicándose de forma desacoplada y sin intermediarios pesados a través de un núcleo transaccional compartido de **SQLite en modo WAL (Write-Ahead Logging)** con búsqueda de texto completo **FTS5**.

---

## 🏛️ Arquitectura del Sistema (Las 3 Cabezas)

El sistema resuelve el problema clásico de la telemetría en nodos *edge*, entornos embebidos o servidores de bajo recurso: ¿cómo ingerir miles de eventos por segundo, despachar alertas concurrentes con reintentos y ofrecer búsqueda instantánea sobre texto libre sin levantar un cluster pesado de Kafka, Redis o Elasticsearch que consuma gigabytes de memoria?

```mermaid
flowchart TD
    subgraph INGRESS ["Capa de Ingesta & Clientes"]
        Producers["Productores de Software<br/>(Servicios, Proxies, Nodos Edge)"]
        SecAnalysts["Operadores & Analistas<br/>(Navegador Web / CLI)"]
        ExtHooks["Receptores Webhook Externos<br/>(Slack, Discord, PagerDuty, SIEM)"]
    end

    subgraph HEAD1 ["CABEZA 1: Ingestor de Ultra Bajo Consumo (C11)"]
        C_Server["Servidor HTTP / CLI (:8080)<br/>• Non-blocking Socket I/O<br/>• Monotonic Slowloris Protection<br/>• Content-Length Overflow Guard"]
        C_Validator["Validador Frontera C11<br/>• Zero-allocation bounds<br/>• Enum Level check<br/>• Anti-SSRF / CRLF URL parser"]
        C_Stmt["Prepared Statements Precompilados<br/>• sqlite3_prepare_v2<br/>• Atomic BEGIN IMMEDIATE / COMMIT"]
        C_Server --> C_Validator --> C_Stmt
    end

    subgraph STORAGE ["NÚCLEO DE PERSISTENCIA COMPARTIDO (SQLite WAL Mode)"]
        direction TB
        DB_WAL[("cerberus.db-wal<br/>(Sequential Write-Ahead Log)")]
        DB_MAIN[("cerberus.db<br/>(Tablas Relacionales)")]
        DB_SHM[("cerberus.db-shm<br/>(Shared-Memory Index)")]
        
        subgraph TABLES ["Esquema Maestro (schema/schema.sql)"]
            T_EVENTS["events<br/>• id, source, level, message<br/>• metadata_json (CHECK json_valid)<br/>• created_at"]
            T_ALERTS["alert_deliveries<br/>• event_id, target_url, status<br/>• attempts, max_attempts, next_retry_at<br/>• ON DELETE CASCADE"]
            T_FTS["events_fts (Virtual Table FTS5)<br/>• External content='events'<br/>• Triggers AI, AU, AD automáticos"]
        end
    end

    subgraph HEAD2 ["CABEZA 2: Motor de Despacho Concurrente (Go)"]
        GO_Poller["Polling Loop No Bloqueante (:9090)<br/>• PRAGMA busy_timeout = 5000<br/>• Reclamo atómico de PENDING / FAILED"]
        GO_Pool["Worker Pool Concurrente<br/>• Goroutines acotadas por contexto<br/>• Exponential Backoff + Full Jitter<br/>• Dead-Letter Queue (DLQ tras max_attempts)"]
        GO_Net["Capa de Red Anti-SSRF<br/>• net.Dialer.Control (DNS Rebinding Guard)<br/>• Bloqueo Cloud Metadata 169.254.0.0/16<br/>• Response Body Limit (4KB) & Timeouts"]
        GO_HMAC["Firma Criptográfica<br/>• X-Cerberus-Signature-256 (HMAC-SHA256)"]
        GO_Poller --> GO_Pool --> GO_Net --> GO_HMAC
    end

    subgraph HEAD3 ["CABEZA 3: Motor de Búsqueda & API UI (Rust)"]
        RUST_Server["Servidor HTTP Seguro (:8081)<br/>• Strict GET / Only<br/>• CSP, X-Frame-Options: DENY, nosniff"]
        RUST_Sanitizer["Lexical FTS5 Tokenizer & Sanitizer<br/>• Neutraliza operadores inyectables<br/>• Auto-quoting & Safe Prefix search"]
        RUST_Engine["Motor FTS5 & BM25 Ranking<br/>• rusqlite (bundled, Zero unwrap)<br/>• Highlight Snippets con [términos]"]
        RUST_UI["Dashboard Web Minimalista Embebido<br/>• include_str!(static/index.html)<br/>• 100% Vanilla JS/CSS (16 KB, 0 deps)"]
        RUST_Server --> RUST_Sanitizer --> RUST_Engine
        RUST_Server --> RUST_UI
    end

    %% Relaciones de flujo de datos
    Producers -->|"POST /ingest (JSON)"| C_Server
    C_Stmt -->|"Append secuencial 1-Writer (Sin contención)"| DB_WAL
    
    DB_WAL -.->|"Checkpoint periódico"| DB_MAIN
    DB_SHM -.->|"Lecturas snapshot en memoria"| TABLES

    T_EVENTS -.->|"Disparo de Triggers FTS5"| T_FTS
    T_EVENTS -.->|"Crea entrega si level >= ERROR"| T_ALERTS

    T_ALERTS -->|"Lecturas concurrentes N-Readers"| GO_Poller
    GO_HMAC -->|"POST Webhook firmado"| ExtHooks
    GO_Pool -->|"UPDATE alert_deliveries (SENT/FAILED/DEAD)"| DB_WAL

    T_FTS -->|"Consultas FTS5 BM25 de alta velocidad"| RUST_Engine
    T_EVENTS -->|"Agregaciones analíticas (/summary)"| RUST_Engine
    SecAnalysts -->|"Navegador Web / REST API"| RUST_Server
    RUST_UI -.->|"Dispara simulación directa"| C_Server
```

---

## 🎯 Filosofía Políglota: ¿Por qué cada lenguaje para su tarea?

En el desarrollo de sistemas modernos, ningún lenguaje es el mejor en todos los frentes. Cerberus aprovecha las fortalezas absolutas de cada uno:

| Componente | Lenguaje | Razón Técnica de Elección | Rol en Cerberus |
|---|---|---|---|
| **`ingestor-c`** | **C11** | • Huella de memoria mínima (< 2 MB de RSS).<br/>• Cero pausas de *Garbage Collector*.<br/>• Acceso directo a llamadas al sistema POSIX (`socket`, `fcntl`, `clock_gettime`).<br/>• Compilación nativa con SQLite embebido. | Agente colector que puede correr en nodos de borde, contenedores pequeños o como demonio del sistema sin consumir recursos. |
| **`alerter-go`** | **Go 1.23** | • Modelo de concurrencia nativo con goroutines y canales.<br/>• Ecosistema de red maduro con control a nivel de socket (`net.Dialer.Control`).<br/>• Excelente manejo de cancelación distribuida con `context.Context`.<br/>• Compilación estática sin dependencias de runtime. | Despachador asíncrono y resiliente capaz de gestionar cientos de llamadas HTTP salientes en paralelo con reintentos y tolerancia a fallos. |
| **`search-rust`** | **Rust 2021** | • Seguridad de memoria garantizada en tiempo de compilación sin overhead de GC.<br/>• Tipado algebraico estricto (`Result<T, SearchError>`) que erradica excepciones no controladas.<br/>• Sanitización léxica segura de consultas.<br/>• Serialización JSON ultrarrápida con `serde`. | API de consulta y motor analítico que expone búsqueda Full-Text FTS5 con ranking BM25 y sirve la interfaz web embebida. |
| **Núcleo** | **SQLite (WAL)** | • Formato de archivo único, universal e independiente de arquitectura.<br/>• Modo WAL: 1 escritor exclusivo no bloquea a $N$ lectores concurrentes.<br/>• Extensión FTS5 nativa integrada con triggers automáticos. | Bus transaccional y almacén persistente que une los tres servicios sin requerir un cluster externo. |

---

## ⚡ Concurrencia en SQLite: Mecánica del Modo WAL

Cerberus configura explícitamente:
```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
```

### ¿Por qué WAL (Write-Ahead Logging)?
En el modo tradicional de SQLite (*rollback journal*), cualquier operación de escritura bloquea la base de datos por completo para los lectores. En modo **WAL**:

1. **Lectores no bloquean a escritores:** `search-rust` puede estar ejecutando una consulta analítica pesada o un escaneo FTS5 mientras `ingestor-c` inserta nuevos eventos simultáneamente.
2. **Escritores no bloquean a lectores:** Cuando `ingestor-c` escribe, los cambios se anexan secuencialmente al archivo `cerberus.db-wal`. Los lectores (`alerter-go` y `search-rust`) continúan leyendo la última instantánea (*snapshot*) consistente desde `cerberus.db` y `cerberus.db-shm` (memoria compartida).
3. **Escritor único ordenado:** `ingestor-c` utiliza transacciones `BEGIN IMMEDIATE` y `alerter-go` actualiza el estado de la cola con `busy_timeout = 5000ms`, garantizando que ninguna actualización transaccional se pierda por colisión.

---

## 🛡️ Matriz de Amenazas y Seguridad Defensiva (SecOps)

Cerberus fue auditado y sometido a pruebas de penetración activas durante su construcción. Cada vector de ataque cuenta con una mitigación estructural y pruebas automatizadas:

| Vector de Ataque / Amenaza | Riesgo | Mitigación Implementada en Cerberus | Módulo / Componente |
|---|---|---|---|
| **SSRF y DNS Rebinding** | Un atacante configura una URL de webhook apuntando a `169.254.169.254` (AWS/GCP metadata) o cambia dinámicamente el registro DNS a `127.0.0.1` tras la validación. | `net.Dialer.Control` intercepta y valida la IP física resuelta **antes** del handshake TCP. Bloqueo estricto de `169.254.0.0/16`, `100.100.100.200/32`, `fd00:ec2::254`, NAT64 `64:ff9b::/96`, `0.0.0.0/8`, y RFC1918. | `alerter-go` |
| **Open Redirect SSRF** | Un endpoint externo responde con `302 Found` redirigiendo al cliente hacia un servicio interno privado. | `http.Client.CheckRedirect` aborta inmediatamente cualquier intento de redirección HTTP. | `alerter-go` |
| **Inyección de Sintaxis FTS5** | Un usuario ingresa caracteres como `" OR 1=1 --`, `NEAR(...)`, `NOT AND OR` para alterar la lógica de búsqueda en SQLite. | Sanitizador léxico en Rust (`sanitize_fts5_query`) que extrae tokens válidos, aplica prefijo seguro `*` y envuelve cada término entre comillas escapadas, limitando a un máximo de 16 tokens (`MAX_QUERY_TOKENS`). | `search-rust` |
| **Denegación de Servicio por Deep-Pagination** | Peticiones con `offset = usize::MAX` o valores astronómicos causan integer overflow en la conversión a `i64` o consumo masivo de CPU. | Validación estricta con `MAX_OFFSET = 100_000` y límite `limit <= 100`. | `search-rust` |
| **Slowloris / Conexiones Lentas** | Un cliente envía 1 byte cada varios segundos para agotar el pool de descriptores del servidor HTTP en C11. | Doble control: timeout por socket `SO_RCVTIMEO` / `SO_SNDTIMEO` sumado a un temporizador monotónico total de pared (`clock_gettime(CLOCK_MONOTONIC)`) de 2000 ms. | `ingestor-c` |
| **Contrabando HTTP e Integer Overflow** | Cabeceras `Content-Length` malformadas, duplicadas o con valores superiores a `SIZE_MAX`. | Parser manual dígito a dígito en C11 con cota fija de 32 KB (`MAX_HTTP_REQ_SIZE`), rechazando valores negativos o duplicados con `413 Payload Too Large`. | `ingestor-c` |
| **Falsificación de Alertas (Tampering)** | El receptor del webhook no puede verificar si la alerta realmente proviene de Cerberus. | Firma criptográfica HMAC-SHA256 incluida en la cabecera `X-Cerberus-Signature-256` calculada con clave compartida. | `alerter-go` |
| **Inyección de Código XSS** | Mensajes o orígenes con `<script>alert(1)</script>` almacenados en SQLite se renderizan en el navegador. | Cabeceras de seguridad estrictas (`Content-Security-Policy`, `X-Frame-Options: DENY`, `nosniff`) y renderizado DOM exclusivamente con `escapeHtml` y creación segura de nodos de texto. | `search-rust` (UI) |

---

## 💻 Interfaz de Usuario Minimalista (Dashboard Embebido)

Cerberus incluye una consola web operativa de **un único archivo HTML/CSS/JS (16 KB)** embebida directamente dentro del binario compilado de Rust (`include_str!`).

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 🟢 CERBERUS Telemetry & Security     [C11 :8080] [Go :9090] [Rust :8081] [SQLite WAL]  │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ TOTAL EVENTS: 1,420 │ CRITICAL/ERR: 12 │ WEBHOOKS SENT: 12 │ DEAD-LETTER QUEUE: 0      │
├─────────────────────────────────────┬──────────────────────────────────────────────────┤
│ SIMULADOR DE INGESTA (C11)          │ BÚSQUEDA EN VIVO FTS5 & EVENT STREAM             │
│                                     │ ┌───────────────────────────────┐ ┌────────────┐ │
│ Source:   [payment-api            ] │ │ q: timeout*                   │ │ [CRITICAL] ▼│ │
│ Level:    [CRITICAL             ▼]  │ └───────────────────────────────┘ └────────────┘ │
│ Message:  [Gateway timeout 5000ms ] │ #12 [CRITICAL] payment-api [timeout] in ledger   │
│ Webhook:  [https://webhook.site/..] │ #11 [ERROR]    auth-service DB connection [time] │
│                                     │ #10 [INFO]     worker-node CPU ok (45%)          │
│ [ INGEST VIA C11 ]                  │                                                  │
│ ✔ Event #12 ingested successfully! │ Mostrando coincidencias ordenadas por BM25       │
└─────────────────────────────────────┴──────────────────────────────────────────────────┘
```

* **Acceso inmediato:** Disponible en `http://127.0.0.1:8081` en cuanto se inicia el sistema.
* **Auto-refresco:** Sincronización automática de métricas cada 3 segundos.
* **Búsqueda con Debounce:** Filtrado reactivo (250 ms) con resaltado visual (`<mark class="hl">`) de los términos coincidentes devueltos por SQLite FTS5.

---

## 🚀 Inicio Rápido con el Lanzador (`cerberus.sh`)

El proyecto incluye un script orquestador integral para administrar los servicios sin tener que abrir múltiples terminales:

### 1. Verificar herramientas instaladas
```bash
./cerberus.sh check
```
Verifica que tu sistema cuente con `cc` (C11), `go` (>=1.23), `cargo` (>=1.80), `make` y `python3`.

### 2. Iniciar el sistema completo
```bash
./cerberus.sh start
```
Compila los binarios si no existen y levanta las 3 cabezas en segundo plano:
* **Ingestor C11:** `http://127.0.0.1:8080` (endpoints `POST /ingest`, `GET /health`)
* **Alerter Go:** `http://127.0.0.1:9090` (endpoints `GET /health`, `GET /stats`)
* **Search Rust & Web UI:** `http://127.0.0.1:8081` (interfaz visual en `/`, `GET /search`, `GET /summary`)

### 3. Abrir la consola en el navegador
Abre **[http://127.0.0.1:8081](http://127.0.0.1:8081)** para interactuar con la plataforma.

### 4. Ejecutar una demostración automática
```bash
./cerberus.sh demo
```
Inserta eventos de prueba a través de C11, ejecuta consultas FTS5 en Rust y muestra el estado de las alertas en Go.

### 5. Ver estado y detener
```bash
./cerberus.sh status   # Ver PIDs y estado de ejecución
./cerberus.sh logs     # Inspeccionar los últimos logs de los 3 procesos
./cerberus.sh stop     # Detención limpia de todos los servicios
```

---

## 📡 Especificación de la API HTTP

### 1. Ingestor (`ingestor-c` en puerto `8080`)
* **`POST /ingest`**: Ingesta un nuevo evento en SQLite.
  ```bash
  curl -X POST http://127.0.0.1:8080/ingest \
    -H 'Content-Type: application/json' \
    -d '{
      "source": "payment-api",
      "level": "CRITICAL",
      "message": "Stripe API timeout after 5000ms",
      "metadata": {"transaction_id": "tx_9941", "retry": 3},
      "webhook_url": "https://hooks.example.com/alerts"
    }'
  ```
  **Respuesta:** `201 Created` / `{"status":"ok","event_id":142}`
* **`GET /health`**: `200 OK` `{"status":"ok","service":"cerberus-ingestor-c"}`

### 2. Buscador & Analítica (`search-rust` en puerto `8081`)
* **`GET /search?q=timeout*&level=CRITICAL&limit=10&offset=0`**: Búsqueda Full-Text FTS5 con ranking BM25 y snippets.
  ```json
  {
    "sanitized_query": "\"timeout\"*",
    "level": "CRITICAL",
    "source": null,
    "limit": 10,
    "offset": 0,
    "count": 1,
    "total_matches": 1,
    "results": [
      {
        "id": 142,
        "source": "payment-api",
        "level": "CRITICAL",
        "message": "Stripe API timeout after 5000ms",
        "snippet": "Stripe API [timeout] after 5000ms",
        "metadata_json": "{\"transaction_id\":\"tx_9941\",\"retry\":3}",
        "created_at": 1793140341,
        "rank": -1.0620689655172414e-6
      }
    ]
  }
  ```
* **`GET /summary`**: Métricas agregadas por severidad, orígenes top y estado de la cola de webhooks.
* **`GET /`**: Retorna el dashboard interactivo en HTML5/JS vanilla.

### 3. Observabilidad de Alertas (`alerter-go` en puerto `9090`)
* **`GET /stats`**: Métricas de entrega de webhooks:
  ```json
  {"pending": 0, "sent": 14, "failed": 1, "dead": 0, "total": 15}
  ```

---

## 🧪 Batería de Pruebas y Cobertura (100% Passing)

Todas las suites se ejecutan de forma orquestada con:
```bash
make test
```

| Módulo | Pruebas Unitarias & Integración | Pruebas de Seguridad / Ataque Red Team | Resultado |
|---|---|---|---|
| **`schema/`** | • WAL mode & Foreign Keys activas.<br/>• CRUD y sincronización FTS5 por triggers.<br/>• Restricciones de longitud y niveles.<br/>• Borrado en cascada `ON DELETE CASCADE`. | • Payloads de inyección SQL en todos los campos.<br/>• Bombas lógicas (>16KB JSON, >8KB texto).<br/>• Rechazo de JSON escalar/arrays.<br/>• Bloqueo de SSRF y URLs malformadas.<br/>• Auditoría de permisos `0600` e higiene de secretos. | **9 / 9 PASS** |
| **`ingestor-c/`** | • Permisos restrictivos `0600` en `.db`.<br/>• Inserción de 5 niveles de severidad.<br/>• Reglas de creación atómica en `alert_deliveries`.<br/>• Ingesta masiva por lotes (`cerberus_ingest_batch`) y *rollback* ante fallo.<br/>• Self-test integrado en el binario CLI. | • Inmunidad ante `SIGPIPE` en desconexiones abruptas.<br/>• Desbordamiento de enteros en `Content-Length`.<br/>• Bloqueo de payloads de 100 KB (`413 Payload Too Large`).<br/>• Ataques Slowloris y clientes lentos.<br/>• Evasión de SSRF con IPs decimales/hexadecimales. | **11 / 11 PASS** |
| **`alerter-go/`** | • Entrega exitosa con verificación de firma HMAC-SHA256.<br/>• Recuperación tras fallo transitorio (`500` / timeout).<br/>• Transición automática a Dead-Letter Queue (`DEAD`).<br/>• Worker pool concurrente (26 alertas simultáneas sin `SQLITE_BUSY`). | • Bloqueo de DNS Rebinding en `net.Dialer.Control`.<br/>• Bloqueo de Open Redirect (`301`/`302`/`307`).<br/>• Bombas de respuesta HTTP de 10 MB (Tar Pit).<br/>• Truncamiento seguro de errores en límites de runes UTF-8.<br/>• Timeouts de cabecera anti-Slowloris en métricas. | **11 / 11 PASS** |
| **`search-rust/`** | • Indexación y ordenamiento por relevancia BM25.<br/>• Búsqueda por prefijo seguro (`timeout*`).<br/>• Paginación multi-página con `total_matches`.<br/>• Validación de límites `limit` y `offset`.<br/>• Resumen analítico tipado (`get_summary`). | • Inyección de operadores FTS5 y comillas desbalanceadas.<br/>• Bloqueo de bytes nulos `%00` y caracteres de control.<br/>• DoS por bombas de tokens (`MAX_QUERY_TOKENS = 16`).<br/>• Desbordamiento de paginación (`MAX_OFFSET = 100_000`).<br/>• Enmascaramiento de errores internos en respuestas `500`. | **19 / 19 PASS** |
| **E2E Pipeline** | • **Flujo Completo Políglota:** C11 ingesta eventos → Go despacha webhooks firmados con verificación HMAC → Rust indexa y entrega resultados FTS5 en la interfaz web. | **1 / 1 PASS** |

---

## 📦 Estructura del Repositorio

```text
Cerberus/
├── cerberus.sh               # Script orquestador (check, build, start, status, demo, stop)
├── Makefile                  # Orquestador Make para compilación y pruebas globales
├── requirements.txt          # Requisitos de toolchain del sistema (0 dependencias PyPI)
├── schema/
│   ├── schema.sql            # Esquema maestro SQLite WAL + FTS5 + Triggers
│   ├── test_schema.py        # Pruebas funcionales de base de datos
│   └── test_security_schema.py# Pruebas de inyección y ataques a nivel de esquema
├── ingestor-c/               # Cabeza 1: Ingestor de baja latencia en C11
│   ├── include/              # API pública (cerberus_ingestor.h)
│   ├── src/                  # Implementación del ingestor y servidor HTTP
│   ├── tests/                # Pruebas C11 y suite de ataque contra el servidor HTTP
│   └── vendor/               # Amalgamación SQLite3 oficial (compilada localmente)
├── alerter-go/               # Cabeza 2: Despachador de alertas y webhooks en Go
│   ├── cmd/alerter/          # Punto de entrada y servidor de observabilidad
│   └── internal/dispatcher/  # Worker pool, lógica de reintentos y filtro anti-SSRF
├── search-rust/              # Cabeza 3: Buscador FTS5 y analítica en Rust
│   ├── src/                  # Motor de búsqueda, sanitizador FTS5 y servidor HTTP
│   ├── src/static/           # Dashboard Web minimalista embebido (index.html)
│   └── tests/                # Pruebas de integración y pruebas de ataque
└── tests/
    └── test_e2e_cerberus.py  # Prueba de integración end-to-end de las tres cabezas
```

---

## 📜 Licencia

Desarrollado bajo licencia MIT. Código abierto para fines educativos, investigación y bases de proyectos de infraestructura de alto rendimiento.
