# Cerberus — Polyglot Telemetry, Alerting & Search Engine

**Cerberus** es un sistema de telemetría, alerta temprana y búsqueda de eventos de seguridad de alto rendimiento diseñado bajo una arquitectura políglota de tres cabezas (**C**, **Go** y **Rust**) sincronizadas a través de un motor de base de datos compartido **SQLite en modo WAL (Write-Ahead Logging)** con indexación de texto completo **FTS5**.

---

## Arquitectura del Sistema (Las 3 Cabezas)

```mermaid
flowchart LR
    Clients["Productores / Agentes"] -->|TCP / UNIX / HTTP| IngestorC["1. ingestor-c (C11)"]
    IngestorC -->|INSERT Batch + Trigger FTS5| SQLiteWAL[("SQLite3 (WAL + FTS5)")]
    SQLiteWAL -->|Polling Cola / PENDING| AlerterGo["2. alerter-go (Go)"]
    AlerterGo -->|Webhooks + Backoff Exponencial| Targets["Destinos HTTP/S"]
    AlerterGo -->|UPDATE Status / Retry| SQLiteWAL
    SQLiteWAL -->|Consultas FTS5 BM25 / RO| SearchRust["3. search-rust (Rust)"]
    Users["Analistas / CLI / API"] -->|Query FTS5 + Filtros| SearchRust
```

### 1. `ingestor-c` (C11) — Ingesta de Baja Latencia
- **Responsabilidad**: Recepción, validación estricta en frontera y persistencia transaccional de eventos (`DEBUG`, `INFO`, `WARN`, `ERROR`, `CRITICAL`).
- **Diseño**: Cero dependencias innecesarias, uso de *prepared statements* parametrizados (`sqlite3_prepare_v2`), manejo seguro de memoria y generación automática de órdenes de despacho en `alert_deliveries` para eventos críticos.

### 2. `alerter-go` (Go) — Despachador Concurrente y Resiliente
- **Responsabilidad**: Procesamiento asíncrono de la cola `alert_deliveries`, envío de webhooks con *exponential backoff* + *jitter* y transición de estados (`PENDING` -> `SENT` / `FAILED` / `DEAD`).
- **Diseño**: *Worker pool* controlado por contexto (`context.Context`), *timeouts* estrictos de red, protección contra fugas de goroutines y cierre limpio (*graceful shutdown*).

### 3. `search-rust` (Rust) — Motor de Búsqueda Full-Text y Analítica
- **Responsabilidad**: Búsqueda ultrarrápida sobre eventos históricos utilizando el índice virtual **SQLite FTS5** (ranking BM25), filtrado por severidad, origen y rangos temporales.
- **Diseño**: Seguridad de memoria garantizada por el compilador, consultas parametrizadas de solo lectura o baja contención, y manejo explícito de errores sin `unwrap()` en rutas de producción.

### Núcleo Compartido: `schema/schema.sql` (SQLite WAL + FTS5)
- **Concurrencia**: `PRAGMA journal_mode = WAL;` permite múltiples lectores concurrentes (`search-rust`, `alerter-go`) mientras `ingestor-c` escribe sin bloqueos mutuos, apoyado por `PRAGMA busy_timeout = 5000;`.
- **Integridad en Base de Datos**: Restricciones `CHECK` a nivel de esquema para longitud de campos, validación nativa de JSON (`json_valid(metadata_json)`), enumeraciones de nivel/estado y llaves foráneas (`ON DELETE CASCADE`).
- **Sincronización FTS5 Automática**: Tabla virtual `events_fts` en modo *external content* (`content='events'`) mantenida en tiempo real mediante triggers `AFTER INSERT`, `AFTER DELETE` y `AFTER UPDATE`.

---

## Estructura del Proyecto

```text
Cerberus/
├── .gitignore
├── README.md
├── schema/
│   └── schema.sql        # Esquema maestro SQLite WAL + FTS5 + Triggers
├── ingestor-c/           # Cabeza 1: Ingestor de eventos en C11
├── alerter-go/           # Cabeza 2: Motor de alertas con reintentos en Go
└── search-rust/          # Cabeza 3: Buscador FTS5 y analítica en Rust
```

---

## Gobernanza de Seguridad y Calidad (Equipo Cerberus)

1. **Defensa en Profundidad y Cero SQL Injection**:
   - Prohibida la interpolación de cadenas para construir SQL en cualquiera de los tres lenguajes. Todas las consultas usan parámetros enlazados (`?1`, `?2`, etc.).
2. **Validación Estricta de Datos**:
   - Límites de tamaño impuestos tanto en código como en las cláusulas `CHECK` de SQLite (`source <= 128`, `message <= 8192`, `metadata_json <= 16384` y válido según `json_valid`).
3. **Seguridad de Memoria y Recursos**:
   - **C**: Compilación limpia con `-Wall -Wextra -Werror -pedantic -O2`, verificación de retornos de asignaciones y cierre determinista de *statements* y descriptores.
   - **Go**: Clientes HTTP con `Timeout` estricto, límite de lectura de cuerpo de respuesta (`io.LimitReader`) y validación de esquemas `http://` o `https://`.
   - **Rust**: Tipado fuerte, manejo de errores con `Result<T, E>` y prevención de inyecciones en sintaxis de consulta FTS5.
4. **Higiene de Secretos y Permisos**:
   - Ninguna credencial o base de datos operativa se versiona en Git. Archivos de configuración sensibles o bases de datos locales operan bajo permisos restrictivos (`chmod 600`).
