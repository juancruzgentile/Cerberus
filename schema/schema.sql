-- ==============================================================================
-- Cerberus - Shared SQLite Schema (WAL + FTS5 External Content)
-- ==============================================================================

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

-- ------------------------------------------------------------------------------
-- 1. Tabla Principal de Eventos: events
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL CHECK(length(source) > 0 AND length(source) <= 128),
    level TEXT NOT NULL CHECK(level IN ('DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL')),
    message TEXT NOT NULL CHECK(length(message) > 0 AND length(message) <= 8192),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(metadata_json) AND json_type(metadata_json) = 'object' AND length(metadata_json) <= 16384),
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ------------------------------------------------------------------------------
-- 2. Tabla de Cola de Despacho de Alertas: alert_deliveries
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alert_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    target_url TEXT NOT NULL CHECK(
        length(target_url) >= 10
        AND length(target_url) <= 1024
        AND (target_url GLOB 'http://?*' OR target_url GLOB 'https://?*')
        AND instr(target_url, ' ') = 0
        AND instr(target_url, char(9)) = 0
        AND instr(target_url, char(10)) = 0
        AND instr(target_url, char(13)) = 0
        AND instr(lower(target_url), '169.254.169.254') = 0
        AND instr(lower(target_url), 'metadata.google.internal') = 0
        AND instr(lower(target_url), '0.0.0.0') = 0
    ),
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING', 'SENT', 'FAILED', 'DEAD')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    max_attempts INTEGER NOT NULL DEFAULT 3 CHECK(max_attempts >= 1 AND max_attempts <= 10),
    next_retry_at INTEGER NOT NULL DEFAULT (unixepoch()),
    last_error TEXT NOT NULL DEFAULT '' CHECK(length(last_error) <= 2048),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ------------------------------------------------------------------------------
-- 3. Índices Optimizados
-- ------------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_events_level_created
    ON events(level, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_events_source
    ON events(source, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_status_retry
    ON alert_deliveries(status, next_retry_at ASC);

-- ------------------------------------------------------------------------------
-- 4. Índice de Texto Completo (FTS5) con Contenido Externo
-- ------------------------------------------------------------------------------
CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
    source,
    level,
    message,
    metadata_json,
    content='events',
    content_rowid='id'
);

-- ------------------------------------------------------------------------------
-- 5. Triggers de Sincronización Automática para events_fts
-- ------------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS trg_events_ai AFTER INSERT ON events BEGIN
    INSERT INTO events_fts(rowid, source, level, message, metadata_json)
    VALUES (new.id, new.source, new.level, new.message, new.metadata_json);
END;

CREATE TRIGGER IF NOT EXISTS trg_events_ad AFTER DELETE ON events BEGIN
    INSERT INTO events_fts(events_fts, rowid, source, level, message, metadata_json)
    VALUES ('delete', old.id, old.source, old.level, old.message, old.metadata_json);
END;

CREATE TRIGGER IF NOT EXISTS trg_events_au AFTER UPDATE ON events BEGIN
    INSERT INTO events_fts(events_fts, rowid, source, level, message, metadata_json)
    VALUES ('delete', old.id, old.source, old.level, old.message, old.metadata_json);
    INSERT INTO events_fts(rowid, source, level, message, metadata_json)
    VALUES (new.id, new.source, new.level, new.message, new.metadata_json);
END;
