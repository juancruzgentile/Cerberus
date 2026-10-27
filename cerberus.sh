#!/usr/bin/env bash
# ==============================================================================
# Cerberus — Lanzador
# ==============================================================================
# Uso: ./cerberus.sh <comando>
#
#   check    Verifica que estén instaladas las herramientas necesarias
#   build    Compila las 3 cabezas (C, Go, Rust)
#   start    Levanta ingestor (C), alerter (Go) y search (Rust) en segundo plano
#   stop     Detiene los 3 servicios
#   status   Muestra el estado de cada servicio
#   logs     Muestra los últimos logs de cada servicio
#   demo     Envía eventos de ejemplo y consulta búsqueda/resumen
#   test     Ejecuta todas las suites de prueba
#
# Configuración por variables de entorno (valores por defecto entre paréntesis):
#   CERBERUS_DB             Ruta a la base SQLite         (./data/cerberus.db)
#   CERBERUS_INGEST_PORT    Puerto del ingestor C          (8080)
#   CERBERUS_SEARCH_PORT    Puerto del buscador Rust       (8081)
#   CERBERUS_METRICS_PORT   Puerto de métricas del alerter (9090)
#   CERBERUS_WEBHOOK_SECRET Secreto HMAC para firmar webhooks (opcional)
#   CERBERUS_ALERTER_FLAGS  Flags extra para el alerter (ej. "--allow-loopback")
# ==============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/go/bin:$PATH"

DB="${CERBERUS_DB:-$ROOT/data/cerberus.db}"
INGEST_PORT="${CERBERUS_INGEST_PORT:-8080}"
SEARCH_PORT="${CERBERUS_SEARCH_PORT:-8081}"
METRICS_PORT="${CERBERUS_METRICS_PORT:-9090}"
RUN_DIR="$ROOT/run"

INGESTOR_BIN="$ROOT/ingestor-c/bin/cerberus-ingestor"
ALERTER_BIN="$ROOT/alerter-go/bin/cerberus-alerter"
SEARCH_BIN="$ROOT/search-rust/target/release/cerberus-search"
SCHEMA="$ROOT/schema/schema.sql"

SERVICES=(ingestor alerter search)

c_ok()   { printf '\033[32m✔\033[0m %s\n' "$*"; }
c_err()  { printf '\033[31m✘\033[0m %s\n' "$*" >&2; }
c_info() { printf '\033[36m➜\033[0m %s\n' "$*"; }

pid_file() { echo "$RUN_DIR/$1.pid"; }

is_running() {
    local pf; pf="$(pid_file "$1")"
    [[ -f "$pf" ]] && kill -0 "$(cat "$pf")" 2>/dev/null
}

wait_health() {
    local url="$1" name="$2"
    for _ in $(seq 1 50); do
        if curl -fsS "$url" >/dev/null 2>&1; then return 0; fi
        sleep 0.1
    done
    c_err "$name no respondió en $url (ver ./cerberus.sh logs)"
    return 1
}

cmd_check() {
    local missing=0
    check_tool() {
        if command -v "$1" >/dev/null 2>&1; then
            c_ok "$1 -> $("$@" 2>&1 | head -n1)"
        else
            c_err "$1 no encontrado"; missing=1
        fi
    }
    check_tool python3 --version
    check_tool cc --version
    check_tool make --version
    check_tool go version
    check_tool cargo --version
    command -v curl >/dev/null 2>&1 && c_ok "curl (opcional)" || c_info "curl no encontrado (solo necesario para 'demo')"
    if [[ $missing -ne 0 ]]; then
        c_err "Faltan herramientas. Ver requirements.txt"
        return 1
    fi
    c_ok "Entorno listo"
}

cmd_build() {
    make -C "$ROOT" build
    c_ok "Compilación completa"
}

ensure_built() {
    for bin in "$INGESTOR_BIN" "$ALERTER_BIN" "$SEARCH_BIN"; do
        if [[ ! -x "$bin" ]]; then
            c_info "Binarios no encontrados; compilando..."
            cmd_build
            return
        fi
    done
}

spawn() {
    local name="$1"; shift
    if is_running "$name"; then
        c_info "$name ya está en ejecución (pid $(cat "$(pid_file "$name")"))"
        return
    fi
    nohup "$@" >"$RUN_DIR/$name.log" 2>&1 &
    echo $! >"$(pid_file "$name")"
}

cmd_start() {
    ensure_built
    mkdir -p "$RUN_DIR" "$(dirname "$DB")"
    chmod 700 "$RUN_DIR"

    # 1) Ingestor C: crea/inicializa la base con el esquema
    spawn ingestor "$INGESTOR_BIN" --db "$DB" --schema "$SCHEMA" --serve "$INGEST_PORT"
    wait_health "http://127.0.0.1:$INGEST_PORT/health" "ingestor"
    c_ok "ingestor (C)   -> http://127.0.0.1:$INGEST_PORT  (POST /ingest, GET /health)"

    # 2) Alerter Go: despacho continuo de webhooks
    # shellcheck disable=SC2086
    spawn alerter "$ALERTER_BIN" --db "$DB" --metrics-addr "127.0.0.1:$METRICS_PORT" ${CERBERUS_ALERTER_FLAGS:-}
    wait_health "http://127.0.0.1:$METRICS_PORT/health" "alerter"
    c_ok "alerter (Go)   -> http://127.0.0.1:$METRICS_PORT  (GET /health, GET /stats)"

    # 3) Search Rust: búsqueda FTS5 y resumen
    spawn search "$SEARCH_BIN" --db "$DB" --serve "$SEARCH_PORT"
    wait_health "http://127.0.0.1:$SEARCH_PORT/health" "search"
    c_ok "search (Rust)  -> http://127.0.0.1:$SEARCH_PORT  (Web UI en /, GET /search, GET /summary)"
    c_ok "Web Dashboard  -> Abre http://127.0.0.1:$SEARCH_PORT en tu navegador"

    c_info "Base de datos: $DB"
    c_info "Detener con: ./cerberus.sh stop"
}

cmd_stop() {
    for name in "${SERVICES[@]}"; do
        local pf; pf="$(pid_file "$name")"
        if is_running "$name"; then
            kill "$(cat "$pf")" 2>/dev/null || true
            for _ in $(seq 1 30); do is_running "$name" || break; sleep 0.1; done
            is_running "$name" && kill -9 "$(cat "$pf")" 2>/dev/null || true
            c_ok "$name detenido"
        else
            c_info "$name no estaba en ejecución"
        fi
        rm -f "$pf"
    done
}

cmd_status() {
    for name in "${SERVICES[@]}"; do
        if is_running "$name"; then
            c_ok "$name en ejecución (pid $(cat "$(pid_file "$name")"))"
        else
            c_err "$name detenido"
        fi
    done
}

cmd_logs() {
    for name in "${SERVICES[@]}"; do
        echo "===== $name ====="
        tail -n 20 "$RUN_DIR/$name.log" 2>/dev/null || echo "(sin logs)"
    done
}

cmd_demo() {
    command -v curl >/dev/null || { c_err "curl es necesario para la demo"; return 1; }
    for name in "${SERVICES[@]}"; do
        is_running "$name" || { c_err "$name no está corriendo; ejecute ./cerberus.sh start"; return 1; }
    done
    local url="http://127.0.0.1:$INGEST_PORT/ingest"
    c_info "Enviando eventos de ejemplo al ingestor C..."
    curl -fsS -X POST "$url" -H 'Content-Type: application/json' \
        -d '{"source":"auth-service","level":"INFO","message":"User login succeeded for alice"}'
    curl -fsS -X POST "$url" -H 'Content-Type: application/json' \
        -d '{"source":"payment-api","level":"ERROR","message":"Database timeout in payment ledger","metadata":{"region":"eu-west-1"}}'
    curl -fsS -X POST "$url" -H 'Content-Type: application/json' \
        -d '{"source":"payment-api","level":"CRITICAL","message":"Payment gateway timeouts exceeded threshold"}'
    echo
    c_info "Búsqueda FTS5 en Rust: q=timeout*"
    curl -fsS "http://127.0.0.1:$SEARCH_PORT/search?q=timeout*&limit=5"; echo
    c_info "Resumen del sistema:"
    curl -fsS "http://127.0.0.1:$SEARCH_PORT/summary"; echo
    c_info "Estado de alertas (Go):"
    curl -fsS "http://127.0.0.1:$METRICS_PORT/stats"; echo
}

cmd_test() { make -C "$ROOT" test; }

usage() { sed -n '3,25p' "$0" | sed 's/^# \{0,1\}//'; }

case "${1:-}" in
    check)  cmd_check ;;
    build)  cmd_build ;;
    start)  cmd_start ;;
    stop)   cmd_stop ;;
    restart) cmd_stop; cmd_start ;;
    status) cmd_status ;;
    logs)   cmd_logs ;;
    demo)   cmd_demo ;;
    test)   cmd_test ;;
    *)      usage; exit 1 ;;
esac
