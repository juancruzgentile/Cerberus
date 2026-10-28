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
#   CERBERUS_WEBHOOK_SECRET Secreto HMAC para firmar webhooks (sin él NO se firman)
#   CERBERUS_ALERTER_FLAGS  Flags extra para el alerter (ej. "--allow-loopback")
#   CERBERUS_HEALTH_TIMEOUT Segundos máximos de espera por servicio al arrancar (10)
#   CERBERUS_RUN_DIR        Carpeta de PIDs, logs y lock           (./run)
# ==============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/go/bin:$PATH"

DB="${CERBERUS_DB:-$ROOT/data/cerberus.db}"
INGEST_PORT="${CERBERUS_INGEST_PORT:-8080}"
SEARCH_PORT="${CERBERUS_SEARCH_PORT:-8081}"
METRICS_PORT="${CERBERUS_METRICS_PORT:-9090}"
RUN_DIR="${CERBERUS_RUN_DIR:-$ROOT/run}"
HEALTH_TIMEOUT="${CERBERUS_HEALTH_TIMEOUT:-10}"   # segundos totales por servicio

INGESTOR_BIN="$ROOT/ingestor-c/bin/cerberus-ingestor"
ALERTER_BIN="$ROOT/alerter-go/bin/cerberus-alerter"
SEARCH_BIN="$ROOT/search-rust/target/release/cerberus-search"
SCHEMA="$ROOT/schema/schema.sql"

SERVICES=(ingestor alerter search)

c_ok()   { printf '\033[32m✔\033[0m %s\n' "$*"; }
c_err()  { printf '\033[31m✘\033[0m %s\n' "$*" >&2; }
c_info() { printf '\033[36m➜\033[0m %s\n' "$*"; }

# ------------------------------------------------------------------------------
# Gestión de procesos
#   El archivo PID guarda "pid starttime binario". Antes de considerar vivo
#   (o matar) un proceso se comprueba que:
#     - el PID tiene formato numérico estricto,
#     - su tiempo de inicio (/proc/<pid>/stat, campo 22) coincide,
#     - su ejecutable (/proc/<pid>/exe) es el binario de Cerberus esperado.
#   Así un PID antiguo reutilizado por otro proceso nunca se termina.
# ------------------------------------------------------------------------------
pid_file() { echo "$RUN_DIR/$1.pid"; }

bin_of() {
    case "$1" in
        ingestor) echo "$INGESTOR_BIN" ;;
        alerter)  echo "$ALERTER_BIN" ;;
        search)   echo "$SEARCH_BIN" ;;
    esac
}

# Tiempo de inicio del proceso en ticks desde el arranque (vacío si no existe).
proc_starttime() {
    local stat
    stat="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
    stat="${stat##*) }"              # el nombre (campo 2) puede tener espacios
    # shellcheck disable=SC2086
    set -- $stat
    echo "${20}"                     # campo 22 del archivo = 20 tras quitar pid y nombre
}

# Imprime el PID si el archivo es válido y apunta a NUESTRO proceso.
owned_pid() {
    local name="$1" pf pid start exe expected cur_start cur_exe
    pf="$(pid_file "$name")"
    [[ -f "$pf" && ! -L "$pf" ]] || return 1
    read -r pid start exe <"$pf" || true
    [[ "$pid" =~ ^[1-9][0-9]{0,9}$ && "$start" =~ ^[0-9]+$ ]] || return 1
    expected="$(readlink -f "$(bin_of "$name")")"
    [[ "$exe" == "$expected" ]] || return 1
    cur_start="$(proc_starttime "$pid")" || return 1
    [[ "$cur_start" == "$start" ]] || return 1
    cur_exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null)" || return 1
    [[ "$cur_exe" == "$expected" ]] || return 1
    echo "$pid"
}

is_running() { owned_pid "$1" >/dev/null; }

# Bloqueo exclusivo: evita dos start/stop simultáneos del lanzador.
acquire_lock() {
    mkdir -p "$RUN_DIR"
    chmod 700 "$RUN_DIR"
    exec 9>"$RUN_DIR/cerberus.lock"
    if ! flock -n 9; then
        c_err "Otra ejecución de cerberus.sh está en curso"
        exit 1
    fi
}

# Espera /health con plazo total real (cada curl tiene su propio límite)
# y aborta antes si el proceso murió.
wait_health() {
    local url="$1" name="$2" deadline=$((SECONDS + HEALTH_TIMEOUT))
    while (( SECONDS < deadline )); do
        if curl -fsS --connect-timeout 1 --max-time 2 "$url" >/dev/null 2>&1; then
            return 0
        fi
        if ! is_running "$name"; then
            c_err "$name terminó durante el arranque (ver ./cerberus.sh logs)"
            return 1
        fi
        sleep 0.2
    done
    c_err "$name no respondió en $url tras ${HEALTH_TIMEOUT}s (ver ./cerberus.sh logs)"
    return 1
}

version_ge() {  # version_ge <actual> <mínima>
    [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" == "$2" ]]
}

cmd_check() {
    local missing=0
    check_tool() {  # check_tool <cmd> <versión mínima o "-"> <comando de versión...>
        local tool="$1" min="$2"; shift 2
        if ! command -v "$tool" >/dev/null 2>&1; then
            c_err "$tool no encontrado"; missing=1; return
        fi
        local out ver
        out="$("$@" 2>&1 | head -n1)"
        ver="$(grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' <<<"$out" | head -n1)"
        if [[ "$min" != "-" ]] && ! version_ge "${ver:-0}" "$min"; then
            c_err "$tool $ver < $min (mínimo requerido)"; missing=1; return
        fi
        if [[ "$min" == "-" ]]; then c_ok "$tool ${ver:-?}"; else c_ok "$tool ${ver:-?} (mínimo $min)"; fi
    }
    check_tool python3 3.10 python3 --version
    check_tool cc      -    cc --version
    check_tool make    4.0  make --version
    # Versión efectiva de Go para el módulo (con GOTOOLCHAIN=auto, Go descarga
    # solo la toolchain que pide alerter-go/go.mod).
    check_tool go      1.26 bash -c 'cd "$1" && go version' _ "$ROOT/alerter-go"
    check_tool rustc   1.89 rustc --version
    check_tool cargo   1.89 cargo --version
    check_tool curl    -    curl --version
    check_tool flock   -    flock --version
    if [[ $missing -ne 0 ]]; then
        c_err "Faltan herramientas o versiones. Ver requirements.txt"
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

STARTED_NOW=()   # servicios lanzados en ESTE intento (para revertir)

spawn() {
    local name="$1"; shift
    if is_running "$name"; then
        c_info "$name ya está en ejecución (pid $(owned_pid "$name"))"
        return
    fi
    rm -f "$(pid_file "$name")"
    # 9>&-: el servicio no debe heredar el descriptor del lock del lanzador
    nohup "$@" >"$RUN_DIR/$name.log" 2>&1 9>&- &
    local pid=$! start
    start="$(proc_starttime "$pid")" || { c_err "$name no pudo iniciarse"; return 1; }
    printf '%s %s %s\n' "$pid" "$start" "$(readlink -f "$1")" >"$(pid_file "$name")"
    STARTED_NOW+=("$name")
}

stop_service() {
    local name="$1" pid pf
    pf="$(pid_file "$name")"
    if pid="$(owned_pid "$name")"; then
        kill "$pid" 2>/dev/null || true
        for _ in $(seq 1 50); do is_running "$name" || break; sleep 0.1; done
        if is_running "$name"; then
            kill -9 "$pid" 2>/dev/null || true
        fi
        c_ok "$name detenido"
    elif [[ -f "$pf" ]]; then
        c_info "$name: archivo PID obsoleto o ajeno; se elimina sin matar nada"
    else
        c_info "$name no estaba en ejecución"
    fi
    rm -f "$pf"
}

# Si falla un servicio, se detienen SOLO los que arrancó este intento.
rollback_start() {
    c_err "Arranque fallido; revirtiendo servicios iniciados en este intento"
    local i
    for (( i=${#STARTED_NOW[@]}-1; i>=0; i-- )); do
        stop_service "${STARTED_NOW[$i]}"
    done
    exit 1
}

cmd_start() {
    command -v curl >/dev/null || { c_err "curl es necesario para 'start' (ver ./cerberus.sh check)"; return 1; }
    ensure_built
    mkdir -p "$(dirname "$DB")"
    chmod 700 "$(dirname "$DB")" 2>/dev/null || true

    # 1) Ingestor C: crea/inicializa la base con el esquema.
    #    Acepta peticiones del navegador solo desde el dashboard (CORS explícito).
    spawn ingestor "$INGESTOR_BIN" --db "$DB" --schema "$SCHEMA" --serve "$INGEST_PORT" \
        --cors-origin "http://127.0.0.1:$SEARCH_PORT" --cors-origin "http://localhost:$SEARCH_PORT" \
        || rollback_start
    wait_health "http://127.0.0.1:$INGEST_PORT/health" ingestor || rollback_start
    c_ok "ingestor (C)   -> http://127.0.0.1:$INGEST_PORT  (POST /ingest, GET /health)"

    # 2) Alerter Go: despacho continuo de webhooks
    # shellcheck disable=SC2086
    spawn alerter "$ALERTER_BIN" --db "$DB" --metrics-addr "127.0.0.1:$METRICS_PORT" ${CERBERUS_ALERTER_FLAGS:-} \
        || rollback_start
    wait_health "http://127.0.0.1:$METRICS_PORT/health" alerter || rollback_start
    c_ok "alerter (Go)   -> http://127.0.0.1:$METRICS_PORT  (GET /health, GET /stats)"

    # 3) Search Rust: búsqueda FTS5, resumen y dashboard (usa el puerto real del ingestor)
    spawn search "$SEARCH_BIN" --db "$DB" --serve "$SEARCH_PORT" \
        --ingest-url "http://127.0.0.1:$INGEST_PORT" || rollback_start
    wait_health "http://127.0.0.1:$SEARCH_PORT/health" search || rollback_start
    c_ok "search (Rust)  -> http://127.0.0.1:$SEARCH_PORT  (Web UI en /, GET /search, GET /summary)"
    c_ok "Web Dashboard  -> Abre http://127.0.0.1:$SEARCH_PORT en tu navegador"

    c_info "Base de datos: $DB"
    c_info "Detener con: ./cerberus.sh stop"
}

cmd_stop() {
    local name
    for name in "${SERVICES[@]}"; do
        stop_service "$name"
    done
}

cmd_status() {
    for name in "${SERVICES[@]}"; do
        if is_running "$name"; then
            c_ok "$name en ejecución (pid $(owned_pid "$name"))"
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

usage() { sed -n '3,27p' "$0" | sed 's/^# \{0,1\}//'; }

case "${1:-}" in
    check)  cmd_check ;;
    build)  cmd_build ;;
    start)  acquire_lock; cmd_start ;;
    stop)   acquire_lock; cmd_stop ;;
    restart) acquire_lock; cmd_stop; cmd_start ;;
    status) cmd_status ;;
    logs)   cmd_logs ;;
    demo)   cmd_demo ;;
    test)   cmd_test ;;
    *)      usage; exit 1 ;;
esac
