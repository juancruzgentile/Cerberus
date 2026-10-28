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
#   El archivo PID guarda "pid starttime dispositivo:inodo ruta-del-binario"
#   (la ruta va al final y puede contener espacios). También se acepta el
#   formato antiguo "pid starttime ruta-del-binario".
#   - PID + starttime (/proc/<pid>/stat, campo 22) identifican el proceso:
#     un PID reutilizado tiene otro starttime.
#   - dispositivo:inodo del ejecutable identifica el binario aunque se haya
#     recompilado o reemplazado mientras corre (la ruta pasa a "(deleted)",
#     pero /proc/<pid>/exe sigue apuntando al mismo inodo).
#   Estados (variable PID_STATE; REC_PID = pid del registro):
#     none     no hay registro
#     stale    el proceso del registro ya no existe (o el registro es ilegible):
#              se puede borrar, no hay nada que matar
#     owned    proceso vivo, mismo starttime y mismo ejecutable: es nuestro
#     unproven proceso vivo con ese starttime, pero el ejecutable no coincide:
#              NO se mata ni se borra el registro; se informa un fallo
#   Así nunca se termina un proceso ajeno y nunca se pierde el control del
#   propio.
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

# "dispositivo:inodo" de un archivo (sigue enlaces, incluido /proc/<pid>/exe).
exe_ident() { stat -L -c '%d:%i' "$1" 2>/dev/null; }

PID_STATE=none
REC_PID=""
pid_state() {
    local name="$1" pf line="" pid start rest ident="" path="" cur_start cur_exe expected
    PID_STATE=none; REC_PID=""
    pf="$(pid_file "$name")"
    [[ -e "$pf" || -L "$pf" ]] || return 0
    PID_STATE=stale
    [[ -f "$pf" && ! -L "$pf" ]] || return 0
    # Se lee la línea entera: la ruta del binario puede contener espacios.
    IFS= read -r line <"$pf" || true
    [[ "$line" =~ ^([1-9][0-9]{0,9})\ ([0-9]+)\ (.+)$ ]] || return 0
    pid="${BASH_REMATCH[1]}"; start="${BASH_REMATCH[2]}"; rest="${BASH_REMATCH[3]}"
    if [[ "$rest" =~ ^([0-9]+:[0-9]+)\ (/.*)$ ]]; then
        ident="${BASH_REMATCH[1]}"; path="${BASH_REMATCH[2]}"   # formato actual
    elif [[ "$rest" == /* ]]; then
        path="$rest"                                           # formato antiguo
    else
        return 0                                               # ilegible
    fi
    cur_start="$(proc_starttime "$pid")" || return 0
    [[ "$cur_start" == "$start" ]] || return 0
    # El mismo proceso que se registró sigue vivo: ¿es nuestro binario?
    REC_PID="$pid"
    PID_STATE=unproven
    if [[ -n "$ident" ]]; then
        [[ "$(exe_ident "/proc/$pid/exe")" == "$ident" ]] && PID_STATE=owned
    else
        # Registro antiguo "pid starttime ruta": se acepta solo si la ruta coincide.
        expected="$(readlink -f "$(bin_of "$name")")"
        cur_exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null)" || cur_exe=""
        [[ "$path" == "$expected" && "$cur_exe" == "$expected" ]] && PID_STATE=owned
    fi
    return 0
}

# Imprime el PID si el registro apunta a NUESTRO proceso vivo.
owned_pid() {
    pid_state "$1"
    [[ "$PID_STATE" == owned ]] || return 1
    echo "$REC_PID"
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

# ------------------------------------------------------------------------------
# Propiedad del puerto
#   Un 200 en /health no prueba nada por sí solo: otro proceso puede tener el
#   puerto. Se lee /proc/net/tcp{,6} (estado 0A = LISTEN) y se exige que TODOS
#   los sockets a la escucha en ese puerto pertenezcan a NUESTRO PID
#   (/proc/<pid>/fd -> socket:[inodo]).
# ------------------------------------------------------------------------------
listen_inodes() {  # listen_inodes <puerto>
    local hex
    hex="$(printf ':%04X' "$1")"
    awk -v p="$hex" 'FNR > 1 && $4 == "0A" && substr($2, length($2) - 4) == p { print $10 }' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null || true
}

port_in_use() { [[ -n "$(listen_inodes "$1")" ]]; }

listener_owned_by() {  # listener_owned_by <pid> <puerto>
    local pid="$1" port="$2" inodes fds ino f
    inodes="$(listen_inodes "$port")"
    [[ -n "$inodes" ]] || return 1
    fds="$(for f in /proc/"$pid"/fd/*; do readlink "$f" 2>/dev/null; done)"
    for ino in $inodes; do
        grep -qxF "socket:[$ino]" <<<"$fds" || return 1
    done
}

# Antes de lanzar: si el puerto ya está ocupado por algo que no es nuestro
# servicio, fallar de inmediato con un mensaje claro.
ensure_port_free() {  # ensure_port_free <servicio> <puerto>
    local name="$1" port="$2"
    is_running "$name" && return 0
    if port_in_use "$port"; then
        c_err "$name: el puerto $port ya está ocupado por otro proceso"
        return 1
    fi
}

# Espera /health con plazo total real (cada curl tiene su propio límite).
# Solo acepta el arranque si, ANTES y DESPUÉS del health check, el proceso
# lanzado sigue vivo (mismo PID, starttime y binario) y es el dueño del
# socket que escucha en el puerto. Si muere, o si responde otro, falla.
wait_health() {  # wait_health <url> <servicio> <puerto>
    local url="$1" name="$2" port="$3" deadline=$((SECONDS + HEALTH_TIMEOUT)) pid=""
    local foreign=0
    while (( SECONDS < deadline )); do
        if ! pid="$(owned_pid "$name")"; then
            c_err "$name terminó durante el arranque (ver ./cerberus.sh logs)"
            return 1
        fi
        if curl -fsS --connect-timeout 1 --max-time 2 "$url" >/dev/null 2>&1; then
            if ! is_running "$name" || [[ "$(owned_pid "$name")" != "$pid" ]]; then
                c_err "$name terminó durante el arranque (ver ./cerberus.sh logs)"
                return 1
            fi
            if listener_owned_by "$pid" "$port"; then
                return 0
            fi
            foreign=1   # alguien respondió, pero no es nuestro proceso
        fi
        sleep 0.2
    done
    if (( foreign )); then
        c_err "$name: $url respondió, pero el puerto $port no pertenece al proceso lanzado (pid $pid)"
    else
        c_err "$name no respondió en $url tras ${HEALTH_TIMEOUT}s (ver ./cerberus.sh logs)"
    fi
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
    local pf ident
    pf="$(pid_file "$name")"
    pid_state "$name"
    case "$PID_STATE" in
        owned)
            c_info "$name ya está en ejecución (pid $REC_PID)"
            return 0 ;;
        unproven)
            c_err "$name: el proceso $REC_PID del registro sigue vivo pero no se puede acreditar que sea nuestro; no se lanza otro (revíselo y borre $pf a mano)"
            return 1 ;;
    esac
    rm -f "$pf"
    ident="$(exe_ident "$1")" || { c_err "$name: no se encuentra el binario $1"; return 1; }
    # 9>&-: el servicio no debe heredar el descriptor del lock del lanzador
    nohup "$@" >"$RUN_DIR/$name.log" 2>&1 9>&- &
    local pid=$! start
    start="$(proc_starttime "$pid")" || { c_err "$name no pudo iniciarse"; return 1; }
    # Esperar (máx. 2 s) a que nohup haya hecho exec del binario.
    for _ in $(seq 1 100); do
        [[ "$(exe_ident "/proc/$pid/exe")" == "$ident" ]] && break
        [[ -d "/proc/$pid" ]] || break
        sleep 0.02
    done
    printf '%s %s %s %s\n' "$pid" "$start" "$ident" "$(readlink -f "$1")" >"$pf"
    STARTED_NOW+=("$name")
}

# Devuelve 1 si el servicio no se pudo detener o su propiedad no se acreditó.
stop_service() {
    local name="$1" pf pid
    pf="$(pid_file "$name")"
    pid_state "$name"
    case "$PID_STATE" in
        owned)
            pid="$REC_PID"
            kill "$pid" 2>/dev/null || true
            for _ in $(seq 1 50); do pid_state "$name"; [[ "$PID_STATE" == owned ]] || break; sleep 0.1; done
            if [[ "$PID_STATE" == owned ]]; then
                kill -9 "$pid" 2>/dev/null || true
                for _ in $(seq 1 20); do pid_state "$name"; [[ "$PID_STATE" == owned ]] || break; sleep 0.1; done
            fi
            if [[ "$PID_STATE" == owned ]]; then
                c_err "$name (pid $pid) no se pudo detener; se conserva $pf"
                return 1
            fi
            rm -f "$pf"
            c_ok "$name detenido" ;;
        unproven)
            c_err "$name: el pid $REC_PID sigue vivo pero su ejecutable no es el registrado; no se mata nada y se conserva $pf"
            return 1 ;;
        stale)
            c_info "$name: archivo PID obsoleto; se elimina sin matar nada"
            rm -f "$pf" ;;
        none)
            c_info "$name no estaba en ejecución" ;;
    esac
}

# Si falla un servicio, se detienen SOLO los que arrancó este intento.
rollback_start() {
    c_err "Arranque fallido; revirtiendo servicios iniciados en este intento"
    local i
    for (( i=${#STARTED_NOW[@]}-1; i>=0; i-- )); do
        stop_service "${STARTED_NOW[$i]}" || true
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
    ensure_port_free ingestor "$INGEST_PORT" || rollback_start
    spawn ingestor "$INGESTOR_BIN" --db "$DB" --schema "$SCHEMA" --serve "$INGEST_PORT" \
        --cors-origin "http://127.0.0.1:$SEARCH_PORT" --cors-origin "http://localhost:$SEARCH_PORT" \
        || rollback_start
    wait_health "http://127.0.0.1:$INGEST_PORT/health" ingestor "$INGEST_PORT" || rollback_start
    c_ok "ingestor (C)   -> http://127.0.0.1:$INGEST_PORT  (POST /ingest, GET /health)"

    # 2) Alerter Go: despacho continuo de webhooks
    ensure_port_free alerter "$METRICS_PORT" || rollback_start
    # shellcheck disable=SC2086
    spawn alerter "$ALERTER_BIN" --db "$DB" --metrics-addr "127.0.0.1:$METRICS_PORT" ${CERBERUS_ALERTER_FLAGS:-} \
        || rollback_start
    wait_health "http://127.0.0.1:$METRICS_PORT/health" alerter "$METRICS_PORT" || rollback_start
    c_ok "alerter (Go)   -> http://127.0.0.1:$METRICS_PORT  (GET /health, GET /stats)"

    # 3) Search Rust: búsqueda FTS5, resumen y dashboard (usa el puerto real del ingestor)
    ensure_port_free search "$SEARCH_PORT" || rollback_start
    spawn search "$SEARCH_BIN" --db "$DB" --serve "$SEARCH_PORT" \
        --ingest-url "http://127.0.0.1:$INGEST_PORT" || rollback_start
    wait_health "http://127.0.0.1:$SEARCH_PORT/health" search "$SEARCH_PORT" || rollback_start
    c_ok "search (Rust)  -> http://127.0.0.1:$SEARCH_PORT  (Web UI en /, GET /search, GET /summary)"
    c_ok "Web Dashboard  -> Abre http://127.0.0.1:$SEARCH_PORT en tu navegador"

    c_info "Base de datos: $DB"
    c_info "Detener con: ./cerberus.sh stop"
}

cmd_stop() {
    local name rc=0
    for name in "${SERVICES[@]}"; do
        stop_service "$name" || rc=1
    done
    return "$rc"
}

cmd_status() {
    local name
    for name in "${SERVICES[@]}"; do
        pid_state "$name"
        case "$PID_STATE" in
            owned)    c_ok "$name en ejecución (pid $REC_PID)" ;;
            unproven) c_err "$name: pid $REC_PID vivo pero sin propiedad acreditada (ver $(pid_file "$name"))" ;;
            *)        c_err "$name detenido" ;;
        esac
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

# Al hacer "source" (tests) solo se cargan las funciones.
[[ "${BASH_SOURCE[0]}" == "$0" ]] || return 0

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
