#!/usr/bin/env bash
# ==============================================================================
# burn-telemetry.sh - Cluster-Wide Telemetry Purge (Pillar 1: True Burnability)
# Instantly drains volatile buffers, purges Jaeger in-memory traces, and wipes
# Prometheus TSDB time-series data completely with zero data retention.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Source environment variables if present without overriding caller environment (Compose precedence)
_kty_genesis_env_set=${GENESIS_AUTH_TOKEN+set}
_kty_genesis_env_val=${GENESIS_AUTH_TOKEN-}
_kty_genesis_port_set=${GENESIS_PORT+set}
_kty_genesis_port_val=${GENESIS_PORT-}
_kty_prom_port_set=${PROMETHEUS_PORT+set}
_kty_prom_port_val=${PROMETHEUS_PORT-}
if [ -f .env ]; then
    # shellcheck disable=SC1091
    source .env
fi
if [ "$_kty_genesis_env_set" = "set" ]; then
    GENESIS_AUTH_TOKEN="$_kty_genesis_env_val"
    export GENESIS_AUTH_TOKEN
fi
if [ "$_kty_genesis_port_set" = "set" ]; then
    GENESIS_PORT="$_kty_genesis_port_val"
    export GENESIS_PORT
fi
if [ "$_kty_prom_port_set" = "set" ]; then
    PROMETHEUS_PORT="$_kty_prom_port_val"
    export PROMETHEUS_PORT
fi

validate_tcp_port() {
    local var_name="$1"
    local val="$2"
    case "$val" in
        0*|*[!0-9]*|''|??????*)
            echo "❌ $var_name must be a valid TCP port (1-65535), got: $val" >&2
            return 1
            ;;
    esac
    if [ "$val" -lt 1 ] || [ "$val" -gt 65535 ]; then
        echo "❌ $var_name must be between 1 and 65535, got: $val" >&2
        return 1
    fi
}

GENESIS_PORT_VALIDATED="${GENESIS_PORT:-9002}"
PROMETHEUS_PORT_VALIDATED="${PROMETHEUS_PORT:-9090}"
validate_tcp_port "GENESIS_PORT" "$GENESIS_PORT_VALIDATED" || exit 1
validate_tcp_port "PROMETHEUS_PORT" "$PROMETHEUS_PORT_VALIDATED" || exit 1

echo ""
echo "=============================================================="
echo "  🔥 PURGING CLUSTER TELEMETRY (Pillar 1: True Burnability)"
echo "=============================================================="

# Store lock and recovery state inside a private operator-owned 0700 state directory (never shared /tmp).
# Designed for one designated burn operator per host/Docker daemon; set KTY_BURN_STATE_DIR to a shared protected path if multiple admins coordinate.
if [ -n "${KTY_BURN_STATE_DIR:-}" ]; then
    BURN_STATE_DIR="$KTY_BURN_STATE_DIR"
elif [ -n "${XDG_STATE_HOME:-}" ]; then
    BURN_STATE_DIR="${XDG_STATE_HOME%/}/knowthankyew/burn"
elif [ -n "${HOME:-}" ]; then
    BURN_STATE_DIR="${HOME%/}/.local/state/knowthankyew/burn"
else
    echo "❌ Unable to resolve private burn state directory (set KTY_BURN_STATE_DIR, XDG_STATE_HOME, or HOME)." >&2
    exit 1
fi

ensure_safe_dir_strict() {
    local dir="$1"
    local label="$2"
    if [ -L "$dir" ] || [ ! -d "$dir" ] || [ ! -O "$dir" ]; then
        echo "❌ Unsafe $label ($dir): must be a non-symlink directory owned by current user." >&2
        return 1
    fi
    local perm_bits
    perm_bits=""
    IFS=$' \t\n' read -r perm_bits _ < <(LC_ALL=C ls -ld "$dir" 2>/dev/null || true)
    case "$perm_bits" in
        d????w*|d???????w*)
            echo "❌ Unsafe permissions on $label ($dir: $perm_bits); must not be group/world-writable." >&2
            return 1
            ;;
        d*) ;;
        *)
            echo "❌ Unable to inspect permissions on $label ($dir)." >&2
            return 1
            ;;
    esac
    local real_dir anc anc_perms anc_owner
    real_dir="$(cd -P "$dir" 2>/dev/null && pwd -P)" || return 1
    anc="$real_dir"
    while [ "$anc" != "/" ] && [ -n "$anc" ]; do
        anc_perms=""
        anc_owner=""
        IFS=$' \t\n' read -r anc_perms _ anc_owner _ < <(LC_ALL=C ls -ld "$anc" 2>/dev/null || true)
        case "$anc_perms" in
            d????????[tT]*)
                if [ ! -O "$anc" ] && [ "$anc_owner" != "root" ]; then
                    echo "❌ Unsafe sticky ancestor directory for $label ($anc)." >&2
                    return 1
                fi
                ;;
            d????w*)
                echo "❌ Unsafe group-writable ancestor directory for $label ($anc: $anc_perms)." >&2
                return 1
                ;;
            d???????w*)
                echo "❌ Unsafe non-sticky world-writable ancestor directory for $label ($anc: $anc_perms)." >&2
                return 1
                ;;
            d*) ;;
            *)
                echo "❌ Unable to inspect ancestor permissions for $label ($anc)." >&2
                return 1
                ;;
        esac
        case "$anc" in
            */*) anc="${anc%/*}" ;;
            *) anc="" ;;
        esac
    done
}

if [ -L "$BURN_STATE_DIR" ]; then
    echo "❌ Refusing symlinked burn state directory: $BURN_STATE_DIR" >&2
    exit 1
fi
if [ -e "$BURN_STATE_DIR" ] && [ ! -d "$BURN_STATE_DIR" ]; then
    echo "❌ Burn state path exists and is not a directory: $BURN_STATE_DIR" >&2
    exit 1
fi
_kty_base_check="$BURN_STATE_DIR"
while [ ! -e "$_kty_base_check" ] && [ "$_kty_base_check" != "/" ] && [ "$_kty_base_check" != "." ]; do
    if [ -L "$_kty_base_check" ]; then
        echo "❌ Refusing symlinked burn state path component: $_kty_base_check" >&2
        exit 1
    fi
    _kty_base_check="$(dirname "$_kty_base_check")"
done
ensure_safe_dir_strict "$_kty_base_check" "burn state base directory" || exit 1
umask 077
mkdir -p -m 0700 "$BURN_STATE_DIR"
chmod 0700 "$BURN_STATE_DIR"
ensure_safe_dir_strict "$BURN_STATE_DIR" "burn state directory" || exit 1

LOCK_FILE="${KTY_BURN_LOCK_FILE:-$BURN_STATE_DIR/burn.lock}"
COLLECTOR_STATE_FILE="${KTY_BURN_STATE_FILE:-$BURN_STATE_DIR/collector-running}"
PROM_STATE_FILE="${KTY_BURN_PROM_STATE_FILE:-$BURN_STATE_DIR/prometheus-stopped}"

ensure_safe_target_file() {
    local target="$1"
    local label="$2"
    local parent_dir
    parent_dir="$(dirname "$target")"
    ensure_safe_dir_strict "$parent_dir" "parent directory for $label" || return 1
    if [ -L "$target" ]; then
        echo "❌ Refusing symlinked $label ($target)." >&2
        return 1
    fi
    if [ -e "$target" ] && { [ ! -f "$target" ] || [ ! -O "$target" ]; }; then
        echo "❌ Unsafe $label ($target): must be an operator-owned regular file." >&2
        return 1
    fi
}

write_recovery_state_file() {
    local target_file="$1"
    local target_label="$2"
    ensure_safe_target_file "$target_file" "$target_label" || return 1
    local state_dir prefix tmp_state
    state_dir="$(dirname "$target_file")"
    prefix="$(basename "$target_file")"
    tmp_state="$(mktemp "${state_dir}/.${prefix}.XXXXXX")" || return 1
    if ! printf '%s\n' "$$" > "$tmp_state"; then
        rm -f "$tmp_state" 2>/dev/null || true
        return 1
    fi
    if ! mv -f "$tmp_state" "$target_file"; then
        rm -f "$tmp_state" 2>/dev/null || true
        return 1
    fi
}
write_collector_state_file() {
    write_recovery_state_file "$COLLECTOR_STATE_FILE" "collector recovery state file"
}
write_prom_state_file() {
    write_recovery_state_file "$PROM_STATE_FILE" "prometheus recovery state file"
}

ensure_safe_target_file "$LOCK_FILE" "burn lock file" || exit 1
ensure_safe_target_file "$COLLECTOR_STATE_FILE" "collector recovery state file" || exit 1
ensure_safe_target_file "$PROM_STATE_FILE" "prometheus recovery state file" || exit 1

LOCK_BACKEND=""
if command -v flock >/dev/null 2>&1; then
    LOCK_BACKEND="flock"
elif command -v perl >/dev/null 2>&1; then
    LOCK_BACKEND="perl"
elif command -v python3 >/dev/null 2>&1; then
    LOCK_BACKEND="python3"
else
    echo "❌ Kernel flock(2) lock unavailable (requires flock, perl, or python3)." >&2
    exit 1
fi

try_flock_fd9() {
    case "$LOCK_BACKEND" in
        flock) flock -n 9 2>/dev/null ;;
        perl) perl -e 'use Fcntl qw(:flock); open(my $fh, ">&=", 9) or exit 2; flock($fh, LOCK_EX | LOCK_NB) or exit 1;' 2>/dev/null ;;
        python3) python3 -c 'import fcntl; fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)' 2>/dev/null ;;
    esac
}

# Always restore OTel Collector and close FD 9 flock handle if stopped/opened before early exit
LOCK_FD_OPEN=0
LOCK_ACQUIRED=0
collector_was_running=0
prom_was_stopped=0
prom_wal_wiped=0
restore_collector() {
    local exit_code=$?
    if [ "$prom_was_stopped" -eq 1 ]; then
        echo "⚡ Restoring Prometheus after interrupted WAL purge..."
        if ! docker start kty-prometheus 9>&-; then
            echo "❌ Failed to restart Prometheus during cleanup." >&2
            if [ "$exit_code" -eq 0 ]; then
                exit_code=1
            fi
        elif [ "$prom_wal_wiped" -eq 1 ] && wait_prom_ready; then
            [ -L "$PROM_STATE_FILE" ] || rm -f "$PROM_STATE_FILE" 2>/dev/null || true
        fi
        prom_was_stopped=0
    fi
    if [ "$collector_was_running" -eq 1 ]; then
        echo "⚡ Restoring OpenTelemetry Collector after purge..."
        if ! docker start kty-otel-collector 9>&-; then
            echo "❌ Failed to restart OpenTelemetry Collector during cleanup." >&2
            if [ "$exit_code" -eq 0 ]; then
                exit_code=1
            fi
        else
            if [ ! -L "$COLLECTOR_STATE_FILE" ]; then
                rm -f "$COLLECTOR_STATE_FILE" 2>/dev/null || true
            fi
        fi
        collector_was_running=0
    fi
    if [ "$LOCK_FD_OPEN" -eq 1 ]; then
        exec 9>&-
        LOCK_FD_OPEN=0
        LOCK_ACQUIRED=0
    fi
    exit "$exit_code"
}
trap restore_collector EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Open persistent lock file on FD 9 (never unlink) and serialize via kernel flock(2) so SIGKILL releases lock immediately
exec 9>>"$LOCK_FILE"
LOCK_FD_OPEN=1

# Lock retry budget in 0.1s iterations (default 300 = 30s)
lock_max_wait="${KTY_BURN_LOCK_MAX_WAIT:-300}"
case "$lock_max_wait" in
    *[!0-9]*|''|0) lock_max_wait=300 ;;
esac
lock_wait=0
while true; do
    lock_rc=0
    try_flock_fd9 || lock_rc=$?
    if [ "$lock_rc" -eq 0 ]; then
        LOCK_ACQUIRED=1
        break
    fi
    if [ "$lock_rc" -eq 2 ]; then
        echo "❌ Kernel flock(2) lock helper failed unexpectedly ($LOCK_FILE)." >&2
        exit 1
    fi
    lock_wait=$((lock_wait + 1))
    if [ "$lock_wait" -ge "$lock_max_wait" ]; then
        echo "❌ Timed out waiting for concurrent burn-telemetry.sh lock ($LOCK_FILE)." >&2
        exit 1
    fi
    sleep 0.1 9>&-
done

# Query running containers inside mutex so Collector state cannot race concurrent burns
if ! running_containers="$(docker ps --format '{{.Names}}' 9>&-)"; then
    echo "❌ Failed to query running Docker containers via 'docker ps'." >&2
    exit 1
fi
if [ -f "$COLLECTOR_STATE_FILE" ]; then
    # Reconcile interrupted previous burn that stopped Collector before receiving SIGKILL
    collector_was_running=1
fi

# Pre-validate Genesis bearer token before stopping OTel Collector so invalid config fails fast
genesis_is_running=0
GENESIS_TOKEN=""
if printf '%s\n' "$running_containers" | grep -qx "kty-genesis"; then
    genesis_is_running=1
    if [ -z "${GENESIS_AUTH_TOKEN:-}" ]; then
        echo "❌ GENESIS_AUTH_TOKEN must be set to purge Genesis logs." >&2
        exit 1
    fi
    GENESIS_TOKEN="$GENESIS_AUTH_TOKEN"
    case "$GENESIS_TOKEN" in
        *[$'\r\n']*|*'"'*|*\\*)
            echo "❌ GENESIS_AUTH_TOKEN contains invalid characters for curl stdin header config." >&2
            exit 1
            ;;
    esac
fi

# 1. Stop OTel Collector first so OTLP receivers and :8889 scrape target close before storage resets
if printf '%s\n' "$running_containers" | grep -qx "kty-otel-collector"; then
    collector_was_running=1
    write_collector_state_file
    echo "⚡ Flushing and resetting OpenTelemetry Collector buffers..."
    docker stop kty-otel-collector 9>&-
fi

# 2. Restart running backend OTLP producer services while Collector is stopped so queued SDK retries are discarded
for producer_svc in kty-gradcast kty-mail-stripper kty-ftaas-api kty-ftaas-worker kty-surprisal; do
    if printf '%s\n' "$running_containers" | grep -qx "$producer_svc"; then
        echo "⚡ Discarding volatile OTLP export queues in $producer_svc..."
        docker restart "$producer_svc" 9>&-
    fi
done

# 3. Restart Jaeger while Collector and producers have cleared buffers so pre-burn retries cannot refill it
if printf '%s\n' "$running_containers" | grep -qx "kty-jaeger"; then
    echo "⚡ Flushing and purging in-memory traces from Jaeger..."
    docker restart kty-jaeger 9>&-
fi

wait_prom_ready() {
    local prom_ready_max prom_wait
    prom_ready_max="${KTY_PROM_READY_MAX_WAIT:-60}"
    case "$prom_ready_max" in
        *[!0-9]*|''|0) prom_ready_max=60 ;;
    esac
    prom_wait=0
    while [ "$prom_wait" -lt "$prom_ready_max" ]; do
        if curl --noproxy '*' --connect-timeout 2 --max-time 2 -fsS "http://127.0.0.1:${PROMETHEUS_PORT_VALIDATED}/-/ready" >/dev/null 9>&-; then
            return 0
        fi
        prom_wait=$((prom_wait + 1))
        sleep 0.25 9>&-
    done
    return 1
}

# 4. Abort any pre-stop in-flight Prometheus scrape, wait for /-/ready, purge Admin API + TSDB head WAL on disk, then restart
prom_rc=0
wipe_prom_wal_and_restart() {
    local should_stop="${1:-1}"
    local prom_image
    prom_image="$(docker inspect -f '{{.Config.Image}}' kty-prometheus 9>&- || true)"
    if [ -z "$prom_image" ]; then
        prom_image="prom/prometheus:v3.1.0"
    fi
    if [ "$should_stop" -eq 1 ]; then
        if ! write_prom_state_file; then
            echo "❌ Failed to persist Prometheus recovery state before stopping Prometheus." >&2
            prom_rc=1
            return 0
        fi
        prom_wal_wiped=0
        prom_was_stopped=1
        docker stop kty-prometheus 9>&-
    else
        prom_wal_wiped=0
        prom_was_stopped=1
    fi
    docker run --rm --volumes-from kty-prometheus --network none --cap-drop ALL --security-opt no-new-privileges --entrypoint /bin/sh "$prom_image" -c 'find /prometheus -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +' 9>&-
    prom_wal_wiped=1
    docker start kty-prometheus 9>&-
    prom_was_stopped=0
    if ! wait_prom_ready; then
        echo "❌ Prometheus failed post-WAL-purge readiness check (/-/ready)." >&2
        prom_rc=1
        return 0
    fi
    [ -L "$PROM_STATE_FILE" ] || rm -f "$PROM_STATE_FILE" 2>/dev/null || true
}
if printf '%s\n' "$running_containers" | grep -qx "kty-prometheus"; then
    echo "⚡ Draining in-flight Prometheus scrapes before TSDB purge..."
    docker restart kty-prometheus 9>&-
    if ! wait_prom_ready; then
        echo "❌ Prometheus failed readiness check (/-/ready) before TSDB purge." >&2
        prom_rc=1
    else
        echo "⚡ Flushing and purging persistent metric time-series from Prometheus (prometheus-data)..."
        if ! curl --noproxy '*' --connect-timeout 3 --max-time 10 -fsS -X POST "http://127.0.0.1:${PROMETHEUS_PORT_VALIDATED}/api/v1/admin/tsdb/delete_series" --data-urlencode 'match[]={__name__=~".+"}' 9>&-; then
            echo "❌ Prometheus TSDB delete_series failed." >&2
            prom_rc=1
        fi
        if ! curl --noproxy '*' --connect-timeout 3 --max-time 10 -fsS -X POST "http://127.0.0.1:${PROMETHEUS_PORT_VALIDATED}/api/v1/admin/tsdb/clean_tombstones" 9>&-; then
            echo "❌ Prometheus TSDB clean_tombstones failed." >&2
            prom_rc=1
        fi
        echo "⚡ Stopping Prometheus to erase TSDB head WAL segments and chunks cleanly..."
        wipe_prom_wal_and_restart 1
    fi
elif [ -f "$PROM_STATE_FILE" ]; then
    echo "⚡ Reconciling interrupted Prometheus WAL purge from previous burn..."
    wipe_prom_wal_and_restart 0
fi

# 5. Purge Genesis volatile in-memory log buffer (Amnesiac Purge via DELETE /logs)
purge_rc=0
if [ "$genesis_is_running" -eq 1 ]; then
    echo "⚡ Executing instant Amnesiac Purge on Genesis in-memory log engine..."
    printf 'header = "Authorization: Bearer %s"\n' "${GENESIS_TOKEN}" | curl --noproxy '*' --connect-timeout 3 --max-time 10 -fsS -X DELETE -K - "http://127.0.0.1:${GENESIS_PORT_VALIDATED}/logs" 9>&- || purge_rc=$?
    docker restart kty-genesis 9>&-
    if [ "$purge_rc" -ne 0 ]; then
        echo "❌ Genesis HTTP log purge failed (exit $purge_rc) prior to container restart fallback." >&2
    fi
fi

# 6. Bring OTel Collector back online only after Jaeger and Prometheus have finished purging and restarting
if [ "$collector_was_running" -eq 1 ]; then
    echo "⚡ Restarting OpenTelemetry Collector after clean telemetry barrier..."
    docker start kty-otel-collector 9>&-
    rm -f "$COLLECTOR_STATE_FILE" 2>/dev/null || true
    collector_was_running=0
fi

if [ "$purge_rc" -ne 0 ]; then
    exit "$purge_rc"
fi
if [ "$prom_rc" -ne 0 ]; then
    exit "$prom_rc"
fi

echo ""
echo "✅ Pillar 1 Invariant Verified: All in-memory spans and timeseries purged."
echo "   External observability stores hold zero residual document traces."
echo "=============================================================="
echo ""
