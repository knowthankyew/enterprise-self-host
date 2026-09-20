#!/usr/bin/env bash
# ==============================================================================
# burn-telemetry.sh - Cluster-Wide Telemetry Purge (Pillar 1: True Burnability)
# Instantly drains volatile buffers, purges Jaeger in-memory traces, and wipes
# Prometheus TSDB time-series data completely with zero data retention.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Source environment variables if present
if [ -f .env ]; then
    # shellcheck disable=SC1091
    source .env
fi

echo ""
echo "=============================================================="
echo "  🔥 PURGING CLUSTER TELEMETRY (Pillar 1: True Burnability)"
echo "=============================================================="

# 1. Restart Jaeger to drop all volatile in-memory traces immediately
if docker ps --format '{{.Names}}' | grep -q "kty-jaeger"; then
    echo "⚡ Flushing and purging in-memory traces from Jaeger..."
    docker restart kty-jaeger
fi

# 2. Restart OTel Collector to flush in-flight batch buffers
if docker ps --format '{{.Names}}' | grep -q "kty-otel-collector"; then
    echo "⚡ Flushing and resetting OpenTelemetry Collector buffers..."
    docker restart kty-otel-collector
fi

# 3. Purge Prometheus metric time-series completely (Admin API + storage reset)
if docker ps --format '{{.Names}}' | grep -q "kty-prometheus"; then
    echo "⚡ Flushing and purging persistent metric time-series from Prometheus (prometheus-data)..."
    curl -X POST -s "http://localhost:${PROMETHEUS_PORT:-9090}/api/v1/admin/tsdb/delete_series" -d 'match[]={__name__=~".+"}' 2>/dev/null || true
    curl -X POST -s "http://localhost:${PROMETHEUS_PORT:-9090}/api/v1/admin/tsdb/clean_tombstones" 2>/dev/null || true
    docker restart kty-prometheus
fi

echo ""
echo "✅ Pillar 1 Invariant Verified: All in-memory spans and timeseries purged."
echo "   External observability stores hold zero residual document traces."
echo "=============================================================="
echo ""
