#!/usr/bin/env bash
# ==============================================================================
# start.sh - Launch the knowthankyew Enterprise Self-Host Suite
# ==============================================================================

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MODE="${1:-enterprise}"

echo ""
echo "=============================================================="
echo "  🛡️  knowthankyew Enterprise Self-Host Suite"
echo "  Target Mode: ${MODE}"
echo "=============================================================="

# Preflight check for docker
if ! command -v docker &> /dev/null; then
    echo "❌ Error: Docker is not installed or not in PATH."
    exit 1
fi

if ! docker info &> /dev/null; then
    echo "❌ Error: Docker daemon is not running. Please start Docker."
    exit 1
fi

# Ensure .env exists
if [ ! -f .env ]; then
    echo "ℹ️  Creating default .env from .env.example..."
    cp .env.example .env
fi

if [ "$MODE" = "consumer" ]; then
    echo "🚀 Starting in PURE AIR-GAPPED CONSUMER mode (No Telemetry Collectors)..."
    docker compose -f docker-compose.yml -f docker-compose.consumer.yml up -d --build
else
    echo "🚀 Starting in ENTERPRISE mode (OTel Collector, Jaeger, Prometheus, Grafana)..."
    docker compose -f docker-compose.yml -f docker-compose.enterprise.yml up -d --build
fi

echo ""
echo "=============================================================="
echo "  🎉 Suite is LIVE!"
echo "  👉 Enterprise Portal:    http://localhost:8080"
if [ "$MODE" = "enterprise" ]; then
    echo "  👉 Grafana Dashboards:  http://localhost:3000"
    echo "  👉 Jaeger Traces:        http://localhost:16686"
    echo "  👉 Prometheus Metrics:   http://localhost:9090"
fi
echo "=============================================================="
echo "  Run ./burn-telemetry.sh to purge in-memory telemetry (Pillar 1)"
echo "  Run ./stop.sh to shut down all containers"
echo "=============================================================="
echo ""
