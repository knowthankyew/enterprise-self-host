#!/usr/bin/env bash
# ==============================================================================
# stop.sh - Cleanly shut down the knowthankyew Enterprise Suite
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🛑 Stopping all knowthankyew enterprise containers..."
docker compose down

echo "✅ All containers stopped cleanly."
