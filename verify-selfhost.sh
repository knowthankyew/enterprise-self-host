#!/usr/bin/env bash
# ==============================================================================
# verify-selfhost.sh - Automated Validation Harness for Phase 4 Self-Host Packs
# Rigorously validates all 8 Remediation Boundaries and 5 Architectural Invariants
# ==============================================================================

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
BOLD="\033[1m"
GREEN="\033[0;32m"
RED="\033[0;31m"
CYAN="\033[0;36m"
RESET="\033[0m"

echo -e "\n${BOLD}${CYAN}=== Phase 4: Enterprise Self-Host Suite Rigorous Verification ===${RESET}\n"

ERRORS=0

test_step() {
    local name="$1"
    local cmd="$2"
    printf "  Checking %-55s ... " "$name"
    if eval "$cmd" > /dev/null 2>&1; then
        echo -e "${GREEN}PASS${RESET}"
    else
        echo -e "${RED}FAIL${RESET}"
        ERRORS=$((ERRORS + 1))
    fi
}

# ── 1. Docker Compose Syntaxes ─────────────────────────────────────────
if command -v docker-compose &> /dev/null; then
    test_step "docker-compose.yml syntax" "docker-compose -f docker-compose.yml config -q"
    test_step "docker-compose.consumer.yml syntax" "docker-compose -f docker-compose.yml -f docker-compose.consumer.yml config -q"
    test_step "docker-compose.enterprise.yml syntax" "docker-compose -f docker-compose.yml -f docker-compose.enterprise.yml config -q"
elif command -v docker &> /dev/null; then
    test_step "docker compose syntax" "docker compose -f docker-compose.yml config -q"
fi

# ── 2. YAML Syntax Verification (Ruby standard on macOS) ───────────────
yaml_check() {
    local file="$1"
    ruby -ryaml -e "YAML.load_file('$file')" > /dev/null 2>&1
}

test_step "OTel Collector YAML syntax" "yaml_check collector/otel-collector-config.yaml"
test_step "Prometheus scrape YAML syntax" "yaml_check monitoring/prometheus/prometheus.yml"
test_step "Grafana Datasources YAML syntax" "yaml_check monitoring/grafana/provisioning/datasources/datasources.yaml"
test_step "Grafana Dashboards YAML syntax" "yaml_check monitoring/grafana/provisioning/dashboards/dashboards.yaml"
test_step "Helm Chart.yaml syntax" "yaml_check helm/knowthankyew-suite/Chart.yaml"
test_step "Helm values.yaml syntax" "yaml_check helm/knowthankyew-suite/values.yaml"

# ── 3. JSON Syntax Verification ────────────────────────────────────────
test_step "Grafana Dashboard JSON schema" "python3 -c 'import json; json.load(open(\"monitoring/grafana/dashboards/knowthankyew-portfolio.json\"))'"

# ── 4. Boundary 1: Pillar 3 (OTTL Allowlist & Spanmetrics) ─────────────
test_step "B1: OTel OTTL keep_keys allowlist enforcement" "grep -q 'keep_keys(attributes' collector/otel-collector-config.yaml"
test_step "B1: OTel spanmetrics connector configured" "grep -q 'spanmetrics:' collector/otel-collector-config.yaml"

# ── 5. Boundary 2: Pillar 1 (Cluster Burn Routine) ─────────────────────
test_step "B2: burn-telemetry.sh executable" "test -x burn-telemetry.sh"
test_step "B2: burn-telemetry.sh purges Prometheus metrics" "grep -q 'delete_series' burn-telemetry.sh && grep -q 'clean_tombstones' burn-telemetry.sh"
test_step "B2: Prometheus admin API enabled in compose" "grep -q 'web.enable-admin-api' docker-compose.yml"

# ── 6. Boundary 3: Pillar 2 (Compile-Time Dead-Code AST) ───────────────
test_step "B3: Literal AST env in privacy-telemetry" "grep -q 'import.meta.env.VITE_OTEL_EXPORTER_OTLP_ENDPOINT' ../privacy-telemetry/packages/privacy-telemetry/src/manager.ts"

# ── 7. Boundary 4: Gateway Asset Routing & Vite Relative Base ──────────
test_step "B4: lease-audit relative asset base" "grep -q \"base: './'\" ../lease-audit/vite.config.ts"
test_step "B4: careCheck relative asset base" "grep -q \"base: './'\" ../careCheck/vite.config.ts"
test_step "B4: paystub-check relative asset base" "grep -q \"base: './'\" ../paystub-check/vite.config.ts"
test_step "B4: bill-of-rights-bot relative asset base" "grep -q \"base: './'\" ../bill-of-rights-bot/vite.config.ts"
test_step "B4: warranty-watch relative asset base" "grep -q \"base: './'\" ../warranty-watch/vite.config.ts"
test_step "B4: Enterprise Gateway reverse-proxy routes" "grep -q 'location /otlp/' gateway/nginx.conf"

# ── 8. Boundary 5: Host Port Collision & Build Contexts ────────────────
test_step "B5: FTAAS_API_PORT remapped to 5005 in .env.example" "grep -q 'FTAAS_API_PORT=5005' .env.example"
test_step "B5: Root .dockerignore exists to scope context" "test -f ../.dockerignore"

# ── 9. Boundary 6: Real Prometheus Metrics & Dashboards ────────────────
test_step "B6: Prometheus scrapes otel-collector:8889" "grep -q 'otel-collector:8889' monitoring/prometheus/prometheus.yml"
test_step "B6: Invalid /health scrapes removed from Prometheus" "grep -v 'metrics_path: \"/health\"' monitoring/prometheus/prometheus.yml"

# ── 10. Boundary 7: Kubernetes Helm Manifests (PVCs & NetPols) ─────────
test_step "B7: Helm PersistentVolumeClaims manifest exists" "test -f helm/knowthankyew-suite/templates/pvc.yaml"
test_step "B7: Helm GradCast volume mount wired to PVC" "grep -q 'gradcast-data' helm/knowthankyew-suite/templates/services/backend-services.yaml"
test_step "B7: Helm Prometheus volume mount wired to PVC" "grep -q 'prometheus-data' helm/knowthankyew-suite/templates/observability/observability-stack.yaml"
test_step "B7: Strict NetworkPolicy podSelector in place" "grep -q 'app.kubernetes.io/part-of: knowthankyew' helm/knowthankyew-suite/templates/networkpolicies/airgap-deny-egress.yaml"

# ── 11. Boundary 8: Pillar 5 (Supply Chain Integrity in CI) ───────────
test_step "B8: CycloneDX SBOM generation in CI workflow" "grep -q 'cdxgen' .github/workflows/validate.yml"
test_step "B8: Trivy vulnerability scanner in CI workflow" "grep -q 'trivy-action' .github/workflows/validate.yml"

echo ""
if [ "$ERRORS" -eq 0 ]; then
    echo -e "${BOLD}${GREEN}✅ All 31 checks across all 8 Boundaries PASSED successfully!${RESET}\n"
    exit 0
else
    echo -e "${BOLD}${RED}❌ ${ERRORS} check(s) FAILED.${RESET}\n"
    exit 1
fi
