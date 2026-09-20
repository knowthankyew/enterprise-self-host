#!/usr/bin/env bash
# ==============================================================================
# verify-selfhost.sh - Automated Validation Harness for Phase 4 Self-Host Packs
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

echo -e "\n${BOLD}${CYAN}=== Phase 4: Enterprise Self-Host Suite Verification ===${RESET}\n"

ERRORS=0

test_step() {
    local name="$1"
    local cmd="$2"
    printf "  Checking %-50s ... " "$name"
    if eval "$cmd" > /dev/null 2>&1; then
        echo -e "${GREEN}PASS${RESET}"
    else
        echo -e "${RED}FAIL${RESET}"
        ERRORS=$((ERRORS + 1))
    fi
}

# 1. Docker Compose Syntaxes
if command -v docker-compose &> /dev/null; then
    test_step "docker-compose.yml syntax" "docker-compose -f docker-compose.yml config -q"
    test_step "docker-compose.consumer.yml syntax" "docker-compose -f docker-compose.yml -f docker-compose.consumer.yml config -q"
    test_step "docker-compose.enterprise.yml syntax" "docker-compose -f docker-compose.yml -f docker-compose.enterprise.yml config -q"
elif command -v docker &> /dev/null; then
    test_step "docker compose syntax" "docker compose -f docker-compose.yml config -q"
fi

# 2. YAML syntax verification using Ruby yaml module (standard on macOS)
yaml_check() {
    local file="$1"
    ruby -ryaml -e "YAML.load_file('$file')" > /dev/null 2>&1
}

test_step "OTel Collector YAML" "yaml_check collector/otel-collector-config.yaml"
test_step "Prometheus scrape YAML" "yaml_check monitoring/prometheus/prometheus.yml"
test_step "Grafana Datasources YAML" "yaml_check monitoring/grafana/provisioning/datasources/datasources.yaml"
test_step "Grafana Dashboards YAML" "yaml_check monitoring/grafana/provisioning/dashboards/dashboards.yaml"
test_step "Helm Chart.yaml" "yaml_check helm/knowthankyew-suite/Chart.yaml"
test_step "Helm values.yaml" "yaml_check helm/knowthankyew-suite/values.yaml"

# 3. JSON syntax verification
test_step "Grafana Dashboard JSON" "python3 -c 'import json; json.load(open(\"monitoring/grafana/dashboards/knowthankyew-portfolio.json\"))'"

# 4. Invariant Checks
test_step "OTel Collector Allowlist Processor" "grep -q 'audit.allowlist_enforced' collector/otel-collector-config.yaml"
test_step "Helm Airgap NetworkPolicy" "grep -q 'airgap-deny-egress' helm/knowthankyew-suite/templates/networkpolicies/airgap-deny-egress.yaml"
test_step "Helm OTel Collector Ingress NetworkPolicy" "grep -q 'allow-collector-ingress' helm/knowthankyew-suite/templates/networkpolicies/allow-collector.yaml"
test_step "Enterprise Gateway CORS Proxy" "grep -q 'location /otlp/' gateway/nginx.conf"
test_step "Pillar 1 Burn Script Exists" "test -x burn-telemetry.sh"

echo ""
if [ "$ERRORS" -eq 0 ]; then
    echo -e "${BOLD}${GREEN}✅ All Phase 4 verification checks PASSED successfully!${RESET}\n"
    exit 0
else
    echo -e "${BOLD}${RED}❌ ${ERRORS} check(s) FAILED.${RESET}\n"
    exit 1
fi
