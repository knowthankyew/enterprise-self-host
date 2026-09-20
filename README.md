# knowthankyew Enterprise Self-Host & Collector Packs

> Turnkey Docker Compose & Kubernetes Helm charts for deploying the full `knowthankyew` reality engine suite with local-only, air-gapped OpenTelemetry observability.

---

## 1. Overview & Architectural Invariants

This package enables universities, non-profits, legal aid clinics, healthcare advocates, and tenant unions to deploy the entire `knowthankyew` reality engine suite internally on their own infrastructure without sacrificing our **5 Pillars**:

```
+-------------------------------------------------------------------------------+
|                       5 INVARIANTS OF THE PORTFOLIO                           |
+------------------------------------+------------------------------------------+
| 1. Volatile Memory Telemetry       | Zero network egress; memory circular     |
|    by Default                      | buffer; hard tombstone on "Burn".        |
+------------------------------------+------------------------------------------+
| 2. Compile-Time Dead Code          | OTLP endpoints baked at build time;      |
|    Over Runtime Toggles            | public consumer CDN bundles cannot leak. |
+------------------------------------+------------------------------------------+
| 3. Strict Key Allowlists           | Non-allowlisted keys sanitized to        |
|    Over Brittle Denylists          | [REDACTED_BY_DEFAULT_ALLOWLIST].         |
+------------------------------------+------------------------------------------+
| 4. Single Source of Truth for      | Central getPrivacyClaims() suppresses    |
|    Honest UI Claims                | local claims and triggers amber banner.  |
+------------------------------------+------------------------------------------+
| 5. Universal CI Supply-Chain       | Automated CycloneDX SBOM (bom.json);     |
|    Integrity                       | fail-closed vulnerability gates.         |
+------------------------------------+------------------------------------------+
```

---

## 2. Directory Structure

```
enterprise-self-host/
├── docker-compose.yml              # Unified multi-container composition
├── docker-compose.consumer.yml     # Air-gapped consumer profile (zero telemetry)
├── docker-compose.enterprise.yml   # Enterprise overlay (OTel, Jaeger, Prometheus, Grafana)
├── .env.example                    # Port mappings and environment defaults
├── start.sh                        # One-click startup script
├── stop.sh                         # Clean shutdown script
├── burn-telemetry.sh               # Pillar 1 cluster-wide trace purge script
├── verify-selfhost.sh              # Automated verification harness
│
├── collector/
│   └── otel-collector-config.yaml  # OTel Contrib config with OTTL allowlist enforcement
│
├── monitoring/
│   ├── prometheus/
│   │   └── prometheus.yml          # Prometheus scrape configs
│   └── grafana/
│       ├── provisioning/           # Auto-provisioned datasources & dashboard providers
│       └── dashboards/
│           └── knowthankyew-portfolio.json # Privacy & Observability Dashboard
│
├── gateway/
│   ├── nginx.conf                  # Reverse-proxy router & CORS terminator
│   └── portal/
│       └── index.html              # Interactive catalog portal landing page
│
└── helm/
    └── knowthankyew-suite/         # Kubernetes Helm 3 chart suite
        ├── Chart.yaml
        ├── values.yaml
        └── templates/              # Apps, Services, Observability, Ingress, NetworkPolicies
```

---

## 3. Quickstart: Docker Compose

### Prerequisites
- Docker Engine & Docker Compose v2+

### A. Launch in Enterprise Mode (Full Suite + Observability)
Attaches local OpenTelemetry Collector, Jaeger, Prometheus, and Grafana:

```bash
./start.sh enterprise
```
*Or manually:*
```bash
docker compose -f docker-compose.yml -f docker-compose.enterprise.yml up -d --build
```

Access the **Enterprise Gateway Portal** at:
👉 **`http://localhost:8080`**

From the portal, you can access:
- **Reality Engines**: `/lease-audit/`, `/care-check/`, `/paystub-check/`, `/bill-of-rights/`, `/warranty-watch/`
- **Backend APIs**: `/gradcast/`, `/mail-stripper/`, `/ftaas/`
- **Observability**: `/grafana/` (Port 3000), `/jaeger/` (Port 16686), `/prometheus/` (Port 9090)

---

### B. Launch in Air-Gapped Consumer Mode (Zero Telemetry)
Runs all tools with zero external collector containers and zero network telemetry egress:

```bash
./start.sh consumer
```
*Or manually:*
```bash
docker compose -f docker-compose.yml -f docker-compose.consumer.yml up -d --build
```

---

## 4. Quickstart: Kubernetes Helm Chart

### Prerequisites
- Kubernetes cluster (1.26+)
- Helm v3+

### Installation
```bash
# 1. Install using default enterprise values
helm install knowthankyew ./helm/knowthankyew-suite

# 2. Or install in pure consumer air-gapped mode
helm install knowthankyew ./helm/knowthankyew-suite --set mode=consumer --set observability.collector.enabled=false
```

### Air-Gap Network Policies
The Helm chart includes strict Kubernetes `NetworkPolicy` manifests (`templates/networkpolicies/airgap-deny-egress.yaml`) that:
1. Block reality engine pods from transmitting packets to public internet CIDRs.
2. Restrict outbound traffic strictly to internal cluster DNS and the intra-cluster OTel collector service.

---

## 5. The True Burn Routine (Pillar 1)

To purge all in-memory traces and flush buffers cluster-wide:

```bash
./burn-telemetry.sh
```

This instantly flushes collector batches, drops in-memory traces from Jaeger, and guarantees that external observability stores hold zero residual document metadata.

---

## 6. Service Port Reference

| Service | Container Name | Internal Port | Host Port | Path on Gateway (:8080) |
| :--- | :--- | :--- | :--- | :--- |
| **Gateway Portal** | `kty-gateway` | 80 | `8080` | `/` |
| **LeaseAudit** | `kty-lease-audit` | 80 | `8081` | `/lease-audit/` |
| **CareCheck** | `kty-care-check` | 80 | `8082` | `/care-check/` |
| **PaystubCheck** | `kty-paystub-check` | 80 | `8083` | `/paystub-check/` |
| **Bill of Rights Bot** | `kty-bill-of-rights-bot` | 80 | `8084` | `/bill-of-rights/` |
| **WarrantyWatch** | `kty-warranty-watch` | 80 | `8085` | `/warranty-watch/` |
| **GradCast** | `kty-gradcast` | 5062 | `5062` | `/gradcast/` |
| **MailStripper** | `kty-mail-stripper` | 5001 | `5001` | `/mail-stripper/` |
| **FTaaS Control Plane** | `kty-ftaas-api` | 5000 | `5000` | `/ftaas/` |
| **RabbitMQ** | `kty-rabbitmq` | 5672 / 15672 | `5672` / `15672` | N/A |
| **MLflow** | `kty-mlflow` | 5000 | `5002` | N/A |
| **OTel Collector** | `kty-otel-collector` | 4317 / 4318 / 8889 | `4317` / `4318` / `8889` | `/otlp/` |
| **Jaeger** | `kty-jaeger` | 16686 / 4317 | `16686` | `/jaeger/` |
| **Prometheus** | `kty-prometheus` | 9090 | `9090` | `/prometheus/` |
| **Grafana** | `kty-grafana` | 3000 | `3000` | `/grafana/` |
