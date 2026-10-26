<!-- diagram-meta
  last-validated: 2026-10-19
  covers: [collector/**, helm/**, monitoring/**, gateway/**, docker-compose*.yml]
  generated-by: manual
-->

# Architecture & Orchestration Specification: Enterprise Self-Host

> Production Docker Compose, Helm chart, OpenTelemetry Collector, and reverse-proxy deployment harness for the `knowthankyew` portfolio.

---

## 1. Executive Summary

`enterprise-self-host` provides the infrastructure orchestration harness for deploying the complete `knowthankyew` suite within enterprise VPCs, private Kubernetes clusters, or air-gapped on-premise environments. It demonstrates the portfolio's core architectural pattern: client applications remain air-gapped and zero-egress by default in consumer profiles, while enterprise profiles enable local OpenTelemetry aggregation via an explicit build-time shim without code changes or upstream forks.

---

## 2. System Architecture & Deployment Topology

### A. Container Topology & Network Isolation

```mermaid
flowchart TD
    subgraph PublicBoundary["External / Edge Ingress"]
        ClientBrowser["🌐 Corporate Users & Legal Teams"]
        Gateway["🚪 Reverse Proxy Gateway (:80 / :443)<br/><code>gateway/nginx.conf</code>"]
    end

    subgraph InternalNetwork["Internal Private Docker Network ('kty-network')"]
        subgraph WebEngines["Consumer Reality Engines (Node/Nginx)"]
            Lease["lease-audit (:3001)"]
            Care["careCheck (:3002)"]
            BOR["bill-of-rights-bot (:3003)"]
            Paystub["paystub-check (:3004)"]
            Warranty["warranty-watch (:3005)"]
        end

        subgraph ServiceEngines["Backend Services (.NET 10 / Python)"]
            Grad["gradcast (:5000)"]
            Mail["mailStripper (:5200)"]
            FTaaS["ml / event-driven-ftaas (:5100)"]
        end

        subgraph ObservabilityStack["Local Enterprise Observability (Private VPC)"]
            OTelCollector["📡 OpenTelemetry Collector (:4317 / :4318)<br/><code>collector/otel-collector-config.yaml</code>"]
            Prometheus["📊 Prometheus Time-Series DB (:9090)<br/><code>monitoring/prometheus/prometheus.yml</code>"]
            Grafana["📈 Grafana Dashboards (:3000)<br/><code>monitoring/grafana/dashboards</code>"]
        end
    end

    %% Routing
    ClientBrowser -->|"HTTPS"| Gateway
    Gateway -->|"Route /lease"| Lease
    Gateway -->|"Route /care"| Care
    Gateway -->|"Route /bot"| BOR
    Gateway -->|"Route /paystub"| Paystub
    Gateway -->|"Route /warranty"| Warranty
    Gateway -->|"Route /gradcast"| Grad
    Gateway -->|"Route /mail"| Mail
    Gateway -->|"Route /ftaas"| FTaaS

    %% Telemetry pipeline (Enterprise profile only)
    WebEngines -.->|"OTLP HTTP Protobuf (if configured)"| OTelCollector
    ServiceEngines -.->|"OTLP gRPC (if configured)"| OTelCollector
    OTelCollector -->|"Metrics Scrape"| Prometheus
    Prometheus -->|"Visualize"| Grafana

    classDef edge fill:#0f172a,stroke:#64748b,stroke-width:1px,color:#f8fafc;
    classDef web fill:#1e293b,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;
    classDef srv fill:#14532d,stroke:#22c55e,stroke-width:2px,color:#f8fafc;
    classDef obs fill:#312e81,stroke:#818cf8,stroke-width:1px,color:#f8fafc;

    class ClientBrowser,Gateway edge;
    class Lease,Care,BOR,Paystub,Warranty web;
    class Grad,Mail,FTaaS srv;
    class OTelCollector,Prometheus,Grafana obs;
```

### B. Dual-Profile Execution Boundary

```mermaid
flowchart LR
    subgraph Profiles["Deployment Profiles"]
        ConsumerProfile["🟢 Consumer Profile<br/><code>docker-compose.consumer.yml</code>"]
        EnterpriseProfile["🏢 Enterprise Profile<br/><code>docker-compose.enterprise.yml</code>"]
    end

    subgraph Guarantees["Enforced Architectural Invariants"]
        ZeroEgress["🛡️ 100% Air-Gapped<br/>• OTLP collectors disabled<br/>• In-memory circular buffer only<br/>• 'Zero Egress' green UI badge"]
        LocalObs["📊 Monitored Local VPC<br/>• Local OTel Collector attached<br/>• Persistent amber enterprise UI banner<br/>• Zero public cloud data egress"]
    end

    ConsumerProfile --> ZeroEgress
    EnterpriseProfile --> LocalObs

    classDef cp fill:#14532d,stroke:#22c55e,stroke-width:2px,color:#f8fafc;
    classDef ep fill:#1e293b,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;
    classDef g fill:#0f172a,stroke:#64748b,stroke-width:1px,color:#f8fafc;

    class ConsumerProfile cp;
    class EnterpriseProfile ep;
    class ZeroEgress,LocalObs g;
```

---

## 3. Core Architectural Invariants

| # | Invariant | Description & Enforcement |
|:--|:----------|:--------------------------|
| 1 | **Air-Gap Verification Gate** | Automated harness `verify-selfhost.sh` spins up stacks and verifies zero unexpected outbound network connections via socket inspection. |
| 2 | **Local-Only Observability** | In enterprise mode, all metrics and traces remain inside the local Docker network / VPC; zero external SaaS telemetry beacons. |
| 3 | **Dynamic UI Honesty** | Applications launched under the enterprise profile automatically show the amber `[ENTERPRISE (OTLP)]` banner via `getPrivacyClaims()`. |
| 4 | **Universal Nuclear Burn Orchestration** | Shell script `burn-telemetry.sh` broadcasts atomic purge signals across all running containers and storage mounts. |
| 5 | **Kubernetes / Helm Production Readiness** | Ready-to-deploy Helm charts (`helm/`) specifying resource limits, liveness probes, and non-root security contexts. |

---

## 4. Directory Structure

```
enterprise-self-host/
├── docker-compose.yml           # Base orchestration across all 12 services
├── docker-compose.consumer.yml  # Zero-egress public profile override
├── docker-compose.enterprise.yml # Local OTel collector profile override
├── collector/
│   └── otel-collector-config.yaml # OpenTelemetry pipeline & receivers
├── gateway/
│   └── nginx.conf               # Unified reverse proxy routing
├── monitoring/
│   ├── prometheus/
│   │   └── prometheus.yml       # Prometheus scrape configurations
│   └── grafana/
│       └── dashboards/          # Grafana pre-built portfolio dashboards
├── helm/                        # Production Kubernetes Helm chart
├── burn-telemetry.sh            # Global amnesiac state purge orchestrator
├── clone-siblings.sh            # Sibling repository sync script
├── verify-selfhost.sh           # Automated integration & air-gap validation test
├── start.sh                     # Launch runner
└── stop.sh                      # Teardown script
```
