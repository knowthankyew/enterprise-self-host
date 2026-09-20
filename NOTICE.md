# Legal, Privacy, and Third-Party Attribution Notice

**knowthankyew Enterprise Self-Host & Collector Packs**  
Copyright © 2026 knowthankyew contributors  
Repository: [https://github.com/knowthankyew/enterprise-self-host](https://github.com/knowthankyew/enterprise-self-host)

---

## 1. Enterprise Self-Hosting & Privacy Architecture Notice

This repository provides turnkey Docker Compose profiles, Kubernetes Helm charts, and local OpenTelemetry collector orchestration for deploying the `knowthankyew` reality engine portfolio.

### The 5 Architectural Invariants
1. **Volatile Memory Telemetry by Default**: Local in-memory circular buffers, zero cloud egress by default, and hard tombstones on Burn.
2. **Compile-Time Dead Code Over Runtime Switches**: Consumer builds physically eliminate telemetry exporters; enterprise overlays explicitly attach local collectors.
3. **Strict Key Allowlists**: Telemetry attributes are validated against `SAFE_ALLOWLIST_KEYS` in both application code and collector OTTL transform processors. Unrecognized keys are redacted to `[REDACTED_BY_DEFAULT_ALLOWLIST]`.
4. **Single Source of Truth for Honest UI Claims**: Central `getPrivacyClaims()` suppresses local claims and triggers an amber warning banner in enterprise mode.
5. **Universal Supply-Chain Integrity**: Minimalist, unprivileged base images and automated CycloneDX SBOMs.

---

## 2. Air-Gapped Operation

All services in this suite are capable of running completely air-gapped with zero internet connectivity. The included Kubernetes NetworkPolicies block outbound internet traffic from reality engine pods, restricting communication strictly to intra-cluster services and DNS.

---

## 3. Software License

Licensed under the MIT License. See [LICENSE](./LICENSE) for details.
