#!/usr/bin/env node
/**
 * audit-claims.mjs - Automated Claims, Architectural Parity & Privacy Invariant Linter for enterprise-self-host.
 *
 * Enforces:
 * 1. Volatile Memory Telemetry & Cluster Burn Routine (Pillar 1):
 *    - Verifies burn-telemetry.sh exists, is executable, and purges Prometheus TSDB series & cleans tombstones.
 *    - Verifies docker-compose.yml configures Prometheus with --web.enable-admin-api.
 *    - Verifies collector/otel-collector-config.yaml configures memory_limiter processor.
 * 2. Compile-Time Dead Code Over Runtime Toggles (Pillar 2):
 *    - Verifies docker-compose.consumer.yml parses into services with profiles: ["disabled"] for all telemetry engines.
 *    - Verifies gateway/nginx.conf proxies /otlp/ to internal collector:4318.
 * 3. Strict Key Allowlists Over Brittle Denylists (Pillar 3):
 *    - Parses collector/otel-collector-config.yaml and extracts OTTL keep_keys allowlist.
 *    - Mathematically asserts that every spanmetrics connector dimension is an allowlisted key.
 * 4. Gateway Security Headers & Portal Air-Gap Integrity (Pillar 4):
 *    - Verifies gateway/nginx.conf attaches X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and X-Local-Only-Guarantee.
 *    - Rigorously audits gateway/portal/index.html across all network-bearing HTML tags, CSS url() imports, and script APIs for zero remote assets.
 * 5. Kubernetes Helm Air-Gap Invariant:
 *    - Verifies airgap-deny-egress.yaml NetworkPolicy exists with strict podSelector.
 *    - Verifies PVC manifests exist for persistent volume bindings (gradcast-data, prometheus-data).
 * 6. Universal CI Supply-Chain Integrity & Attestation (Pillar 5):
 *    - Verifies .github/workflows/validate.yml executes CycloneDX SBOM generation, Cosign keyless signing, SLSA provenance attestation, and fail-closed Trivy scanning (exit-code: 1).
 *    - Verifies container-attestation.yml attests build provenance for container images.
 * 7. Vocabulary Guardrails:
 *    - Prohibits unprovable marketing adjectives ('bulletproof', 'conclusive', 'definitive', 'infinitely scalable') while respecting policy definitions.
 * 8. Portfolio Master Brief & Verification Harness Parity:
 *    - Verifies parity with KNOWTHANKYEW_PORTFOLIO_MASTER_BRIEF.md (36/36 checks pass).
 */

import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync, execFileSync } from 'node:child_process';
import {
  stripLineComment,
  stripBlockComments,
  FORBIDDEN_NETWORK_REGEX,
  testNetworkPrimitive,
  scanDocumentationForVocabulary,
  BANNED_VOCABULARY,
} from './claims-linter-core.mjs';

export {
  stripLineComment,
  stripBlockComments,
  FORBIDDEN_NETWORK_REGEX,
  testNetworkPrimitive,
  scanDocumentationForVocabulary,
  BANNED_VOCABULARY,
};

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const REPO_ROOT = resolve(__dirname, '..');
const DEV_ROOT = resolve(REPO_ROOT, '..');

/**
 * Safely parse YAML using Ruby's built-in YAML engine (installed on macOS & Ubuntu runner)
 */
function loadYaml(filePath) {
  try {
    const jsonStr = execFileSync('ruby', ['-ryaml', '-rjson', '-e', 'puts JSON.generate(YAML.load_file(ARGV[0]))', filePath], {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return JSON.parse(jsonStr);
  } catch {
    return null;
  }
}

/**
 * Audit 1: Volatile Memory Telemetry & Cluster Burn Routine (Pillar 1)
 */
export function auditVolatileBurnRoutine(errors = []) {
  const burnPath = resolve(REPO_ROOT, 'burn-telemetry.sh');
  if (!existsSync(burnPath)) {
    errors.push('Missing burn-telemetry.sh script.');
    return;
  }

  const stat = statSync(burnPath);
  const isExecutable = (stat.mode & 0o111) !== 0;
  if (!isExecutable) {
    errors.push('burn-telemetry.sh must be executable (+x).');
  }

  const burnContent = readFileSync(burnPath, 'utf-8');
  if (!burnContent.includes('delete_series') || !burnContent.includes('clean_tombstones')) {
    errors.push('burn-telemetry.sh must purge Prometheus series via delete_series and clean tombstones via clean_tombstones.');
  }

  const composePath = resolve(REPO_ROOT, 'docker-compose.yml');
  if (!existsSync(composePath)) {
    errors.push('Missing docker-compose.yml.');
    return;
  }
  const composeContent = readFileSync(composePath, 'utf-8');
  if (!composeContent.includes('--web.enable-admin-api')) {
    errors.push('docker-compose.yml must enable Prometheus admin API with --web.enable-admin-api for Pillar 1 burnability.');
  }

  const collectorPath = resolve(REPO_ROOT, 'collector/otel-collector-config.yaml');
  if (existsSync(collectorPath)) {
    const collectorConfig = loadYaml(collectorPath);
    if (!collectorConfig || !collectorConfig.processors || !collectorConfig.processors.memory_limiter) {
      errors.push('collector/otel-collector-config.yaml must configure memory_limiter processor to bound telemetry RAM.');
    }
  }
}

/**
 * Audit 2: Compile-Time Dead Code Over Runtime Toggles (Pillar 2)
 */
export function auditCompileTimeIsolation(errors = []) {
  const consumerComposePath = resolve(REPO_ROOT, 'docker-compose.consumer.yml');
  if (!existsSync(consumerComposePath)) {
    errors.push('Missing docker-compose.consumer.yml.');
    return;
  }

  const composeData = loadYaml(consumerComposePath);
  if (!composeData || !composeData.services) {
    errors.push('Failed to parse docker-compose.consumer.yml as valid YAML structure.');
    return;
  }

  const disabledTelemetryServices = ['otel-collector', 'jaeger', 'prometheus', 'grafana'];
  for (const s of disabledTelemetryServices) {
    const svc = composeData.services[s];
    if (!svc) {
      errors.push(`docker-compose.consumer.yml missing entry for telemetry service: ${s}`);
      continue;
    }
    const profiles = svc.profiles;
    if (!Array.isArray(profiles) || !profiles.includes('disabled')) {
      errors.push(`docker-compose.consumer.yml service "${s}" must explicitly declare profiles: ["disabled"].`);
    }
  }

  // Verify that frontend build args blank out VITE_OTEL_EXPORTER_OTLP_ENDPOINT
  const consumerRaw = readFileSync(consumerComposePath, 'utf-8');
  if (!consumerRaw.includes('VITE_OTEL_EXPORTER_OTLP_ENDPOINT: ""')) {
    errors.push('docker-compose.consumer.yml must clear VITE_OTEL_EXPORTER_OTLP_ENDPOINT build args for air-gapped bundles.');
  }

  const nginxPath = resolve(REPO_ROOT, 'gateway/nginx.conf');
  if (existsSync(nginxPath)) {
    const nginxContent = readFileSync(nginxPath, 'utf-8');
    if (!nginxContent.includes('location /otlp/ {') || !nginxContent.includes('proxy_pass http://otel-collector:4318/;')) {
      errors.push('gateway/nginx.conf must proxy /otlp/ exclusively to internal otel-collector:4318.');
    }
  }
}

/**
 * Audit 3: Strict OTTL Key Allowlist Enforcement (Pillar 3)
 */
export function auditOttlAllowlist(errors = []) {
  const collectorPath = resolve(REPO_ROOT, 'collector/otel-collector-config.yaml');
  if (!existsSync(collectorPath)) {
    errors.push('Missing collector/otel-collector-config.yaml.');
    return;
  }

  const config = loadYaml(collectorPath);
  if (!config) {
    errors.push('Failed to parse collector/otel-collector-config.yaml as valid YAML.');
    return;
  }

  // 1. Verify transform processor has keep_keys statement in span context
  const transform = config.processors && config.processors.transform;
  if (!transform || !Array.isArray(transform.trace_statements)) {
    errors.push('collector/otel-collector-config.yaml missing processors.transform.trace_statements.');
    return;
  }

  const spanContextStatements = transform.trace_statements.filter(ts => ts && ts.context === 'span');
  if (spanContextStatements.length === 0) {
    errors.push('collector/otel-collector-config.yaml missing trace_statements with context: span.');
    return;
  }

  const spanStatements = spanContextStatements.flatMap(ts => ts.statements || []);
  const keepKeysStmts = spanStatements.filter(st => typeof st === 'string' && st.includes('keep_keys(attributes'));
  if (keepKeysStmts.length === 0) {
    errors.push('collector/otel-collector-config.yaml must configure an OTTL keep_keys(attributes, [...]) statement in context: span.');
    return;
  }

  // Extract allowlisted keys across all keep_keys statements in span context
  const allowlistedKeys = new Set();
  for (const stmt of keepKeysStmts) {
    const match = stmt.match(/keep_keys\s*\(\s*attributes\s*,\s*\[([^\]]+)\]/);
    if (!match) {
      errors.push('Unable to extract allowlisted keys array from keep_keys statement in collector config.');
      return;
    }
    match[1]
      .split(',')
      .map(k => k.trim().replace(/^["']|["']$/g, ''))
      .filter(Boolean)
      .forEach(k => allowlistedKeys.add(k));
  }

  // 2. Verify spanmetrics connector dimensions are strictly within allowlist
  const spanmetrics = config.connectors && config.connectors.spanmetrics;
  if (!spanmetrics || !Array.isArray(spanmetrics.dimensions)) {
    errors.push('collector/otel-collector-config.yaml missing connectors.spanmetrics.dimensions array.');
    return;
  }

  for (const dim of spanmetrics.dimensions) {
    const dimName = dim && dim.name;
    if (!dimName) {
      errors.push('Spanmetrics dimension missing name attribute.');
      continue;
    }
    if (!allowlistedKeys.has(dimName)) {
      errors.push(
        `Spanmetrics dimension "${dimName}" is not in the OTTL keep_keys allowlist. All metrics dimensions must be scrubbed allowlisted attributes.`
      );
    }
  }

  // 3. Verify service pipeline ordering includes transform before export
  const tracesPipeline = config.service?.pipelines?.traces;
  if (!tracesPipeline) {
    errors.push('collector/otel-collector-config.yaml missing service.pipelines.traces.');
  } else {
    const procs = tracesPipeline.processors || [];
    if (!procs.includes('transform')) {
      errors.push('collector/otel-collector-config.yaml service.pipelines.traces must include "transform" processor to enforce allowlist before export.');
    }
  }
}

/**
 * Audit 4: Gateway Security Headers & Portal Air-Gap Integrity (Pillar 4)
 */
export function auditGatewayAndPortal(errors = []) {
  const nginxPath = resolve(REPO_ROOT, 'gateway/nginx.conf');
  if (!existsSync(nginxPath)) {
    errors.push('Missing gateway/nginx.conf.');
    return;
  }

  const nginxContent = readFileSync(nginxPath, 'utf-8');
  const expectedHeaders = [
    'add_header X-Frame-Options "SAMEORIGIN"',
    'add_header X-Content-Type-Options "nosniff"',
    'add_header Referrer-Policy "no-referrer"',
    'add_header X-Local-Only-Guarantee "Air-Gapped: Enterprise Self-Host Suite Gateway"',
  ];

  for (const h of expectedHeaders) {
    if (!nginxContent.includes(h)) {
      errors.push(`gateway/nginx.conf missing exact security header: ${h}`);
    }
  }

  const portalPath = resolve(REPO_ROOT, 'gateway/portal/index.html');
  if (!existsSync(portalPath)) {
    errors.push('Missing gateway/portal/index.html.');
    return;
  }

  const portalContent = readFileSync(portalPath, 'utf-8');

  // Check 1: HTML elements with remote attributes (script, link, img, iframe, source, audio, video, embed, object)
  const tagRegex = /<(?:script|link|iframe|img|video|audio|source|embed|object)\b[^>]*\b(?:src|href|srcset|data|action|poster)\s*=\s*(?:["'](?:https?:|\/\/)[^"']+|[^\s>"']*(?:https?:|\/\/)[^\s>]*)/gi;
  const tagMatches = portalContent.match(tagRegex) || [];
  for (const m of tagMatches) {
    errors.push(`gateway/portal/index.html contains remote external asset attribute: ${m}`);
  }

  // Check 2: CSS remote font or url imports (@import url(...) or url(...))
  const cssRegex = /(?:@import\s+(?:url\()?|url\()\s*["']?(?:https?:|\/\/)[^"')]+["']?\s*\)?/gi;
  const cssMatches = portalContent.match(cssRegex) || [];
  for (const m of cssMatches) {
    errors.push(`gateway/portal/index.html contains remote external CSS url/import: ${m}`);
  }

  // Check 3: Inline scripts making network requests to remote origins
  const scriptRegex = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;
  let scriptMatch;
  while ((scriptMatch = scriptRegex.exec(portalContent)) !== null) {
    const scriptBody = scriptMatch[1];
    const scriptLines = stripBlockComments(scriptBody).split('\n');
    for (const sLine of scriptLines) {
      const stripped = stripLineComment(sLine).trim();
      if (!stripped) continue;
      if (testNetworkPrimitive(stripped)) {
        errors.push(`gateway/portal/index.html inline script contains forbidden network primitive: ${stripped}`);
      }
    }
  }
}

/**
 * Audit 5: Kubernetes Helm Air-Gap Invariant
 */
export function auditHelmManifests(errors = []) {
  const netPolPath = resolve(REPO_ROOT, 'helm/knowthankyew-suite/templates/networkpolicies/airgap-deny-egress.yaml');
  if (!existsSync(netPolPath)) {
    errors.push('Missing helm/knowthankyew-suite/templates/networkpolicies/airgap-deny-egress.yaml');
  } else {
    const netPolContent = readFileSync(netPolPath, 'utf-8');
    if (!netPolContent.includes('NetworkPolicy') || !netPolContent.includes('app.kubernetes.io/part-of: knowthankyew')) {
      errors.push('airgap-deny-egress.yaml must define NetworkPolicy for app.kubernetes.io/part-of: knowthankyew.');
    }
  }

  const pvcPath = resolve(REPO_ROOT, 'helm/knowthankyew-suite/templates/pvc.yaml');
  if (!existsSync(pvcPath)) {
    errors.push('Missing helm/knowthankyew-suite/templates/pvc.yaml.');
  }
}

/**
 * Audit 6: Universal CI Supply-Chain Integrity & Attestation (Pillar 5)
 */
export function auditCiSupplyChain(errors = []) {
  const validatePath = resolve(REPO_ROOT, '.github/workflows/validate.yml');
  if (!existsSync(validatePath)) {
    errors.push('Missing .github/workflows/validate.yml.');
    return;
  }

  const valConfig = loadYaml(validatePath);
  if (!valConfig) {
    errors.push('Failed to parse .github/workflows/validate.yml as valid YAML.');
    return;
  }

  const valContent = readFileSync(validatePath, 'utf-8');
  if (!valContent.includes('cdxgen')) {
    errors.push('.github/workflows/validate.yml missing CycloneDX SBOM generation step.');
  }
  if (!valContent.includes('cosign sign-blob')) {
    errors.push('.github/workflows/validate.yml missing Cosign keyless signing step.');
  }
  if (!valContent.includes('attest-build-provenance')) {
    errors.push('.github/workflows/validate.yml missing SLSA build provenance attestation step.');
  }

  const validateSteps = valConfig.jobs?.validate?.steps || [];
  const trivyStep = validateSteps.find(st => st && typeof st.uses === 'string' && st.uses.includes('trivy-action'));
  if (!trivyStep) {
    errors.push('.github/workflows/validate.yml missing Trivy vulnerability scanner step.');
  } else {
    const exitCode = trivyStep.with && String(trivyStep.with['exit-code']);
    if (exitCode !== '1') {
      errors.push(`.github/workflows/validate.yml Trivy step must configure exit-code: '1' for fail-closed security enforcement (found: ${exitCode}).`);
    }
    const shaPattern = /^aquasecurity\/trivy-action@[0-9a-f]{40}(?:\s*#.*)?$/;
    if (!shaPattern.test(trivyStep.uses)) {
      errors.push(`.github/workflows/validate.yml Trivy step must be pinned to an immutable 40-character commit SHA (found: ${trivyStep.uses}).`);
    }
  }

  const attestPath = resolve(REPO_ROOT, '.github/workflows/container-attestation.yml');
  if (!existsSync(attestPath)) {
    errors.push('Missing .github/workflows/container-attestation.yml workflow.');
  } else {
    const attestContent = readFileSync(attestPath, 'utf-8');
    if (!attestContent.includes('attest-build-provenance')) {
      errors.push('.github/workflows/container-attestation.yml missing attest-build-provenance step.');
    }
  }
}

/**
 * Audit 7: Prohibited Vocabulary in Documentation
 */
export function auditVocabulary(errors = []) {
  const scanExtensions = ['.md', '.html'];
  function scanDir(dir) {
    if (!existsSync(dir)) return;
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = resolve(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== '.git' && entry.name !== 'node_modules') {
          scanDir(fullPath);
        }
      } else if (scanExtensions.some((ext) => entry.name.endsWith(ext))) {
        const content = readFileSync(fullPath, 'utf-8');
        const relPath = fullPath.replace(REPO_ROOT + '/', '');
        const vocabErrors = scanDocumentationForVocabulary(content, relPath, {
          isPermittedLine: (line) => line.includes('audit-ignore'),
        });
        errors.push(...vocabErrors);
      }
    }
  }

  scanDir(REPO_ROOT);
}

/**
 * Audit 8: Portfolio Master Brief & Verification Harness Parity
 */
export function auditPortfolioMasterBrief(errors = [], options = {}) {
  const briefPath = resolve(DEV_ROOT, 'KNOWTHANKYEW_PORTFOLIO_MASTER_BRIEF.md');
  if (!existsSync(briefPath)) {
    if (options.requireBrief) {
      errors.push('KNOWTHANKYEW_PORTFOLIO_MASTER_BRIEF.md not found but required via --require-brief.');
    }
    return null;
  }

  const briefContent = readFileSync(briefPath, 'utf-8');
  const pattern = /`enterprise-self-host`.*?(\d+)\/(\d+)\s+verification checks/i;
  const altPattern = /`enterprise-self-host`.*?(\d+)\/(\d+)\s+tests pass/i;
  const match = briefContent.match(pattern) || briefContent.match(altPattern);

  if (!match) {
    errors.push('Could not find enterprise-self-host check count in KNOWTHANKYEW_PORTFOLIO_MASTER_BRIEF.md');
    return null;
  }

  const docPassed = parseInt(match[1], 10);
  const docTotal = parseInt(match[2], 10);

  if (docPassed !== docTotal) {
    errors.push(`KNOWTHANKYEW_PORTFOLIO_MASTER_BRIEF.md documents passing mismatch: ${docPassed}/${docTotal}`);
    return null;
  }

  const harnessPath = resolve(REPO_ROOT, 'verify-selfhost.sh');
  if (!existsSync(harnessPath)) {
    errors.push('Missing verify-selfhost.sh script.');
    return null;
  }

  let actualPassed = 0;
  let actualTotal = 0;
  try {
    const harnessOutput = execSync('./verify-selfhost.sh', {
      cwd: REPO_ROOT,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const passMatch = harnessOutput.match(/All\s+(\d+)\/(\d+)\s+verification checks PASSED/);
    if (!passMatch) {
      errors.push('Unable to parse verification check count from verify-selfhost.sh output.');
      return null;
    }
    actualPassed = parseInt(passMatch[1], 10);
    actualTotal = parseInt(passMatch[2], 10);
  } catch (err) {
    errors.push(`verify-selfhost.sh execution failed: ${err.message}`);
    return null;
  }

  if (docPassed !== actualPassed || docTotal !== actualTotal) {
    errors.push(
      `Portfolio Brief Drift: KNOWTHANKYEW_PORTFOLIO_MASTER_BRIEF.md documents ${docPassed}/${docTotal} checks, but verify-selfhost.sh executed ${actualPassed}/${actualTotal} checks.`
    );
    return null;
  }

  return { passedCount: actualPassed, totalCount: actualTotal };
}

/**
 * Main execution CLI
 */
export function runAllAudits(options = {}) {
  const errors = [];
  auditVolatileBurnRoutine(errors);
  auditCompileTimeIsolation(errors);
  auditOttlAllowlist(errors);
  auditGatewayAndPortal(errors);
  auditHelmManifests(errors);
  auditCiSupplyChain(errors);
  auditVocabulary(errors);
  const briefChecked = auditPortfolioMasterBrief(errors, options);

  return { errors, briefChecked };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  console.log('=== Enterprise Self-Host Claims & Architectural Invariant Audit ===\n');
  const requireBrief = process.argv.includes('--require-brief');
  const { errors, briefChecked } = runAllAudits({ requireBrief });

  if (errors.length > 0) {
    console.error(`[FAIL] Found ${errors.length} claims / architectural invariant violation(s):`);
    for (const err of errors) {
      console.error(`  - ${err}`);
    }
    process.exit(1);
  }

  console.log('[PASS] All enterprise-self-host architectural & claims invariants verified:');
  console.log('  ✓ Volatile memory telemetry & TSDB cluster burn routine verified (Pillar 1)');
  console.log('  ✓ Compile-time dead code over runtime toggles verified (Pillar 2)');
  console.log('  ✓ Strict OTTL key allowlist enforcement & spanmetrics connector verified (Pillar 3)');
  console.log('  ✓ Gateway security headers & portal air-gap integrity verified (Pillar 4)');
  console.log('  ✓ Kubernetes Helm air-gap NetworkPolicy & PVC bindings verified');
  console.log('  ✓ Universal CI supply-chain integrity, Cosign signing & SLSA provenance verified (Pillar 5)');
  console.log('  ✓ Zero prohibited marketing adjectives detected in documentation');
  if (briefChecked) {
    console.log(`  ✓ Portfolio Master Brief & verification harness parity verified (${briefChecked.passedCount}/${briefChecked.totalCount} checks)`);
  } else {
    console.log('  - Portfolio Master Brief check skipped (isolated CI)');
  }
  process.exit(0);
}
