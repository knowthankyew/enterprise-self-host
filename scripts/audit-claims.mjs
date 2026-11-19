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
 *    - Verifies parity with KNOWTHANKYEW_PORTFOLIO_MASTER_BRIEF.md (verified harness count).
 */

import {
  readFileSync,
  readdirSync,
  existsSync,
  statSync,
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  chmodSync,
  symlinkSync,
  rmSync,
} from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
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

export const CANONICAL_COLLECTOR_RESOURCE_KEYS = new Set([
  'deployment.environment',
  'service.instance.id',
  'service.name',
  'service.namespace',
  'service.version',
  'telemetry.sdk.language',
  'telemetry.sdk.name',
  'telemetry.sdk.version',
]);

export const CANONICAL_COLLECTOR_ALLOWED_KEYS = new Set([
  'action',
  'adapter_path',
  'adapter_size_bytes',
  'audit.allowlist_enforced',
  'audit.collector_verified',
  'audit_status',
  'base_model',
  'char_count',
  'charity_eligible',
  'clause_count',
  'current_step',
  'dataset_hash',
  'dataset_relative_path',
  'device',
  'discount_percent',
  'discrepancy_count',
  'duration_ms',
  'duration_sec',
  'error_code',
  'error_type',
  'exchange',
  'flagged_clauses',
  'flagged_count',
  'has_balance_due',
  'has_deductions',
  'has_illegal_tie_in',
  'has_implied_disclaimer',
  'has_income_verified',
  'has_itemized_breakdown',
  'has_overtime',
  'howso.cases.ablated_count',
  'howso.cases.anomalous_count',
  'howso.cases.original_count',
  'howso.preflight.duration_ms',
  'howso.preflight.enabled',
  'howso.preflight.status',
  'http.method',
  'http.status_code',
  'is_compliant',
  'job_id',
  'jurisdiction',
  'line_count',
  'loss',
  'matched_violations',
  'ocr_used',
  'overtime_hours',
  'parsed_line_count',
  'product_category',
  'product_type',
  'progress_pct',
  'protection_score',
  'redflag_count',
  'regular_hours',
  'risk_level',
  'routing_key',
  'rule_id',
  'rule_ids',
  'score_percentage',
  'service',
  'service.name',
  'sidecar_active',
  'span.kind',
  'standard_count',
  'state',
  'status',
  'status.code',
  'statute_code',
  'step',
  'surprisal.cases.ablated_count',
  'surprisal.cases.anomalous_count',
  'surprisal.cases.original_count',
  'surprisal.preflight.duration_ms',
  'surprisal.preflight.enabled',
  'surprisal.preflight.status',
  'total_clauses',
  'total_steps',
  'unconditional_gift_triggered',
  'unenforceable_count',
  'unlawful_count',
  'violations_count',
  'warranty_type',
  'watch_count',
]);

const EXPECTED_TRACES_PROCESSORS = ['memory_limiter', 'filter/drop_noncompliant_traces', 'transform', 'batch'];
const EXPECTED_METRICS_PROCESSORS = [
  'memory_limiter',
  'transform/metrics_preflight',
  'filter/drop_noncompliant_metrics',
  'transform',
  'batch',
];

function checkExactProcessorSequence(procs, expectedSequence, pipelineId, labelPrefix, errors) {
  const unexpectedProcs = procs.filter(p => !expectedSequence.includes(String(p)));
  const exactMatch =
    procs.length === expectedSequence.length &&
    expectedSequence.every((p, idx) => procs[idx] === p);
  if (unexpectedProcs.length > 0 || !exactMatch) {
    errors.push(
      `${labelPrefix} service.pipelines.${pipelineId} must use only reviewed processors in exact order [${expectedSequence.join(', ')}] with zero unreviewed or post-transform processors.`
    );
  }
}

/**
 * Safely parse YAML using Ruby's built-in YAML engine (installed on macOS & Ubuntu runner)
 */
function loadYamlFromString(yamlText) {
  try {
    const jsonStr = execFileSync(
      'ruby',
      ['-ryaml', '-rjson', '-e', 'puts JSON.generate(YAML.safe_load(STDIN.read))'],
      {
        input: yamlText,
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
      }
    );
    return JSON.parse(jsonStr);
  } catch {
    return null;
  }
}

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
export function auditBurnTelemetryScript(burnContent, errors = []) {
  if (!burnContent.includes('delete_series') || !burnContent.includes('clean_tombstones')) {
    errors.push('burn-telemetry.sh must purge Prometheus series via delete_series and clean tombstones via clean_tombstones.');
  }
  const isLoopbackHostname = hostname => {
    const h = String(hostname || '').toLowerCase();
    return h === '127.0.0.1' || h === 'localhost' || h === '::1' || h === '[::1]';
  };
  const extractLastCurlMaxTimeSeconds = lineOrArgs => {
    let last;
    if (Array.isArray(lineOrArgs)) {
      for (let i = 0; i < lineOrArgs.length; i += 1) {
        const arg = lineOrArgs[i];
        if ((arg === '-m' || arg === '--max-time') && i + 1 < lineOrArgs.length) {
          last = lineOrArgs[i + 1];
          i += 1;
        } else if (arg.startsWith('--max-time=')) {
          last = arg.slice('--max-time='.length);
        } else if (arg.startsWith('-m') && arg.length > 2) {
          last = arg.slice(2);
        }
      }
    } else {
      const matches = [...lineOrArgs.matchAll(/(?:^|\s)(?:--max-time(?:=|\s+)|-m(?:=|\s*)?)([^\s'"]+)/g)];
      if (matches.length > 0) {
        last = matches[matches.length - 1][1];
      }
    }
    if (last === undefined || !/^\d+(?:\.\d+)?$/.test(last)) return null;
    const parsed = Number(last);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
  };
  const extractLastCurlNoproxy = args => {
    let last;
    for (let i = 0; i < args.length; i += 1) {
      const arg = args[i];
      if (arg === '--noproxy' && i + 1 < args.length) {
        last = args[i + 1];
        i += 1;
      } else if (arg.startsWith('--noproxy=')) {
        last = arg.slice('--noproxy='.length);
      }
    }
    return last;
  };
  const hasEffectiveCurlFail = args => {
    let effectiveFail = false;
    for (const arg of args) {
      if (arg === '--') break;
      if (arg === '--fail' || arg === '--fail-with-body') {
        effectiveFail = true;
      } else if (arg === '--no-fail' || arg === '--no-fail-with-body') {
        effectiveFail = false;
      } else if (/^-[fsSLkviI046]*f[fsSLkviI046]*$/.test(arg)) {
        effectiveFail = true;
      }
    }
    return effectiveFail;
  };
  const extractLoopbackCurlUrls = args => {
    const urls = [];
    for (const arg of args) {
      if (/^https?:\/\//i.test(arg)) {
        try {
          const parsed = new URL(arg);
          if (isLoopbackHostname(parsed.hostname)) {
            urls.push(parsed);
          }
        } catch {
          // ignore malformed URL arguments
        }
      }
    }
    return urls;
  };
  const burnLines = burnContent.split('\n');
  let sawDeleteSeries = false;
  let sawCleanTombstones = false;
  for (const rawLine of burnLines) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    for (const curlCmd of trimmed.match(/\bcurl\b[^|;&\n]*/g) || []) {
      if (/(?:^|\s)(?:-H|--header)(?:=|\s|$)/.test(curlCmd) && /(?:Authorization|Bearer|GENESIS_(?:AUTH_)?TOKEN)/i.test(curlCmd)) {
        errors.push(`burn-telemetry.sh must pass Genesis Authorization via curl stdin (-K -), never via CLI header flags: ${curlCmd}`);
      } else if (/GENESIS_(?:AUTH_)?TOKEN/.test(curlCmd)) {
        errors.push(`burn-telemetry.sh must never pass Genesis auth token variables on the curl command line: ${curlCmd}`);
      }
    }
    if (/\bcurl\b/.test(trimmed) && /(?:localhost|127\.0\.0\.1|\[::1\])/.test(trimmed)) {
      if (!/--noproxy(?:=|\s+)(?:'\*'|"\*"|\*)/.test(trimmed)) {
        errors.push(`burn-telemetry.sh loopback curl command must bypass proxy env vars with --noproxy '*': ${trimmed}`);
      }
      if (extractLastCurlMaxTimeSeconds(trimmed) === null) {
        errors.push(`burn-telemetry.sh loopback curl command must set a finite positive timeout (--max-time <sec> > 0): ${trimmed}`);
      }
      if (/\|\|\s*true\b/.test(trimmed) || /2>\/dev\/null/.test(trimmed)) {
        errors.push(`burn-telemetry.sh curl command must not suppress failures with || true or 2>/dev/null: ${trimmed}`);
      }
    }
    if (/\bcurl\b/.test(trimmed) && (trimmed.includes('delete_series') || trimmed.includes('clean_tombstones'))) {
      if (trimmed.includes('delete_series')) sawDeleteSeries = true;
      if (trimmed.includes('clean_tombstones')) sawCleanTombstones = true;
      if (!/-fsS\b/.test(trimmed) || /--no-fail(?:-with-body)?\b/.test(trimmed) || /\|\|\s*true\b/.test(trimmed) || /2>\/dev\/null/.test(trimmed)) {
        errors.push(`burn-telemetry.sh Prometheus TSDB purge command must use -fsS without --no-fail or error suppression: ${trimmed}`);
      }
    }
  }
  if (!sawDeleteSeries || !sawCleanTombstones || !burnContent.includes('prom_rc=')) {
    errors.push('burn-telemetry.sh must track prom_rc failure status across Prometheus delete_series and clean_tombstones.');
  }

  // Behavioral check: run a temporary sandboxed copy with stubbed docker & curl
  // failing delete_series and clean_tombstones separately so unconditional exits cannot pass.
  const sandboxDir = mkdtempSync(join(tmpdir(), 'kty-burn-audit-'));
  try {
    const binDir = join(sandboxDir, 'bin');
    mkdirSync(binDir, { recursive: true });

    const scriptPath = join(sandboxDir, 'burn-telemetry.sh');
    writeFileSync(scriptPath, burnContent, 'utf-8');
    chmodSync(scriptPath, 0o700);

    const dockerStub = `#!/usr/bin/env bash
if [ -n "\${KTY_MOCK_DOCKER_LOG_DIR:-}" ] && [ "\${1:-}" != "ps" ]; then
  seq_file="\${KTY_MOCK_DOCKER_LOG_DIR}/.seq"
  n=$(cat "$seq_file" 2>/dev/null || echo 0)
  n=$((n + 1))
  printf '%s' "$n" > "$seq_file"
  call_file="\${KTY_MOCK_DOCKER_LOG_DIR}/docker.$(printf '%06d' "$n")"
  printf '%s\\0' "$@" > "$call_file"
fi
if [ -n "\${KTY_MOCK_DOCKER_TRACE_FILE:-}" ] && [ "\${1:-}" != "ps" ]; then
  printf '%s:%s:%s\\n' "\${KTY_BURN_TRACE_TAG:-main}" "\${1:-}" "\${2:-}" >> "\${KTY_MOCK_DOCKER_TRACE_FILE}"
fi
if [ -n "\${KTY_MOCK_EVENT_LOG:-}" ] && [ "\${1:-}" != "ps" ]; then
  printf 'docker\\t%s\\t%s\\n' "\${1:-}" "\${2:-}" >> "\${KTY_MOCK_EVENT_LOG}"
fi
if [ -n "\${KTY_MOCK_DOCKER_SLEEP:-}" ] && [ "\${1:-}" = "restart" ] && [ "\${2:-}" = "kty-jaeger" ]; then
  sleep "$KTY_MOCK_DOCKER_SLEEP"
fi
if [ "\${1:-}" = "ps" ]; then
  if [ "\${KTY_MOCK_DOCKER_PS_FAIL:-0}" = "1" ]; then
    echo "mock docker daemon unreachable" >&2
    exit 1
  fi
  for c in kty-jaeger kty-otel-collector kty-prometheus kty-genesis kty-gradcast kty-mail-stripper kty-ftaas-api kty-ftaas-worker kty-surprisal; do
    case ",\${KTY_MOCK_DOCKER_STOPPED:-}," in
      *",$c,"*) ;;
      *) printf '%s\\n' "$c" ;;
    esac
  done
  exit 0
fi
if [ "\${1:-}" = "inspect" ]; then
  printf 'prom/prometheus:v3.1.0\\n'
  exit 0
fi
if [ "\${1:-}" = "run" ] && [ "\${KTY_MOCK_DOCKER_FAIL_ACTION:-}" = "run" ]; then
  for arg in "$@"; do
    if [ "$arg" = "\${KTY_MOCK_DOCKER_FAIL_TARGET:-__none__}" ]; then
      exit 1
    fi
  done
fi
if ( [ "\${1:-}" = "restart" ] || [ "\${1:-}" = "stop" ] || [ "\${1:-}" = "start" ] ) && [ "\${2:-}" = "\${KTY_MOCK_DOCKER_FAIL_TARGET:-__none__}" ] && { [ -z "\${KTY_MOCK_DOCKER_FAIL_ACTION:-}" ] || [ "\${1:-}" = "\${KTY_MOCK_DOCKER_FAIL_ACTION}" ]; }; then
  exit 1
fi
exit 0
`;
    const curlStub = `#!/usr/bin/env bash
if [ -n "\${KTY_MOCK_LOG_DIR:-}" ]; then
  seq_file="\${KTY_MOCK_LOG_DIR}/.seq"
  n=$(cat "$seq_file" 2>/dev/null || echo 0)
  n=$((n + 1))
  printf '%s' "$n" > "$seq_file"
  call_file="\${KTY_MOCK_LOG_DIR}/call.$(printf '%06d' "$n")"
  printf '%s\\0' "$@" > "$call_file"
  prev_is_k=0
  read_stdin_cfg=0
  for arg in "$@"; do
    if [ "$prev_is_k" = "1" ] && [ "$arg" = "-" ]; then
      read_stdin_cfg=1
    fi
    case "$arg" in
      -K|--config) prev_is_k=1 ;;
      -K-|--config=-) read_stdin_cfg=1; prev_is_k=0 ;;
      *) prev_is_k=0 ;;
    esac
  done
  if [ "$read_stdin_cfg" = "1" ]; then
    cat > "$call_file.stdin"
  fi
fi
if [ -n "\${KTY_MOCK_EVENT_LOG:-}" ]; then
  ev_line="curl"
  for arg in "$@"; do
    ev_line="\${ev_line}"$'\\t'"\${arg}"
  done
  printf '%s\\n' "$ev_line" >> "\${KTY_MOCK_EVENT_LOG}"
fi
for arg in "$@"; do
  case "$arg" in
    *"\${KTY_MOCK_FAIL_TARGET:-__none__}"*)
      exit 22
      ;;
  esac
done
exit 0
`;
    const readRecordedCallRecords = dir => {
      if (!existsSync(dir)) return [];
      return readdirSync(dir)
        .filter(file => !file.startsWith('.') && !file.endsWith('.stdin'))
        .sort()
        .map(file => {
          const stdinPath = join(dir, `${file}.stdin`);
          return {
            args: readFileSync(join(dir, file), 'utf-8').split('\0').slice(0, -1),
            stdin: existsSync(stdinPath) ? readFileSync(stdinPath, 'utf-8') : '',
          };
        });
    };
    const readRecordedCalls = dir => readRecordedCallRecords(dir).map(rec => rec.args);
    const hasCurlMethod = (args, method) => {
      const upperMethod = method.toUpperCase();
      let lastMethod = null;
      for (let i = 0; i < args.length; i += 1) {
        const arg = args[i];
        if ((arg === '-X' || arg === '--request') && i + 1 < args.length) {
          lastMethod = args[i + 1].toUpperCase();
          i += 1;
          continue;
        }
        const eqMatch = arg.match(/^(?:-X|--request=?)([A-Za-z]+)$/);
        if (eqMatch) {
          lastMethod = eqMatch[1].toUpperCase();
        }
      }
      return lastMethod === upperMethod;
    };
    const hasUrlEncodedDeleteSeriesSelector = (args, expected = 'match[]={__name__=~".+"}') => {
      for (let i = 0; i < args.length; i += 1) {
        const arg = args[i];
        if (arg === '--data-urlencode' && i + 1 < args.length && args[i + 1] === expected) {
          return true;
        }
        if (arg.startsWith('--data-urlencode=') && arg.slice('--data-urlencode='.length) === expected) {
          return true;
        }
        let rawVal = null;
        if ((arg === '-d' || arg === '--data' || arg === '--data-raw') && i + 1 < args.length) {
          rawVal = args[i + 1];
        } else if (arg.startsWith('-d') && arg.length > 2) {
          rawVal = arg.slice(2);
        } else {
          const longEq = arg.match(/^--data(?:-raw)?=(.*)$/);
          if (longEq) rawVal = longEq[1];
        }
        if (rawVal !== null && !rawVal.includes('+')) {
          try {
            if (decodeURIComponent(rawVal) === expected) return true;
          } catch {
            // ignore malformed percent encoding
          }
        }
      }
      return false;
    };

    writeFileSync(join(binDir, 'docker'), dockerStub, 'utf-8');
    chmodSync(join(binDir, 'docker'), 0o700);
    writeFileSync(join(binDir, 'curl'), curlStub, 'utf-8');
    chmodSync(join(binDir, 'curl'), 0o700);

    // Baseline pass (no failures injected): script must exit 0, create 0700 state dir, invoke endpoints, and honor Prometheus scrape-drain barrier.
    const okCallsDir = join(sandboxDir, 'ok-calls');
    const okDockerDir = join(sandboxDir, 'ok-docker');
    const okStateDir = join(sandboxDir, 'ok-burn-state');
    const okEventLog = join(sandboxDir, 'ok-events.log');
    mkdirSync(okCallsDir, { recursive: true });
    mkdirSync(okDockerDir, { recursive: true });
    let baselineOk = true;
    let baselineStdout = '';
    try {
      baselineStdout = execFileSync('bash', [scriptPath], {
        cwd: sandboxDir,
        env: {
          PATH: `${binDir}:${process.env.PATH || ''}`,
          GENESIS_AUTH_TOKEN: 'audit-test-token',
          KTY_MOCK_FAIL_TARGET: '__never_match__',
          KTY_MOCK_LOG_DIR: okCallsDir,
          KTY_MOCK_DOCKER_LOG_DIR: okDockerDir,
          KTY_MOCK_EVENT_LOG: okEventLog,
          KTY_BURN_STATE_DIR: okStateDir,
        },
        encoding: 'utf-8',
        stdio: 'pipe',
        timeout: 5000,
      });
    } catch {
      baselineOk = false;
    }
    const okCurlRecords = readRecordedCallRecords(okCallsDir);
    const okCalls = okCurlRecords.map(rec => rec.args);
    const okDockerCalls = readRecordedCalls(okDockerDir);
    const okEventLines = existsSync(okEventLog) ? readFileSync(okEventLog, 'utf-8').split('\n').filter(Boolean) : [];
    const PROM_READY_PATH = '/-/ready';
    const DELETE_SERIES_PATH = '/api/v1/admin/tsdb/delete_series';
    const CLEAN_TOMBSTONES_PATH = '/api/v1/admin/tsdb/clean_tombstones';
    const GENESIS_LOGS_PATH = '/logs';
    const promReadyCall = okCalls.find(args => extractLoopbackCurlUrls(args).some(u => u.pathname === PROM_READY_PATH));
    const deleteSeriesCall = okCalls.find(args => extractLoopbackCurlUrls(args).some(u => u.pathname === DELETE_SERIES_PATH));
    const cleanTombstonesCall = okCalls.find(args => extractLoopbackCurlUrls(args).some(u => u.pathname === CLEAN_TOMBSTONES_PATH));
    const genesisLogsRecord = okCurlRecords.find(rec => extractLoopbackCurlUrls(rec.args).some(u => u.pathname === GENESIS_LOGS_PATH));
    const genesisLogsCall = genesisLogsRecord?.args;
    const findDockerActionIdx = (action, target) => okDockerCalls.findIndex(args => args[0] === action && args[1] === target);
    for (const args of okCalls) {
      if (extractLoopbackCurlUrls(args).length > 0) {
        if (extractLastCurlMaxTimeSeconds(args) === null) {
          errors.push(`burn-telemetry.sh loopback curl call executed with missing or non-positive --max-time: ${args.join(' ')}`);
        }
        if (extractLastCurlNoproxy(args) !== '*') {
          errors.push(`burn-telemetry.sh loopback curl call effective --noproxy must be '*': ${args.join(' ')}`);
        }
        if (!hasEffectiveCurlFail(args)) {
          errors.push(`burn-telemetry.sh loopback curl call must effectively enable HTTP failure (-f/--fail without trailing --no-fail): ${args.join(' ')}`);
        }
      }
    }
    if (!baselineOk) {
      errors.push('burn-telemetry.sh exited non-zero when all purge endpoints succeeded.');
    } else {
      if (!promReadyCall) {
        errors.push('burn-telemetry.sh healthy control run did not invoke exact loopback path /-/ready before Prometheus TSDB purge.');
      }
      if (!deleteSeriesCall || !cleanTombstonesCall) {
        errors.push('burn-telemetry.sh healthy control run did not invoke exact loopback paths for delete_series and clean_tombstones.');
      } else {
        if (!hasCurlMethod(deleteSeriesCall, 'POST') || !hasUrlEncodedDeleteSeriesSelector(deleteSeriesCall, 'match[]={__name__=~".+"}')) {
          errors.push('burn-telemetry.sh delete_series call must send -X POST with URL-encoded selector --data-urlencode match[]={__name__=~".+"}.');
        }
        if (!hasCurlMethod(cleanTombstonesCall, 'POST')) {
          errors.push('burn-telemetry.sh clean_tombstones call must send -X POST.');
        }
      }
      if (!existsSync(okStateDir) || (statSync(okStateDir).mode & 0o777) !== 0o700) {
        errors.push('burn-telemetry.sh must create its private burn state directory with 0700 permissions.');
      }
      if (existsSync(join(okStateDir, 'prometheus-stopped'))) {
        errors.push('burn-telemetry.sh failed to clear prometheus-stopped state after successful WAL purge and readiness.');
      }
      if (burnContent.includes('/logs')) {
        if (!genesisLogsCall || !hasCurlMethod(genesisLogsCall, 'DELETE')) {
          errors.push('burn-telemetry.sh Genesis purge call must send -X DELETE to exact loopback path /logs.');
        } else {
          if (genesisLogsCall.some(arg => arg.includes('audit-test-token'))) {
            errors.push('burn-telemetry.sh leaked Genesis bearer token onto curl command-line argv; use curl -K - stdin config.');
          }
          const stdinLines = genesisLogsRecord.stdin.split('\n').filter(Boolean);
          if (
            stdinLines.length !== 1 ||
            !/^header\s*=\s*"Authorization:\s*Bearer\s+audit-test-token"\s*$/.test(stdinLines[0])
          ) {
            errors.push('burn-telemetry.sh Genesis purge call must pass Authorization: Bearer <token> via curl -K - stdin config.');
          }
        }
      }
      const collectorStopIdx = findDockerActionIdx('stop', 'kty-otel-collector');
      const collectorRestartIdx = findDockerActionIdx('restart', 'kty-otel-collector');
      const collectorStartIdx = findDockerActionIdx('start', 'kty-otel-collector');
      const jaegerRestartIdx = findDockerActionIdx('restart', 'kty-jaeger');
      if (collectorStopIdx === -1 && collectorRestartIdx === -1) {
        errors.push('burn-telemetry.sh healthy control run did not stop/reset kty-otel-collector.');
      }
      if (jaegerRestartIdx === -1) {
        errors.push('burn-telemetry.sh healthy control run did not invoke docker restart kty-jaeger.');
      }
      if (collectorRestartIdx !== -1 || collectorStopIdx === -1 || collectorStartIdx === -1) {
        errors.push('burn-telemetry.sh must stop kty-otel-collector before resetting storage and start it only after kty-jaeger completes restart.');
      } else {
        if (jaegerRestartIdx !== -1 && !(collectorStopIdx < jaegerRestartIdx && jaegerRestartIdx < collectorStartIdx)) {
          errors.push('burn-telemetry.sh must execute stop kty-otel-collector -> restart kty-jaeger -> start kty-otel-collector barrier so delayed exports cannot repopulate Jaeger.');
        }
        for (const producerSvc of ['kty-gradcast', 'kty-mail-stripper', 'kty-ftaas-api', 'kty-ftaas-worker', 'kty-surprisal']) {
          const producerRestartIdx = findDockerActionIdx('restart', producerSvc);
          if (producerRestartIdx === -1 || !(collectorStopIdx < producerRestartIdx && producerRestartIdx < collectorStartIdx)) {
            errors.push(`burn-telemetry.sh must restart running producer ${producerSvc} while kty-otel-collector is stopped so pre-burn SDK export queues cannot refill storage.`);
          }
        }
        const findEventDockerIdx = (action, target) => okEventLines.indexOf(`docker\t${action}\t${target}`);
        const findEventCurlIdx = pathname =>
          okEventLines.findIndex(
            line => line.startsWith('curl\t') && extractLoopbackCurlUrls(line.split('\t').slice(1)).some(u => u.pathname === pathname)
          );
        const findEventLastCurlIdx = pathname => {
          for (let idx = okEventLines.length - 1; idx >= 0; idx -= 1) {
            const line = okEventLines[idx];
            if (line.startsWith('curl\t') && extractLoopbackCurlUrls(line.split('\t').slice(1)).some(u => u.pathname === pathname)) {
              return idx;
            }
          }
          return -1;
        };
        const evStopIdx = findEventDockerIdx('stop', 'kty-otel-collector');
        const evPromDrainRestartIdx = findEventDockerIdx('restart', 'kty-prometheus');
        const evPromPreReadyIdx = findEventCurlIdx(PROM_READY_PATH);
        const evDeleteSeriesIdx = findEventCurlIdx(DELETE_SERIES_PATH);
        const evCleanTombstonesIdx = findEventCurlIdx(CLEAN_TOMBSTONES_PATH);
        const evPromStopIdx = findEventDockerIdx('stop', 'kty-prometheus');
        const evPromWalRunIdx = okEventLines.findIndex(line => line.startsWith('docker\trun\t'));
        const evPromStartIdx = findEventDockerIdx('start', 'kty-prometheus');
        const evPromPostReadyIdx = findEventLastCurlIdx(PROM_READY_PATH);
        const evStartIdx = findEventDockerIdx('start', 'kty-otel-collector');
        const evGenesisLogsIdx = findEventCurlIdx(GENESIS_LOGS_PATH);
        const promWalCleanCall = okDockerCalls.find(
          args =>
            args[0] === 'run' &&
            args.includes('--volumes-from') &&
            args.includes('kty-prometheus') &&
            args.some(a => /find\s+\/prometheus\b.*rm\s+-rf/.test(a))
        );
        if (
          evStopIdx === -1 ||
          evPromDrainRestartIdx === -1 ||
          evPromPreReadyIdx === -1 ||
          evDeleteSeriesIdx === -1 ||
          evCleanTombstonesIdx === -1 ||
          evPromStopIdx === -1 ||
          evPromWalRunIdx === -1 ||
          evPromStartIdx === -1 ||
          evPromPostReadyIdx === -1 ||
          evStartIdx === -1 ||
          !promWalCleanCall ||
          !(
            evStopIdx < evPromDrainRestartIdx &&
            evPromDrainRestartIdx < evPromPreReadyIdx &&
            evPromPreReadyIdx < evDeleteSeriesIdx &&
            evDeleteSeriesIdx < evCleanTombstonesIdx &&
            evCleanTombstonesIdx < evPromStopIdx &&
            evPromStopIdx < evPromWalRunIdx &&
            evPromWalRunIdx < evPromStartIdx &&
            evPromStartIdx < evPromPostReadyIdx &&
            evPromPostReadyIdx < evStartIdx
          )
        ) {
          errors.push(
            'burn-telemetry.sh must execute stop kty-otel-collector -> restart kty-prometheus -> wait /-/ready -> delete_series -> clean_tombstones -> stop kty-prometheus -> erase /prometheus WAL/chunks -> start kty-prometheus -> wait /-/ready -> start kty-otel-collector in one strict barrier order.'
          );
        }
        if (burnContent.includes('/logs') && (evGenesisLogsIdx === -1 || !(evStopIdx < evGenesisLogsIdx && evGenesisLogsIdx < evStartIdx))) {
          errors.push('burn-telemetry.sh must execute Genesis DELETE /logs while kty-otel-collector is stopped.');
        }
      }
      if (
        !baselineStdout.includes('Flushing and purging in-memory traces from Jaeger') ||
        !baselineStdout.includes('Flushing and resetting OpenTelemetry Collector buffers')
      ) {
        errors.push('burn-telemetry.sh healthy control run did not emit Jaeger and OTel Collector buffer-drain messages.');
      }
    }

    const curlTargets = burnContent.includes('/logs')
      ? [PROM_READY_PATH, DELETE_SERIES_PATH, CLEAN_TOMBSTONES_PATH, GENESIS_LOGS_PATH]
      : [PROM_READY_PATH, DELETE_SERIES_PATH, CLEAN_TOMBSTONES_PATH];
    for (const target of curlTargets) {
      const targetCallsDir = join(sandboxDir, `calls-${target.replace(/\W+/g, '')}`);
      mkdirSync(targetCallsDir, { recursive: true });
      let exitedNonZero = false;
      try {
        execFileSync('bash', [scriptPath], {
          cwd: sandboxDir,
          env: {
            PATH: `${binDir}:${process.env.PATH || ''}`,
            GENESIS_AUTH_TOKEN: 'audit-test-token',
            KTY_BURN_STATE_DIR: join(sandboxDir, `state-${target.replace(/\W+/g, '')}`),
            KTY_PROM_READY_MAX_WAIT: '2',
            KTY_MOCK_FAIL_TARGET: target,
            KTY_MOCK_LOG_DIR: targetCallsDir,
          },
          stdio: 'pipe',
          timeout: 5000,
        });
      } catch (err) {
        if (err && typeof err === 'object' && 'status' in err && Number(err.status) !== 0) {
          exitedNonZero = true;
        }
      }
      const targetCalls = readRecordedCalls(targetCallsDir);
      const invokedTarget = targetCalls.some(args => extractLoopbackCurlUrls(args).some(u => u.pathname === target));
      if (!invokedTarget) {
        errors.push(`burn-telemetry.sh did not execute ${target} curl call before exiting.`);
      } else if (!exitedNonZero) {
        errors.push(`burn-telemetry.sh exited 0 when ${target} failed; purge failures must exit non-zero.`);
      }
    }

    const dockerFailScenarios = [
      { name: 'kty-jaeger', target: 'kty-jaeger', action: '', checkRestoreAfterStop: true, requirePriorStop: false },
      { name: 'kty-prometheus', target: 'kty-prometheus', action: 'restart', checkRestoreAfterStop: true, requirePriorStop: false },
      {
        name: 'kty-prometheus-wal-purge',
        target: 'kty-prometheus',
        action: 'run',
        checkRestoreAfterStop: true,
        checkPromRestoreAfterStop: true,
        requirePriorStop: false,
      },
      { name: 'kty-ftaas-api', target: 'kty-ftaas-api', action: '', checkRestoreAfterStop: true, requirePriorStop: false },
      { name: 'kty-otel-collector', target: 'kty-otel-collector', action: '', checkRestoreAfterStop: false, requirePriorStop: false },
      { name: 'kty-otel-collector-start', target: 'kty-otel-collector', action: 'start', checkRestoreAfterStop: false, requirePriorStop: true },
    ];
    for (const scenario of dockerFailScenarios) {
      const dockerFailDir = join(sandboxDir, `docker-fail-${scenario.name}`);
      const dockerFailStateDir = join(sandboxDir, `docker-fail-state-${scenario.name}`);
      mkdirSync(dockerFailDir, { recursive: true });
      let restartExitedNonZero = false;
      try {
        execFileSync('bash', [scriptPath], {
          cwd: sandboxDir,
          env: {
            PATH: `${binDir}:${process.env.PATH || ''}`,
            GENESIS_AUTH_TOKEN: 'audit-test-token',
            KTY_BURN_STATE_DIR: dockerFailStateDir,
            KTY_MOCK_DOCKER_FAIL_TARGET: scenario.target,
            ...(scenario.action ? { KTY_MOCK_DOCKER_FAIL_ACTION: scenario.action } : {}),
            KTY_MOCK_DOCKER_LOG_DIR: dockerFailDir,
          },
          stdio: 'pipe',
          timeout: 5000,
        });
      } catch (err) {
        if (err && typeof err === 'object' && 'status' in err && Number(err.status) !== 0) {
          restartExitedNonZero = true;
        }
      }
      const restartCalls = readRecordedCalls(dockerFailDir);
      const stopCollectorIdx = restartCalls.findIndex(args => args[0] === 'stop' && args[1] === 'kty-otel-collector');
      const invokedDockerOp = scenario.action
        ? restartCalls.some(args => args[0] === scenario.action && (args[1] === scenario.target || args.includes(scenario.target)))
        : restartCalls.some(
            args => (args[0] === 'restart' || args[0] === 'stop' || args[0] === 'start') && args[1] === scenario.target
          );
      if (scenario.requirePriorStop) {
        const startAfterStopIdx = restartCalls.findIndex(
          (args, idx) => idx > stopCollectorIdx && args[0] === 'start' && args[1] === scenario.target
        );
        if (stopCollectorIdx === -1 || startAfterStopIdx === -1) {
          errors.push(`burn-telemetry.sh did not run docker stop then docker start on ${scenario.target} in ${scenario.name} test.`);
          continue;
        }
      }
      if (!invokedDockerOp) {
        errors.push(`burn-telemetry.sh did not invoke docker ${scenario.action || 'stop/restart'} on ${scenario.target} before exiting.`);
      } else if (!restartExitedNonZero) {
        errors.push(`burn-telemetry.sh exited 0 when docker ${scenario.action || 'operation'} on ${scenario.target} failed; failures must exit non-zero.`);
      }
      if (scenario.checkPromRestoreAfterStop) {
        const stopPromIdx = restartCalls.findIndex(args => args[0] === 'stop' && args[1] === 'kty-prometheus');
        const startPromAfterStopIdx = restartCalls.findIndex(
          (args, idx) => idx > stopPromIdx && args[0] === 'start' && args[1] === 'kty-prometheus'
        );
        if (stopPromIdx !== -1 && startPromAfterStopIdx === -1) {
          errors.push('burn-telemetry.sh failed to restore kty-prometheus (docker start) when WAL purge failed.');
        }
        if (!existsSync(join(dockerFailStateDir, 'prometheus-stopped'))) {
          errors.push('burn-telemetry.sh deleted prometheus-stopped state even though WAL purge failed.');
        }
      }
      if (scenario.checkRestoreAfterStop) {
        const startCollectorAfterStopIdx = restartCalls.findIndex(
          (args, idx) => idx > stopCollectorIdx && args[0] === 'start' && args[1] === 'kty-otel-collector'
        );
        if (stopCollectorIdx !== -1 && startCollectorAfterStopIdx === -1) {
          errors.push('burn-telemetry.sh failed to restore kty-otel-collector (docker start) when mid-burn step failed.');
        }
      }
    }

    // docker ps failures must abort cleanly non-zero before assuming containers are absent or stopping anything
    const psFailDockerDir = join(sandboxDir, 'docker-ps-fail');
    const psFailCallsDir = join(sandboxDir, 'curl-ps-fail');
    mkdirSync(psFailDockerDir, { recursive: true });
    mkdirSync(psFailCallsDir, { recursive: true });
    let psFailExitedNonZero = false;
    try {
      execFileSync('bash', [scriptPath], {
        cwd: sandboxDir,
        env: {
          PATH: `${binDir}:${process.env.PATH || ''}`,
          GENESIS_AUTH_TOKEN: 'audit-test-token',
          KTY_BURN_STATE_DIR: join(sandboxDir, 'ps-fail-state'),
          KTY_MOCK_DOCKER_PS_FAIL: '1',
          KTY_MOCK_DOCKER_LOG_DIR: psFailDockerDir,
          KTY_MOCK_LOG_DIR: psFailCallsDir,
        },
        stdio: 'pipe',
        timeout: 5000,
      });
    } catch (err) {
      if (err && typeof err === 'object' && 'status' in err && Number(err.status) !== 0) {
        psFailExitedNonZero = true;
      }
    }
    if (!psFailExitedNonZero || readRecordedCalls(psFailDockerDir).length > 0 || readRecordedCalls(psFailCallsDir).length > 0) {
      errors.push('burn-telemetry.sh must fail non-zero immediately when `docker ps` fails instead of silently skipping purges.');
    }

    if (burnContent.includes('/logs')) {
      const dotenvPath = join(sandboxDir, '.env');
      writeFileSync(dotenvPath, 'GENESIS_AUTH_TOKEN=dotenv-stale-token\n', 'utf-8');
      try {
        // Caller-exported token must beat .env (Docker Compose precedence)
        const overrideCallsDir = join(sandboxDir, 'override-calls');
        const overrideDockerDir = join(sandboxDir, 'override-docker');
        mkdirSync(overrideCallsDir, { recursive: true });
        mkdirSync(overrideDockerDir, { recursive: true });
        let overrideOk = true;
        try {
          execFileSync('bash', [scriptPath], {
            cwd: sandboxDir,
            env: {
              PATH: `${binDir}:${process.env.PATH || ''}`,
              GENESIS_AUTH_TOKEN: 'caller-override-token',
              KTY_BURN_STATE_DIR: join(sandboxDir, 'override-state'),
              KTY_MOCK_LOG_DIR: overrideCallsDir,
              KTY_MOCK_DOCKER_LOG_DIR: overrideDockerDir,
            },
            stdio: 'pipe',
            timeout: 5000,
          });
        } catch {
          overrideOk = false;
        }
        const overrideGenesisRec = readRecordedCallRecords(overrideCallsDir).find(rec =>
          extractLoopbackCurlUrls(rec.args).some(u => u.pathname === GENESIS_LOGS_PATH)
        );
        if (
          !overrideOk ||
          !overrideGenesisRec ||
          !/^header\s*=\s*"Authorization:\s*Bearer\s+caller-override-token"\s*$/m.test(overrideGenesisRec.stdin)
        ) {
          errors.push('burn-telemetry.sh .env file must not override caller-exported GENESIS_AUTH_TOKEN.');
        }

        // Caller explicit empty token must fail closed BEFORE stopping OTel Collector
        const emptyDockerDir = join(sandboxDir, 'empty-docker');
        mkdirSync(emptyDockerDir, { recursive: true });
        let emptyFailedClosed = false;
        try {
          execFileSync('bash', [scriptPath], {
            cwd: sandboxDir,
            env: {
              PATH: `${binDir}:${process.env.PATH || ''}`,
              GENESIS_AUTH_TOKEN: '',
              KTY_BURN_STATE_DIR: join(sandboxDir, 'empty-state'),
              KTY_MOCK_DOCKER_LOG_DIR: emptyDockerDir,
            },
            stdio: 'pipe',
            timeout: 5000,
          });
        } catch (err) {
          if (err && typeof err === 'object' && 'status' in err && Number(err.status) !== 0) {
            emptyFailedClosed = true;
          }
        }
        const emptyDockerCalls = readRecordedCalls(emptyDockerDir);
        if (!emptyFailedClosed || emptyDockerCalls.some(args => args[0] === 'stop' && args[1] === 'kty-otel-collector')) {
          errors.push(
            'burn-telemetry.sh must fail closed on empty caller GENESIS_AUTH_TOKEN (without .env override or stopping kty-otel-collector).'
          );
        }

        // Single-backslash in caller token (e.g. abc\ndef) must also fail closed BEFORE stopping OTel Collector
        const backslashDockerDir = join(sandboxDir, 'backslash-docker');
        mkdirSync(backslashDockerDir, { recursive: true });
        let backslashFailedClosed = false;
        try {
          execFileSync('bash', [scriptPath], {
            cwd: sandboxDir,
            env: {
              PATH: `${binDir}:${process.env.PATH || ''}`,
              GENESIS_AUTH_TOKEN: 'abc\\ndef',
              KTY_BURN_STATE_DIR: join(sandboxDir, 'backslash-state'),
              KTY_MOCK_DOCKER_LOG_DIR: backslashDockerDir,
            },
            stdio: 'pipe',
            timeout: 5000,
          });
        } catch (err) {
          if (err && typeof err === 'object' && 'status' in err && Number(err.status) !== 0) {
            backslashFailedClosed = true;
          }
        }
        const backslashDockerCalls = readRecordedCalls(backslashDockerDir);
        if (!backslashFailedClosed || backslashDockerCalls.some(args => args[0] === 'stop' && args[1] === 'kty-otel-collector')) {
          errors.push(
            'burn-telemetry.sh must reject single backslash characters in GENESIS_AUTH_TOKEN before stopping kty-otel-collector.'
          );
        }

        // When caller omits GENESIS_AUTH_TOKEN, .env fallback must work
        const fallbackCallsDir = join(sandboxDir, 'fallback-calls');
        mkdirSync(fallbackCallsDir, { recursive: true });
        let fallbackOk = true;
        try {
          execFileSync('bash', [scriptPath], {
            cwd: sandboxDir,
            env: {
              PATH: `${binDir}:${process.env.PATH || ''}`,
              KTY_BURN_STATE_DIR: join(sandboxDir, 'fallback-state'),
              KTY_MOCK_LOG_DIR: fallbackCallsDir,
            },
            stdio: 'pipe',
            timeout: 5000,
          });
        } catch {
          fallbackOk = false;
        }
        const fallbackGenesisRec = readRecordedCallRecords(fallbackCallsDir).find(rec =>
          extractLoopbackCurlUrls(rec.args).some(u => u.pathname === GENESIS_LOGS_PATH)
        );
        if (
          !fallbackOk ||
          !fallbackGenesisRec ||
          !/^header\s*=\s*"Authorization:\s*Bearer\s+dotenv-stale-token"\s*$/m.test(fallbackGenesisRec.stdin)
        ) {
          errors.push('burn-telemetry.sh did not fall back to .env GENESIS_AUTH_TOKEN when unset in caller environment.');
        }
      } finally {
        rmSync(dotenvPath, { force: true });
      }
    }

    const verifyConcurrentBurnPair = (stateDirPath, traceFilePath, tagA, tagB, token, failMsg) => {
      let exitedClean = true;
      try {
        execFileSync(
          'bash',
          [
            '-c',
            'p1=""; p2=""; trap \'for c in $p1 $p2; do pkill -KILL -P "$c" 2>/dev/null || true; kill -KILL "$c" 2>/dev/null || true; done; wait 2>/dev/null || true\' INT TERM EXIT; KTY_BURN_TRACE_TAG="$2" bash "$1" & p1=$!; KTY_BURN_TRACE_TAG="$3" bash "$1" & p2=$!; rc1=0; rc2=0; wait "$p1" || rc1=$?; wait "$p2" || rc2=$?; [ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ]',
            '_',
            scriptPath,
            tagA,
            tagB,
          ],
          {
            cwd: sandboxDir,
            env: {
              PATH: `${binDir}:${process.env.PATH || ''}`,
              GENESIS_AUTH_TOKEN: token,
              KTY_BURN_STATE_DIR: stateDirPath,
              KTY_MOCK_DOCKER_TRACE_FILE: traceFilePath,
              KTY_MOCK_DOCKER_SLEEP: '0.15',
            },
            stdio: 'pipe',
            timeout: 3000,
          }
        );
      } catch {
        exitedClean = false;
      }
      const traceLines = existsSync(traceFilePath)
        ? readFileSync(traceFilePath, 'utf-8').trim().split('\n').filter(Boolean)
        : [];
      const spanForTag = tag => ({
        stop: traceLines.indexOf(`${tag}:stop:kty-otel-collector`),
        start: traceLines.lastIndexOf(`${tag}:start:kty-otel-collector`),
      });
      const first = spanForTag(tagA);
      const second = spanForTag(tagB);
      const serialized =
        first.stop !== -1 &&
        first.start > first.stop &&
        second.stop !== -1 &&
        second.start > second.stop &&
        (first.start < second.stop || second.start < first.stop);
      if (!exitedClean || !serialized) {
        errors.push(failMsg);
      }
    };

    // Concurrent burn invocations must serialize stop..start via kernel flock(2) so neither restarts Collector mid-purge
    verifyConcurrentBurnPair(
      join(sandboxDir, 'concurrent-burn-state'),
      join(sandboxDir, 'concurrent-trace.log'),
      'burn1',
      'burn2',
      'concurrent-test-token',
      'burn-telemetry.sh concurrent invocations must acquire mutual exclusion across stop..start to prevent early Collector restoration.'
    );

    // Real SIGKILL mid-burn must release kernel flock immediately (even with sleeping child) and let next burn recover Collector state
    const sigkillStateDir = join(sandboxDir, 'sigkill-burn-state');
    const sigkillTraceFile = join(sandboxDir, 'sigkill-trace.log');
    const sigkillStateFile = join(sigkillStateDir, 'collector-running');
    let sigkillRecovered = true;
    try {
      execFileSync(
        'bash',
        [
          '-c',
          'p1=""; trap \'if [ -n "$p1" ]; then pkill -KILL -P "$p1" 2>/dev/null || true; kill -KILL "$p1" 2>/dev/null || true; fi; wait 2>/dev/null || true\' INT TERM EXIT; KTY_BURN_TRACE_TAG=crashed KTY_MOCK_DOCKER_SLEEP=2.5 bash "$1" & p1=$!; i=0; while { [ ! -f "$2" ] || ! grep -qx "crashed:restart:kty-jaeger" "$3" 2>/dev/null; } && [ "$i" -lt 100 ]; do sleep 0.02; i=$((i + 1)); done; kill -KILL "$p1" 2>/dev/null || true; wait "$p1" 2>/dev/null || true; p1=""; KTY_MOCK_DOCKER_STOPPED=kty-otel-collector KTY_BURN_TRACE_TAG=rescuer KTY_MOCK_DOCKER_SLEEP="" KTY_BURN_LOCK_MAX_WAIT=2 bash "$1"',
          '_',
          scriptPath,
          sigkillStateFile,
          sigkillTraceFile,
        ],
        {
          cwd: sandboxDir,
          env: {
            PATH: `${binDir}:${process.env.PATH || ''}`,
            GENESIS_AUTH_TOKEN: 'sigkill-test-token',
            KTY_BURN_STATE_DIR: sigkillStateDir,
            KTY_MOCK_DOCKER_TRACE_FILE: sigkillTraceFile,
          },
          stdio: 'pipe',
          timeout: 4000,
        }
      );
    } catch {
      sigkillRecovered = false;
    }
    const sigkillTraceLines = existsSync(sigkillTraceFile)
      ? readFileSync(sigkillTraceFile, 'utf-8').trim().split('\n').filter(Boolean)
      : [];
    if (
      !sigkillRecovered ||
      !sigkillTraceLines.includes('rescuer:start:kty-otel-collector') ||
      existsSync(sigkillStateFile)
    ) {
      errors.push(
        'burn-telemetry.sh must release lock immediately on SIGKILL (without leaking FD 9 to children) and reconcile Collector recovery state.'
      );
    }

    // Active kernel flock held by another live process must trigger bounded timeout non-zero without touching Docker
    const heldLockStateDir = join(sandboxDir, 'active-held-state');
    mkdirSync(heldLockStateDir, { recursive: true, mode: 0o700 });
    const heldLockFile = join(heldLockStateDir, 'burn.lock');
    const heldLockReadyFile = join(heldLockStateDir, 'holder.ready');
    const heldLockDockerDir = join(sandboxDir, 'active-held-docker');
    mkdirSync(heldLockDockerDir, { recursive: true });
    const heldLockRunnerPath = join(sandboxDir, 'run-held-lock-test.sh');
    writeFileSync(
      heldLockRunnerPath,
      `#!/usr/bin/env bash
hp=""
cleanup_holder() {
  if [ -n "$hp" ]; then
    pkill -KILL -P "$hp" 2>/dev/null || true
    kill -KILL "$hp" 2>/dev/null || true
  fi
  wait 2>/dev/null || true
}
trap cleanup_holder INT TERM EXIT
if command -v flock >/dev/null 2>&1; then
  (exec 9>>"$2"; flock -x 9; : > "$3"; exec sleep 5) &
elif command -v perl >/dev/null 2>&1; then
  perl -e 'use Fcntl qw(:flock); open(my $fh, ">>", $ARGV[0]) or die $!; flock($fh, LOCK_EX) or die $!; open(my $r, ">", $ARGV[1]) or die $!; close($r); select(undef, undef, undef, 5);' "$2" "$3" &
else
  python3 -c 'import fcntl, sys, time; f=open(sys.argv[1], "a"); fcntl.flock(f.fileno(), fcntl.LOCK_EX); open(sys.argv[2], "w").close(); time.sleep(5)' "$2" "$3" &
fi
hp=$!
i=0
while [ ! -f "$3" ] && [ "$i" -lt 100 ]; do
  sleep 0.02
  i=$((i + 1))
done
[ -f "$3" ] || exit 99
KTY_BURN_LOCK_MAX_WAIT=2 bash "$1"
`,
      'utf-8'
    );
    let heldLockExitedNonZero = false;
    try {
      execFileSync('bash', [heldLockRunnerPath, scriptPath, heldLockFile, heldLockReadyFile], {
        cwd: sandboxDir,
        env: {
          PATH: `${binDir}:${process.env.PATH || ''}`,
          GENESIS_AUTH_TOKEN: 'held-test-token',
          KTY_BURN_STATE_DIR: heldLockStateDir,
          KTY_MOCK_DOCKER_LOG_DIR: heldLockDockerDir,
        },
        stdio: 'pipe',
        timeout: 4000,
      });
    } catch (err) {
      if (err && typeof err === 'object' && 'status' in err && err.status !== null && Number(err.status) !== 0 && Number(err.status) !== 99) {
        heldLockExitedNonZero = true;
      }
    }
    if (!heldLockExitedNonZero || readRecordedCalls(heldLockDockerDir).length > 0) {
      errors.push('burn-telemetry.sh must fail non-zero within bounded wait when kernel flock is held by another live process.');
    }

    // Refuse fallback to shared /tmp when HOME, XDG_STATE_HOME, and KTY_BURN_STATE_DIR are all unset
    const tmpTrapDir = join(sandboxDir, 'tmp-trap');
    const noHomeDockerDir = join(sandboxDir, 'no-home-docker');
    mkdirSync(tmpTrapDir, { recursive: true });
    mkdirSync(noHomeDockerDir, { recursive: true });
    let noHomeFailed = false;
    try {
      execFileSync('bash', [scriptPath], {
        cwd: sandboxDir,
        env: {
          PATH: `${binDir}:${process.env.PATH || ''}`,
          GENESIS_AUTH_TOKEN: 'no-home-token',
          TMPDIR: tmpTrapDir,
          KTY_MOCK_DOCKER_LOG_DIR: noHomeDockerDir,
        },
        stdio: 'pipe',
        timeout: 3000,
      });
    } catch (err) {
      if (err && typeof err === 'object' && 'status' in err && err.status !== null && Number(err.status) !== 0) {
        noHomeFailed = true;
      }
    }
    if (!noHomeFailed || readdirSync(tmpTrapDir).length > 0 || readRecordedCalls(noHomeDockerDir).length > 0) {
      errors.push('burn-telemetry.sh must fail closed instead of falling back to shared /tmp when state directory env vars are unset.');
    }

    // Refuse symlinked state file, lock file, and state directory without following targets or touching Docker
    const symStateDir = join(sandboxDir, 'sym-check-state');
    mkdirSync(symStateDir, { recursive: true, mode: 0o700 });
    const canaryPath = join(sandboxDir, 'canary.txt');
    writeFileSync(canaryPath, 'untouched-canary\n', 'utf-8');
    const symlinkStateFile = join(symStateDir, 'symlink-collector-running');
    symlinkSync(canaryPath, symlinkStateFile);
    const symlinkPromStateFile = join(symStateDir, 'symlink-prometheus-stopped');
    symlinkSync(canaryPath, symlinkPromStateFile);
    const symlinkLockFile = join(symStateDir, 'symlink-burn.lock');
    symlinkSync(canaryPath, symlinkLockFile);
    const symlinkDirTarget = join(sandboxDir, 'symlink-dir-target');
    mkdirSync(symlinkDirTarget, { recursive: true, mode: 0o700 });
    const symlinkStateDir = join(sandboxDir, 'symlink-burn-dir');
    symlinkSync(symlinkDirTarget, symlinkStateDir);
    for (const [label, extraEnv] of [
      ['KTY_BURN_STATE_FILE', { KTY_BURN_STATE_DIR: symStateDir, KTY_BURN_STATE_FILE: symlinkStateFile }],
      ['KTY_BURN_PROM_STATE_FILE', { KTY_BURN_STATE_DIR: symStateDir, KTY_BURN_PROM_STATE_FILE: symlinkPromStateFile }],
      ['KTY_BURN_LOCK_FILE', { KTY_BURN_STATE_DIR: symStateDir, KTY_BURN_LOCK_FILE: symlinkLockFile }],
      ['KTY_BURN_STATE_DIR', { KTY_BURN_STATE_DIR: symlinkStateDir }],
    ]) {
      const symDockerDir = join(sandboxDir, `sym-docker-${label}`);
      mkdirSync(symDockerDir, { recursive: true });
      let symRejected = false;
      try {
        execFileSync('bash', [scriptPath], {
          cwd: sandboxDir,
          env: {
            PATH: `${binDir}:${process.env.PATH || ''}`,
            GENESIS_AUTH_TOKEN: 'sym-test-token',
            KTY_MOCK_DOCKER_LOG_DIR: symDockerDir,
            ...extraEnv,
          },
          stdio: 'pipe',
          timeout: 3000,
        });
      } catch (err) {
        if (err && typeof err === 'object' && 'status' in err && err.status !== null && Number(err.status) !== 0) {
          symRejected = true;
        }
      }
      if (!symRejected || readRecordedCalls(symDockerDir).length > 0 || readFileSync(canaryPath, 'utf-8') !== 'untouched-canary\n') {
        errors.push(`burn-telemetry.sh must reject symlinked ${label} before writing state or stopping containers.`);
      }
    }

    // Refuse group/world-writable parent directories (e.g. 0777) and non-sticky writable ancestors for lock/state overrides
    const unsafeParentDir = join(sandboxDir, 'unsafe-777-parent');
    mkdirSync(unsafeParentDir, { recursive: true });
    chmodSync(unsafeParentDir, 0o777);
    const unsafeAncBase = join(sandboxDir, 'unsafe-777-anc');
    const unsafeAncLeaf = join(unsafeAncBase, 'safe-leaf');
    mkdirSync(unsafeAncLeaf, { recursive: true, mode: 0o700 });
    chmodSync(unsafeAncBase, 0o777);
    for (const [label, extraEnv] of [
      ['0777 KTY_BURN_LOCK_FILE parent', { KTY_BURN_STATE_DIR: symStateDir, KTY_BURN_LOCK_FILE: join(unsafeParentDir, 'burn.lock') }],
      ['0777 KTY_BURN_STATE_FILE parent', { KTY_BURN_STATE_DIR: symStateDir, KTY_BURN_STATE_FILE: join(unsafeParentDir, 'collector-running') }],
      ['0777 KTY_BURN_PROM_STATE_FILE parent', { KTY_BURN_STATE_DIR: symStateDir, KTY_BURN_PROM_STATE_FILE: join(unsafeParentDir, 'prometheus-stopped') }],
      ['0777 ancestor of KTY_BURN_LOCK_FILE', { KTY_BURN_STATE_DIR: symStateDir, KTY_BURN_LOCK_FILE: join(unsafeAncLeaf, 'burn.lock') }],
    ]) {
      const unsafeDockerDir = join(sandboxDir, `unsafe-dir-${label.replace(/\W+/g, '-')}`);
      mkdirSync(unsafeDockerDir, { recursive: true });
      let unsafeRejected = false;
      try {
        execFileSync('bash', [scriptPath], {
          cwd: sandboxDir,
          env: {
            PATH: `${binDir}:${process.env.PATH || ''}`,
            GENESIS_AUTH_TOKEN: 'unsafe-dir-token',
            KTY_MOCK_DOCKER_LOG_DIR: unsafeDockerDir,
            ...extraEnv,
          },
          stdio: 'pipe',
          timeout: 3000,
        });
      } catch (err) {
        if (err && typeof err === 'object' && 'status' in err && err.status !== null && Number(err.status) !== 0) {
          unsafeRejected = true;
        }
      }
      if (!unsafeRejected || readRecordedCalls(unsafeDockerDir).length > 0) {
        errors.push(`burn-telemetry.sh must reject ${label} before acquiring lock or stopping containers.`);
      }
    }

    // Invalid GENESIS_PORT / PROMETHEUS_PORT (e.g. curl userinfo smuggling or out-of-range) must fail BEFORE stopping containers or calling curl
    let portCheckIdx = 0;
    for (const [portVar, badPort] of [
      ['GENESIS_PORT', '9002@outside.example'],
      ['GENESIS_PORT', '70000'],
      ['GENESIS_PORT', '0'],
      ['PROMETHEUS_PORT', '9090@outside.example'],
    ]) {
      portCheckIdx += 1;
      const portCallsDir = join(sandboxDir, `port-calls-${portCheckIdx}`);
      const portDockerDir = join(sandboxDir, `port-docker-${portCheckIdx}`);
      mkdirSync(portCallsDir, { recursive: true });
      mkdirSync(portDockerDir, { recursive: true });
      let portFailed = false;
      try {
        execFileSync('bash', [scriptPath], {
          cwd: sandboxDir,
          env: {
            PATH: `${binDir}:${process.env.PATH || ''}`,
            GENESIS_AUTH_TOKEN: 'port-validation-token',
            [portVar]: badPort,
            KTY_BURN_STATE_DIR: join(sandboxDir, `port-state-${portCheckIdx}`),
            KTY_MOCK_LOG_DIR: portCallsDir,
            KTY_MOCK_DOCKER_LOG_DIR: portDockerDir,
          },
          stdio: 'pipe',
          timeout: 3000,
        });
      } catch (err) {
        if (err && typeof err === 'object' && 'status' in err && err.status !== null && Number(err.status) !== 0) {
          portFailed = true;
        }
      }
      const portCurlCalls = readRecordedCallRecords(portCallsDir);
      const portDockerCalls = readRecordedCalls(portDockerDir);
      if (!portFailed || portCurlCalls.length > 0 || portDockerCalls.length > 0) {
        errors.push(`burn-telemetry.sh must reject invalid ${portVar}="${badPort}" before stopping containers or invoking curl.`);
      }
    }

    // Collector recovery state persistence: reconcile interrupted burn without starting an intentionally stopped Collector
    const interruptedStateDir = join(sandboxDir, 'interrupted-state-dir');
    mkdirSync(interruptedStateDir, { recursive: true, mode: 0o700 });
    const stateFile = join(interruptedStateDir, 'collector-running');
    writeFileSync(stateFile, '999999\n', 'utf-8');
    const interruptedDockerDir = join(sandboxDir, 'interrupted-docker');
    mkdirSync(interruptedDockerDir, { recursive: true });
    let interruptedOk = true;
    try {
      execFileSync('bash', [scriptPath], {
        cwd: sandboxDir,
        env: {
          PATH: `${binDir}:${process.env.PATH || ''}`,
          GENESIS_AUTH_TOKEN: 'state-restore-token',
          KTY_MOCK_DOCKER_STOPPED: 'kty-otel-collector',
          KTY_MOCK_DOCKER_LOG_DIR: interruptedDockerDir,
          KTY_BURN_STATE_DIR: interruptedStateDir,
        },
        stdio: 'pipe',
        timeout: 4000,
      });
    } catch {
      interruptedOk = false;
    }
    const interruptedDockerCalls = readRecordedCalls(interruptedDockerDir);
    if (!interruptedOk || !interruptedDockerCalls.some(a => a[0] === 'start' && a[1] === 'kty-otel-collector') || existsSync(stateFile)) {
      errors.push('burn-telemetry.sh must reconcile persisted Collector recovery state after an interrupted burn and clear it upon restart.');
    }

    const intentionalDockerDir = join(sandboxDir, 'intentional-stopped-docker');
    const intentionalStateDir = join(sandboxDir, 'intentional-state-dir');
    mkdirSync(intentionalDockerDir, { recursive: true });
    let intentionalOk = true;
    try {
      execFileSync('bash', [scriptPath], {
        cwd: sandboxDir,
        env: {
          PATH: `${binDir}:${process.env.PATH || ''}`,
          GENESIS_AUTH_TOKEN: 'intentional-stopped-token',
          KTY_MOCK_DOCKER_STOPPED: 'kty-otel-collector,kty-prometheus',
          KTY_MOCK_DOCKER_LOG_DIR: intentionalDockerDir,
          KTY_BURN_STATE_DIR: intentionalStateDir,
        },
        stdio: 'pipe',
        timeout: 4000,
      });
    } catch {
      intentionalOk = false;
    }
    const intentionalDockerCalls = readRecordedCalls(intentionalDockerDir);
    if (
      !intentionalOk ||
      intentionalDockerCalls.some(a => a[0] === 'start' && (a[1] === 'kty-otel-collector' || a[1] === 'kty-prometheus')) ||
      intentionalDockerCalls.some(a => a[0] === 'run' && a.includes('kty-prometheus'))
    ) {
      errors.push('burn-telemetry.sh must not start intentionally stopped kty-otel-collector or kty-prometheus when no interrupted burn state exists.');
    }

    // Prometheus WAL purge recovery state persistence: wipe WAL, restart, wait /-/ready, and clear state only on full success
    const interruptedPromStateDir = join(sandboxDir, 'interrupted-prom-state-dir');
    mkdirSync(interruptedPromStateDir, { recursive: true, mode: 0o700 });
    const interruptedPromCollectorFile = join(interruptedPromStateDir, 'collector-running');
    const interruptedPromFile = join(interruptedPromStateDir, 'prometheus-stopped');
    writeFileSync(interruptedPromCollectorFile, '999998\n', 'utf-8');
    writeFileSync(interruptedPromFile, '999999\n', 'utf-8');
    const interruptedPromDockerDir = join(sandboxDir, 'interrupted-prom-docker');
    const interruptedPromEventsFile = join(sandboxDir, 'interrupted-prom-events.log');
    mkdirSync(interruptedPromDockerDir, { recursive: true });
    let interruptedPromOk = true;
    try {
      execFileSync('bash', [scriptPath], {
        cwd: sandboxDir,
        env: {
          PATH: `${binDir}:${process.env.PATH || ''}`,
          GENESIS_AUTH_TOKEN: 'prom-restore-token',
          KTY_MOCK_DOCKER_STOPPED: 'kty-otel-collector,kty-prometheus',
          KTY_MOCK_DOCKER_LOG_DIR: interruptedPromDockerDir,
          KTY_MOCK_EVENT_LOG: interruptedPromEventsFile,
          KTY_BURN_STATE_DIR: interruptedPromStateDir,
        },
        stdio: 'pipe',
        timeout: 4000,
      });
    } catch {
      interruptedPromOk = false;
    }
    const interruptedPromCalls = readRecordedCalls(interruptedPromDockerDir);
    const interruptedPromEvents = existsSync(interruptedPromEventsFile)
      ? readFileSync(interruptedPromEventsFile, 'utf-8').split('\n').filter(Boolean)
      : [];
    const recPromRunIdx = interruptedPromCalls.findIndex(
      a => a[0] === 'run' && a.includes('kty-prometheus') && a.some(x => /find\s+\/prometheus\b.*rm\s+-rf/.test(x))
    );
    const recPromStartIdx = interruptedPromCalls.findIndex(a => a[0] === 'start' && a[1] === 'kty-prometheus');
    const recCollectorStartIdx = interruptedPromCalls.findIndex(a => a[0] === 'start' && a[1] === 'kty-otel-collector');
    const recEvRunIdx = interruptedPromEvents.findIndex(l => l.startsWith('docker\trun\t'));
    const recEvPromStartIdx = interruptedPromEvents.indexOf('docker\tstart\tkty-prometheus');
    const recEvPromReadyIdx = interruptedPromEvents.findIndex(l => l.startsWith('curl\t') && l.includes('/-/ready'));
    const recEvColStartIdx = interruptedPromEvents.indexOf('docker\tstart\tkty-otel-collector');
    if (
      !interruptedPromOk ||
      recPromRunIdx === -1 ||
      recPromStartIdx === -1 ||
      recCollectorStartIdx === -1 ||
      !(recPromRunIdx < recPromStartIdx && recPromStartIdx < recCollectorStartIdx) ||
      !(recEvRunIdx !== -1 && recEvPromStartIdx !== -1 && recEvPromReadyIdx !== -1 && recEvRunIdx < recEvPromStartIdx && recEvPromStartIdx < recEvPromReadyIdx && recEvPromReadyIdx < recEvColStartIdx) ||
      existsSync(interruptedPromFile) ||
      existsSync(interruptedPromCollectorFile)
    ) {
      errors.push('burn-telemetry.sh must reconcile persisted Prometheus WAL purge recovery state across stopped-Prometheus crashes before restarting Collector.');
    }

    // If recovery WAL wipe fails, fail non-zero, attempt Prometheus start cleanup, and preserve prometheus-stopped
    const recFailStateDir = join(sandboxDir, 'interrupted-prom-fail-state-dir');
    mkdirSync(recFailStateDir, { recursive: true, mode: 0o700 });
    const recFailPromFile = join(recFailStateDir, 'prometheus-stopped');
    writeFileSync(recFailPromFile, '999999\n', 'utf-8');
    const recFailDockerDir = join(sandboxDir, 'interrupted-prom-fail-docker');
    mkdirSync(recFailDockerDir, { recursive: true });
    let recFailExitedNonZero = false;
    try {
      execFileSync('bash', [scriptPath], {
        cwd: sandboxDir,
        env: {
          PATH: `${binDir}:${process.env.PATH || ''}`,
          GENESIS_AUTH_TOKEN: 'prom-restore-fail-token',
          KTY_MOCK_DOCKER_STOPPED: 'kty-prometheus',
          KTY_MOCK_DOCKER_FAIL_TARGET: 'kty-prometheus',
          KTY_MOCK_DOCKER_FAIL_ACTION: 'run',
          KTY_MOCK_DOCKER_LOG_DIR: recFailDockerDir,
          KTY_BURN_STATE_DIR: recFailStateDir,
        },
        stdio: 'pipe',
        timeout: 4000,
      });
    } catch (err) {
      if (err && typeof err === 'object' && 'status' in err && Number(err.status) !== 0) {
        recFailExitedNonZero = true;
      }
    }
    const recFailCalls = readRecordedCalls(recFailDockerDir);
    if (!recFailExitedNonZero || !recFailCalls.some(a => a[0] === 'start' && a[1] === 'kty-prometheus') || !existsSync(recFailPromFile)) {
      errors.push('burn-telemetry.sh must exit non-zero, attempt Prometheus restore, and preserve prometheus-stopped when recovery WAL purge fails.');
    }
  } finally {
    rmSync(sandboxDir, { recursive: true, force: true });
  }
}

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
  auditBurnTelemetryScript(burnContent, errors);

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
    if (!/location\s+\^~\s+\/otlp\/\s*\{/.test(nginxContent) || !nginxContent.includes('proxy_pass http://otel-collector:4318/;')) {
      errors.push('gateway/nginx.conf must proxy ^~ /otlp/ exclusively to internal otel-collector:4318.');
    }
  }
}

function extractKeysList(stmt, fnRegex) {
  const match = stmt.match(fnRegex);
  if (!match) return null;
  return new Set(
    match[1]
      .split(',')
      .map(k => k.trim().replace(/^["']|["']$/g, ''))
      .filter(Boolean)
  );
}

function compareKeySets(expectedSet, actualSet, label, errors) {
  for (const k of expectedSet) {
    if (!actualSet.has(k)) {
      errors.push(`${label} missing allowlisted key "${k}".`);
    }
  }
  for (const k of actualSet) {
    if (!expectedSet.has(k)) {
      errors.push(`${label} includes unreviewed key "${k}" missing from canonical allowlist.`);
    }
  }
}

function isUnconditionalBlock(block) {
  if (!block || typeof block !== 'object') return false;
  if (block.conditions === undefined || block.conditions === null) return true;
  return Array.isArray(block.conditions) && block.conditions.length === 0;
}

function isUnconditionalKeepKeysStmt(stmt) {
  return typeof stmt === 'string' && /^keep_keys\s*\(\s*attributes\s*,\s*\[[^\]]*\]\s*\)$/.test(stmt.trim());
}

function escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function normalizeOttlExpr(str) {
  return typeof str === 'string' ? str.trim().replace(/\s+/g, ' ') : '';
}

function splitTopLevelDisjunction(expr) {
  const parts = [];
  let depth = 0;
  let quote = null;
  let start = 0;
  for (let i = 0; i < expr.length; i += 1) {
    const ch = expr[i];
    if (quote) {
      if (ch === '\\' && i + 1 < expr.length) {
        i += 1;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === '"') {
      quote = ch;
      continue;
    }
    if (ch === '(') depth += 1;
    else if (ch === ')') depth -= 1;
    else if (depth === 0) {
      const orMatch = expr.slice(i).match(/^\s+or\s+/i);
      if (orMatch) {
        parts.push(expr.slice(start, i).trim());
        i += orMatch[0].length - 1;
        start = i + 1;
      }
    }
  }
  if (depth !== 0 || quote !== null) return null;
  parts.push(expr.slice(start).trim());
  return parts;
}

export const NUMERIC_COLLECTOR_KEYS = new Set([
  'adapter_size_bytes',
  'char_count',
  'clause_count',
  'current_step',
  'discount_percent',
  'discrepancy_count',
  'duration_ms',
  'duration_sec',
  'flagged_clauses',
  'flagged_count',
  'howso.cases.ablated_count',
  'howso.cases.anomalous_count',
  'howso.cases.original_count',
  'howso.preflight.duration_ms',
  'http.status_code',
  'line_count',
  'loss',
  'matched_violations',
  'overtime_hours',
  'parsed_line_count',
  'progress_pct',
  'protection_score',
  'redflag_count',
  'regular_hours',
  'score_percentage',
  'standard_count',
  'step',
  'surprisal.cases.ablated_count',
  'surprisal.cases.anomalous_count',
  'surprisal.cases.original_count',
  'surprisal.preflight.duration_ms',
  'total_clauses',
  'total_steps',
  'unenforceable_count',
  'unlawful_count',
  'violations_count',
  'watch_count',
]);

export const BOOLEAN_COLLECTOR_KEYS = new Set([
  'charity_eligible',
  'has_balance_due',
  'has_deductions',
  'has_illegal_tie_in',
  'has_implied_disclaimer',
  'has_income_verified',
  'has_itemized_breakdown',
  'has_overtime',
  'howso.preflight.enabled',
  'is_compliant',
  'ocr_used',
  'sidecar_active',
  'surprisal.preflight.enabled',
  'unconditional_gift_triggered',
]);

export const AUDIT_FLAG_COLLECTOR_KEYS = new Set([
  'audit.allowlist_enforced',
  'audit.collector_verified',
]);

const APPROVED_US_STATE_CODE_GROUP =
  '(?:AL|AK|AZ|AR|CA|CO|CT|DE|DC|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY)';
const APPROVED_RULE_ID_TOKEN_PATTERN =
  `(?:AR-00[1-3]|ARB-00[1-3]|UNI-00[12]|SURV-00[12]|US-(?:CO|IL|OR)-001|EU-(?:AR-00[12]|SURV-001)|UK-(?:AR-00[12]|CONS-001)|CA-(?:SEC-DEP-CAP-01|SEC-DEP-RET-02|ENTRY-NOT-03|EVICT-SLF-04|HABIT-REP-05|LATE-FEE-06)|FL-(?:SEC-DEP-RET-01|ENTRY-NOT-02|PROHIB-PRAC-03|HABIT-REP-04)|IL-(?:SEC-DEP-RET-01|EVICT-SLF-02|RETALIAT-03|DEP-INT-04)|NY-(?:SEC-DEP-CAP-01|SEC-DEP-RET-02|ENTRY-NOT-06|LATE-FEE-03|EVICT-SLF-04|HABIT-WAR-05|OCCUP-ROOM-07)|TX-(?:SEC-DEP-RET-01|LATE-FEE-02|LOCKOUT-SLF-03|UTIL-SHUT-04|HABIT-REP-05)|FED-(?:FHA-FAM-01|FHA-DIS-02|SCRA-MIL-03|LEAD-DISC-04)|illegal_(?:register_shortage|uniform_equipment)_deduction|salaried_under_(?:exemption_)?threshold|missing_overtime_multiplier|unexplained_mandatory_fee|fica_math_mismatch|KTY-WARRANTY-(?:EXCL|DISCLAIM)-001|WARRANTY_VOID_IF_REMOVED|CA_CIV_1950_5|FLSA_EXEMPT_541|implied_warranty_disclaimer|state_(?:daily_overtime|implied_override)_${APPROVED_US_STATE_CODE_GROUP}|hmac:[a-f0-9]{16,64}|sha256:[a-f0-9]{64})`;
export const APPROVED_RULE_ID_OTTL_PATTERN =
  `^\\\\[(?:\\\\x22${APPROVED_RULE_ID_TOKEN_PATTERN}\\\\x22(?:,\\\\x22${APPROVED_RULE_ID_TOKEN_PATTERN}\\\\x22)*)?\\\\]$`;
export const APPROVED_RULE_IDS_CSV_OTTL_PATTERN =
  `^${APPROVED_RULE_ID_TOKEN_PATTERN}(?:,${APPROVED_RULE_ID_TOKEN_PATTERN})*$`;
export const APPROVED_ADAPTER_PATH_OTTL_PATTERN = '^hmac:[0-9a-f]{16}$';
export const DATASET_NUMERIC_STEM_REJECT_PATTERN = '^[0-9]{13,19}\\\\.jsonl$';
export const APPROVED_DATASET_RELATIVE_PATH_OTTL_PATTERN =
  '^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,64}|(?:job|test-job|run|task|j)[-_](?:[0-9]{1,8}|[0-9a-fA-F]{16,64}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}))\\\\.jsonl$';

export const APPROVED_SPAN_NAME_OTTL_PATTERN =
  '^(?:extension\\\\.page_scan|evaluate_subscription_agreement|evaluate_charity_care|audit_medical_bill|evaluate_lease_rules|evaluate_edge_semantic_lora|analyze_paystub|analyze_warranty|job\\\\.(?:accepted|publish_failed|published|edge_export_requested|edge_exported|consumed|training\\\\.(?:started|finished)|registered|failed|completed|transition(?:\\\\.(?:pending|queued|training|succeeded|failed))?))$';
export const APPROVED_EVENT_NAME_OTTL_PATTERN =
  '^(?:job\\\\.(?:completed|accepted|consumed|training\\\\.(?:started|finished)|registered|failed)|rule\\\\.evaluated)$';
export const APPROVED_SCOPE_NAME_OTTL_PATTERN =
  '^(?:@knowthankyew/[a-z0-9_-]{1,40}|KnowThankYew(?:\\\\.[A-Za-z0-9_-]{1,36}){1,5}|Kty(?:\\\\.[A-Za-z0-9_-]{1,36}){1,5}|FtaaSService(?:\\\\.[A-Za-z0-9_-]{1,36}){1,5}|knowthankyew(?:-[a-z0-9_-]{1,32})?|spanmetrics(?:connector)?|opentelemetry(?:-collector|\\\\.[A-Za-z0-9_.-]{1,36})?)$';
export const APPROVED_SCOPE_VERSION_OTTL_PATTERN =
  '^v?[0-9]+\\\\.[0-9]+\\\\.[0-9]+(?:[-+][0-9A-Za-z]{1,12}(?:\\\\.[0-9A-Za-z]{1,12}){0,2})?$';
export const APPROVED_STATUS_OTTL_PATTERN =
  '^(?:OK|ERROR|UNSET|Pending|Queued|Training|TrainingFinished|Succeeded|Failed|Completed|Cancelled|Canceled|Timeout|Unknown|ok|error|unset|pending|queued|training|training_finished|succeeded|failed|completed|cancelled|canceled|timeout|unknown|degraded|burned|Standard|Watch|Flagged|LikelyUnenforceable|Unenforceable|Compliant|NonCompliant|Disabled|disabled|Skipped|skipped|FellBack)$';
export const APPROVED_JURISDICTION_OTTL_PATTERN =
  '^(?:AL|AK|AZ|AR|CA|CO|CT|DE|DC|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|AS|GU|MP|PR|VI|FED|FEDERAL|FTC|DEFAULT|US|UK|EU|EU_CRD|UK_DMCC|CA-ON|Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|District of Columbia|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New Hampshire|New Jersey|New Mexico|New York|North Carolina|North Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode Island|South Carolina|South Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West Virginia|Wisconsin|Wyoming|Puerto Rico|American Samoa|Virgin Islands|Guam|Northern Mariana Islands|United States|US Federal|Federal|United Kingdom|European Union)$';
export const APPROVED_SCALAR_RULE_ID_OTTL_PATTERN =
  `^${APPROVED_RULE_ID_TOKEN_PATTERN}$`;
export const APPROVED_ACTION_OTTL_PATTERN =
  '^(?:scan_started|scan_complete|scan_completed|document_ingested|rules_evaluated|audit_performed|handoff_sent|handoff_received|handoff_rejected|edge_inference_started|edge_inference_completed|edge_inference_failed|edge_export|ocr_started|ocr_completed|pdf_extracted|burn|hard_burn|export|dispute_generated)$';
export const APPROVED_AUDIT_STATUS_OTTL_PATTERN =
  '^(?:Standard|Watch|Flagged|LikelyUnenforceable|Unenforceable|Compliant|NonCompliant|Passed|Failed|Completed|Pending|OK|ERROR|Unknown|standard|watch|flagged|likely_unenforceable|unenforceable|compliant|non_compliant|passed|failed|completed|pending|ok|error|unknown)$';
export const APPROVED_BASE_MODEL_OTTL_PATTERN =
  '^(?:HuggingFaceTB/SmolLM2-135M|google/gemma-2-2b-it|microsoft/BitNet-b1\\\\.58-2B-4T|hmac:[a-f0-9]{16,64}|sha256:[a-f0-9]{64})$';
export const BASE_MODEL_PATH_REJECT_PATTERN =
  '(?i)(?:^\\\\.\\\\.|/\\\\.\\\\.|^(?:Users|home|tmp|var|private|etc)/|^[A-Za-z]:/)';
export const APPROVED_DATASET_HASH_OTTL_PATTERN = '^(?:sha256:)?(?:[0-9a-f]{12,64}|[0-9A-F]{12,64})$';
export const APPROVED_DEVICE_OTTL_PATTERN =
  '^(?i:cpu|cuda(?::[0-7])?|mps|webgpu|wasm|gpu|npu|ane|xpu|rocm|directml|auto|none|unknown|x64|arm64)$';
export const APPROVED_ERROR_CODE_OTTL_PATTERN =
  '^(?:[A-Z][A-Z0-9_]{1,63}|[A-Z][A-Za-z0-9]{1,48}(?:Exception|Error|Fault|Timeout)|[a-z][a-z0-9]{1,24}(?:_[a-z0-9]{1,24}){1,5}|(?:HTTP_)?[45][0-9]{2})$';
export const APPROVED_EXCHANGE_OTTL_PATTERN = '^(?:ftaas\\\\.(?:direct|dlx|events|topic)|default|direct)$';
export const APPROVED_PREFLIGHT_STATUS_OTTL_PATTERN =
  '^(?:Disabled|Skipped|Completed|FellBack|Passed|Failed|Error|OK|disabled|skipped|completed|fell_back|passed|failed|error|ok)$';
export const APPROVED_HTTP_METHOD_OTTL_PATTERN = '^(?:GET|HEAD|POST|PUT|DELETE|PATCH|OPTIONS|CONNECT|TRACE)$';
export const JOB_ID_NUMERIC_REJECT_PATTERN = '^(?:[0-9]{13,19}|(?:job|test-job|run|task|j)[-_][0-9]{13,19})$';
export const APPROVED_JOB_ID_OTTL_PATTERN =
  '^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,64}|hmac:[a-f0-9]{16,64}|sha256:[a-f0-9]{64}|(?:job|test-job|run|task|j)[-_](?:[0-9]{1,8}|[0-9a-fA-F]{16,64}|hmac:[a-f0-9]{16,64}|sha256:[a-f0-9]{64}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}))$';
export const APPROVED_PRODUCT_TYPE_OTTL_PATTERN =
  '^(?:Electronics(?: & (?:Laptops|Computers))?|Automotive(?: & EV Accessories| / EV| Vehicle)?|Home Appliances?|Tools(?: & (?:Hardware|Equipment))?|Smart Home Devices|Furniture & Home Goods|General(?: Consumer Product)?|Consumer Electronics|Appliances)$';
export const APPROVED_RISK_LEVEL_OTTL_PATTERN =
  '^(?:Critical|High|Medium|Moderate|Low|Info|Warning|None|Minimal|Elevated|Severe|CRITICAL|HIGH|MEDIUM|MODERATE|LOW|INFO|WARNING|NONE|critical|high|medium|moderate|low|info|warning|none)$';
export const APPROVED_ROUTING_KEY_OTTL_PATTERN =
  '^(?:job\\\\.(?:requested|updated|status|completed|failed|dlq|cancelled|canceled|progress|edge_export))$';
export const APPROVED_SERVICE_NAME_OTTL_PATTERN =
  '^(?:knowthankyew-(?:app|extension)|privacy-telemetry|lease-audit|care-check|careCheck|paystub-check|bill-of-rights-bot|warranty-watch|ftaas-(?:api|worker|inference)|surprisal-service|howso-preflight|mail-stripper(?:-imap)?|unsubscribe-shield-ext|gradcast|genesis|mac-screen-record|kty-ntfs|enterprise-self-host|test-svc|unknown|unknown_service(?::(?:python|node|nodejs|dotnet|go|webjs))?)$';
export const APPROVED_SPAN_KIND_OTTL_PATTERN =
  '^(?:INTERNAL|SERVER|CLIENT|PRODUCER|CONSUMER|UNSPECIFIED|internal|server|client|producer|consumer|unspecified|SPAN_KIND_(?:INTERNAL|SERVER|CLIENT|PRODUCER|CONSUMER|UNSPECIFIED))$';
export const APPROVED_STATUS_CODE_OTTL_PATTERN =
  '^(?:OK|ERROR|UNSET|ok|error|unset|STATUS_CODE_(?:OK|ERROR|UNSET))$';
export const APPROVED_STATUTE_CODE_OTTL_PATTERN =
  '^(?:[0-9]{1,3}\\\\s+(?:U\\\\.?S\\\\.?C\\\\.?|C\\\\.?F\\\\.?R\\\\.?|Stat\\\\.)\\\\s+(?:(?:§§?|Part)\\\\s*)?[0-9][A-Za-z0-9_.\\\\-()]{0,24}|[0-9]{1,4}\\\\s+[A-Z]{2,8}\\\\s+[0-9][A-Za-z0-9_.\\\\-/()]{0,20}|(?:Cal\\\\.|N\\\\.Y\\\\.|Mass\\\\.|Tex\\\\.|Fla\\\\.|Ill\\\\.|Wash\\\\.|Colo\\\\.|Or\\\\.|Pa\\\\.|N\\\\.J\\\\.|Va\\\\.|Md\\\\.|Ga\\\\.|N\\\\.C\\\\.|S\\\\.C\\\\.|Minn\\\\.|Wis\\\\.|Ariz\\\\.|Nev\\\\.|Mich\\\\.|Conn\\\\.|Ind\\\\.|Ohio|Iowa|Utah|Tenn\\\\.|Ky\\\\.|La\\\\.|Ala\\\\.|Ark\\\\.|Kan\\\\.|Mo\\\\.|Neb\\\\.|Mont\\\\.|Idaho|Wyo\\\\.|Me\\\\.|Vt\\\\.|N\\\\.H\\\\.|R\\\\.I\\\\.|Del\\\\.|Alaska|Hawaii|D\\\\.C\\\\.|UCC|FDCPA|FCRA|FLSA|TILA|SCRA|FHA|HIPAA|ROSCA|CCPA|CPRA|BIPA|FTC)(?:\\\\s+(?:Rev\\\\.|Gen\\\\.|Bus\\\\.|Prof\\\\.|Civ\\\\.|Lab\\\\.|Prop\\\\.|Penal|Ins\\\\.|Health|Educ\\\\.|Fin\\\\.|Gov\\\\.|Com\\\\.|Code|Laws?|Stat\\\\.|Act|Ann\\\\.|ch\\\\.|c\\\\.|Part|Title|&|GBL|RPL|Art\\\\.|[0-9]{1,4}[A-Za-z]?)){0,5}(?:,\\\\s*|\\\\s*)(?:§§?\\\\s*[0-9][A-Za-z0-9_.\\\\-()]{0,24}|Ch\\\\.\\\\s*[0-9]{1,4}(?:\\\\s*§§?\\\\s*[0-9][A-Za-z0-9_.\\\\-()]{0,20})?)|(?:EU\\\\s+)?(?:GDPR(?:\\\\s+Art\\\\.?\\\\s*[0-9][A-Za-z0-9_.\\\\-()]{0,16})?|Directive\\\\s+[0-9]{4}/[0-9]{1,4}/[A-Z]{2,4}(?:,?\\\\s+Art(?:icle)?\\\\.?\\\\s*[0-9][A-Za-z0-9_.\\\\-()]{0,16})?)|UK\\\\s+(?:Consumer\\\\s+Rights|DMCC|Data\\\\s+Protection|Employment\\\\s+Rights)\\\\s+Act\\\\s+[0-9]{4}(?:,?\\\\s+(?:Part|Chapter|Section|Sec\\\\.|§)\\\\s*[0-9][A-Za-z0-9_.\\\\-()]{0,16}){0,3})$';
export const APPROVED_WARRANTY_TYPE_OTTL_PATTERN = '^(?:Full|Limited|Disclaimed / As-Is|Unspecified)$';

export const APPROVED_DEPLOYMENT_ENVIRONMENT_OTTL_PATTERN =
  '^(?:development|dev|staging|stage|production|prod|test|testing|ci|local|sandbox|preview|Development|Staging|Production|enterprise|consumer|airgap|self-hosted)$';
export const APPROVED_SERVICE_NAMESPACE_OTTL_PATTERN = '^(?:knowthankyew(?:-[a-z0-9_-]{1,32})?|ftaas)$';
export const APPROVED_APP_VERSION_OTTL_PATTERN =
  '^v?[0-9]+\\\\.[0-9]+\\\\.[0-9]+(?:\\\\.[0-9]+)?(?:[-+][0-9A-Za-z._-]{1,32})?$';
export const APPROVED_SERVICE_INSTANCE_ID_OTTL_PATTERN =
  '^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{12,64}|(?:hmac|sha256):[0-9a-f]{16,64})$';
export const APPROVED_SDK_LANGUAGE_OTTL_PATTERN =
  '^(?:cpp|dotnet|erlang|go|java|js|nodejs|php|python|ruby|rust|swift|webjs)$';
export const APPROVED_SDK_NAME_OTTL_PATTERN =
  '^(?:opentelemetry|otlp-json|@knowthankyew/[a-z0-9_-]{1,40}|KnowThankYew\\\\.[A-Za-z0-9_.-]{1,48})$';

export const PATH_COLLECTOR_SCHEMAS = {
  adapter_path: { pattern: APPROVED_ADAPTER_PATH_OTTL_PATTERN, redactTo: '[REDACTED_PATH]' },
  dataset_relative_path: {
    pattern: APPROVED_DATASET_RELATIVE_PATH_OTTL_PATTERN,
    rejectPattern: DATASET_NUMERIC_STEM_REJECT_PATTERN,
    redactTo: '[REDACTED_PATH]',
  },
};

export const BOUNDED_SCALAR_STRING_SCHEMAS = {
  action: { pattern: APPROVED_ACTION_OTTL_PATTERN },
  audit_status: { pattern: APPROVED_AUDIT_STATUS_OTTL_PATTERN },
  base_model: { pattern: APPROVED_BASE_MODEL_OTTL_PATTERN, rejectPattern: BASE_MODEL_PATH_REJECT_PATTERN },
  dataset_hash: { pattern: APPROVED_DATASET_HASH_OTTL_PATTERN },
  device: { pattern: APPROVED_DEVICE_OTTL_PATTERN },
  error_code: { pattern: APPROVED_ERROR_CODE_OTTL_PATTERN },
  error_type: { pattern: APPROVED_ERROR_CODE_OTTL_PATTERN },
  exchange: { pattern: APPROVED_EXCHANGE_OTTL_PATTERN },
  'howso.preflight.status': { pattern: APPROVED_PREFLIGHT_STATUS_OTTL_PATTERN },
  'http.method': { pattern: APPROVED_HTTP_METHOD_OTTL_PATTERN },
  job_id: { pattern: APPROVED_JOB_ID_OTTL_PATTERN, rejectPattern: JOB_ID_NUMERIC_REJECT_PATTERN },
  jurisdiction: { pattern: APPROVED_JURISDICTION_OTTL_PATTERN },
  product_category: { pattern: APPROVED_PRODUCT_TYPE_OTTL_PATTERN },
  product_type: { pattern: APPROVED_PRODUCT_TYPE_OTTL_PATTERN },
  risk_level: { pattern: APPROVED_RISK_LEVEL_OTTL_PATTERN },
  routing_key: { pattern: APPROVED_ROUTING_KEY_OTTL_PATTERN },
  rule_id: { pattern: APPROVED_SCALAR_RULE_ID_OTTL_PATTERN },
  service: { pattern: APPROVED_SERVICE_NAME_OTTL_PATTERN },
  'service.name': { pattern: APPROVED_SERVICE_NAME_OTTL_PATTERN },
  'span.kind': { pattern: APPROVED_SPAN_KIND_OTTL_PATTERN },
  state: { pattern: APPROVED_JURISDICTION_OTTL_PATTERN },
  status: { pattern: APPROVED_STATUS_OTTL_PATTERN },
  'status.code': { pattern: APPROVED_STATUS_CODE_OTTL_PATTERN },
  statute_code: { pattern: APPROVED_STATUTE_CODE_OTTL_PATTERN, maxLength: 64 },
  'surprisal.preflight.status': { pattern: APPROVED_PREFLIGHT_STATUS_OTTL_PATTERN },
  warranty_type: { pattern: APPROVED_WARRANTY_TYPE_OTTL_PATTERN },
};

export const BOUNDED_RESOURCE_STRING_SCHEMAS = {
  'deployment.environment': { pattern: APPROVED_DEPLOYMENT_ENVIRONMENT_OTTL_PATTERN },
  'service.instance.id': { pattern: APPROVED_SERVICE_INSTANCE_ID_OTTL_PATTERN },
  'service.name': { pattern: APPROVED_SERVICE_NAME_OTTL_PATTERN },
  'service.namespace': { pattern: APPROVED_SERVICE_NAMESPACE_OTTL_PATTERN },
  'service.version': { pattern: APPROVED_APP_VERSION_OTTL_PATTERN },
  'telemetry.sdk.language': { pattern: APPROVED_SDK_LANGUAGE_OTTL_PATTERN },
  'telemetry.sdk.name': { pattern: APPROVED_SDK_NAME_OTTL_PATTERN },
  'telemetry.sdk.version': { pattern: APPROVED_APP_VERSION_OTTL_PATTERN },
};

function getAttrTypeGuardClause(key, attrNamespace = 'attributes') {
  const ref = `${attrNamespace}["${key}"]`;
  if (attrNamespace === 'attributes' && key === 'rule_ids') {
    return `(${ref} != nil and not (IsString(${ref}) and (${ref} == "" or ${ref} == "[REDACTED_SENSITIVE_VALUE]" or (Len(${ref}) <= 3600 and not IsMatch(${ref}, "^(?:[^,]*,){50}") and not IsMatch(${ref}, "[^,]{72}") and IsMatch(${ref}, "${APPROVED_RULE_IDS_CSV_OTTL_PATTERN}")))) and not (IsList(${ref}) and Len(${ref}) <= 50 and not IsMatch(${ref}, "[^\\\\x22]{72}") and IsMatch(${ref}, "${APPROVED_RULE_ID_OTTL_PATTERN}")))`;
  }
  if (NUMERIC_COLLECTOR_KEYS.has(key)) {
    return `(${ref} != nil and not IsInt(${ref}) and not IsDouble(${ref}))`;
  }
  if (BOOLEAN_COLLECTOR_KEYS.has(key)) {
    return `(${ref} != nil and not IsBool(${ref}))`;
  }
  if (AUDIT_FLAG_COLLECTOR_KEYS.has(key)) {
    return `(${ref} != nil and not IsBool(${ref}) and ${ref} != "true" and ${ref} != "false")`;
  }
  if (
    attrNamespace === 'resource.attributes' ||
    Object.hasOwn(PATH_COLLECTOR_SCHEMAS, key) ||
    Object.hasOwn(BOUNDED_SCALAR_STRING_SCHEMAS, key) ||
    Object.hasOwn(BOUNDED_RESOURCE_STRING_SCHEMAS, key)
  ) {
    return `(${ref} != nil and not IsString(${ref}))`;
  }
  return `(${ref} != nil and not IsString(${ref}) and not IsBool(${ref}) and not IsInt(${ref}) and not IsDouble(${ref}))`;
}

export function extractNonScalarGuardedKeys(expr, attrNamespace = 'attributes') {
  if (typeof expr !== 'string' || !expr.trim()) return null;
  const parts = splitTopLevelDisjunction(expr.trim());
  if (!parts || parts.length === 0) return null;
  const escapedNs = escapeRegExp(attrNamespace);
  const keyExtractRegex = new RegExp(`^\\s*\\(?\\s*${escapedNs}\\["([^"]+)"\\]\\s*!=\\s*nil\\b`);
  const keys = new Set();
  for (const rawPart of parts) {
    const trimmedPart = rawPart.trim();
    const km = trimmedPart.match(keyExtractRegex);
    if (!km) return null;
    const key = km[1];
    const expectedNormalized = getAttrTypeGuardClause(key, attrNamespace).slice(1, -1).replace(/\s+/g, '');
    let candidate = trimmedPart;
    if (candidate.startsWith('(') && candidate.endsWith(')')) {
      candidate = candidate.slice(1, -1).trim();
    }
    if (candidate.replace(/\s+/g, '') !== expectedNormalized) {
      return null;
    }
    keys.add(key);
  }
  return keys;
}

export function buildNonScalarAttributeClauses(keys, attrNamespace = 'attributes', chunkSize = 10) {
  const sorted = [...keys].sort();
  const chunks = [];
  for (let i = 0; i < sorted.length; i += chunkSize) {
    chunks.push(sorted.slice(i, i + chunkSize).map(k => getAttrTypeGuardClause(k, attrNamespace)).join(' or '));
  }
  return chunks;
}

const REQUIRED_RESOURCE_KEYS = ['service.name', 'service.namespace', 'telemetry.sdk.version'];
const FORBIDDEN_METRIC_STMT_REGEX = /\b(?:aggregate_on_attributes|convert_exponential_histogram_to_histogram)\s*\(/;
const PREFLIGHT_RAW_RESOURCE_LEN_REGEX = /^set\s*\(\s*cache\["kty_raw_resource_len"\]\s*,\s*Len\(attributes\)\s*\)$/;
const PREFLIGHT_SCRUBBED_RESOURCE_LEN_REGEX = /^set\s*\(\s*cache\["kty_scrubbed_resource_len"\]\s*,\s*Len\(attributes\)\s*\)$/;
const PREFLIGHT_MARK_RESOURCE_OVERFLOW_REGEX =
  /^set\s*\(\s*attributes\["kty\.resource_overflow"\]\s*,\s*"drop"\s*\)\s+where\s+cache\["kty_scrubbed_resource_len"\]\s*<\s*cache\["kty_raw_resource_len"\]$/;
const PREFLIGHT_MARK_RESOURCE_NON_SCALAR_STMT_REGEX =
  /^set\s*\(\s*attributes\["kty\.resource_overflow"\]\s*,\s*"drop"\s*\)\s+where\s+(.+)$/;
const PREFLIGHT_RAW_SCOPE_LEN_REGEX = /^set\s*\(\s*cache\["kty_raw_scope_len"\]\s*,\s*Len\(attributes\)\s*\)$/;
const PREFLIGHT_MARK_SCOPE_OVERFLOW_REGEX =
  /^set\s*\(\s*attributes\["kty\.scope_overflow"\]\s*,\s*"drop"\s*\)\s+where\s+cache\["kty_raw_scope_len"\]\s*>\s*0$/;
const PREFLIGHT_RAW_LEN_REGEX = /^set\s*\(\s*cache\["kty_raw_len"\]\s*,\s*Len\(attributes\)\s*\)$/;
const PREFLIGHT_SCRUBBED_LEN_REGEX = /^set\s*\(\s*cache\["kty_scrubbed_len"\]\s*,\s*Len\(attributes\)\s*\)$/;
const PREFLIGHT_MARK_OVERFLOW_REGEX =
  /^set\s*\(\s*attributes\["kty\.scrubbed_overflow"\]\s*,\s*"drop"\s*\)\s+where\s+cache\["kty_scrubbed_len"\]\s*<\s*cache\["kty_raw_len"\]$/;
const PREFLIGHT_MARK_DP_NON_SCALAR_STMT_REGEX =
  /^set\s*\(\s*attributes\["kty\.scrubbed_overflow"\]\s*,\s*"drop"\s*\)\s+where\s+(.+)$/;
const TRACE_REDACT_STATUS_MSG_REGEX =
  /^set\s*\(\s*status\.message\s*,\s*"\[REDACTED_STATUS_MESSAGE\]"\s*\)\s+where\s+status\.message\s*!=\s*""$/;
const TRACE_REDACT_SPAN_NAME_REGEX = new RegExp(
  `^set\\s*\\(\\s*name\\s*,\\s*"\\[REDACTED_SPAN_NAME\\]"\\s*\\)\\s+where\\s+not\\s+IsMatch\\s*\\(\\s*name\\s*,\\s*"${escapeRegExp(APPROVED_SPAN_NAME_OTTL_PATTERN)}"\\s*\\)$`
);
const TRACE_REDACT_EVENT_NAME_REGEX = new RegExp(
  `^set\\s*\\(\\s*name\\s*,\\s*"\\[REDACTED_EVENT_NAME\\]"\\s*\\)\\s+where\\s+not\\s+IsMatch\\s*\\(\\s*name\\s*,\\s*"${escapeRegExp(APPROVED_EVENT_NAME_OTTL_PATTERN)}"\\s*\\)$`
);
const SCOPE_REDACT_NAME_REGEX = new RegExp(
  `^set\\s*\\(\\s*name\\s*,\\s*"\\[REDACTED_SCOPE_NAME\\]"\\s*\\)\\s+where\\s+name\\s*!=\\s*""\\s+and\\s+not\\s+IsMatch\\s*\\(\\s*name\\s*,\\s*"${escapeRegExp(APPROVED_SCOPE_NAME_OTTL_PATTERN)}"\\s*\\)$`
);
const SCOPE_PREFLIGHT_DROP_NAME_REGEX = new RegExp(
  `^set\\s*\\(\\s*attributes\\["kty\\.scope_overflow"\\]\\s*,\\s*"drop"\\s*\\)\\s+where\\s+name\\s*!=\\s*""\\s+and\\s+not\\s+IsMatch\\s*\\(\\s*name\\s*,\\s*"${escapeRegExp(APPROVED_SCOPE_NAME_OTTL_PATTERN)}"\\s*\\)$`
);
const SCOPE_CLEAR_VERSION_REGEX = new RegExp(
  `^set\\s*\\(\\s*version\\s*,\\s*""\\s*\\)\\s+where\\s+version\\s*!=\\s*""\\s+and\\s+not\\s+IsMatch\\s*\\(\\s*version\\s*,\\s*"${escapeRegExp(APPROVED_SCOPE_VERSION_OTTL_PATTERN)}"\\s*\\)$`
);
const SCOPE_CLEAR_SCHEMA_URL_REGEX =
  /^set\s*\(\s*schema_url\s*,\s*""\s*\)(?:\s+where\s+schema_url\s*!=\s*"")?$/;
const RESOURCE_CLEAR_SCHEMA_URL_REGEX = SCOPE_CLEAR_SCHEMA_URL_REGEX;
const TRACE_CLEAR_TRACE_STATE_REGEX =
  /^set\s*\(\s*trace_state\s*,\s*""\s*\)(?:\s+where\s+trace_state\s*!=\s*"")?$/;

export function buildScalarSchemaPredicate(attrKey, schema) {
  const extraParts = [];
  if (schema.rejectPattern) {
    extraParts.push(`IsMatch(attributes["${attrKey}"], "${schema.rejectPattern}")`);
  }
  if (Number.isInteger(schema.maxLength)) {
    extraParts.push(`Len(attributes["${attrKey}"]) > ${schema.maxLength}`);
  }
  const extraPrefix = extraParts.length > 0 ? `${extraParts.join(' or ')} or ` : '';
  return `attributes["${attrKey}"] != nil and (not IsString(attributes["${attrKey}"]) or ${extraPrefix}(attributes["${attrKey}"] != "" and attributes["${attrKey}"] != "[REDACTED_SENSITIVE_VALUE]" and not IsMatch(attributes["${attrKey}"], "${schema.pattern}")))`;
}

export function buildScalarSchemaRedactStmt(attrKey, schema) {
  const target = schema.redactTo || '[REDACTED_SENSITIVE_VALUE]';
  return `set(attributes["${attrKey}"], "${target}") where ${buildScalarSchemaPredicate(attrKey, schema)}`;
}

export function buildScalarSchemaPreflightDropStmt(attrKey, schema, overflowKey = 'kty.scrubbed_overflow') {
  return `set(attributes["${overflowKey}"], "drop") where ${buildScalarSchemaPredicate(attrKey, schema)}`;
}

export function buildLogTypeRedactStmt(key) {
  const inner = getAttrTypeGuardClause(key, 'attributes').slice(1, -1);
  return `set(attributes["${key}"], "[REDACTED_SENSITIVE_VALUE]") where ${inner}`;
}

function buildScalarAttrPredicateRegexPattern(attrKey, schema) {
  const k = escapeRegExp(attrKey);
  const p = escapeRegExp(schema.pattern);
  const extraParts = [];
  if (schema.rejectPattern) {
    extraParts.push(`IsMatch\\s*\\(\\s*attributes\\["${k}"\\]\\s*,\\s*"${escapeRegExp(schema.rejectPattern)}"\\s*\\)`);
  }
  if (Number.isInteger(schema.maxLength)) {
    extraParts.push(`Len\\(\\s*attributes\\["${k}"\\]\\s*\\)\\s*>\\s*${schema.maxLength}`);
  }
  const extraPrefix = extraParts.length > 0 ? `${extraParts.join('\\s+or\\s+')}\\s+or\\s+` : '';
  return `attributes\\["${k}"\\]\\s*!=\\s*nil\\s+and\\s+\\(\\s*not\\s+IsString\\s*\\(\\s*attributes\\["${k}"\\]\\s*\\)\\s+or\\s+${extraPrefix}\\(\\s*attributes\\["${k}"\\]\\s*!=\\s*""\\s+and\\s+attributes\\["${k}"\\]\\s*!=\\s*"\\[REDACTED_SENSITIVE_VALUE\\]"\\s+and\\s+not\\s+IsMatch\\s*\\(\\s*attributes\\["${k}"\\]\\s*,\\s*"${p}"\\s*\\)\\s*\\)\\s*\\)`;
}

function buildScalarRedactRegex(attrKey, schema) {
  const k = escapeRegExp(attrKey);
  const target = escapeRegExp(schema.redactTo || '[REDACTED_SENSITIVE_VALUE]');
  return new RegExp(`^set\\s*\\(\\s*attributes\\["${k}"\\]\\s*,\\s*"${target}"\\s*\\)\\s+where\\s+${buildScalarAttrPredicateRegexPattern(attrKey, schema)}$`);
}

function buildScalarPreflightDropRegex(attrKey, schema, overflowKey = 'kty.scrubbed_overflow') {
  const ok = escapeRegExp(overflowKey);
  return new RegExp(`^set\\s*\\(\\s*attributes\\["${ok}"\\]\\s*,\\s*"drop"\\s*\\)\\s+where\\s+${buildScalarAttrPredicateRegexPattern(attrKey, schema)}$`);
}

const PATH_REDACT_MATCHERS = Object.entries(PATH_COLLECTOR_SCHEMAS).map(([key, schema]) => ({
  key,
  tag: `redact_${key}`,
  regex: buildScalarRedactRegex(key, schema),
}));
const SCALAR_STRING_REDACT_MATCHERS = Object.entries(BOUNDED_SCALAR_STRING_SCHEMAS).map(([key, schema]) => ({
  key,
  tag: `redact_${key}`,
  regex: buildScalarRedactRegex(key, schema),
}));
const RESOURCE_STRING_REDACT_MATCHERS = Object.entries(BOUNDED_RESOURCE_STRING_SCHEMAS).map(([key, schema]) => ({
  key,
  tag: `redact_resource_${key}`,
  regex: buildScalarRedactRegex(key, schema),
}));
const DP_PREFLIGHT_DROP_MATCHERS = [
  ...Object.entries(PATH_COLLECTOR_SCHEMAS).map(([key, schema]) => ({
    key,
    tag: `drop_invalid_${key}`,
    regex: buildScalarPreflightDropRegex(key, schema, 'kty.scrubbed_overflow'),
  })),
  ...Object.entries(BOUNDED_SCALAR_STRING_SCHEMAS).map(([key, schema]) => ({
    key,
    tag: `drop_invalid_${key}`,
    regex: buildScalarPreflightDropRegex(key, schema, 'kty.scrubbed_overflow'),
  })),
];
const RESOURCE_PREFLIGHT_DROP_MATCHERS = Object.entries(BOUNDED_RESOURCE_STRING_SCHEMAS).map(([key, schema]) => ({
  key,
  tag: `drop_invalid_resource_${key}`,
  regex: buildScalarPreflightDropRegex(key, schema, 'kty.resource_overflow'),
}));
const LOG_TYPE_REDACT_MATCHER_KEYS = new Set([
  ...NUMERIC_COLLECTOR_KEYS,
  ...BOOLEAN_COLLECTOR_KEYS,
  ...AUDIT_FLAG_COLLECTOR_KEYS,
  'rule_ids',
]);
function matchLogTypeRedactStmt(stmt) {
  const m = stmt.match(/^set\s*\(\s*attributes\["([^"]+)"\]\s*,\s*"\[REDACTED_SENSITIVE_VALUE\]"\s*\)\s+where\s+(.+)$/);
  if (!m) return null;
  const [, key, cond] = m;
  if (!LOG_TYPE_REDACT_MATCHER_KEYS.has(key)) return null;
  const expectedInner = getAttrTypeGuardClause(key, 'attributes').slice(1, -1).replace(/\s+/g, '');
  if (cond.trim().replace(/\s+/g, '') !== expectedInner) return null;
  return `redact_type_${key}`;
}
const METRIC_CLEAR_DESCRIPTION_REGEX =
  /^set\s*\(\s*description\s*,\s*""\s*\)\s+where\s+description\s*!=\s*""$/;
const CROSS_CONTEXT_ATTR_REGEX = /\b(?:resource|scope|instrumentation_scope)\.attributes\b/;

/**
 * Validates an entire ordered OTTL statement list (without discarding non-keep_keys statements),
 * rejecting unreviewed writes, post-scrub mutations, conditional allowlists, and cross-context access.
 */
function inspectStatementList(statementBlocks, contextRules, labelPrefix, listName, errors) {
  const seenContexts = [];
  const state = Object.fromEntries(
    Object.keys(contextRules).map(ctx => [ctx, { keepKeyStmts: [], matchedStmts: [], events: [], blocks: [] }])
  );

  for (const block of statementBlocks) {
    if (!block || typeof block !== 'object') {
      errors.push(`${labelPrefix} ${listName} contains non-object statement block.`);
      continue;
    }
    const rule = contextRules[block.context];
    if (!rule) {
      errors.push(`${labelPrefix} ${listName} contains unreviewed context "${block.context}".`);
      if (Array.isArray(block.statements)) {
        for (const stmt of block.statements) {
          if (typeof stmt === 'string' && FORBIDDEN_METRIC_STMT_REGEX.test(stmt)) {
            errors.push(`${labelPrefix} ${listName} context "${block.context}" uses forbidden stateful/lossy OTTL statement: ${stmt.trim()}`);
          }
        }
      }
      continue;
    }
    seenContexts.push(block.context);
    if (!Array.isArray(block.statements)) {
      errors.push(`${labelPrefix} ${listName} context "${block.context}" is missing statements array.`);
      continue;
    }

    const uncond = isUnconditionalBlock(block);
    const blockEvents = [];
    for (const stmt of block.statements) {
      if (typeof stmt !== 'string') {
        errors.push(`${labelPrefix} ${listName} context "${block.context}" contains non-string statement.`);
        continue;
      }
      const trimmed = stmt.trim();
      if (FORBIDDEN_METRIC_STMT_REGEX.test(trimmed)) {
        errors.push(`${labelPrefix} ${listName} context "${block.context}" uses forbidden stateful/lossy OTTL statement: ${trimmed}`);
        continue;
      }
      if (CROSS_CONTEXT_ATTR_REGEX.test(trimmed)) {
        errors.push(`${labelPrefix} ${listName} context "${block.context}" contains forbidden cross-context attribute reference: ${trimmed}`);
        continue;
      }
      if (isUnconditionalKeepKeysStmt(trimmed)) {
        if (!uncond || !rule.allowKeepKeys) {
          errors.push(`${labelPrefix} ${listName} context "${block.context}" has conditional or unreviewed keep_keys statement: ${trimmed}`);
          continue;
        }
        state[block.context].keepKeyStmts.push(trimmed);
        state[block.context].events.push('keep_keys');
        blockEvents.push('keep_keys');
        continue;
      }

      const tag = rule.matchOtherStmt ? rule.matchOtherStmt(trimmed, uncond) : null;
      if (!tag) {
        errors.push(
          `${labelPrefix} ${listName} context "${block.context}" contains unreviewed OTTL statement${uncond ? '' : ' in conditional block'}: ${trimmed}`
        );
        continue;
      }
      state[block.context].matchedStmts.push({ stmt: trimmed, tag });
      state[block.context].events.push(tag);
      blockEvents.push(tag);
    }
    state[block.context].blocks.push({ uncond, events: blockEvents });
  }

  return { state, seenContexts };
}

function checkSensitiveKeys(keySet, contextLabel, labelPrefix, errors) {
  const collectorProhibitedKeys = ['agreement_title', 'hospital_id', 'household_size', 'fpl_percentage', 'http.target', 'span.name'];
  const canonicalSet = contextLabel.includes('resource')
    ? CANONICAL_COLLECTOR_RESOURCE_KEYS
    : CANONICAL_COLLECTOR_ALLOWED_KEYS;
  for (const badKey of collectorProhibitedKeys) {
    if (keySet.has(badKey)) {
      errors.push(`${labelPrefix} ${contextLabel} must exclude sensitive/unverified key "${badKey}".`);
    }
  }
  for (const key of keySet) {
    if (!canonicalSet.has(key) && !collectorProhibitedKeys.includes(key)) {
      errors.push(`${labelPrefix} ${contextLabel} includes unreviewed key "${key}" missing from canonical collector allowlist.`);
    }
  }
}

/**
 * Evaluates sequential unconditional keep_keys(attributes, [...]) statements.
 * Because OTTL statements execute sequentially, only the key intersection
 * survives all statements, while prohibited/non-empty scope checks apply per statement.
 */
function evaluateKeepKeysStatements(
  stmts,
  {
    contextLabel,
    labelPrefix,
    errors,
    requireEmptyEach = false,
    emptyScopeError = null,
    requireNonEmptyResult = false,
    nonEmptyError = null,
  }
) {
  let intersected = null;
  let hadScopeViolation = false;

  for (const stmt of stmts) {
    const keys = extractKeysList(stmt, /keep_keys\s*\(\s*attributes\s*,\s*\[([^\]]*)\]/);
    if (!keys) {
      errors.push(`${labelPrefix} unable to extract allowlisted keys array from keep_keys statement.`);
      continue;
    }

    checkSensitiveKeys(keys, contextLabel, labelPrefix, errors);

    if (requireEmptyEach && keys.size > 0 && !hadScopeViolation) {
      errors.push(emptyScopeError);
      hadScopeViolation = true;
    }

    if (intersected === null) {
      intersected = new Set(keys);
    } else {
      for (const existing of intersected) {
        if (!keys.has(existing)) {
          intersected.delete(existing);
        }
      }
    }
  }

  const effectiveKeys = intersected ?? new Set();
  if (requireNonEmptyResult && effectiveKeys.size === 0) {
    errors.push(nonEmptyError || `${labelPrefix} ${contextLabel} effective allowlist is empty.`);
  }
  return effectiveKeys;
}

export function auditCollectorConfigObject(
  config,
  errors = [],
  { schemaContent = null, labelPrefix = 'collector/otel-collector-config.yaml', requireSpanmetrics = true, requireCanonicalExact = false } = {}
) {
  const transform = config?.processors?.transform;
  if (!transform || !Array.isArray(transform.trace_statements)) {
    errors.push(`${labelPrefix} missing processors.transform.trace_statements.`);
    return { allowlistedKeys: new Set(), resourceKeys: new Set() };
  }
  if (transform.error_mode !== 'propagate') {
    errors.push(`${labelPrefix} processors.transform must set error_mode: propagate for fail-closed scrubbing.`);
  }

  const REQUIRED_SCOPE_METADATA_EVENTS = ['redact_scope_name', 'clear_scope_version', 'clear_scope_schema_url'];
  const resourceMetadataMatch = (stmt, uncond) => {
    if (!uncond) return null;
    if (RESOURCE_CLEAR_SCHEMA_URL_REGEX.test(stmt)) return 'clear_resource_schema_url';
    return null;
  };
  const resourceRedactMatch = (stmt, uncond) => {
    const metaTag = resourceMetadataMatch(stmt, uncond);
    if (metaTag) return metaTag;
    if (!uncond) return null;
    for (const matcher of RESOURCE_STRING_REDACT_MATCHERS) {
      if (matcher.regex.test(stmt)) return matcher.tag;
    }
    return null;
  };
  const pathOnlyMatch = (stmt, uncond) => {
    if (!uncond) return null;
    for (const matcher of PATH_REDACT_MATCHERS) {
      if (matcher.regex.test(stmt)) return matcher.tag;
    }
    return null;
  };
  const attrSanitizationMatch = (stmt, uncond) => {
    const pathTag = pathOnlyMatch(stmt, uncond);
    if (pathTag) return pathTag;
    if (!uncond) return null;
    for (const matcher of SCALAR_STRING_REDACT_MATCHERS) {
      if (matcher.regex.test(stmt)) return matcher.tag;
    }
    return null;
  };
  const scopeMetadataMatch = (stmt, uncond) => {
    if (!uncond) return null;
    if (SCOPE_REDACT_NAME_REGEX.test(stmt)) return 'redact_scope_name';
    if (SCOPE_CLEAR_VERSION_REGEX.test(stmt)) return 'clear_scope_version';
    if (SCOPE_CLEAR_SCHEMA_URL_REGEX.test(stmt)) return 'clear_scope_schema_url';
    return null;
  };

  // 1. Inspect ordered trace_statements across resource, scope, span, and spanevent
  const traceInspection = inspectStatementList(
    transform.trace_statements,
    {
      resource: { allowKeepKeys: true, matchOtherStmt: resourceRedactMatch },
      scope: { allowKeepKeys: true, matchOtherStmt: scopeMetadataMatch },
      span: {
        allowKeepKeys: true,
        matchOtherStmt: (stmt, uncond) => {
          if (!uncond) return null;
          if (/^set\s*\(\s*attributes\["audit\.(?:collector_verified|allowlist_enforced)"\]\s*,\s*"true"\s*\)$/.test(stmt)) {
            return 'audit_marker';
          }
          if (TRACE_REDACT_STATUS_MSG_REGEX.test(stmt)) {
            return 'redact_status_message';
          }
          if (TRACE_CLEAR_TRACE_STATE_REGEX.test(stmt)) {
            return 'clear_trace_state';
          }
          if (TRACE_REDACT_SPAN_NAME_REGEX.test(stmt)) {
            return 'redact_span_name';
          }
          return attrSanitizationMatch(stmt, uncond);
        },
      },
      spanevent: {
        allowKeepKeys: true,
        matchOtherStmt: (stmt, uncond) => {
          if (!uncond) return null;
          if (TRACE_REDACT_EVENT_NAME_REGEX.test(stmt)) {
            return 'redact_event_name';
          }
          return attrSanitizationMatch(stmt, uncond);
        },
      },
    },
    labelPrefix,
    'transform.trace_statements',
    errors
  );

  if (!traceInspection.state.resource.events.includes('clear_resource_schema_url')) {
    errors.push(`${labelPrefix} trace_statements context: resource missing unconditional clear_resource_schema_url statement.`);
  }
  if (!traceInspection.state.span.events.includes('redact_status_message')) {
    errors.push(`${labelPrefix} trace_statements context: span must unconditionally redact non-empty status.message before export.`);
  }
  if (!traceInspection.state.span.events.includes('clear_trace_state')) {
    errors.push(`${labelPrefix} trace_statements context: span must unconditionally clear non-empty trace_state before export.`);
  }
  if (!traceInspection.state.span.events.includes('redact_span_name')) {
    errors.push(`${labelPrefix} trace_statements context: span must unconditionally normalize non-allowlisted span name before export.`);
  }
  if (!traceInspection.state.spanevent.events.includes('redact_event_name')) {
    errors.push(`${labelPrefix} trace_statements context: spanevent must unconditionally normalize non-allowlisted event name before export.`);
  }
  for (const ev of REQUIRED_SCOPE_METADATA_EVENTS) {
    if (!traceInspection.state.scope.events.includes(ev)) {
      errors.push(`${labelPrefix} trace_statements context: scope missing unconditional ${ev} statement.`);
    }
  }

  const resourceStmts = traceInspection.state.resource.keepKeyStmts;
  let traceResourceKeys = new Set();
  if (resourceStmts.length === 0) {
    errors.push(`${labelPrefix} missing unconditional trace_statements keep_keys in context: resource.`);
  } else {
    traceResourceKeys = evaluateKeepKeysStatements(resourceStmts, {
      contextLabel: 'trace resource allowlist',
      labelPrefix,
      errors,
    });
  }

  const traceScopeStmts = traceInspection.state.scope.keepKeyStmts;
  if (traceScopeStmts.length === 0) {
    errors.push(`${labelPrefix} missing unconditional trace_statements keep_keys in context: scope.`);
  } else {
    evaluateKeepKeysStatements(traceScopeStmts, {
      contextLabel: 'trace scope allowlist',
      labelPrefix,
      errors,
      requireEmptyEach: true,
      emptyScopeError: `${labelPrefix} trace_statements scope keep_keys must clear instrumentation-scope attributes ([]).`,
    });
  }

  const spanStmts = traceInspection.state.span.keepKeyStmts;
  if (spanStmts.length === 0) {
    errors.push(`${labelPrefix} must configure unconditional keep_keys(attributes, [...]) in trace_statements context: span.`);
    return { allowlistedKeys: new Set(), resourceKeys: traceResourceKeys };
  }

  const allowlistedKeys = evaluateKeepKeysStatements(spanStmts, {
    contextLabel: 'span allowlist',
    labelPrefix,
    errors,
    requireNonEmptyResult: true,
    nonEmptyError: `${labelPrefix} unable to extract allowlisted keys array from keep_keys statement.`,
  });
  if (allowlistedKeys.size === 0) {
    return { allowlistedKeys, resourceKeys: traceResourceKeys };
  }

  const spanEventStmts = traceInspection.state.spanevent.keepKeyStmts;
  if (spanEventStmts.length === 0) {
    errors.push(`${labelPrefix} missing unconditional trace_statements keep_keys in context: spanevent.`);
  } else {
    const spanEventKeys = evaluateKeepKeysStatements(spanEventStmts, {
      contextLabel: 'spanevent allowlist',
      labelPrefix,
      errors,
    });
    compareKeySets(allowlistedKeys, spanEventKeys, `${labelPrefix} spanevent keep_keys`, errors);
  }

  // 2. Verify spanmetrics connector dimensions are strictly within allowlist and closed finite enums, and exclude span.name
  const RESERVED_SPANMETRICS_DIMENSIONS = new Set(['service.name', 'span.kind', 'status.code']);
  const SPANMETRICS_CLOSED_DOMAIN_DIMENSIONS = new Set([
    'status',
    'jurisdiction',
    'telemetry.sdk.language',
    'telemetry.sdk.name',
  ]);
  if (requireSpanmetrics) {
    const spanmetrics = config.connectors && config.connectors.spanmetrics;
    if (!spanmetrics || !Array.isArray(spanmetrics.dimensions)) {
      errors.push(`${labelPrefix} missing connectors.spanmetrics.dimensions array.`);
    } else {
      for (const dim of spanmetrics.dimensions) {
        const dimName = dim && dim.name;
        if (!dimName) {
          errors.push('Spanmetrics dimension missing name attribute.');
          continue;
        }
        if (RESERVED_SPANMETRICS_DIMENSIONS.has(dimName)) {
          errors.push(
            `${labelPrefix} connectors.spanmetrics.dimensions must not include OTel-reserved core dimension "${dimName}" (spanmetrics emits service.name, span.kind, and status.code by default without listing them in dimensions).`
          );
          continue;
        }
        if (!allowlistedKeys.has(dimName)) {
          errors.push(
            `Spanmetrics dimension "${dimName}" is not in the OTTL keep_keys allowlist. All metrics dimensions must be scrubbed allowlisted attributes.`
          );
        }
        if (!SPANMETRICS_CLOSED_DOMAIN_DIMENSIONS.has(dimName)) {
          errors.push(
            `${labelPrefix} connectors.spanmetrics.dimensions entry "${dimName}" has an unbounded domain; v0.118.0 cumulative spanmetrics maps retain per-series state per resource, so dimensions must use closed finite enums (${[...SPANMETRICS_CLOSED_DOMAIN_DIMENSIONS].join(', ')}).`
          );
        }
      }
      if (!Array.isArray(spanmetrics.exclude_dimensions) || !spanmetrics.exclude_dimensions.includes('span.name')) {
        errors.push(
          `${labelPrefix} connectors.spanmetrics.exclude_dimensions must include "span.name" to prevent unallowlisted high-cardinality span names in exported metrics.`
        );
      }
      if ('aggregation_cardinality_limit' in spanmetrics) {
        errors.push(
          `${labelPrefix} connectors.spanmetrics.aggregation_cardinality_limit is unsupported in otel/opentelemetry-collector-contrib:0.118.0; configure dimensions_cache_size, resource_metrics_cache_size, and metrics_expiration instead.`
        );
      }
      for (const [cacheKey, maxVal] of [
        ['dimensions_cache_size', 10000],
        ['resource_metrics_cache_size', 10000],
      ]) {
        const cacheVal = spanmetrics[cacheKey];
        if (typeof cacheVal !== 'number' || !Number.isInteger(cacheVal) || cacheVal <= 0 || cacheVal > maxVal) {
          errors.push(
            `${labelPrefix} connectors.spanmetrics.${cacheKey} must be a positive integer <= ${maxVal} to bound v0.118.0 spanmetrics series cardinality.`
          );
        }
      }
      const expRaw = spanmetrics.metrics_expiration;
      const expValid = (() => {
        if (typeof expRaw !== 'string' || !/^(?:\d+(?:ns|us|µs|ms|s|m|h))+$/.test(expRaw.trim())) return false;
        const unitMs = { ns: 1e-6, us: 1e-3, 'µs': 1e-3, ms: 1, s: 1000, m: 60000, h: 3600000 };
        let totalMs = 0;
        for (const m of expRaw.trim().matchAll(/(\d+)(ns|us|µs|ms|s|m|h)/g)) {
          totalMs += Number(m[1]) * unitMs[m[2]];
        }
        return totalMs > 0 && totalMs <= 24 * 3600000;
      })();
      if (!expValid) {
        errors.push(
          `${labelPrefix} connectors.spanmetrics.metrics_expiration must be a positive Go duration <= 24h (e.g. "180m") to evict stale spanmetrics series.`
        );
      }
    }
  }

  if (resourceStmts.length > 0) {
    for (const reqResKey of REQUIRED_RESOURCE_KEYS) {
      if (!traceResourceKeys.has(reqResKey)) {
        errors.push(`${labelPrefix} trace_statements resource keep_keys missing required resource key "${reqResKey}".`);
      }
    }
  }

  const checkNonScalarCoverage = (expectedKeys, guardedKeys, label) => {
    for (const key of expectedKeys) {
      if (!guardedKeys.has(key)) {
        errors.push(`${label} missing non-scalar / strict-type attribute guard for allowlisted key "${key}".`);
      }
    }
  };

  // 2b. Verify filter/drop_noncompliant_traces (drops SpanLinks and non-scalar attribute values fail-closed),
  //     transform/metrics_preflight (strips resource/scope/datapoint attrs cleanly & flags overflow/non-scalar),
  //     and filter/drop_noncompliant_metrics.
  const dropTraceFilter = config?.processors?.['filter/drop_noncompliant_traces'];
  const dropTraceSpanConditions = dropTraceFilter?.traces?.span;
  const dropTraceEventConditions = dropTraceFilter?.traces?.spanevent;
  let hasLinksDropPredicate = false;
  const guardedTraceSpanResKeys = new Set();
  const guardedTraceSpanAttrKeys = new Set();
  if (Array.isArray(dropTraceSpanConditions)) {
    for (const cond of dropTraceSpanConditions) {
      if (typeof cond !== 'string') {
        errors.push(`${labelPrefix} filter/drop_noncompliant_traces.traces.span contains non-string condition.`);
        continue;
      }
      if (cond.replace(/\s+/g, '') === 'Len(links)>0') {
        hasLinksDropPredicate = true;
        continue;
      }
      const resKeys = extractNonScalarGuardedKeys(cond, 'resource.attributes');
      if (resKeys) {
        for (const k of resKeys) guardedTraceSpanResKeys.add(k);
        continue;
      }
      const attrKeys = extractNonScalarGuardedKeys(cond, 'attributes');
      if (attrKeys) {
        for (const k of attrKeys) guardedTraceSpanAttrKeys.add(k);
        continue;
      }
      errors.push(`${labelPrefix} filter/drop_noncompliant_traces.traces.span contains unreviewed condition: ${cond}`);
    }
  }
  if (!dropTraceFilter || dropTraceFilter.error_mode !== 'propagate' || !hasLinksDropPredicate) {
    errors.push(
      `${labelPrefix} missing processors.filter/drop_noncompliant_traces (error_mode: propagate, traces.span dropping 'Len(links) > 0').`
    );
  }
  const guardedTraceEventAttrKeys = new Set();
  if (Array.isArray(dropTraceEventConditions)) {
    for (const cond of dropTraceEventConditions) {
      if (typeof cond !== 'string') {
        errors.push(`${labelPrefix} filter/drop_noncompliant_traces.traces.spanevent contains non-string condition.`);
        continue;
      }
      const attrKeys = extractNonScalarGuardedKeys(cond, 'attributes');
      if (attrKeys) {
        for (const k of attrKeys) guardedTraceEventAttrKeys.add(k);
        continue;
      }
      errors.push(`${labelPrefix} filter/drop_noncompliant_traces.traces.spanevent contains unreviewed condition: ${cond}`);
    }
  } else {
    errors.push(`${labelPrefix} missing processors.filter/drop_noncompliant_traces.traces.spanevent non-scalar attribute guards.`);
  }
  if (traceResourceKeys.size > 0) {
    checkNonScalarCoverage(traceResourceKeys, guardedTraceSpanResKeys, `${labelPrefix} filter/drop_noncompliant_traces.traces.span resource`);
  }
  checkNonScalarCoverage(allowlistedKeys, guardedTraceSpanAttrKeys, `${labelPrefix} filter/drop_noncompliant_traces.traces.span`);
  checkNonScalarCoverage(allowlistedKeys, guardedTraceEventAttrKeys, `${labelPrefix} filter/drop_noncompliant_traces.traces.spanevent`);

  const guardedPreflightResKeys = new Set();
  const guardedPreflightDpKeys = new Set();
  const preflight = config?.processors?.['transform/metrics_preflight'];
  if (!preflight || !Array.isArray(preflight.metric_statements)) {
    errors.push(`${labelPrefix} missing processors.transform/metrics_preflight.metric_statements.`);
  } else {
    if (preflight.error_mode !== 'propagate') {
      errors.push(`${labelPrefix} processors.transform/metrics_preflight must set error_mode: propagate.`);
    }
    const preflightInspection = inspectStatementList(
      preflight.metric_statements,
      {
        resource: {
          allowKeepKeys: true,
          matchOtherStmt: (stmt, uncond) => {
            if (!uncond) return null;
            if (PREFLIGHT_RAW_RESOURCE_LEN_REGEX.test(stmt)) return 'cache_raw_resource_len';
            if (PREFLIGHT_SCRUBBED_RESOURCE_LEN_REGEX.test(stmt)) return 'cache_scrubbed_resource_len';
            if (PREFLIGHT_MARK_RESOURCE_OVERFLOW_REGEX.test(stmt)) return 'mark_resource_overflow';
            for (const matcher of RESOURCE_PREFLIGHT_DROP_MATCHERS) {
              if (matcher.regex.test(stmt)) return matcher.tag;
            }
            const nonScalarMatch = stmt.match(PREFLIGHT_MARK_RESOURCE_NON_SCALAR_STMT_REGEX);
            if (nonScalarMatch) {
              const keys = extractNonScalarGuardedKeys(nonScalarMatch[1], 'attributes');
              if (keys && keys.size > 0) {
                for (const k of keys) guardedPreflightResKeys.add(k);
                return 'mark_resource_non_scalar';
              }
            }
            return resourceMetadataMatch(stmt, uncond);
          },
        },
        scope: {
          allowKeepKeys: true,
          matchOtherStmt: (stmt, uncond) => {
            if (!uncond) return null;
            if (PREFLIGHT_RAW_SCOPE_LEN_REGEX.test(stmt)) return 'cache_raw_scope_len';
            if (PREFLIGHT_MARK_SCOPE_OVERFLOW_REGEX.test(stmt)) return 'mark_scope_overflow';
            if (SCOPE_PREFLIGHT_DROP_NAME_REGEX.test(stmt)) return 'drop_invalid_scope_name';
            if (SCOPE_CLEAR_VERSION_REGEX.test(stmt)) return 'clear_scope_version';
            if (SCOPE_CLEAR_SCHEMA_URL_REGEX.test(stmt)) return 'clear_scope_schema_url';
            return null;
          },
        },
        datapoint: {
          allowKeepKeys: true,
          matchOtherStmt: (stmt, uncond) => {
            if (!uncond) return null;
            if (PREFLIGHT_RAW_LEN_REGEX.test(stmt)) return 'cache_raw_len';
            if (PREFLIGHT_SCRUBBED_LEN_REGEX.test(stmt)) return 'cache_scrubbed_len';
            if (PREFLIGHT_MARK_OVERFLOW_REGEX.test(stmt)) return 'mark_overflow';
            for (const matcher of DP_PREFLIGHT_DROP_MATCHERS) {
              if (matcher.regex.test(stmt)) return matcher.tag;
            }
            const nonScalarMatch = stmt.match(PREFLIGHT_MARK_DP_NON_SCALAR_STMT_REGEX);
            if (nonScalarMatch) {
              const keys = extractNonScalarGuardedKeys(nonScalarMatch[1], 'attributes');
              if (keys && keys.size > 0) {
                for (const k of keys) guardedPreflightDpKeys.add(k);
                return 'mark_non_scalar';
              }
            }
            return null;
          },
        },
      },
      labelPrefix,
      'transform/metrics_preflight.metric_statements',
      errors
    );

    const resBlocks = preflightInspection.state.resource.blocks;
    const expectedResPrefix = ['cache_raw_resource_len', 'keep_keys', 'cache_scrubbed_resource_len', 'mark_resource_overflow'];
    const resEvents = resBlocks[0]?.events || [];
    const resTail = resEvents.slice(expectedResPrefix.length);
    let resNonScalarCount = 0;
    while (resNonScalarCount < resTail.length && resTail[resNonScalarCount] === 'mark_resource_non_scalar') {
      resNonScalarCount += 1;
    }
    const resPostNonScalar = resTail.slice(resNonScalarCount);
    const allowedResDropEvents = new Set(RESOURCE_PREFLIGHT_DROP_MATCHERS.map(m => m.tag));
    const resHasTrailingClear = resPostNonScalar.length >= 1 && resPostNonScalar[resPostNonScalar.length - 1] === 'clear_resource_schema_url';
    const resDrops = resHasTrailingClear ? resPostNonScalar.slice(0, -1) : [];
    const resBlockOk =
      resBlocks.length === 1 &&
      expectedResPrefix.every((ev, i) => resEvents[i] === ev) &&
      resNonScalarCount >= 1 &&
      resHasTrailingClear &&
      resDrops.every(ev => allowedResDropEvents.has(ev));
    if (!resBlockOk) {
      errors.push(
        `${labelPrefix} transform/metrics_preflight context: resource must strictly execute [${expectedResPrefix.join(', ')}, ...mark_resource_non_scalar, ...drop_invalid_resource_values, clear_resource_schema_url] within one statement block (found blocks: ${JSON.stringify(resBlocks.map(b => b.events))}).`
      );
    }

    const preflightResStmts = preflightInspection.state.resource.keepKeyStmts;
    if (preflightResStmts.length === 0) {
      errors.push(`${labelPrefix} missing unconditional transform/metrics_preflight resource keep_keys.`);
    } else {
      const preflightResKeys = evaluateKeepKeysStatements(preflightResStmts, {
        contextLabel: 'preflight metric resource allowlist',
        labelPrefix,
        errors,
      });
      compareKeySets(traceResourceKeys, preflightResKeys, `${labelPrefix} transform/metrics_preflight resource keep_keys`, errors);
      checkNonScalarCoverage(preflightResKeys, guardedPreflightResKeys, `${labelPrefix} transform/metrics_preflight resource`);
      for (const matcher of RESOURCE_PREFLIGHT_DROP_MATCHERS) {
        if (preflightResKeys.has(matcher.key) && !preflightInspection.state.resource.events.includes(matcher.tag)) {
          errors.push(
            `${labelPrefix} transform/metrics_preflight context: resource missing unconditional ${matcher.tag} guard for "${matcher.key}".`
          );
        }
      }
    }

    const scopeBlocks = preflightInspection.state.scope.blocks;
    const expectedScopeSeq = [
      'cache_raw_scope_len',
      'keep_keys',
      'mark_scope_overflow',
      'drop_invalid_scope_name',
      'clear_scope_version',
      'clear_scope_schema_url',
    ];
    const scopeBlockOk =
      scopeBlocks.length === 1 &&
      scopeBlocks[0].events.length === expectedScopeSeq.length &&
      expectedScopeSeq.every((ev, i) => scopeBlocks[0].events[i] === ev);
    if (!scopeBlockOk) {
      errors.push(
        `${labelPrefix} transform/metrics_preflight context: scope must strictly execute [${expectedScopeSeq.join(', ')}] within one statement block (found blocks: ${JSON.stringify(scopeBlocks.map(b => b.events))}).`
      );
    }

    const preflightScopeStmts = preflightInspection.state.scope.keepKeyStmts;
    if (preflightScopeStmts.length === 0) {
      errors.push(`${labelPrefix} missing unconditional transform/metrics_preflight scope keep_keys.`);
    } else {
      evaluateKeepKeysStatements(preflightScopeStmts, {
        contextLabel: 'preflight metric scope allowlist',
        labelPrefix,
        errors,
        requireEmptyEach: true,
        emptyScopeError: `${labelPrefix} transform/metrics_preflight scope keep_keys must clear instrumentation-scope attributes ([]).`,
      });
    }

    const dpBlocks = preflightInspection.state.datapoint.blocks;
    const expectedSeq = ['cache_raw_len', 'keep_keys', 'cache_scrubbed_len', 'mark_overflow'];
    const dpEvents = dpBlocks[0]?.events || [];
    const dpTail = dpEvents.slice(expectedSeq.length);
    let nonScalarCount = 0;
    while (nonScalarCount < dpTail.length && dpTail[nonScalarCount] === 'mark_non_scalar') {
      nonScalarCount += 1;
    }
    const postNonScalar = dpTail.slice(nonScalarCount);
    const allowedDropEvents = new Set(DP_PREFLIGHT_DROP_MATCHERS.map(m => m.tag));
    const dpBlockOk =
      dpBlocks.length === 1 &&
      dpEvents.length >= expectedSeq.length + 1 &&
      expectedSeq.every((ev, i) => dpEvents[i] === ev) &&
      nonScalarCount >= 1 &&
      postNonScalar.every(ev => allowedDropEvents.has(ev));
    if (!dpBlockOk) {
      errors.push(
        `${labelPrefix} transform/metrics_preflight context: datapoint must strictly execute [${expectedSeq.join(', ')}, ...mark_non_scalar, ...drop_invalid_values] within one statement block (found blocks: ${JSON.stringify(dpBlocks.map(b => b.events))}).`
      );
    }

    const preflightDpStmts = preflightInspection.state.datapoint.keepKeyStmts;
    if (preflightDpStmts.length > 0) {
      const preflightDpKeys = evaluateKeepKeysStatements(preflightDpStmts, {
        contextLabel: 'preflight metric datapoint allowlist',
        labelPrefix,
        errors,
      });
      compareKeySets(allowlistedKeys, preflightDpKeys, `${labelPrefix} transform/metrics_preflight datapoint keep_keys`, errors);
      checkNonScalarCoverage(preflightDpKeys, guardedPreflightDpKeys, `${labelPrefix} transform/metrics_preflight datapoint`);
    }
    for (const matcher of DP_PREFLIGHT_DROP_MATCHERS) {
      if (allowlistedKeys.has(matcher.key) && !preflightInspection.state.datapoint.events.includes(matcher.tag)) {
        errors.push(
          `${labelPrefix} transform/metrics_preflight context: datapoint missing unconditional ${matcher.tag} guard for "${matcher.key}".`
        );
      }
    }
  }

  const dropFilter = config?.processors?.['filter/drop_noncompliant_metrics'];
  const dropMetricConditions = dropFilter?.metrics?.metric;
  const dropDatapointConditions = dropFilter?.metrics?.datapoint;
  const normalizedMetricConditions = new Set(
    Array.isArray(dropMetricConditions) ? dropMetricConditions.filter(c => typeof c === 'string').map(normalizeOttlExpr) : []
  );
  const REQUIRED_METRIC_PREDICATES = [
    { name: 'kty.resource_overflow', expr: 'resource.attributes["kty.resource_overflow"] == "drop"' },
    { name: 'kty.scope_overflow', expr: 'instrumentation_scope.attributes["kty.scope_overflow"] == "drop"' },
    {
      name: 'name',
      expr: 'name != "calls" and name != "duration" and name != "traces.span.metrics.calls" and name != "traces.span.metrics.duration"',
    },
    {
      name: 'duration unit',
      expr: '(name == "duration" or name == "traces.span.metrics.duration") and unit != "ms" and unit != "s"',
    },
    {
      name: 'calls unit',
      expr: '(name == "calls" or name == "traces.span.metrics.calls") and unit != "" and unit != "1" and unit != "{call}" and unit != "{calls}"',
    },
  ];
  const missingMetricPredicates = REQUIRED_METRIC_PREDICATES.filter(p => !normalizedMetricConditions.has(p.expr)).map(p => p.name);
  const hasDpDropPredicate =
    Array.isArray(dropDatapointConditions) &&
    dropDatapointConditions.some(c => typeof c === 'string' && normalizeOttlExpr(c) === 'attributes["kty.scrubbed_overflow"] == "drop"');
  const hasExemplarDropPredicate =
    Array.isArray(dropDatapointConditions) &&
    dropDatapointConditions.some(
      c =>
        typeof c === 'string' &&
        /^metric\.type\s*!=\s*METRIC_DATA_TYPE_SUMMARY\s+and\s+metric\.type\s*!=\s*METRIC_DATA_TYPE_NONE\s+and\s+Len\(\s*exemplars\s*\)\s*>\s*0$/.test(
          c.trim()
        )
    );
  if (!dropFilter || dropFilter.error_mode !== 'propagate' || missingMetricPredicates.length > 0 || !hasDpDropPredicate || !hasExemplarDropPredicate) {
    errors.push(
      `${labelPrefix} missing processors.filter/drop_noncompliant_metrics (error_mode: propagate, metrics.metric [${missingMetricPredicates.join(', ') || 'verified'}], and metrics.datapoint dropping kty.scrubbed_overflow == "drop" and guarded Len(exemplars) > 0).`
    );
  }

  // 3. Verify transform.metric_statements resource, scope, metric description scrubbing, and datapoint keep_keys (no stateful metric aggregation)
  let metricInspection = null;
  if (!Array.isArray(transform.metric_statements)) {
    errors.push(`${labelPrefix} missing processors.transform.metric_statements.`);
  } else {
    metricInspection = inspectStatementList(
      transform.metric_statements,
      {
        resource: {
          allowKeepKeys: true,
          matchOtherStmt: (stmt, uncond) => {
            if (!uncond) return null;
            for (const matcher of RESOURCE_STRING_REDACT_MATCHERS) {
              if (matcher.regex.test(stmt)) {
                errors.push(
                  `${labelPrefix} transform.metric_statements context: resource must not mutate cumulative series identity attribute "${matcher.key}" to "[REDACTED_SENSITIVE_VALUE]" (reject in transform/metrics_preflight instead): ${stmt}`
                );
                return `forbidden_res_${matcher.tag}`;
              }
            }
            return resourceMetadataMatch(stmt, uncond);
          },
        },
        scope: { allowKeepKeys: true, matchOtherStmt: scopeMetadataMatch },
        metric: {
          allowKeepKeys: false,
          matchOtherStmt: (stmt, uncond) => {
            if (!uncond) return null;
            if (METRIC_CLEAR_DESCRIPTION_REGEX.test(stmt)) return 'clear_metric_description';
            return null;
          },
        },
        datapoint: {
          allowKeepKeys: true,
          matchOtherStmt: (stmt, uncond) => {
            if (!uncond) return null;
            for (const matcher of SCALAR_STRING_REDACT_MATCHERS) {
              if (matcher.regex.test(stmt)) {
                errors.push(
                  `${labelPrefix} transform.metric_statements context: datapoint must not mutate cumulative series identity attribute "${matcher.key}" to "[REDACTED_SENSITIVE_VALUE]" (reject in transform/metrics_preflight instead): ${stmt}`
                );
                return 'forbidden_dp_dim_mutation';
              }
            }
            return pathOnlyMatch(stmt, uncond);
          },
        },
      },
      labelPrefix,
      'transform.metric_statements',
      errors
    );

    if (!metricInspection.state.resource.events.includes('clear_resource_schema_url')) {
      errors.push(`${labelPrefix} metric_statements context: resource missing unconditional clear_resource_schema_url statement.`);
    }
    if (!metricInspection.state.metric.events.includes('clear_metric_description')) {
      errors.push(`${labelPrefix} transform.metric_statements context: metric must unconditionally clear non-empty description.`);
    }
    for (const ev of REQUIRED_SCOPE_METADATA_EVENTS) {
      if (!metricInspection.state.scope.events.includes(ev)) {
        errors.push(`${labelPrefix} metric_statements context: scope missing unconditional ${ev} statement.`);
      }
    }

    const metricResStmts = metricInspection.state.resource.keepKeyStmts;
    if (metricResStmts.length === 0) {
      errors.push(`${labelPrefix} missing unconditional metric_statements keep_keys in context: resource.`);
    } else {
      const metricResKeys = evaluateKeepKeysStatements(metricResStmts, {
        contextLabel: 'metric resource allowlist',
        labelPrefix,
        errors,
      });
      compareKeySets(traceResourceKeys, metricResKeys, `${labelPrefix} metric resource keep_keys`, errors);
    }

    const metricScopeStmts = metricInspection.state.scope.keepKeyStmts;
    if (metricScopeStmts.length === 0) {
      errors.push(`${labelPrefix} missing unconditional metric_statements keep_keys in context: scope.`);
    } else {
      evaluateKeepKeysStatements(metricScopeStmts, {
        contextLabel: 'metric scope allowlist',
        labelPrefix,
        errors,
        requireEmptyEach: true,
        emptyScopeError: `${labelPrefix} metric_statements scope keep_keys must clear instrumentation-scope attributes ([]).`,
      });
    }

    const datapointStmts = metricInspection.state.datapoint.keepKeyStmts;
    if (datapointStmts.length === 0) {
      errors.push(`${labelPrefix} must configure unconditional keep_keys(attributes, [...]) in metric_statements context: datapoint.`);
    } else {
      const metricAllowlistedKeys = evaluateKeepKeysStatements(datapointStmts, {
        contextLabel: 'metric datapoint allowlist',
        labelPrefix,
        errors,
      });
      compareKeySets(allowlistedKeys, metricAllowlistedKeys, `${labelPrefix} metric_statements datapoint keep_keys`, errors);
    }
  }

  // 3b. Verify log_statements resource, scope, log keep_keys, and body redaction defense-in-depth
  let logInspection = null;
  if (!Array.isArray(transform.log_statements)) {
    errors.push(`${labelPrefix} missing processors.transform.log_statements defense-in-depth.`);
  } else {
    logInspection = inspectStatementList(
      transform.log_statements,
      {
        resource: { allowKeepKeys: true, matchOtherStmt: resourceRedactMatch },
        scope: { allowKeepKeys: true, matchOtherStmt: scopeMetadataMatch },
        log: {
          allowKeepKeys: true,
          matchOtherStmt: (stmt, uncond) => {
            if (!uncond) return null;
            if (/^set\s*\(\s*body\s*,\s*"\[REDACTED_LOG_BODY\]"\s*\)(?:\s+where\s+body\s*!=\s*nil)?$/.test(stmt)) {
              return 'redact_body';
            }
            const typeTag = matchLogTypeRedactStmt(stmt);
            if (typeTag) return typeTag;
            return attrSanitizationMatch(stmt, uncond);
          },
        },
      },
      labelPrefix,
      'transform.log_statements',
      errors
    );

    if (!logInspection.state.resource.events.includes('clear_resource_schema_url')) {
      errors.push(`${labelPrefix} log_statements context: resource missing unconditional clear_resource_schema_url statement.`);
    }

    const logResStmts = logInspection.state.resource.keepKeyStmts;
    if (logResStmts.length === 0) {
      errors.push(`${labelPrefix} missing unconditional log_statements keep_keys in context: resource.`);
    } else {
      const logResKeys = evaluateKeepKeysStatements(logResStmts, {
        contextLabel: 'log resource allowlist',
        labelPrefix,
        errors,
      });
      compareKeySets(traceResourceKeys, logResKeys, `${labelPrefix} log resource keep_keys`, errors);
    }

    const logScopeStmts = logInspection.state.scope.keepKeyStmts;
    if (logScopeStmts.length === 0) {
      errors.push(`${labelPrefix} missing unconditional log_statements keep_keys in context: scope.`);
    } else {
      evaluateKeepKeysStatements(logScopeStmts, {
        contextLabel: 'log scope allowlist',
        labelPrefix,
        errors,
        requireEmptyEach: true,
        emptyScopeError: `${labelPrefix} log_statements scope keep_keys must clear instrumentation-scope attributes ([]).`,
      });
    }
    for (const ev of REQUIRED_SCOPE_METADATA_EVENTS) {
      if (!logInspection.state.scope.events.includes(ev)) {
        errors.push(`${labelPrefix} log_statements context: scope missing unconditional ${ev} statement.`);
      }
    }

    const logKeep = logInspection.state.log.keepKeyStmts;
    const logBodyRedact = logInspection.state.log.events.includes('redact_body');
    if (logKeep.length === 0 || !logBodyRedact) {
      errors.push(`${labelPrefix} log_statements context: log must unconditionally enforce keep_keys and redact body.`);
    } else {
      const logKeys = evaluateKeepKeysStatements(logKeep, {
        contextLabel: 'log allowlist',
        labelPrefix,
        errors,
      });
      compareKeySets(allowlistedKeys, logKeys, `${labelPrefix} log_statements log keep_keys`, errors);
    }
  }

  for (const matcher of RESOURCE_STRING_REDACT_MATCHERS) {
    if (traceResourceKeys.has(matcher.key)) {
      if (!traceInspection.state.resource.events.includes(matcher.tag)) {
        errors.push(`${labelPrefix} trace_statements context: resource missing unconditional ${matcher.tag} statement for "${matcher.key}".`);
      }
      if (logInspection && !logInspection.state.resource.events.includes(matcher.tag)) {
        errors.push(`${labelPrefix} log_statements context: resource missing unconditional ${matcher.tag} statement for "${matcher.key}".`);
      }
    }
  }

  for (const matcher of [...PATH_REDACT_MATCHERS, ...SCALAR_STRING_REDACT_MATCHERS]) {
    if (allowlistedKeys.has(matcher.key)) {
      if (!traceInspection.state.span.events.includes(matcher.tag)) {
        errors.push(`${labelPrefix} trace_statements context: span missing unconditional ${matcher.tag} statement for "${matcher.key}".`);
      }
      if (!traceInspection.state.spanevent.events.includes(matcher.tag)) {
        errors.push(`${labelPrefix} trace_statements context: spanevent missing unconditional ${matcher.tag} statement for "${matcher.key}".`);
      }
      if (
        (matcher.key === 'adapter_path' || matcher.key === 'dataset_relative_path') &&
        metricInspection &&
        !metricInspection.state.datapoint.events.includes(matcher.tag)
      ) {
        errors.push(`${labelPrefix} metric_statements context: datapoint missing unconditional ${matcher.tag} statement for "${matcher.key}".`);
      }
      if (logInspection && !logInspection.state.log.events.includes(matcher.tag)) {
        errors.push(`${labelPrefix} log_statements context: log missing unconditional ${matcher.tag} statement for "${matcher.key}".`);
      }
    }
  }

  for (const key of LOG_TYPE_REDACT_MATCHER_KEYS) {
    if (allowlistedKeys.has(key) && logInspection) {
      const requiredTag = `redact_type_${key}`;
      if (!logInspection.state.log.events.includes(requiredTag)) {
        errors.push(`${labelPrefix} log_statements context: log missing unconditional ${requiredTag} strict-type guard for "${key}".`);
      }
    }
  }

  // 5. Verify sibling PRIVACY_TELEMETRY_SCHEMA.md documents every collector & resource key when present
  if (schemaContent) {
    for (const key of allowlistedKeys) {
      if (!schemaContent.includes(`\`${key}\``)) {
        errors.push(`Collector key "${key}" is missing from privacy-telemetry/PRIVACY_TELEMETRY_SCHEMA.md.`);
      }
    }
    for (const key of traceResourceKeys) {
      if (!schemaContent.includes(`\`${key}\``)) {
        errors.push(`Resource key "${key}" is missing from privacy-telemetry/PRIVACY_TELEMETRY_SCHEMA.md.`);
      }
    }
  }

  // 7. Verify ALL service pipelines (including named signal/name pipelines):
  // traces -> transform before batch;
  // metrics -> [memory_limiter?, transform/metrics_preflight, filter/drop_noncompliant_metrics, transform, batch] in strict order;
  // logs* -> rejected completely.
  const forbiddenStatefulProcs = Object.keys(config.processors || {}).filter(procId => {
    const baseType = procId.split('/')[0];
    return baseType === 'cumulativetodelta' || baseType === 'deltatocumulative';
  });
  if (forbiddenStatefulProcs.length > 0) {
    errors.push(
      `${labelPrefix} must not configure "cumulativetodelta" or "deltatocumulative" processors (found: ${forbiddenStatefulProcs.join(', ')}).`
    );
  }

  const pipelines = config.service?.pipelines || {};
  const pipelineEntries = Object.entries(pipelines);
  let hasTracesPipeline = false;
  let hasMetricsPipeline = false;

  const APPROVED_EXPORTERS = new Set(['otlp/jaeger', 'prometheus', 'debug', 'spanmetrics']);
  const ALLOWED_JAEGER_ENDPOINT_REGEX = /^(?:jaeger|127\.0\.0\.1|localhost|\[::1\])(?::\d+)?$/;
  const ALLOWED_PROMETHEUS_ENDPOINT_REGEX = /^(?:0\.0\.0\.0|127\.0\.0\.1|localhost|\[::1\])(?::\d+)?$/;

  const configuredExporters = config.exporters && typeof config.exporters === 'object' ? config.exporters : null;
  if (configuredExporters) {
    for (const [expName, expCfg] of Object.entries(configuredExporters)) {
      if (!APPROVED_EXPORTERS.has(expName)) {
        errors.push(`${labelPrefix} configures unreviewed exporter "${expName}" in exporters.`);
        continue;
      }
      if (expName === 'otlp/jaeger') {
        const ep = typeof expCfg?.endpoint === 'string' ? expCfg.endpoint.trim() : '';
        if (!ALLOWED_JAEGER_ENDPOINT_REGEX.test(ep)) {
          errors.push(
            `${labelPrefix} exporters.otlp/jaeger.endpoint must target internal/loopback Jaeger only (found: "${expCfg?.endpoint ?? ''}").`
          );
        }
      } else if (expName === 'prometheus') {
        const ep = typeof expCfg?.endpoint === 'string' ? expCfg.endpoint.trim() : '';
        if (!ALLOWED_PROMETHEUS_ENDPOINT_REGEX.test(ep)) {
          errors.push(
            `${labelPrefix} exporters.prometheus.endpoint must bind a local scrape address only (found: "${expCfg?.endpoint ?? ''}").`
          );
        }
        if (expCfg?.resource_to_telemetry_conversion?.enabled !== true) {
          errors.push(
            `${labelPrefix} exporters.prometheus.resource_to_telemetry_conversion.enabled must be true so Prometheus exports keep distinct resource identity labels.`
          );
        }
      }
    }
  } else if (requireSpanmetrics) {
    errors.push(`${labelPrefix} missing exporters configuration block.`);
  }

  for (const [pipelineId, pipelineCfg] of pipelineEntries) {
    const signal = pipelineId.split('/')[0];
    const procs = pipelineCfg?.processors;

    if (Array.isArray(pipelineCfg?.exporters)) {
      for (const expName of pipelineCfg.exporters) {
        if (!APPROVED_EXPORTERS.has(expName)) {
          errors.push(`${labelPrefix} service.pipelines.${pipelineId}.exporters references unreviewed exporter "${expName}".`);
        }
        if (expName !== 'spanmetrics' && (!configuredExporters || !Object.hasOwn(configuredExporters, expName))) {
          errors.push(`${labelPrefix} service.pipelines.${pipelineId}.exporters references undefined exporter "${expName}".`);
        }
      }
    }

    if (signal === 'logs') {
      errors.push(`${labelPrefix} must not enable logs pipeline "${pipelineId}" in service.pipelines.`);
    } else if (signal === 'traces' || signal === 'metrics') {
      if (signal === 'traces') {
        hasTracesPipeline = true;
      } else {
        hasMetricsPipeline = true;
      }

      if (!Array.isArray(procs) || !procs.includes('transform')) {
        errors.push(`${labelPrefix} service.pipelines.${pipelineId} must include "transform" processor.`);
        continue;
      }

      if (procs.includes('batch') && procs.indexOf('transform') > procs.indexOf('batch')) {
        errors.push(`${labelPrefix} service.pipelines.${pipelineId} must execute "transform" before "batch".`);
      }

      if (signal === 'traces') {
        const traceFilterIdx = procs.indexOf('filter/drop_noncompliant_traces');
        const traceTransIdx = procs.indexOf('transform');
        if (traceFilterIdx === -1 || traceFilterIdx > traceTransIdx) {
          errors.push(
            `${labelPrefix} service.pipelines.${pipelineId} must execute "filter/drop_noncompliant_traces" before "transform" and "batch".`
          );
        }
        checkExactProcessorSequence(procs, EXPECTED_TRACES_PROCESSORS, pipelineId, labelPrefix, errors);
        if (requireSpanmetrics && (!Array.isArray(pipelineCfg?.exporters) || !pipelineCfg.exporters.includes('spanmetrics'))) {
          errors.push(`${labelPrefix} service.pipelines.${pipelineId}.exporters must include "spanmetrics".`);
        }
        if (requireSpanmetrics && (!Array.isArray(pipelineCfg?.exporters) || !pipelineCfg.exporters.includes('otlp/jaeger'))) {
          errors.push(`${labelPrefix} service.pipelines.${pipelineId}.exporters must include reviewed internal "otlp/jaeger".`);
        }
      } else if (signal === 'metrics') {
        const badPipelineProcs = procs.filter(procId => {
          const baseType = String(procId).split('/')[0];
          return baseType === 'cumulativetodelta' || baseType === 'deltatocumulative';
        });
        if (badPipelineProcs.length > 0) {
          errors.push(
            `${labelPrefix} service.pipelines.${pipelineId} must not include stateful "cumulativetodelta" or "deltatocumulative" processors (found: ${badPipelineProcs.join(', ')}).`
          );
        }
        const preIdx = procs.indexOf('transform/metrics_preflight');
        const filterIdx = procs.indexOf('filter/drop_noncompliant_metrics');
        const transIdx = procs.indexOf('transform');
        if (preIdx === -1 || filterIdx === -1 || !(preIdx < filterIdx && filterIdx < transIdx)) {
          errors.push(
            `${labelPrefix} service.pipelines.${pipelineId} must run [transform/metrics_preflight, filter/drop_noncompliant_metrics, transform] in strict order.`
          );
        }
        checkExactProcessorSequence(procs, EXPECTED_METRICS_PROCESSORS, pipelineId, labelPrefix, errors);
        if (requireSpanmetrics && (!Array.isArray(pipelineCfg?.receivers) || !pipelineCfg.receivers.includes('spanmetrics'))) {
          errors.push(`${labelPrefix} service.pipelines.${pipelineId}.receivers must include "spanmetrics".`);
        }
        if (requireSpanmetrics && (!Array.isArray(pipelineCfg?.exporters) || !pipelineCfg.exporters.includes('prometheus'))) {
          errors.push(`${labelPrefix} service.pipelines.${pipelineId}.exporters must include reviewed local "prometheus".`);
        }
      }
    }
  }

  if (requireCanonicalExact) {
    compareKeySets(CANONICAL_COLLECTOR_ALLOWED_KEYS, allowlistedKeys, `${labelPrefix} span keep_keys`, errors);
    compareKeySets(CANONICAL_COLLECTOR_RESOURCE_KEYS, traceResourceKeys, `${labelPrefix} resource keep_keys`, errors);
  }

  if (!hasTracesPipeline) {
    errors.push(`${labelPrefix} service.pipelines must define a traces pipeline with "transform".`);
  }
  if (!hasMetricsPipeline) {
    errors.push(`${labelPrefix} service.pipelines must define a metrics pipeline with "transform".`);
  }

  return { allowlistedKeys, resourceKeys: traceResourceKeys };
}

export function auditHelmCollectorConfig(
  helmContent,
  collectorKeys,
  resourceKeys,
  errors = [],
  { helmFileContent = null, collectorRaw = null } = {}
) {
  const filesGetRegex = /\{\{-?\s*\.Files\.Get\s+"files\/otel-collector-config\.yaml"\s*\|\s*(?:n)?indent\s+4\s*-?\}\}/;
  if (!filesGetRegex.test(helmContent)) {
    errors.push(
      'helm collector-configmap.yaml must source otel-collector-config.yaml via {{ .Files.Get "files/otel-collector-config.yaml" | indent 4 }} instead of duplicating inline config.'
    );
  }
  const stripped = helmContent
    .split('\n')
    .map(line => (filesGetRegex.test(line) ? '    __files_get_placeholder__: true' : line))
    .filter(line => !/^\s*\{\{-?.*?-?\}\}\s*$/.test(line))
    .map(line => line.replace(/\{\{-?.*?-?\}\}/g, 'helm-placeholder'))
    .join('\n');
  const cm = loadYamlFromString(stripped);
  const embeddedYaml = cm?.data?.['otel-collector-config.yaml'];
  if (!cm || cm.kind !== 'ConfigMap' || typeof embeddedYaml !== 'string') {
    errors.push('helm collector-configmap.yaml failed structural YAML parse of ConfigMap data.otel-collector-config.yaml.');
  } else if (!filesGetRegex.test(helmContent) && /\breceivers\s*:/.test(embeddedYaml)) {
    errors.push('helm collector-configmap.yaml must not inline duplicate collector YAML.');
  }

  if (typeof helmFileContent !== 'string') {
    errors.push('Missing helm/knowthankyew-suite/files/otel-collector-config.yaml.');
    return;
  }
  if (typeof collectorRaw === 'string' && helmFileContent !== collectorRaw) {
    errors.push('helm/knowthankyew-suite/files/otel-collector-config.yaml has drifted from collector/otel-collector-config.yaml (must be byte-identical).');
  }
  const helmCollector = loadYamlFromString(helmFileContent);
  if (!helmCollector) {
    errors.push('helm/knowthankyew-suite/files/otel-collector-config.yaml failed YAML parsing.');
    return;
  }
  const result = auditCollectorConfigObject(helmCollector, errors, {
    labelPrefix: 'helm files/otel-collector-config.yaml',
    requireSpanmetrics: true,
  });
  compareKeySets(collectorKeys, result.allowlistedKeys, 'helm files/otel-collector-config.yaml span keep_keys vs collector config', errors);
  compareKeySets(resourceKeys, result.resourceKeys, 'helm files/otel-collector-config.yaml resource keep_keys vs collector config', errors);
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

  const collectorRaw = readFileSync(collectorPath, 'utf-8');
  const config = loadYamlFromString(collectorRaw);
  if (!config) {
    errors.push('Failed to parse collector/otel-collector-config.yaml as valid YAML.');
    return;
  }

  const schemaPath = resolve(DEV_ROOT, 'privacy-telemetry/PRIVACY_TELEMETRY_SCHEMA.md');
  const schemaContent = existsSync(schemaPath) ? readFileSync(schemaPath, 'utf-8') : null;

  const { allowlistedKeys, resourceKeys } = auditCollectorConfigObject(config, errors, {
    schemaContent,
    labelPrefix: 'collector/otel-collector-config.yaml',
    requireSpanmetrics: true,
    requireCanonicalExact: true,
  });

  // 6. Structurally parse and verify Helm collector-configmap (.Files.Get wiring) and byte-identical files/otel-collector-config.yaml
  const helmConfigPath = resolve(REPO_ROOT, 'helm/knowthankyew-suite/templates/observability/collector-configmap.yaml');
  const helmFilePath = resolve(REPO_ROOT, 'helm/knowthankyew-suite/files/otel-collector-config.yaml');
  const helmFileContent = existsSync(helmFilePath) ? readFileSync(helmFilePath, 'utf-8') : null;
  if (existsSync(helmConfigPath)) {
    const helmContent = readFileSync(helmConfigPath, 'utf-8');
    auditHelmCollectorConfig(helmContent, allowlistedKeys, resourceKeys, errors, {
      helmFileContent,
      collectorRaw,
    });
  }
}

const PROHIBITED_UPSTREAM_SERVER_REGEX =
  /^(?:(?:kty-)?genesis|(?:kty-)?surprisal(?:-service)?)(?::\d+)?$|^(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1?\]):(?:9000|9002|5200)$/;

function stripNginxComments(nginxContent) {
  let out = '';
  let quote = null;
  let inComment = false;
  for (let i = 0; i < nginxContent.length; i += 1) {
    const ch = nginxContent[i];
    if (inComment) {
      if (ch === '\n') {
        inComment = false;
        out += '\n';
      }
      continue;
    }
    if (quote) {
      out += ch;
      if (ch === '\\' && i + 1 < nginxContent.length) {
        out += nginxContent[i + 1];
        i += 1;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === '#') {
      inComment = true;
      continue;
    }
    if (ch === '\'' || ch === '"') {
      quote = ch;
    }
    out += ch;
  }
  return out;
}

function tokenizeNginxDirective(stmt) {
  const tokens = [];
  let cur = '';
  let inToken = false;
  let quote = null;
  for (let i = 0; i < stmt.length; i += 1) {
    const ch = stmt[i];
    if (quote) {
      if (ch === '\\' && i + 1 < stmt.length) {
        cur += stmt[i + 1];
        i += 1;
      } else if (ch === quote) {
        quote = null;
      } else {
        cur += ch;
      }
      continue;
    }
    if (ch === '\'' || ch === '"') {
      quote = ch;
      inToken = true;
      continue;
    }
    if (/\s/.test(ch)) {
      if (inToken) {
        tokens.push(cur);
        cur = '';
        inToken = false;
      }
      continue;
    }
    cur += ch;
    inToken = true;
  }
  if (inToken) tokens.push(cur);
  return tokens;
}

function parseNginxBlocks(uncommented, errors) {
  const root = { header: '', kind: 'root', statements: [], children: [], vars: new Map() };
  const stack = [root];
  let buf = '';
  let quote = null;

  const classifyKind = header => {
    if (/^upstream\b/i.test(header)) return 'upstream';
    if (/^server\b/i.test(header)) return 'server';
    if (/^location\b/i.test(header)) return 'location';
    if (/^if\b/i.test(header)) return 'if';
    if (/^limit_except\b/i.test(header)) return 'limit_except';
    if (/^(?:map|geo|split_clients)\b/i.test(header)) return 'dynamic_var';
    return 'block';
  };

  for (let i = 0; i < uncommented.length; i += 1) {
    const ch = uncommented[i];
    if (quote) {
      buf += ch;
      if (ch === '\\' && i + 1 < uncommented.length) {
        buf += uncommented[i + 1];
        i += 1;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === '\'' || ch === '"') {
      quote = ch;
      buf += ch;
      continue;
    }
    if (ch === '{') {
      const header = buf.replace(/\s+/g, ' ').trim();
      buf = '';
      const node = {
        header,
        kind: classifyKind(header),
        statements: [],
        children: [],
        vars: new Map(),
      };
      stack[stack.length - 1].children.push(node);
      stack.push(node);
      continue;
    }
    if (ch === ';') {
      const stmt = buf.replace(/\s+/g, ' ').trim();
      buf = '';
      if (stmt) {
        const cur = stack[stack.length - 1];
        cur.statements.push(stmt);
        const tokens = tokenizeNginxDirective(stmt);
        if (tokens[0] && tokens[0].toLowerCase() === 'set' && tokens.length >= 3 && /^\$[A-Za-z0-9_]+$/.test(tokens[1])) {
          const varName = tokens[1];
          const rawVal = tokens[2];
          if (!cur.vars.has(varName)) cur.vars.set(varName, new Set());
          cur.vars.get(varName).add(rawVal);
        }
      }
      continue;
    }
    if (ch === '}') {
      const trailing = buf.replace(/\s+/g, ' ').trim();
      if (trailing) {
        stack[stack.length - 1].statements.push(trailing);
        buf = '';
      }
      if (stack.length <= 1) {
        errors.push('gateway/nginx.conf contains unexpected closing brace "}".');
      } else {
        stack.pop();
      }
      continue;
    }
    buf += ch;
  }

  if (stack.length > 1) {
    errors.push('gateway/nginx.conf contains unclosed block brace "{".');
  }
  return root;
}

function collectLexicalVarsForScope(scopeChain) {
  const merged = new Map();
  const addVarsFromMap = varsMap => {
    for (const [k, vals] of varsMap.entries()) {
      if (!merged.has(k)) merged.set(k, new Set());
      for (const v of vals) merged.get(k).add(v);
    }
  };
  const collectConditionalDescendants = node => {
    for (const child of node.children) {
      if (child.kind === 'if' || child.kind === 'limit_except') {
        addVarsFromMap(child.vars);
        collectConditionalDescendants(child);
      }
    }
  };

  for (const block of scopeChain) {
    addVarsFromMap(block.vars);
    collectConditionalDescendants(block);
  }
  return merged;
}

function expandNginxVars(rawExpr, nginxVars, dynamicBlockVars, visited = new Set(), depth = 0) {
  if (depth > 6) {
    return { values: [], error: `Exceeded recursion limit resolving variables in proxy_pass target "${rawExpr}".` };
  }
  const uniqueVars = [...new Set([...rawExpr.matchAll(/(\$[A-Za-z0-9_]+)/g)].map(m => m[1]))];
  if (uniqueVars.length === 0) {
    return { values: [rawExpr], error: null };
  }

  const expandedByVar = new Map();
  for (const varName of uniqueVars) {
    if (dynamicBlockVars.has(varName)) {
      return { values: [], error: `Dynamic map/geo/split_clients variable "${varName}" is disallowed in proxy_pass target "${rawExpr}".` };
    }
    if (visited.has(varName)) {
      return { values: [], error: `Cyclic Nginx variable reference "${varName}" in proxy_pass target "${rawExpr}".` };
    }
    const defs = nginxVars.get(varName);
    if (!defs || defs.size === 0) {
      return { values: [], error: `Unresolved or dynamic Nginx variable "${varName}" in proxy_pass target "${rawExpr}".` };
    }
    const nextVisited = new Set(visited);
    nextVisited.add(varName);

    const expandedDefs = [];
    for (const defVal of defs) {
      const sub = expandNginxVars(defVal, nginxVars, dynamicBlockVars, nextVisited, depth + 1);
      if (sub.error) return sub;
      expandedDefs.push(...sub.values);
    }
    expandedByVar.set(varName, [...new Set(expandedDefs)]);
  }

  let results = [rawExpr];
  for (const varName of uniqueVars) {
    const replacements = expandedByVar.get(varName);
    const varTokenRegex = new RegExp(`\\${varName}(?![A-Za-z0-9_])`, 'g');
    const nextResults = [];
    for (const cur of results) {
      for (const rep of replacements) {
        nextResults.push(cur.replace(varTokenRegex, () => rep));
      }
    }
    results = nextResults;
  }
  return { values: results, error: null };
}

export function auditNginxGatewayContent(nginxContent, errors = []) {
  const uncommented = stripNginxComments(nginxContent);

  if (/^\s*location\s+(?:=\s*|\^~\s*|~\*?\s*)?(?:\^)?\/genesis(?:[\/\s{$]|$)/im.test(uncommented)) {
    errors.push('gateway/nginx.conf must not proxy /genesis/ unauthenticated on the gateway.');
  }
  if (/^\s*location\s+(?:=\s*|\^~\s*|~\*?\s*)?(?:\^)?\/surprisal(?:[\/\s{$]|$)/im.test(uncommented)) {
    errors.push('gateway/nginx.conf must not proxy /surprisal/ unauthenticated on the gateway.');
  }

  const ast = parseNginxBlocks(uncommented, errors);
  const prohibitedUpstreams = new Map();
  const upstreamServers = new Map();
  const dynamicBlockVars = new Set();

  const walkMeta = block => {
    if (block.kind === 'upstream') {
      const upHeaderMatch = block.header.match(/^upstream\s+([A-Za-z0-9_.-]+)$/i);
      if (upHeaderMatch) {
        const upName = upHeaderMatch[1].toLowerCase();
        const servers = new Set();
        for (const stmt of block.statements) {
          const tokens = tokenizeNginxDirective(stmt);
          if (tokens[0] && tokens[0].toLowerCase() === 'server' && tokens[1]) {
            const serverTarget = tokens[1].toLowerCase();
            servers.add(serverTarget);
            if (PROHIBITED_UPSTREAM_SERVER_REGEX.test(serverTarget)) {
              prohibitedUpstreams.set(upName, serverTarget);
            }
          }
        }
        upstreamServers.set(upName, servers);
      }
    } else if (block.kind === 'dynamic_var') {
      const dynMatch =
        block.header.match(/^map\s+\S+\s+(\$[A-Za-z0-9_]+)$/i) ||
        block.header.match(/^geo\s+(?:\S+\s+)?(\$[A-Za-z0-9_]+)$/i) ||
        block.header.match(/^split_clients\s+\S+\s+(\$[A-Za-z0-9_]+)$/i);
      if (dynMatch) {
        dynamicBlockVars.add(dynMatch[1]);
      }
    }
    for (const child of block.children) {
      walkMeta(child);
    }
  };
  walkMeta(ast);

  const splitHostPort = raw => {
    const trimmed = String(raw || '').trim().toLowerCase();
    const bracketMatch = trimmed.match(/^(\[[0-9a-f:]+\])(?::(\d+))?$/);
    if (bracketMatch) return { host: bracketMatch[1], port: bracketMatch[2] || null };
    const colonIdx = trimmed.lastIndexOf(':');
    if (colonIdx !== -1 && /^\d+$/.test(trimmed.slice(colonIdx + 1))) {
      return { host: trimmed.slice(0, colonIdx), port: trimmed.slice(colonIdx + 1) };
    }
    return { host: trimmed, port: null };
  };

  const isCollectorHost = host => /^(?:kty-)?otel-collector$/.test(host);
  const COLLECTOR_MGMT_PORTS = new Set(['8889', '13133', '55679', '1777']);
  const isProhibitedCollectorEndpoint = raw => {
    const { host, port } = splitHostPort(raw);
    if (isCollectorHost(host) && port !== '4318') return true;
    if (port && COLLECTOR_MGMT_PORTS.has(port)) return true;
    return false;
  };

  const isOtlpTargetAllowed = destRaw => {
    if (destRaw === 'otel-collector:4318') return true;
    const destHost = destRaw.replace(/:\d+$/, '');
    const servers = upstreamServers.get(destHost);
    return Boolean(servers && servers.size > 0 && [...servers].every(srv => srv === 'otel-collector:4318'));
  };

  const otlpLocationChecks = [];

  const auditBlock = (block, scopeChain) => {
    const nextChain = [...scopeChain, block];
    let otlpEntry = null;
    for (let i = nextChain.length - 1; i >= 0; i -= 1) {
      if (nextChain[i]._otlpEntry) {
        otlpEntry = nextChain[i]._otlpEntry;
        break;
      }
    }

    if (block.kind === 'location') {
      const locMatch = block.header.match(/^location\s+(?:(=|\^~|~\*?)\s+)?(.+)$/i);
      const modifier = locMatch && locMatch[1] ? locMatch[1] : '';
      const pattern = locMatch ? locMatch[2].trim().replace(/^['"]|['"]$/g, '') : '';
      const isRegexLocation = modifier === '~' || modifier === '~*';
      if (/(?:^|[|(^\/])(?:genesis|surprisal)(?:[\/(?*$)|]|$)/i.test(pattern)) {
        errors.push(`gateway/nginx.conf must not expose prohibited route "${pattern}".`);
      }
      if (isRegexLocation && /otlp/i.test(pattern)) {
        errors.push(
          `gateway/nginx.conf OTLP location "${block.header}" must not use regex modifier "${modifier}" (use literal prefix "/otlp/").`
        );
      }
      if (/^(?:\^)?\/otlp(?:[\/(?*$]|$)/i.test(pattern)) {
        if (modifier !== '^~') {
          errors.push(
            `gateway/nginx.conf OTLP location "${block.header}" must use non-regex priority prefix "location ^~ /otlp/" so regex locations cannot override it.`
          );
        } else if (pattern !== '/otlp/') {
          errors.push(`gateway/nginx.conf OTLP location "${pattern}" must be literally "/otlp/".`);
        }
        otlpEntry = { pattern, proxyPassCount: 0 };
        block._otlpEntry = otlpEntry;
        otlpLocationChecks.push(otlpEntry);
      }
    }

    const lexicalVars = collectLexicalVarsForScope(nextChain);
    for (const stmt of block.statements) {
      const tokens = tokenizeNginxDirective(stmt);
      const directive = tokens[0] ? tokens[0].toLowerCase() : '';
      if (/^(?:grpc|fastcgi|uwsgi|scgi|memcached)_pass$/.test(directive)) {
        errors.push(`gateway/nginx.conf must not use unvalidated "${directive}" forwarding directive: ${stmt}`);
        continue;
      }
      if (directive !== 'proxy_pass') continue;
      if (tokens.length !== 2) {
        errors.push(`gateway/nginx.conf malformed proxy_pass directive: ${stmt}`);
        continue;
      }
      const rawTarget = tokens[1];
      if (otlpEntry) {
        otlpEntry.proxyPassCount += 1;
      }
      const expanded = expandNginxVars(rawTarget, lexicalVars, dynamicBlockVars);
      if (expanded.error) {
        errors.push(`gateway/nginx.conf must fail closed on dynamic proxy_pass: ${expanded.error}`);
        continue;
      }
      for (const target of expanded.values) {
        const destMatch = target.match(/^https?:\/\/(\[[0-9a-f:]+\](?::\d+)?|[A-Za-z0-9_.-]+(?::\d+)?)(?:\/[^\s;$]*)?$/i);
        if (!destMatch) {
          errors.push(`gateway/nginx.conf proxy_pass target "${rawTarget}" (resolved: "${target}") must resolve statically to http(s)://<host>[:port][/path] without variables.`);
          continue;
        }
        const destRaw = destMatch[1].toLowerCase();
        const destHost = destRaw.replace(/:\d+$/, '');
        const resolvedServers = upstreamServers.has(destHost)
          ? [...upstreamServers.get(destHost)]
          : [destRaw];

        if (PROHIBITED_UPSTREAM_SERVER_REGEX.test(destRaw) || PROHIBITED_UPSTREAM_SERVER_REGEX.test(destHost)) {
          errors.push(`gateway/nginx.conf must not forward any route to prohibited backend "${target}".`);
        } else if (prohibitedUpstreams.has(destHost)) {
          errors.push(
            `gateway/nginx.conf must not forward route via upstream "${destMatch[1]}" resolving to "${prohibitedUpstreams.get(destHost)}".`
          );
        } else if (resolvedServers.some(isProhibitedCollectorEndpoint)) {
          errors.push(
            `gateway/nginx.conf must not expose collector management or non-4318 endpoint "${target}".`
          );
        } else if (!otlpEntry && resolvedServers.some(srv => isCollectorHost(splitHostPort(srv).host))) {
          errors.push(
            `gateway/nginx.conf may proxy otel-collector:4318 exclusively inside an /otlp/ location (found "${target}").`
          );
        }
        if (otlpEntry && !isOtlpTargetAllowed(destRaw)) {
          errors.push(
            `gateway/nginx.conf OTLP location "${otlpEntry.pattern}" must route exclusively to otel-collector:4318 (found "${target}").`
          );
        }
      }
    }

    for (const child of block.children) {
      auditBlock(child, nextChain);
    }
  };

  auditBlock(ast, []);

  for (const otlpEntry of otlpLocationChecks) {
    if (otlpEntry.proxyPassCount === 0) {
      errors.push(`gateway/nginx.conf OTLP location "${otlpEntry.pattern}" must explicitly proxy_pass to otel-collector:4318.`);
    }
  }
}

const COMPOSE_REPLACE_SERVICE_KEYS = new Set(['command', 'entrypoint']);

function parseComposeEnvironmentToMap(env) {
  const map = new Map();
  if (!env) return map;
  if (Array.isArray(env)) {
    for (const rawEntry of env) {
      const str = String(rawEntry);
      const eqIdx = str.indexOf('=');
      if (eqIdx === -1) {
        map.set(str.trim(), null);
      } else {
        map.set(str.slice(0, eqIdx).trim(), str.slice(eqIdx + 1));
      }
    }
  } else if (typeof env === 'object') {
    for (const [k, v] of Object.entries(env)) {
      map.set(k, v === undefined || v === null ? null : String(v));
    }
  }
  return map;
}

export function mergeComposeConfigs(baseCompose, overlayCompose) {
  if (!baseCompose || typeof baseCompose !== 'object') return structuredClone(overlayCompose || {});
  if (!overlayCompose || typeof overlayCompose !== 'object') return structuredClone(baseCompose);

  const merged = structuredClone(baseCompose);
  if (!merged.services || typeof merged.services !== 'object') {
    merged.services = {};
  }
  if (!overlayCompose.services || typeof overlayCompose.services !== 'object') {
    return merged;
  }

  for (const [svcName, overlaySvc] of Object.entries(overlayCompose.services)) {
    const baseSvc = merged.services[svcName];
    if (!baseSvc || typeof baseSvc !== 'object' || !overlaySvc || typeof overlaySvc !== 'object') {
      merged.services[svcName] = structuredClone(overlaySvc);
      continue;
    }
    const nextSvc = { ...baseSvc };
    for (const [field, val] of Object.entries(overlaySvc)) {
      if (COMPOSE_REPLACE_SERVICE_KEYS.has(field)) {
        nextSvc[field] = structuredClone(val);
      } else if (field === 'environment') {
        const mergedEnv = parseComposeEnvironmentToMap(nextSvc.environment);
        for (const [envKey, envVal] of parseComposeEnvironmentToMap(val)) {
          mergedEnv.set(envKey, envVal);
        }
        nextSvc.environment = Object.fromEntries(mergedEnv);
      } else if (field === 'ports' && Array.isArray(nextSvc.ports) && Array.isArray(val)) {
        const seen = new Set(nextSvc.ports.map(p => JSON.stringify(p)));
        const combined = [...nextSvc.ports];
        for (const item of val) {
          const sig = JSON.stringify(item);
          if (!seen.has(sig)) {
            seen.add(sig);
            combined.push(structuredClone(item));
          }
        }
        nextSvc.ports = combined;
      } else if (Array.isArray(nextSvc[field]) && Array.isArray(val)) {
        nextSvc[field] = [...nextSvc[field], ...structuredClone(val)];
      } else if (
        nextSvc[field] &&
        typeof nextSvc[field] === 'object' &&
        !Array.isArray(nextSvc[field]) &&
        val &&
        typeof val === 'object' &&
        !Array.isArray(val)
      ) {
        nextSvc[field] = { ...nextSvc[field], ...structuredClone(val) };
      } else {
        nextSvc[field] = structuredClone(val);
      }
    }
    merged.services[svcName] = nextSvc;
  }

  return merged;
}

function isLoopbackShortPort(rawEntry) {
  const normalized = String(rawEntry)
    .trim()
    .replace(/\$\{[^}]+\}/g, 'VAR')
    .replace(/\/(?:tcp|udp)$/i, '');
  return /^127\.0\.0\.1:[^:]+:[^:]+$/.test(normalized) || /^\[::1\]:[^:]+:[^:]+$/.test(normalized);
}

export function auditComposePortsObject(composeData, fileLabel, errors = [], { requireDefaultBindings = false } = {}) {
  if (!composeData || typeof composeData !== 'object' || !composeData.services) {
    return;
  }

  const protectedServices = {
    genesis: requireDefaultBindings
      ? ['127.0.0.1:${GENESIS_PORT:-9002}:8080', '127.0.0.1:${GENESIS_TCP_PORT:-9000}:9000']
      : [],
    'surprisal-service': requireDefaultBindings ? ['127.0.0.1:${SURPRISAL_PORT:-5200}:5200'] : [],
  };

  for (const [svcName, expectedPorts] of Object.entries(protectedServices)) {
    const svc = composeData.services[svcName];
    if (!svc) continue;

    if (svc.network_mode === 'host') {
      errors.push(`${fileLabel} service "${svcName}" must not configure network_mode: host.`);
    }

    const ports = svc.ports;
    if (requireDefaultBindings) {
      for (const reqPort of expectedPorts) {
        if (!Array.isArray(ports) || !ports.includes(reqPort)) {
          errors.push(`${fileLabel} service "${svcName}" missing required loopback port binding "${reqPort}".`);
        }
      }
    }

    if (!Array.isArray(ports)) continue;
    for (const entry of ports) {
      if (typeof entry === 'string' || typeof entry === 'number') {
        if (!isLoopbackShortPort(entry)) {
          errors.push(`${fileLabel} service "${svcName}" publishes non-loopback or host-unbound port "${entry}".`);
        }
      } else if (entry && typeof entry === 'object') {
        if (entry.host_ip !== '127.0.0.1' && entry.host_ip !== '::1') {
          errors.push(
            `${fileLabel} service "${svcName}" long-syntax port binding must restrict host_ip to 127.0.0.1 or ::1 (found: ${entry.host_ip ?? 'unset'}).`
          );
        }
      } else {
        errors.push(`${fileLabel} service "${svcName}" has unrecognized ports entry.`);
      }
    }
  }
}

function splitComposeCommandTokens(command) {
  if (Array.isArray(command)) {
    return command.map(part => String(part));
  }
  if (typeof command !== 'string' || !command.trim()) {
    return [];
  }
  const tokens = [];
  let cur = '';
  let inToken = false;
  let quote = null;
  for (let i = 0; i < command.length; i += 1) {
    const ch = command[i];
    if (quote) {
      if (quote === '"' && ch === '\\' && i + 1 < command.length) {
        cur += command[i + 1];
        i += 1;
      } else if (ch === quote) {
        quote = null;
      } else {
        cur += ch;
      }
      inToken = true;
      continue;
    }
    if (ch === '\'' || ch === '"') {
      quote = ch;
      inToken = true;
      continue;
    }
    if (ch === '\\' && i + 1 < command.length) {
      cur += command[i + 1];
      i += 1;
      inToken = true;
      continue;
    }
    if (/\s/.test(ch)) {
      if (inToken) {
        tokens.push(cur);
        cur = '';
        inToken = false;
      }
      continue;
    }
    cur += ch;
    inToken = true;
  }
  if (inToken) {
    tokens.push(cur);
  }
  return tokens;
}

export function auditEffectiveComposeConfig(composeData, modeLabel, errors = []) {
  auditComposePortsObject(composeData, modeLabel, errors, { requireDefaultBindings: true });

  const genesisSvc = composeData?.services?.genesis;
  if (!genesisSvc) {
    errors.push(`${modeLabel} missing genesis service definition.`);
  } else {
    if (genesisSvc.entrypoint !== undefined && genesisSvc.entrypoint !== null) {
      errors.push(`${modeLabel} must not override genesis entrypoint (risks bypassing GENESIS_AUTH_TOKEN enforcement).`);
    }
    const tokens = splitComposeCommandTokens(genesisSvc.command);
    for (const tok of tokens) {
      if (/^--?auth-token(?:=|$)/.test(tok)) {
        errors.push(
          `${modeLabel} must not pass "${tok}" on genesis CLI command (leaks auth token via /proc/<pid>/cmdline; configure GENESIS_AUTH_TOKEN via environment).`
        );
      }
    }

    const mandatoryTokenRegex = /^\$\{GENESIS_AUTH_TOKEN:\?[^}]+\}$/;
    const envOccurrences = [];
    if (Array.isArray(genesisSvc.environment)) {
      for (const rawEntry of genesisSvc.environment) {
        const str = String(rawEntry);
        const eqIdx = str.indexOf('=');
        const key = (eqIdx === -1 ? str : str.slice(0, eqIdx)).trim();
        if (key === 'GENESIS_AUTH_TOKEN') {
          envOccurrences.push({
            raw: str,
            value: eqIdx === -1 ? null : str.slice(eqIdx + 1),
          });
        }
      }
    } else if (genesisSvc.environment && typeof genesisSvc.environment === 'object') {
      if (Object.hasOwn(genesisSvc.environment, 'GENESIS_AUTH_TOKEN')) {
        const rawVal = genesisSvc.environment.GENESIS_AUTH_TOKEN;
        envOccurrences.push({
          raw: `GENESIS_AUTH_TOKEN=${rawVal ?? ''}`,
          value: rawVal === undefined || rawVal === null ? null : String(rawVal),
        });
      }
    }

    if (envOccurrences.length === 0) {
      errors.push(`${modeLabel} must enforce mandatory GENESIS_AUTH_TOKEN=\${GENESIS_AUTH_TOKEN:?...} in genesis.environment.`);
    } else {
      for (const occ of envOccurrences) {
        if (occ.value === null || !mandatoryTokenRegex.test(occ.value)) {
          errors.push(
            `${modeLabel} genesis environment entry "${occ.raw}" weakens mandatory \${GENESIS_AUTH_TOKEN:?...} authentication.`
          );
        }
      }
    }
  }

  const collectorEnv = composeData?.services?.['otel-collector']?.environment;
  const envStr = JSON.stringify(collectorEnv || '');
  if (envStr.includes('FTAAS_TELEMETRY_HMAC_KEY')) {
    errors.push(`${modeLabel} must never expose FTAAS_TELEMETRY_HMAC_KEY to otel-collector.`);
  }
}

export function auditGenesisAuthEnforcement(
  genesisDir,
  errors = [],
  { requireGo = process.env.KTY_REQUIRE_GO_TESTS === '1', goCmd = 'go' } = {}
) {
  const dockerfilePath = resolve(genesisDir, 'Dockerfile');
  const configPath = resolve(genesisDir, 'internal/config/config.go');
  const serverPath = resolve(genesisDir, 'internal/cli/server.go');
  const securityPath = resolve(genesisDir, 'internal/security/security.go');

  for (const [label, filePath] of [
    ['Dockerfile', dockerfilePath],
    ['internal/config/config.go', configPath],
    ['internal/cli/server.go', serverPath],
    ['internal/security/security.go', securityPath],
  ]) {
    if (!existsSync(filePath)) {
      errors.push(`Genesis auth enforcement verification failed: missing ${label} at ${filePath}`);
      return;
    }
  }

  const dockerfileContent = readFileSync(dockerfilePath, 'utf-8');
  if (!/go\s+build[^\n]*\.\/cmd\/server\b/.test(dockerfileContent) || !/ENTRYPOINT\s*\[\s*"\/genesis"\s*\]/.test(dockerfileContent)) {
    errors.push('genesis/Dockerfile must build ./cmd/server and set ENTRYPOINT ["/genesis"] so compose cmd ["server", ...] invokes internal/cli/server.go.');
  }

  const stripGoComments = src => {
    let out = '';
    let state = null; // 'line' | 'block' | '"' | '`' | "'"
    for (let i = 0; i < src.length; i += 1) {
      const ch = src[i];
      const next = src[i + 1];
      if (state === 'line') {
        if (ch === '\n') {
          state = null;
          out += ch;
        }
        continue;
      }
      if (state === 'block') {
        if (ch === '*' && next === '/') {
          state = null;
          i += 1;
        } else if (ch === '\n') {
          out += '\n';
        }
        continue;
      }
      if (state === '"' || state === "'") {
        out += ch;
        if (ch === '\\' && i + 1 < src.length) {
          out += next;
          i += 1;
        } else if (ch === state) {
          state = null;
        }
        continue;
      }
      if (state === '`') {
        out += ch;
        if (ch === '`') state = null;
        continue;
      }
      if (ch === '/' && next === '/') {
        state = 'line';
        i += 1;
        continue;
      }
      if (ch === '/' && next === '*') {
        state = 'block';
        i += 1;
        continue;
      }
      if (ch === '"' || ch === '`' || ch === "'") {
        state = ch;
      }
      out += ch;
    }
    return out;
  };

  const configContent = stripGoComments(readFileSync(configPath, 'utf-8'));
  if (!/os\.Getenv\("GENESIS_AUTH_TOKEN"\)[\s\S]{0,120}?cfg\.AuthToken\s*=\s*v/.test(configContent)) {
    errors.push('genesis/internal/config/config.go must bind GENESIS_AUTH_TOKEN to cfg.AuthToken.');
  }

  const serverContent = stripGoComments(readFileSync(serverPath, 'utf-8'));
  for (const route of ['"/"', '"/query"', '"/stats"', '"/tail"', '"/logs"', '"/burn"']) {
    if (!serverContent.includes(`httpMux.Handle(${route}`) && !serverContent.includes(`httpMux.HandleFunc(${route}`)) {
      errors.push(`genesis/internal/cli/server.go expected route ${route} on httpMux for middleware coverage check.`);
    }
  }
  if (
    !/authenticatedHandler\s*:=\s*security\.AuthMiddleware\(\s*cfg\.AuthToken\s*,\s*httpMux\s*\)/.test(serverContent) ||
    !/Handler:\s*authenticatedHandler\b/.test(serverContent)
  ) {
    errors.push('genesis/internal/cli/server.go must wrap the entire httpMux with security.AuthMiddleware(cfg.AuthToken, httpMux) on http.Server.Handler.');
  }

  const securityContent = readFileSync(securityPath, 'utf-8');
  const findGoDelimiterEnd = (src, openIdx, openCh = '{', closeCh = '}') => {
    let depth = 0;
    let state = null;
    for (let i = openIdx; i < src.length; i += 1) {
      const ch = src[i];
      if (state === '"' || state === "'") {
        if (ch === '\\' && i + 1 < src.length) {
          i += 1;
        } else if (ch === state) {
          state = null;
        }
        continue;
      }
      if (state === '`') {
        if (ch === '`') state = null;
        continue;
      }
      if (ch === '"' || ch === '`' || ch === "'") {
        state = ch;
        continue;
      }
      if (ch === openCh) depth += 1;
      else if (ch === closeCh) {
        depth -= 1;
        if (depth === 0) return i;
      }
    }
    return -1;
  };

  const findTopLevelGoMatch = (src, anchoredRegex, startIdx = 0, prevWordBoundary = false) => {
    let depth = 0;
    let state = null;
    for (let i = 0; i < src.length; i += 1) {
      const ch = src[i];
      if (state === '"' || state === "'") {
        if (ch === '\\' && i + 1 < src.length) i += 1;
        else if (ch === state) state = null;
        continue;
      }
      if (state === '`') {
        if (ch === '`') state = null;
        continue;
      }
      if (ch === '"' || ch === '`' || ch === "'") {
        state = ch;
        continue;
      }
      if (ch === '{') depth += 1;
      else if (ch === '}') depth = Math.max(0, depth - 1);
      else if (depth === 0 && i >= startIdx) {
        if (prevWordBoundary && i > 0 && /[A-Za-z0-9_]/.test(src[i - 1])) continue;
        anchoredRegex.lastIndex = i;
        if (anchoredRegex.test(src)) return i;
      }
    }
    return -1;
  };

  const cleanSec = stripGoComments(securityContent);
  const fnMatch = cleanSec.match(
    /func\s+AuthMiddleware\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s+string\b\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s+http\.Handler\s*\)\s*http\.Handler\s*\{/
  );
  const expectedParam = fnMatch ? fnMatch[1] : '';
  const nextParam = fnMatch ? fnMatch[2] : '';
  const fnOpenIdx = fnMatch ? fnMatch.index + fnMatch[0].length - 1 : -1;
  const fnCloseIdx = fnOpenIdx !== -1 ? findGoDelimiterEnd(cleanSec, fnOpenIdx) : -1;
  const fnBody = fnCloseIdx !== -1 ? cleanSec.slice(fnOpenIdx + 1, fnCloseIdx) : '';

  const firstTopReturnIdx = fnBody ? findTopLevelGoMatch(fnBody, /return\b/y, 0, true) : -1;
  const outerPrefixBeforeReturn = firstTopReturnIdx !== -1 ? fnBody.slice(0, firstTopReturnIdx).trim() : '';
  const expectedParamPattern = expectedParam ? escapeRegExp(expectedParam) : '';
  const nextParamPattern = nextParam ? escapeRegExp(nextParam) : '';
  const safeOuterGuardRe =
    expectedParamPattern && nextParamPattern
      ? new RegExp(`^if\\s+${expectedParamPattern}\\s*==\\s*""\\s*\\{\\s*return\\s+${nextParamPattern}\\s*;?\\s*\\}$`)
      : null;
  const outerPrefixSafe =
    outerPrefixBeforeReturn === '' || (Boolean(safeOuterGuardRe) && safeOuterGuardRe.test(outerPrefixBeforeReturn));
  const handlerMatch =
    firstTopReturnIdx !== -1
      ? fnBody
          .slice(firstTopReturnIdx)
          .match(/^return\s+http\.HandlerFunc\s*\(\s*func\s*\(\s*w\s+http\.ResponseWriter\s*,\s*r\s+\*http\.Request\s*\)\s*\{/)
      : null;
  const hOpenIdx = handlerMatch ? firstTopReturnIdx + handlerMatch[0].length - 1 : -1;
  const hCloseIdx = hOpenIdx !== -1 ? findGoDelimiterEnd(fnBody, hOpenIdx) : -1;
  const handlerBody = hCloseIdx !== -1 ? fnBody.slice(hOpenIdx + 1, hCloseIdx) : '';

  const rawTopLevelIfIdx = handlerBody ? findTopLevelGoMatch(handlerBody, /if\s+subtle\.ConstantTimeCompare\s*\(/y, 0, true) : -1;
  const precededByElse = rawTopLevelIfIdx > 0 && /\belse$/.test(handlerBody.slice(0, rawTopLevelIfIdx).trimEnd());
  const ctMatch = rawTopLevelIfIdx !== -1 && !precededByElse ? handlerBody.slice(rawTopLevelIfIdx).match(/^if\s+subtle\.ConstantTimeCompare\s*\(/) : null;
  const ctOpenIdx = ctMatch ? rawTopLevelIfIdx + ctMatch[0].length - 1 : -1;
  const ctCloseIdx = ctOpenIdx !== -1 ? findGoDelimiterEnd(handlerBody, ctOpenIdx, '(', ')') : -1;
  const postCtMatch = ctCloseIdx !== -1 ? handlerBody.slice(ctCloseIdx + 1).match(/^\s*!=\s*1\s*\{/) : null;
  const rejectIfIdx = ctMatch && postCtMatch ? rawTopLevelIfIdx : -1;
  const rejectOpenIdx = postCtMatch ? ctCloseIdx + postCtMatch[0].length : -1;
  const rejectCloseIdx = rejectOpenIdx !== -1 ? findGoDelimiterEnd(handlerBody, rejectOpenIdx) : -1;
  const rejectBlock = rejectCloseIdx !== -1 ? handlerBody.slice(rejectOpenIdx + 1, rejectCloseIdx) : '';
  const beforeReject = rejectIfIdx !== -1 ? handlerBody.slice(0, rejectIfIdx) : handlerBody;
  const afterReject = rejectCloseIdx !== -1 ? handlerBody.slice(rejectCloseIdx + 1) : '';
  const ctArgs = ctCloseIdx !== -1 ? handlerBody.slice(ctOpenIdx + 1, ctCloseIdx).trim() : '';
  const ctArgsMatch = ctArgs.match(
    /^\[\]byte\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*,\s*\[\]byte\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)$/
  );
  let reqVar = '';
  let ctOperandsOk = false;
  if (ctArgsMatch && expectedParam) {
    const [, lhs, rhs] = ctArgsMatch;
    if (lhs !== rhs && (lhs === expectedParam || rhs === expectedParam)) {
      reqVar = lhs === expectedParam ? rhs : lhs;
      ctOperandsOk = Boolean(reqVar);
    }
  }
  const fnOuterPrefix = hOpenIdx !== -1 ? fnBody.slice(0, hOpenIdx) : '';
  const outerLocalIds = new Set();
  for (const m of fnOuterPrefix.matchAll(/\bvar\s+([A-Za-z_][A-Za-z0-9_]*)\b/g)) {
    outerLocalIds.add(m[1]);
  }
  for (const m of fnOuterPrefix.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*)\s*:=/g)) {
    for (const part of m[1].split(',')) {
      const id = part.trim();
      if (id && id !== '_') outerLocalIds.add(id);
    }
  }
  if (expectedParam) outerLocalIds.add(expectedParam);
  const outerIdList = [...outerLocalIds].map(escapeRegExp);
  const outerIdRegex = outerIdList.length > 0 ? new RegExp(`\\b(?:${outerIdList.join('|')})\\b`) : null;

  const reqVarSafe = reqVar ? escapeRegExp(reqVar) : '';
  const expectedParamSafe = expectedParam ? escapeRegExp(expectedParam) : '';
  const reqVarAssigns = reqVarSafe
    ? [
        ...[...beforeReject.matchAll(new RegExp(`\\bvar\\s+${reqVarSafe}\\s+[^=\\n;]*=(?!=)\\s*([^\\n;]+)`, 'g'))].map(m => m[1].trim()),
        ...[...beforeReject.matchAll(new RegExp(`\\b${reqVarSafe}\\b\\s*(?::=|=(?!=))\\s*([^\\n;]+)`, 'g'))].map(m => m[1].trim()),
      ]
    : [];
  const reqVarDerivedFromRequest =
    Boolean(reqVarSafe) &&
    reqVarAssigns.length > 0 &&
    reqVarAssigns.every(
      rhs =>
        /(?:r\.Header\.Get|authHeader|r\.URL\.Query\(\)\.Get)/.test(rhs) &&
        (!outerIdRegex || !outerIdRegex.test(rhs))
    ) &&
    !new RegExp(`&\\s*${reqVarSafe}\\b`).test(beforeReject);
  const expectedParamReassigned =
    Boolean(expectedParamSafe) && new RegExp(`\\b${expectedParamSafe}\\b\\s*(?:=(?!=)|\\+=)`).test(fnBody);
  const beforeRejectReferencesExpected =
    expectedParamReassigned || (Boolean(outerIdRegex) && outerIdRegex.test(beforeReject));

  const fnBodyNoStrings = fnBody.replace(/`[^`]*`|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, '""');
  const hasGotoOrLabel = /\bgoto\b/.test(fnBodyNoStrings) || /^\s*(?!default\s*:)[A-Za-z_][A-Za-z0-9_]*\s*:\s*$/m.test(fnBodyNoStrings);

  // Verify top-level `w.WriteHeader(http.StatusUnauthorized)` followed by top-level `return` inside rejectBlock
  const unauthIdx = rejectBlock ? findTopLevelGoMatch(rejectBlock, /w\.WriteHeader\(\s*http\.StatusUnauthorized\s*\)/y, 0, true) : -1;
  const hasTopLevelReturnAfterUnauth =
    unauthIdx !== -1 && findTopLevelGoMatch(rejectBlock, /return\b/y, unauthIdx + 1, true) !== -1;
  const hasEarlyTopLevelReturn = Boolean(beforeReject) && findTopLevelGoMatch(beforeReject, /return\b/y, 0, true) !== -1;
  const hasTopLevelServeHttp = Boolean(afterReject) && findTopLevelGoMatch(afterReject, /next\.ServeHTTP\s*\(/y, 0, true) !== -1;

  if (
    !fnBody ||
    !outerPrefixSafe ||
    hasGotoOrLabel ||
    !handlerBody ||
    !rejectBlock ||
    !ctOperandsOk ||
    !reqVarDerivedFromRequest ||
    beforeRejectReferencesExpected ||
    hasEarlyTopLevelReturn ||
    !/r\.Header\.Get\(\s*"Authorization"\s*\)/.test(handlerBody) ||
    !/strings\.HasPrefix\(\s*strings\.ToLower\(\s*authHeader\s*\)\s*,\s*"bearer "\s*\)/.test(handlerBody) ||
    /\bnext\.ServeHTTP\s*\(/.test(beforeReject) ||
    /\bnext\.ServeHTTP\s*\(/.test(rejectBlock) ||
    !hasTopLevelReturnAfterUnauth ||
    !hasTopLevelServeHttp
  ) {
    errors.push('genesis/internal/security/security.go AuthMiddleware must enforce constant-time Bearer validation against the request token, return http.StatusUnauthorized (401) before returning early, and invoke next.ServeHTTP only after authorization succeeds.');
  }

  const securityTestPath = resolve(genesisDir, 'internal/security/security_test.go');
  if (existsSync(securityTestPath)) {
    try {
      execFileSync(goCmd, ['test', '-count=1', './internal/security'], {
        cwd: genesisDir,
        stdio: 'pipe',
        timeout: 60000,
      });
    } catch (err) {
      if (err?.code === 'ENOENT') {
        const msg =
          `genesis/internal/security Go tests skipped: "${goCmd}" binary not found in PATH` +
          (requireGo ? ' while KTY_REQUIRE_GO_TESTS=1.' : ' (set KTY_REQUIRE_GO_TESTS=1 to fail closed).');
        if (requireGo) {
          errors.push(msg);
        } else {
          console.warn(`⚠️  ${msg}`);
        }
        return;
      }
      const stderr = err?.stderr ? String(err.stderr).trim() : '';
      const stdout = err?.stdout ? String(err.stdout).trim() : '';
      errors.push(
        `genesis/internal/security Go tests failed (${err?.message || 'non-zero exit'}): ${stderr || stdout}`
      );
    }
  }
}

/**
 * Audit 3b: Genesis Authentication, Loopback Bindings & Burn Fail-Loud Enforcement
 */
export function auditGenesisAuthAndHardening(errors = []) {
  const genesisDir = resolve(DEV_ROOT, 'genesis');
  if (existsSync(genesisDir)) {
    auditGenesisAuthEnforcement(genesisDir, errors);
  }
  const composeFiles = readdirSync(REPO_ROOT).filter(f => /^docker-compose.*\.ya?ml$/.test(f)).sort();
  const baseComposePath = resolve(REPO_ROOT, 'docker-compose.yml');
  const baseCompose = existsSync(baseComposePath) ? loadYaml(baseComposePath) : null;
  if (!baseCompose) {
    errors.push('Failed to parse docker-compose.yml as valid YAML.');
  } else {
    auditEffectiveComposeConfig(baseCompose, 'docker-compose.yml [standalone]', errors);
  }

  for (const composeFile of composeFiles) {
    if (composeFile === 'docker-compose.yml') continue;
    const fullPath = resolve(REPO_ROOT, composeFile);
    const composeData = loadYaml(fullPath);
    if (!composeData) {
      errors.push(`Failed to parse ${composeFile} as valid YAML.`);
      continue;
    }
    auditComposePortsObject(composeData, composeFile, errors, { requireDefaultBindings: false });
    if (baseCompose) {
      const merged = mergeComposeConfigs(baseCompose, composeData);
      auditEffectiveComposeConfig(merged, `effective compose [docker-compose.yml + ${composeFile}]`, errors);
    }
  }

  const nginxPath = resolve(REPO_ROOT, 'gateway/nginx.conf');
  if (existsSync(nginxPath)) {
    const nginxContent = readFileSync(nginxPath, 'utf-8');
    auditNginxGatewayContent(nginxContent, errors);
  }

  const burnPath = resolve(REPO_ROOT, 'burn-telemetry.sh');
  if (existsSync(burnPath)) {
    const burnContent = readFileSync(burnPath, 'utf-8');
    if (
      !burnContent.includes('Authorization: Bearer') ||
      !/\bcurl\b[^\n]*--noproxy\s+(?:'\*'|"\*"|\*)[^\n]*-fsS\s+-X\s+DELETE/.test(burnContent) ||
      !burnContent.includes('purge_rc=') ||
      !burnContent.includes('docker restart kty-genesis')
    ) {
      errors.push('burn-telemetry.sh must authenticate with Authorization: Bearer, use curl --noproxy \'*\' -fsS -X DELETE, restart kty-genesis on fallback, and preserve non-zero exit status.');
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
function helmGlobToRegExp(globPattern) {
  let reStr = '^';
  for (let i = 0; i < globPattern.length; i += 1) {
    const ch = globPattern[i];
    if (ch === '*') {
      if (globPattern[i + 1] === '*') {
        if (globPattern[i + 2] === '/') {
          reStr += '(?:.*/)?';
          i += 2;
        } else {
          reStr += '.*';
          i += 1;
        }
      } else {
        reStr += '[^/]*';
      }
    } else if (ch === '?') {
      reStr += '[^/]';
    } else if (ch === '[') {
      const closeIdx = globPattern.indexOf(']', i + 1);
      if (closeIdx > i + 1) {
        // Go filepath.Match (used by Helm .helmignore) uses [^...] for negation; [!... ] treats '!' literally.
        const inner = globPattern.slice(i + 1, closeIdx);
        reStr += `[${inner}]`;
        i = closeIdx;
      } else {
        reStr += '\\[';
      }
    } else if ('^$.+(){}|\\'.includes(ch)) {
      reStr += `\\${ch}`;
    } else {
      reStr += ch;
    }
  }
  return new RegExp(`${reStr}$`);
}

export function auditHelmIgnoreContent(ignoreContent, errors = [], targetRelPath = 'files/otel-collector-config.yaml') {
  const normTarget = targetRelPath.replace(/^\/+/, '').replace(/\/+$/, '');
  const parts = normTarget.split('/').filter(Boolean);
  const basename = parts[parts.length - 1] || normTarget;
  const ancestorDirs = [];
  for (let i = 1; i < parts.length; i += 1) {
    ancestorDirs.push(parts.slice(0, i).join('/'));
  }

  for (const rawLine of ignoreContent.split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const matchDirOnly = trimmed.endsWith('/');
    const anchored = trimmed.startsWith('/');
    const body = trimmed.replace(/^\/+/, '').replace(/\/+$/, '');
    if (!body) continue;

    const regex = helmGlobToRegExp(body);
    let matchesTarget = false;
    if (body.includes('/')) {
      matchesTarget = (!matchDirOnly && regex.test(normTarget)) || ancestorDirs.some(dir => regex.test(dir));
    } else if (anchored) {
      const topEntry = parts[0] || normTarget;
      matchesTarget = (parts.length === 1 ? !matchDirOnly : true) && regex.test(topEntry);
    } else {
      matchesTarget = (!matchDirOnly && regex.test(basename)) || ancestorDirs.some(dir => regex.test(dir.split('/').pop()));
    }
    if (matchesTarget) {
      errors.push(`helm/knowthankyew-suite/.helmignore pattern "${trimmed}" would strip ${normTarget} from packaged Helm charts.`);
    }
  }
}

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

  const helmIgnorePath = resolve(REPO_ROOT, 'helm/knowthankyew-suite/.helmignore');
  if (existsSync(helmIgnorePath)) {
    auditHelmIgnoreContent(readFileSync(helmIgnorePath, 'utf-8'), errors, 'files/otel-collector-config.yaml');
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
  if (options.skipBrief) {
    return null;
  }
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
  auditGenesisAuthAndHardening(errors);
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
