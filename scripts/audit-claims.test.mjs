import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  APPROVED_ADAPTER_PATH_OTTL_PATTERN,
  APPROVED_BASE_MODEL_OTTL_PATTERN,
  APPROVED_DATASET_RELATIVE_PATH_OTTL_PATTERN,
  APPROVED_EVENT_NAME_OTTL_PATTERN,
  APPROVED_JURISDICTION_OTTL_PATTERN,
  APPROVED_RULE_ID_OTTL_PATTERN,
  APPROVED_RULE_IDS_CSV_OTTL_PATTERN,
  APPROVED_SCALAR_RULE_ID_OTTL_PATTERN,
  APPROVED_SCOPE_NAME_OTTL_PATTERN,
  APPROVED_SCOPE_VERSION_OTTL_PATTERN,
  APPROVED_SERVICE_INSTANCE_ID_OTTL_PATTERN,
  APPROVED_SPAN_NAME_OTTL_PATTERN,
  APPROVED_STATUS_OTTL_PATTERN,
  AUDIT_FLAG_COLLECTOR_KEYS,
  BOOLEAN_COLLECTOR_KEYS,
  BOUNDED_RESOURCE_STRING_SCHEMAS,
  BOUNDED_SCALAR_STRING_SCHEMAS,
  CANONICAL_COLLECTOR_ALLOWED_KEYS,
  CANONICAL_COLLECTOR_RESOURCE_KEYS,
  DATASET_NUMERIC_STEM_REJECT_PATTERN,
  NUMERIC_COLLECTOR_KEYS,
  PATH_COLLECTOR_SCHEMAS,
  auditBurnTelemetryScript,
  auditCollectorConfigObject,
  auditComposePortsObject,
  auditEffectiveComposeConfig,
  auditGenesisAuthEnforcement,
  auditHelmCollectorConfig,
  auditHelmIgnoreContent,
  auditNginxGatewayContent,
  buildLogTypeRedactStmt,
  buildNonScalarAttributeClauses,
  buildScalarSchemaPreflightDropStmt,
  buildScalarSchemaRedactStmt,
  mergeComposeConfigs,
  runAllAudits,
} from './audit-claims.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');

function buildBoundedDimStmt(attrKey, pattern) {
  return `set(attributes["${attrKey}"], "[REDACTED_SENSITIVE_VALUE]") where attributes["${attrKey}"] != nil and (not IsString(attributes["${attrKey}"]) or (attributes["${attrKey}"] != "" and attributes["${attrKey}"] != "[REDACTED_SENSITIVE_VALUE]" and not IsMatch(attributes["${attrKey}"], "${pattern}")))`;
}

function buildBoundedDimPreflightDropStmt(attrKey, pattern) {
  return `set(attributes["kty.scrubbed_overflow"], "drop") where attributes["${attrKey}"] != nil and (not IsString(attributes["${attrKey}"]) or (attributes["${attrKey}"] != "" and attributes["${attrKey}"] != "[REDACTED_SENSITIVE_VALUE]" and not IsMatch(attributes["${attrKey}"], "${pattern}")))`;
}

function buildValidCollectorConfig() {
  const resourceKeys = ['service.name', 'service.namespace', 'telemetry.sdk.version'];
  const dpKeys = ['status', 'rule_id'];
  const resourceKeysStmt = 'keep_keys(attributes, ["service.name", "service.namespace", "telemetry.sdk.version"])';
  const dpKeysStmt = 'keep_keys(attributes, ["status", "rule_id"])';
  const resPreflightDropStmts = resourceKeys.map(k =>
    buildScalarSchemaPreflightDropStmt(k, BOUNDED_RESOURCE_STRING_SCHEMAS[k], 'kty.resource_overflow')
  );
  const resRedactStmts = resourceKeys.map(k => buildScalarSchemaRedactStmt(k, BOUNDED_RESOURCE_STRING_SCHEMAS[k]));
  const boundedDimStmts = [
    buildBoundedDimStmt('status', APPROVED_STATUS_OTTL_PATTERN),
    buildBoundedDimStmt('rule_id', APPROVED_SCALAR_RULE_ID_OTTL_PATTERN),
  ];
  const boundedDimPreflightDropStmts = [
    buildBoundedDimPreflightDropStmt('status', APPROVED_STATUS_OTTL_PATTERN),
    buildBoundedDimPreflightDropStmt('rule_id', APPROVED_SCALAR_RULE_ID_OTTL_PATTERN),
  ];
  const scopeMetadataStmts = [
    `set(name, "[REDACTED_SCOPE_NAME]") where name != "" and not IsMatch(name, "${APPROVED_SCOPE_NAME_OTTL_PATTERN}")`,
    `set(version, "") where version != "" and not IsMatch(version, "${APPROVED_SCOPE_VERSION_OTTL_PATTERN}")`,
    'set(schema_url, "") where schema_url != ""',
  ];
  const preflightScopeStmts = [
    `set(attributes["kty.scope_overflow"], "drop") where name != "" and not IsMatch(name, "${APPROVED_SCOPE_NAME_OTTL_PATTERN}")`,
    `set(version, "") where version != "" and not IsMatch(version, "${APPROVED_SCOPE_VERSION_OTTL_PATTERN}")`,
    'set(schema_url, "") where schema_url != ""',
  ];
  return {
    connectors: {
      spanmetrics: {
        dimensions_cache_size: 1000,
        resource_metrics_cache_size: 100,
        metrics_expiration: '180m',
        dimensions: [{ name: 'status' }],
        exclude_dimensions: ['span.name'],
      },
    },
    processors: {
      memory_limiter: { check_interval: '1s' },
      batch: { send_batch_size: 256 },
      'transform/metrics_preflight': {
        error_mode: 'propagate',
        metric_statements: [
          {
            context: 'resource',
            statements: [
              'set(cache["kty_raw_resource_len"], Len(attributes))',
              resourceKeysStmt,
              'set(cache["kty_scrubbed_resource_len"], Len(attributes))',
              'set(attributes["kty.resource_overflow"], "drop") where cache["kty_scrubbed_resource_len"] < cache["kty_raw_resource_len"]',
              ...buildNonScalarAttributeClauses(resourceKeys, 'attributes').map(
                clause => `set(attributes["kty.resource_overflow"], "drop") where ${clause}`
              ),
              ...resPreflightDropStmts,
              'set(schema_url, "") where schema_url != ""',
            ],
          },
          {
            context: 'scope',
            statements: [
              'set(cache["kty_raw_scope_len"], Len(attributes))',
              'keep_keys(attributes, [])',
              'set(attributes["kty.scope_overflow"], "drop") where cache["kty_raw_scope_len"] > 0',
              ...preflightScopeStmts,
            ],
          },
          {
            context: 'datapoint',
            statements: [
              'set(cache["kty_raw_len"], Len(attributes))',
              dpKeysStmt,
              'set(cache["kty_scrubbed_len"], Len(attributes))',
              'set(attributes["kty.scrubbed_overflow"], "drop") where cache["kty_scrubbed_len"] < cache["kty_raw_len"]',
              ...buildNonScalarAttributeClauses(dpKeys, 'attributes').map(
                clause => `set(attributes["kty.scrubbed_overflow"], "drop") where ${clause}`
              ),
              ...boundedDimPreflightDropStmts,
            ],
          },
        ],
      },
      'filter/drop_noncompliant_traces': {
        error_mode: 'propagate',
        traces: {
          span: [
            'Len(links) > 0',
            ...buildNonScalarAttributeClauses(resourceKeys, 'resource.attributes'),
            ...buildNonScalarAttributeClauses(dpKeys, 'attributes'),
          ],
          spanevent: [...buildNonScalarAttributeClauses(dpKeys, 'attributes')],
        },
      },
      'filter/drop_noncompliant_metrics': {
        error_mode: 'propagate',
        metrics: {
          metric: [
            'resource.attributes["kty.resource_overflow"] == "drop"',
            'instrumentation_scope.attributes["kty.scope_overflow"] == "drop"',
            'name != "calls" and name != "duration" and name != "traces.span.metrics.calls" and name != "traces.span.metrics.duration"',
            '(name == "duration" or name == "traces.span.metrics.duration") and unit != "ms" and unit != "s"',
            '(name == "calls" or name == "traces.span.metrics.calls") and unit != "" and unit != "1" and unit != "{call}" and unit != "{calls}"',
          ],
          datapoint: [
            'attributes["kty.scrubbed_overflow"] == "drop"',
            'metric.type != METRIC_DATA_TYPE_SUMMARY and metric.type != METRIC_DATA_TYPE_NONE and Len(exemplars) > 0',
          ],
        },
      },
      transform: {
        error_mode: 'propagate',
        trace_statements: [
          {
            context: 'resource',
            statements: [resourceKeysStmt, ...resRedactStmts, 'set(schema_url, "") where schema_url != ""'],
          },
          {
            context: 'scope',
            statements: ['keep_keys(attributes, [])', ...scopeMetadataStmts],
          },
          {
            context: 'span',
            statements: [
              'set(status.message, "[REDACTED_STATUS_MESSAGE]") where status.message != ""',
              `set(name, "[REDACTED_SPAN_NAME]") where not IsMatch(name, "${APPROVED_SPAN_NAME_OTTL_PATTERN}")`,
              'set(trace_state, "") where trace_state != ""',
              dpKeysStmt,
              ...boundedDimStmts,
            ],
          },
          {
            context: 'spanevent',
            statements: [
              `set(name, "[REDACTED_EVENT_NAME]") where not IsMatch(name, "${APPROVED_EVENT_NAME_OTTL_PATTERN}")`,
              dpKeysStmt,
              ...boundedDimStmts,
            ],
          },
        ],
        metric_statements: [
          {
            context: 'resource',
            statements: [resourceKeysStmt, 'set(schema_url, "") where schema_url != ""'],
          },
          {
            context: 'scope',
            statements: ['keep_keys(attributes, [])', ...scopeMetadataStmts],
          },
          {
            context: 'metric',
            statements: ['set(description, "") where description != ""'],
          },
          {
            context: 'datapoint',
            statements: [dpKeysStmt],
          },
        ],
        log_statements: [
          {
            context: 'resource',
            statements: [resourceKeysStmt, ...resRedactStmts, 'set(schema_url, "") where schema_url != ""'],
          },
          {
            context: 'scope',
            statements: ['keep_keys(attributes, [])', ...scopeMetadataStmts],
          },
          {
            context: 'log',
            statements: [
              dpKeysStmt,
              ...boundedDimStmts,
              'set(body, "[REDACTED_LOG_BODY]") where body != nil',
            ],
          },
        ],
      },
    },
    exporters: {
      'otlp/jaeger': { endpoint: 'jaeger:4317', tls: { insecure: true } },
      prometheus: {
        endpoint: '0.0.0.0:8889',
        resource_to_telemetry_conversion: { enabled: true },
      },
      debug: { verbosity: 'basic' },
    },
    service: {
      pipelines: {
        traces: {
          processors: ['memory_limiter', 'filter/drop_noncompliant_traces', 'transform', 'batch'],
          exporters: ['otlp/jaeger', 'spanmetrics'],
        },
        metrics: {
          receivers: ['otlp', 'spanmetrics'],
          processors: [
            'memory_limiter',
            'transform/metrics_preflight',
            'filter/drop_noncompliant_metrics',
            'transform',
            'batch',
          ],
          exporters: ['prometheus', 'debug'],
        },
      },
    },
  };
}

describe('enterprise-self-host audit-claims', () => {
  it('passes full repository audit on clean workspace', () => {
    const { errors } = runAllAudits({ skipBrief: true });
    assert.deepEqual(errors, []);
  });

  it('rejects Nginx location modifiers, variable smuggling, and proxy_pass routes to genesis and surprisal', () => {
    const cases = [
      'location = /genesis/ {\n  proxy_pass http://localhost:9002/;\n}',
      'location ^~ /surprisal/ {\n  proxy_pass http://localhost:5200/;\n}',
      'location ~* ^/genesis {\n  return 200;\n}',
      'location /internal/ {\n  proxy_pass http://genesis:8080/;\n}',
      'location /alt/ {\n  proxy_pass http://surprisal-service:5200/;\n}',
      'upstream private_engine {\n  server genesis:8080;\n}\nserver {\n  location /internal/ {\n    proxy_pass http://private_engine;\n  }\n}',
      'upstream ml_up {\n  server 127.0.0.1:5200 max_fails=2;\n}\nserver {\n  location /ml/ {\n    proxy_pass http://ml_up$request_uri;\n  }\n}',
      'upstream private_engine {\n  server genesis:8080;\n}\nserver {\n  location /indirect/ {\n    set $backend http://private_engine;\n    proxy_pass $backend;\n  }\n}',
      'location /dyn/ {\n  proxy_pass $arg_url;\n}',
      'location /dyn-host/ {\n  proxy_pass http://$arg_host/otlp/;\n}',
      'location /a/ {\n  set $backend http://otel-collector:4318/;\n}\nlocation /b/ {\n  proxy_pass $backend;\n}',
      'map $http_x_dest $dyn_target {\n  default http://otel-collector:4318/;\n}\nserver {\n  location /otlp/ {\n    proxy_pass $dyn_target;\n  }\n}',
      'location /otlp/ {\n  set $target http://otel-collector:4318/;\n  if ($arg_debug) {\n    set $target http://genesis:8080/;\n  }\n  proxy_pass $target;\n}',
      'location /otlp/debug/ {\n  proxy_pass http://jaeger:16686/;\n}',
      'location ^~ /otlp/raw {\n  return 200 "disabled";\n}',
      'location /otlp/ {\n  proxy_pass http://otel-collector:4318/;\n}\nlocation /collector-metrics/ {\n  proxy_pass http://otel-collector:8889/;\n}',
      'upstream collector_mgmt {\n  server otel-collector:8889;\n}\nserver {\n  location /otlp/ {\n    proxy_pass http://otel-collector:4318/;\n  }\n  location /collector-metrics/ {\n    proxy_pass http://collector_mgmt/;\n  }\n}',
      'location /alt-otlp/ {\n  proxy_pass http://otel-collector:4318/;\n}',
      'location /public/otlp/ {\n  proxy_pass http://otel-collector:4318/;\n}',
      'location /otlp/ {\n  proxy_pass http://otel-collector:4318/;\n}\nlocation /public/otlp/ {\n  proxy_pass http://otel-collector:4318/;\n}',
      'location ~ ^/otlp/|^/v1/ {\n  proxy_pass http://otel-collector:4318/;\n}',
      'location ~* ^/v1/|/genesis {\n  proxy_pass http://otel-collector:4318/;\n}',
      'location = /otlp/ {\n  proxy_pass http://otel-collector:4318/;\n}',
      'upstream quoted_otel {\n  server "otel-collector:8889";\n}\nserver {\n  location /otlp/ {\n    proxy_pass http://quoted_otel/;\n  }\n}',
      'upstream quoted_mgmt {\n  server \'kty-otel-collector:13133\';\n}\nserver {\n  location /debug/ {\n    proxy_pass "http://quoted_mgmt/";\n  }\n}',
      'location /raw/ {\n  grpc_pass grpc://otel-collector:4317;\n}',
      'location /otlp/ {\n  proxy_pass http://otel-collector:4318/;\n}\nlocation ~ ^/ {\n  proxy_pass http://example.com/;\n}',
      'location /otlp/ {\n  proxy_pass http://otel-collector:4318/;\n}',
    ];

    for (const snippet of cases) {
      const errors = [];
      auditNginxGatewayContent(snippet, errors);
      assert.ok(errors.length > 0, `Expected failure for snippet:\n${snippet}`);
    }

    const validUpstream = 'upstream otel_up {\n  server otel-collector:4318;\n}\nlocation ^~ /otlp/ {\n  proxy_pass http://otel_up/;\n}\n';
    const validUpErrors = [];
    auditNginxGatewayContent(validUpstream, validUpErrors);
    assert.deepEqual(validUpErrors, []);

    const commentedOnly = '# location = /genesis/\nlocation ^~ /otlp/ {\n  proxy_pass http://otel-collector:4318/;\n}\n';
    const cleanErrors = [];
    auditNginxGatewayContent(commentedOnly, cleanErrors);
    assert.deepEqual(cleanErrors, []);
  });

  it('rejects Compose overlays that weaken GENESIS_AUTH_TOKEN env, leak -auth-token on CLI, override entrypoint, or expose non-loopback ports', () => {
    const base = {
      services: {
        genesis: {
          command: ['server', '-allow-all-interfaces', '-http=:8080', '-tcp=:9000', '-redact'],
          environment: ['GENESIS_AUTH_TOKEN=${GENESIS_AUTH_TOKEN:?required}'],
          ports: ['127.0.0.1:${GENESIS_PORT:-9002}:8080', '127.0.0.1:${GENESIS_TCP_PORT:-9000}:9000'],
        },
        'surprisal-service': {
          ports: ['127.0.0.1:${SURPRISAL_PORT:-5200}:5200'],
        },
      },
    };
    const okErr = [];
    auditEffectiveComposeConfig(base, 'base', okErr);
    assert.deepEqual(okErr, []);

    const cliTokenLeak = mergeComposeConfigs(base, {
      services: { genesis: { command: ['server', '-http=:8080', '-auth-token=${GENESIS_AUTH_TOKEN:?required}'] } },
    });
    const cliErr = [];
    auditEffectiveComposeConfig(cliTokenLeak, 'overlay-cli-token', cliErr);
    assert.ok(cliErr.some(e => e.includes('cmdline')));

    const envCleared = mergeComposeConfigs(base, {
      services: { genesis: { environment: { GENESIS_AUTH_TOKEN: '' } } },
    });
    const envClearedErr = [];
    auditEffectiveComposeConfig(envCleared, 'overlay-env-cleared', envClearedErr);
    assert.ok(envClearedErr.some(e => e.includes('GENESIS_AUTH_TOKEN')));

    const envArrayCleared = mergeComposeConfigs(base, {
      services: { genesis: { environment: ['GENESIS_AUTH_TOKEN=${GENESIS_AUTH_TOKEN:?required}', 'GENESIS_AUTH_TOKEN='] } },
    });
    const envArrErr = [];
    auditEffectiveComposeConfig(envArrayCleared, 'overlay-env-arr-cleared', envArrErr);
    assert.ok(envArrErr.some(e => e.includes('GENESIS_AUTH_TOKEN')));

    const envPassthroughOnly = mergeComposeConfigs(base, {
      services: { genesis: { environment: ['GENESIS_AUTH_TOKEN'] } },
    });
    const passthroughErr = [];
    auditEffectiveComposeConfig(envPassthroughOnly, 'overlay-env-passthrough', passthroughErr);
    assert.ok(passthroughErr.some(e => e.includes('GENESIS_AUTH_TOKEN')));

    const missingEnv = {
      services: {
        genesis: {
          command: ['server', '-allow-all-interfaces', '-http=:8080', '-tcp=:9000', '-redact'],
          ports: ['127.0.0.1:9002:8080'],
        },
        'surprisal-service': { ports: ['127.0.0.1:5200:5200'] },
      },
    };
    const missingEnvErr = [];
    auditEffectiveComposeConfig(missingEnv, 'missing-env', missingEnvErr);
    assert.ok(missingEnvErr.some(e => e.includes('GENESIS_AUTH_TOKEN')));

    const entrypointOverride = mergeComposeConfigs(base, {
      services: { genesis: { entrypoint: ['/bin/sh', '-c', '/app/genesis server'] } },
    });
    const epErr = [];
    auditEffectiveComposeConfig(entrypointOverride, 'overlay-entrypoint', epErr);
    assert.ok(epErr.some(e => e.includes('entrypoint')));

    const portOverride = mergeComposeConfigs(base, {
      services: { genesis: { ports: ['9002:8080'] } },
    });
    const portErr = [];
    auditEffectiveComposeConfig(portOverride, 'overlay-ports', portErr);
    assert.ok(portErr.some(e => e.includes('9002:8080')));
  });

  it('rejects any additional non-loopback port bindings on genesis or surprisal-service', () => {
    const validCompose = {
      services: {
        genesis: {
          ports: [
            '127.0.0.1:${GENESIS_PORT:-9002}:8080',
            '127.0.0.1:${GENESIS_TCP_PORT:-9000}:9000',
          ],
        },
        'surprisal-service': {
          ports: ['127.0.0.1:${SURPRISAL_PORT:-5200}:5200'],
        },
      },
    };
    const okErr = [];
    auditComposePortsObject(validCompose, 'docker-compose.yml', okErr, { requireDefaultBindings: true });
    assert.deepEqual(okErr, []);

    const extraWildcard = structuredClone(validCompose);
    extraWildcard.services['surprisal-service'].ports.push('0.0.0.0:15200:5200');
    const wildcardErr = [];
    auditComposePortsObject(extraWildcard, 'docker-compose.yml', wildcardErr, { requireDefaultBindings: true });
    assert.ok(wildcardErr.some(e => e.includes('0.0.0.0:15200:5200')));

    const unboundPort = structuredClone(validCompose);
    unboundPort.services.genesis.ports.push('15900:9000');
    const unboundErr = [];
    auditComposePortsObject(unboundPort, 'docker-compose.yml', unboundErr, { requireDefaultBindings: true });
    assert.ok(unboundErr.some(e => e.includes('15900:9000')));

    const longSyntaxNoHost = structuredClone(validCompose);
    longSyntaxNoHost.services['surprisal-service'].ports.push({ target: 5200, published: 15200 });
    const longErr = [];
    auditComposePortsObject(longSyntaxNoHost, 'docker-compose.yml', longErr, { requireDefaultBindings: true });
    assert.ok(longErr.some(e => e.includes('long-syntax')));
  });

  it('rejects Helm collector ConfigMap drift across metric pipelines and keysets', () => {
    const collectorRaw = readFileSync(resolve(REPO_ROOT, 'collector/otel-collector-config.yaml'), 'utf-8');
    const validHelm = readFileSync(
      resolve(REPO_ROOT, 'helm/knowthankyew-suite/templates/observability/collector-configmap.yaml'),
      'utf-8'
    );
    const helmFileContent = readFileSync(
      resolve(REPO_ROOT, 'helm/knowthankyew-suite/files/otel-collector-config.yaml'),
      'utf-8'
    );

    const spanMatch = collectorRaw.match(/context:\s*span[\s\S]*?keep_keys\(attributes,\s*\[([^\]]+)\]/);
    const resMatch = collectorRaw.match(/context:\s*resource[\s\S]*?keep_keys\(attributes,\s*\[([^\]]+)\]/);
    assert.ok(spanMatch && resMatch);

    const realKeys = new Set(spanMatch[1].split(',').map(k => k.trim().replace(/^["']|["']$/g, '')));
    const realResourceKeys = new Set(resMatch[1].split(',').map(k => k.trim().replace(/^["']|["']$/g, '')));

    const cleanHelmErrors = [];
    auditHelmCollectorConfig(validHelm, realKeys, realResourceKeys, cleanHelmErrors, {
      helmFileContent,
      collectorRaw,
    });
    assert.deepEqual(cleanHelmErrors, []);

    const missingFilesGetHelm = validHelm.replace(
      /\{\{.*Files\.Get.*\}\}/,
      '    placeholder: true'
    );
    const missingFilesGetErr = [];
    auditHelmCollectorConfig(missingFilesGetHelm, realKeys, realResourceKeys, missingFilesGetErr, {
      helmFileContent,
      collectorRaw,
    });
    assert.ok(missingFilesGetErr.some(e => e.includes('.Files.Get "files/otel-collector-config.yaml"')));

    const missingHelmFileErr = [];
    auditHelmCollectorConfig(validHelm, realKeys, realResourceKeys, missingHelmFileErr, {
      helmFileContent: null,
      collectorRaw,
    });
    assert.ok(missingHelmFileErr.some(e => e.includes('Missing helm/knowthankyew-suite/files/otel-collector-config.yaml')));

    const driftedPipelineFile = helmFileContent.replace(
      'metrics:\n      receivers: [otlp, spanmetrics]\n      processors: [memory_limiter, transform/metrics_preflight, filter/drop_noncompliant_metrics, transform, batch]',
      'metrics:\n      receivers: [otlp, spanmetrics]\n      processors: [memory_limiter, batch]'
    );
    const errors = [];
    auditHelmCollectorConfig(validHelm, realKeys, realResourceKeys, errors, {
      helmFileContent: driftedPipelineFile,
      collectorRaw,
    });
    assert.ok(errors.some(e => e.includes('has drifted from collector/otel-collector-config.yaml')));
    assert.ok(errors.some(e => e.includes('service.pipelines.metrics must include "transform"')));
  });

  it('rejects collector configs missing metric admission filters, spanevent/resource/scope filters, or containing http.target', () => {
    const cfg = buildValidCollectorConfig();
    const okErrors = [];
    auditCollectorConfigObject(cfg, okErrors);
    assert.deepEqual(okErrors, []);

    const badTarget = buildValidCollectorConfig();
    badTarget.processors.transform.trace_statements[2].statements = ['keep_keys(attributes, ["status", "rule_id", "http.target"])'];
    const targetErrors = [];
    auditCollectorConfigObject(badTarget, targetErrors);
    assert.ok(targetErrors.some(e => e.includes('http.target')));

    const badOrder = buildValidCollectorConfig();
    badOrder.service.pipelines.metrics.processors = [
      'memory_limiter',
      'batch',
      'transform/metrics_preflight',
      'filter/drop_noncompliant_metrics',
      'transform',
    ];
    const orderErrors = [];
    auditCollectorConfigObject(badOrder, orderErrors);
    assert.ok(orderErrors.some(e => e.includes('execute "transform" before "batch"')));
  });

  it('rejects conditional scrubbing rules, scope/resource leaks, stateful/lossy metric ops, and named bypass pipelines', () => {
    const conditionalSpanEvent = buildValidCollectorConfig();
    conditionalSpanEvent.processors.transform.trace_statements[3].conditions = ['false'];
    const condErrors = [];
    auditCollectorConfigObject(conditionalSpanEvent, condErrors);
    assert.ok(condErrors.some(e => e.includes('spanevent')));

    const whereClauseKeep = buildValidCollectorConfig();
    whereClauseKeep.processors.transform.trace_statements[3].statements = ['keep_keys(attributes, ["status", "rule_id"]) where false'];
    const whereErrors = [];
    auditCollectorConfigObject(whereClauseKeep, whereErrors);
    assert.ok(whereErrors.some(e => e.includes('spanevent')));

    const scopeLeak = buildValidCollectorConfig();
    scopeLeak.processors.transform.trace_statements[1].statements = ['keep_keys(attributes, ["user.email"])'];
    const scopeErrors = [];
    auditCollectorConfigObject(scopeLeak, scopeErrors);
    assert.ok(scopeErrors.some(e => e.includes('instrumentation-scope')));

    const resLeak = buildValidCollectorConfig();
    resLeak.processors.transform.trace_statements[0].statements = ['keep_keys(attributes, ["service.name", "service.namespace", "telemetry.sdk.version", "hospital_id"])'];
    const resErrors = [];
    auditCollectorConfigObject(resLeak, resErrors);
    assert.ok(resErrors.some(e => e.includes('hospital_id')));

    const missingNamespace = buildValidCollectorConfig();
    for (const stmt of [
      missingNamespace.processors['transform/metrics_preflight'].metric_statements[0].statements,
      missingNamespace.processors.transform.trace_statements[0].statements,
      missingNamespace.processors.transform.metric_statements[0].statements,
      missingNamespace.processors.transform.log_statements[0].statements,
    ]) {
      const idx = stmt.findIndex(s => s.startsWith('keep_keys'));
      stmt[idx] = 'keep_keys(attributes, ["service.name", "telemetry.sdk.version"])';
    }
    const nsErrors = [];
    auditCollectorConfigObject(missingNamespace, nsErrors);
    assert.ok(nsErrors.some(e => e.includes('service.namespace')));

    const namedLogs = buildValidCollectorConfig();
    namedLogs.service.pipelines['logs/otlp'] = { processors: ['memory_limiter', 'batch'] };
    const logsErrors = [];
    auditCollectorConfigObject(namedLogs, logsErrors);
    assert.ok(logsErrors.some(e => e.includes('logs/otlp')));

    const namedUnfilteredTrace = buildValidCollectorConfig();
    namedUnfilteredTrace.service.pipelines['traces/unfiltered'] = { processors: ['memory_limiter', 'batch'] };
    const traceErrors = [];
    auditCollectorConfigObject(namedUnfilteredTrace, traceErrors);
    assert.ok(traceErrors.some(e => e.includes('traces/unfiltered')));

    const namedStatefulMetrics = buildValidCollectorConfig();
    namedStatefulMetrics.processors['cumulativetodelta/raw'] = { initial_value: 'keep', max_staleness: '24h' };
    namedStatefulMetrics.service.pipelines.metrics.processors = [
      'memory_limiter',
      'cumulativetodelta/raw',
      'transform/metrics_preflight',
      'filter/drop_noncompliant_metrics',
      'transform',
      'batch',
    ];
    const statefulErrors = [];
    auditCollectorConfigObject(namedStatefulMetrics, statefulErrors);
    assert.ok(statefulErrors.some(e => e.includes('cumulativetodelta/raw')));

    const injectedAgg = buildValidCollectorConfig();
    injectedAgg.processors.transform.metric_statements.splice(2, 0, {
      context: 'metric',
      statements: [
        'aggregate_on_attributes("sum", ["status", "rule_id"]) where type == METRIC_DATA_TYPE_SUM',
      ],
    });
    const aggErrors = [];
    auditCollectorConfigObject(injectedAgg, aggErrors);
    assert.ok(aggErrors.some(e => e.includes('aggregate_on_attributes')));

    const injectedExpConv = buildValidCollectorConfig();
    injectedExpConv.processors['transform/metrics_preflight'].metric_statements.splice(2, 0, {
      context: 'metric',
      statements: [
        'convert_exponential_histogram_to_histogram("uniform", [0.0, 10.0]) where type == METRIC_DATA_TYPE_EXPONENTIAL_HISTOGRAM',
      ],
    });
    const expConvErrors = [];
    auditCollectorConfigObject(injectedExpConv, expConvErrors);
    assert.ok(expConvErrors.some(e => e.includes('convert_exponential_histogram_to_histogram')));

    const missingSpanNameExclude = buildValidCollectorConfig();
    missingSpanNameExclude.connectors.spanmetrics.exclude_dimensions = [];
    const excludeErr = [];
    auditCollectorConfigObject(missingSpanNameExclude, excludeErr);
    assert.ok(excludeErr.some(e => e.includes('exclude_dimensions')));

    const missingTraceLinkFilter = buildValidCollectorConfig();
    delete missingTraceLinkFilter.processors['filter/drop_noncompliant_traces'];
    const linkFilterErr = [];
    auditCollectorConfigObject(missingTraceLinkFilter, linkFilterErr);
    assert.ok(linkFilterErr.some(e => e.includes('filter/drop_noncompliant_traces')));

    const lateTraceLinkFilter = buildValidCollectorConfig();
    lateTraceLinkFilter.service.pipelines.traces.processors = [
      'memory_limiter',
      'transform',
      'filter/drop_noncompliant_traces',
      'batch',
    ];
    const lateTraceErr = [];
    auditCollectorConfigObject(lateTraceLinkFilter, lateTraceErr);
    assert.ok(lateTraceErr.some(e => e.includes('filter/drop_noncompliant_traces')));

    const missingScopeOverflowDrop = buildValidCollectorConfig();
    missingScopeOverflowDrop.processors['filter/drop_noncompliant_metrics'].metrics.metric = [];
    const scopeDropErr = [];
    auditCollectorConfigObject(missingScopeOverflowDrop, scopeDropErr);
    assert.ok(scopeDropErr.some(e => e.includes('kty.scope_overflow')));

    const postScrubSet = buildValidCollectorConfig();
    postScrubSet.processors.transform.trace_statements[0].statements.push(
      'set(attributes["user.email"], "alice@example.test")'
    );
    const postScrubErr = [];
    auditCollectorConfigObject(postScrubSet, postScrubErr);
    assert.ok(postScrubErr.some(e => e.includes('user.email')));

    const crossContextWrite = buildValidCollectorConfig();
    crossContextWrite.processors.transform.trace_statements[2].statements.push(
      'set(resource.attributes["user.email"], "alice@example.test")'
    );
    const crossErr = [];
    auditCollectorConfigObject(crossContextWrite, crossErr);
    assert.ok(crossErr.some(e => e.includes('cross-context')));

    const wrongPreflightOrder = buildValidCollectorConfig();
    wrongPreflightOrder.service.pipelines.metrics.processors = [
      'memory_limiter',
      'filter/drop_noncompliant_metrics',
      'transform/metrics_preflight',
      'transform',
      'batch',
    ];
    const preflightOrderErr = [];
    auditCollectorConfigObject(wrongPreflightOrder, preflightOrderErr);
    assert.ok(preflightOrderErr.some(e => e.includes('strict order')));

    const unionMaskedDrop = buildValidCollectorConfig();
    unionMaskedDrop.processors.transform.metric_statements[3].statements = [
      'keep_keys(attributes, ["status", "rule_id"])',
      'keep_keys(attributes, ["status"])',
    ];
    const intersectionErrors = [];
    auditCollectorConfigObject(unionMaskedDrop, intersectionErrors);
    assert.ok(intersectionErrors.some(e => e.includes('metric_statements datapoint keep_keys missing allowlisted key "rule_id"')));

    const scopeLeakClearedLater = buildValidCollectorConfig();
    scopeLeakClearedLater.processors.transform.trace_statements[1].statements = [
      'keep_keys(attributes, ["user.email"])',
      'keep_keys(attributes, [])',
    ];
    const scopeMultiErrors = [];
    auditCollectorConfigObject(scopeLeakClearedLater, scopeMultiErrors);
    assert.ok(scopeMultiErrors.some(e => e.includes('instrumentation-scope')));
  });

  it('rejects unlisted keys, span.name, post-transform processors, missing exemplar drop, and fail-open burn scripts', () => {
    const unlistedKey = buildValidCollectorConfig();
    unlistedKey.processors.transform.trace_statements[2].statements = [
      'keep_keys(attributes, ["status", "rule_id", "user.email"])',
    ];
    const unlistedErrors = [];
    auditCollectorConfigObject(unlistedKey, unlistedErrors);
    assert.ok(unlistedErrors.some(e => e.includes('user.email')));

    const spanNameCfg = buildValidCollectorConfig();
    spanNameCfg.processors.transform.trace_statements[2].statements = [
      'keep_keys(attributes, ["status", "rule_id", "span.name"])',
    ];
    const spanNameErrors = [];
    auditCollectorConfigObject(spanNameCfg, spanNameErrors);
    assert.ok(spanNameErrors.some(e => e.includes('span.name')));

    const unlistedResource = buildValidCollectorConfig();
    unlistedResource.processors.transform.trace_statements[0].statements = [
      'keep_keys(attributes, ["service.name", "service.namespace", "user.email"])',
    ];
    const resErrors = [];
    auditCollectorConfigObject(unlistedResource, resErrors);
    assert.ok(resErrors.some(e => e.includes('user.email')));

    const postTransformRestore = buildValidCollectorConfig();
    postTransformRestore.service.pipelines.traces.processors = [
      'memory_limiter',
      'filter/drop_noncompliant_traces',
      'transform',
      'attributes/restore',
      'batch',
    ];
    const procErrors = [];
    auditCollectorConfigObject(postTransformRestore, procErrors);
    assert.ok(procErrors.some(e => e.includes('post-transform processors')));

    const missingExemplarDrop = buildValidCollectorConfig();
    missingExemplarDrop.processors['filter/drop_noncompliant_metrics'].metrics.datapoint = [
      'attributes["kty.scrubbed_overflow"] == "drop"',
    ];
    const exemplarErrors = [];
    auditCollectorConfigObject(missingExemplarDrop, exemplarErrors);
    assert.ok(exemplarErrors.some(e => e.includes('Len(exemplars) > 0')));

    const missingPromResourceConv = buildValidCollectorConfig();
    missingPromResourceConv.exporters.prometheus.resource_to_telemetry_conversion = { enabled: false };
    const promResourceConvErrors = [];
    auditCollectorConfigObject(missingPromResourceConv, promResourceConvErrors);
    assert.ok(promResourceConvErrors.some(e => e.includes('resource_to_telemetry_conversion.enabled')));

    const failOpenBurn = `#!/usr/bin/env bash
set -euo pipefail
curl --noproxy '*' -X POST -s "http://127.0.0.1:9090/api/v1/admin/tsdb/delete_series" -d 'match[]={__name__=~".+"}' 2>/dev/null || true
curl --noproxy '*' -X POST -s "http://127.0.0.1:9090/api/v1/admin/tsdb/clean_tombstones" 2>/dev/null || true
`;
    const burnErrors = [];
    auditBurnTelemetryScript(failOpenBurn, burnErrors);
    assert.ok(burnErrors.some(e => e.includes('|| true')));
    assert.ok(burnErrors.some(e => e.includes('-fsS')));
  });

  it('R8 Hardening: guards Summary exemplars, sanitizes trace text, keeps preflight blocks intact, and tests burn exits behaviorally', () => {
    const unguardedExemplars = buildValidCollectorConfig();
    unguardedExemplars.processors['filter/drop_noncompliant_metrics'].metrics.datapoint = [
      'attributes["kty.scrubbed_overflow"] == "drop"',
      'Len(exemplars) > 0',
    ];
    const exemplarGuardErr = [];
    auditCollectorConfigObject(unguardedExemplars, exemplarGuardErr);
    assert.ok(exemplarGuardErr.some(e => e.includes('guarded Len(exemplars) > 0')));

    const missingSpanRedaction = buildValidCollectorConfig();
    missingSpanRedaction.processors.transform.trace_statements[2].statements = [
      'keep_keys(attributes, ["status", "rule_id"])',
    ];
    const spanTextErr = [];
    auditCollectorConfigObject(missingSpanRedaction, spanTextErr);
    assert.ok(spanTextErr.some(e => e.includes('status.message')));
    assert.ok(spanTextErr.some(e => e.includes('span name')));

    const missingEventNameRedaction = buildValidCollectorConfig();
    missingEventNameRedaction.processors.transform.trace_statements[3].statements = [
      'keep_keys(attributes, ["status", "rule_id"])',
    ];
    const eventTextErr = [];
    auditCollectorConfigObject(missingEventNameRedaction, eventTextErr);
    assert.ok(eventTextErr.some(e => e.includes('spanevent')));

    const splitDpBlocks = buildValidCollectorConfig();
    splitDpBlocks.processors['transform/metrics_preflight'].metric_statements = [
      splitDpBlocks.processors['transform/metrics_preflight'].metric_statements[0],
      splitDpBlocks.processors['transform/metrics_preflight'].metric_statements[1],
      {
        context: 'datapoint',
        statements: ['set(cache["kty_raw_len"], Len(attributes))'],
      },
      {
        context: 'datapoint',
        statements: [
          'keep_keys(attributes, ["status", "rule_id"])',
          'set(cache["kty_scrubbed_len"], Len(attributes))',
          'set(attributes["kty.scrubbed_overflow"], "drop") where cache["kty_scrubbed_len"] < cache["kty_raw_len"]',
        ],
      },
    ];
    const splitDpErr = [];
    auditCollectorConfigObject(splitDpBlocks, splitDpErr);
    assert.ok(splitDpErr.some(e => e.includes('within one statement block')));

    const splitScopeBlocks = buildValidCollectorConfig();
    splitScopeBlocks.processors['transform/metrics_preflight'].metric_statements = [
      splitScopeBlocks.processors['transform/metrics_preflight'].metric_statements[0],
      {
        context: 'scope',
        statements: ['set(cache["kty_raw_scope_len"], Len(attributes))'],
      },
      {
        context: 'scope',
        statements: [
          'keep_keys(attributes, [])',
          'set(attributes["kty.scope_overflow"], "drop") where cache["kty_raw_scope_len"] > 0',
        ],
      },
      splitScopeBlocks.processors['transform/metrics_preflight'].metric_statements[2],
    ];
    const splitScopeErr = [];
    auditCollectorConfigObject(splitScopeBlocks, splitScopeErr);
    assert.ok(splitScopeErr.some(e => e.includes('scope') && e.includes('within one statement block')));

    const silentDeleteSeriesExit = `#!/usr/bin/env bash
set -e
prom_rc=0
echo "Flushing and purging in-memory traces from Jaeger..."
docker restart kty-jaeger || exit 1
echo "Flushing and resetting OpenTelemetry Collector buffers..."
docker restart kty-otel-collector || exit 1
if ! curl --noproxy '*' --connect-timeout 3 --max-time 10 -fsS -X POST "http://127.0.0.1:9090/api/v1/admin/tsdb/delete_series" --data-urlencode 'match[]={__name__=~".+"}'; then
  prom_rc=1
fi
if ! curl --noproxy '*' --connect-timeout 3 --max-time 10 -fsS -X POST "http://127.0.0.1:9090/api/v1/admin/tsdb/clean_tombstones"; then
  :
fi
if [ "$prom_rc" -ne 0 ]; then
  exit "$prom_rc"
fi
exit 0
`;
    const silentCleanErr = [];
    auditBurnTelemetryScript(silentDeleteSeriesExit, silentCleanErr);
    assert.ok(silentCleanErr.some(e => e.includes('clean_tombstones')));
    assert.ok(!silentCleanErr.some(e => e.includes('delete_series')));

    const silentBothExit = `#!/usr/bin/env bash
set -e
prom_rc=0
echo "Flushing and purging in-memory traces from Jaeger..."
docker restart kty-jaeger || exit 1
echo "Flushing and resetting OpenTelemetry Collector buffers..."
docker restart kty-otel-collector || exit 1
if ! curl --noproxy '*' --connect-timeout 3 --max-time 10 -fsS -X POST "http://127.0.0.1:9090/api/v1/admin/tsdb/delete_series" --data-urlencode 'match[]={__name__=~".+"}'; then
  prom_rc=1
fi
if ! curl --noproxy '*' --connect-timeout 3 --max-time 10 -fsS -X POST "http://127.0.0.1:9090/api/v1/admin/tsdb/clean_tombstones"; then
  prom_rc=1
fi
exit 0
`;
    const silentBothErr = [];
    auditBurnTelemetryScript(silentBothExit, silentBothErr);
    assert.ok(silentBothErr.some(e => e.includes('delete_series')));
    assert.ok(silentBothErr.some(e => e.includes('clean_tombstones')));

    const unconditionalFail = `#!/usr/bin/env bash
# fake -fsS delete_series clean_tombstones
exit 1
`;
    const unconditionalFailErr = [];
    auditBurnTelemetryScript(unconditionalFail, unconditionalFailErr);
    assert.ok(unconditionalFailErr.some(e => e.includes('exited non-zero when all purge endpoints succeeded') || e.includes('did not execute')));
  });

  it('R10 Hardening: rejects broad slug regexes, missing non-scalar guards, metric admission gaps, and selectorless burns', () => {
    const broadSpanSlug = buildValidCollectorConfig();
    broadSpanSlug.processors.transform.trace_statements[2].statements[1] =
      'set(name, "[REDACTED_SPAN_NAME]") where not IsMatch(name, "^[a-z][a-z0-9_.-]{0,63}$")';
    const broadSpanErr = [];
    auditCollectorConfigObject(broadSpanSlug, broadSpanErr);
    assert.ok(broadSpanErr.some(e => e.includes('span name') || e.includes('IsMatch')));

    const broadEventSlug = buildValidCollectorConfig();
    broadEventSlug.processors.transform.trace_statements[3].statements[0] =
      'set(name, "[REDACTED_EVENT_NAME]") where not IsMatch(name, "^[a-z][a-z0-9_.-]{0,63}$")';
    const broadEventErr = [];
    auditCollectorConfigObject(broadEventSlug, broadEventErr);
    assert.ok(broadEventErr.some(e => e.includes('spanevent') || e.includes('IsMatch')));

    const missingPreflightResGuard = buildValidCollectorConfig();
    missingPreflightResGuard.processors['transform/metrics_preflight'].metric_statements[0].statements[4] =
      'set(attributes["kty.resource_overflow"], "drop") where ' +
      buildNonScalarAttributeClauses(['service.name', 'service.namespace'], 'attributes')[0];
    const pfResGuardErr = [];
    auditCollectorConfigObject(missingPreflightResGuard, pfResGuardErr);
    assert.ok(pfResGuardErr.some(e => e.includes('telemetry.sdk.version') && e.includes('non-scalar')));

    const missingPreflightDpGuard = buildValidCollectorConfig();
    missingPreflightDpGuard.processors['transform/metrics_preflight'].metric_statements[2].statements[4] =
      'set(attributes["kty.scrubbed_overflow"], "drop") where ' +
      buildNonScalarAttributeClauses(['status'], 'attributes')[0];
    const pfDpGuardErr = [];
    auditCollectorConfigObject(missingPreflightDpGuard, pfDpGuardErr);
    assert.ok(pfDpGuardErr.some(e => e.includes('rule_id') && e.includes('non-scalar')));

    const missingTraceSpanGuard = buildValidCollectorConfig();
    missingTraceSpanGuard.processors['filter/drop_noncompliant_traces'].traces.span = [
      'Len(links) > 0',
      ...buildNonScalarAttributeClauses(['service.name', 'service.namespace', 'telemetry.sdk.version'], 'resource.attributes'),
      ...buildNonScalarAttributeClauses(['status'], 'attributes'),
    ];
    const traceSpanGuardErr = [];
    auditCollectorConfigObject(missingTraceSpanGuard, traceSpanGuardErr);
    assert.ok(traceSpanGuardErr.some(e => e.includes('rule_id') && e.includes('non-scalar')));

    const missingTraceEventGuard = buildValidCollectorConfig();
    missingTraceEventGuard.processors['filter/drop_noncompliant_traces'].traces.spanevent = [
      ...buildNonScalarAttributeClauses(['status'], 'attributes'),
    ];
    const traceEventGuardErr = [];
    auditCollectorConfigObject(missingTraceEventGuard, traceEventGuardErr);
    assert.ok(traceEventGuardErr.some(e => e.includes('spanevent') && e.includes('rule_id')));

    const missingMetricDescClear = buildValidCollectorConfig();
    missingMetricDescClear.processors.transform.metric_statements.splice(2, 1);
    const descErr = [];
    auditCollectorConfigObject(missingMetricDescClear, descErr);
    assert.ok(descErr.some(e => e.includes('clear non-empty description')));

    const missingMetricNameFilter = buildValidCollectorConfig();
    missingMetricNameFilter.processors['filter/drop_noncompliant_metrics'].metrics.metric =
      missingMetricNameFilter.processors['filter/drop_noncompliant_metrics'].metrics.metric.filter(
        c => !c.includes('name !=')
      );
    const metricNameErr = [];
    auditCollectorConfigObject(missingMetricNameFilter, metricNameErr);
    assert.ok(metricNameErr.some(e => e.includes('metrics.metric [name]')));

    const selectorlessBurn = `#!/usr/bin/env bash
set -e
prom_rc=0
echo "Flushing and purging in-memory traces from Jaeger..."
docker restart kty-jaeger || exit 1
echo "Flushing and resetting OpenTelemetry Collector buffers..."
docker restart kty-otel-collector || exit 1
if ! curl --noproxy '*' --connect-timeout 3 --max-time 10 -fsS -X POST "http://127.0.0.1:9090/api/v1/admin/tsdb/delete_series"; then
  prom_rc=1
fi
if ! curl --noproxy '*' --connect-timeout 3 --max-time 10 -fsS -X POST "http://127.0.0.1:9090/api/v1/admin/tsdb/clean_tombstones"; then
  prom_rc=1
fi
if [ "$prom_rc" -ne 0 ]; then
  exit "$prom_rc"
fi
exit 0
`;
    const selectorlessErr = [];
    auditBurnTelemetryScript(selectorlessBurn, selectorlessErr);
    assert.ok(selectorlessErr.some(e => e.includes('match[]={__name__=~".+"}')));
  });

  it('R11 Hardening: enforces scope metadata scrubbing, unprefixed OTTL metric fields, and burn timeout + restart failures', () => {
    // 1. Missing scope metadata scrubbing (name, version, schema_url) in trace/metric/log pipelines must fail.
    for (const [listName, idx] of [
      ['trace_statements', 1],
      ['metric_statements', 1],
      ['log_statements', 1],
    ]) {
      const missingScopeMeta = buildValidCollectorConfig();
      missingScopeMeta.processors.transform[listName][idx].statements = ['keep_keys(attributes, [])'];
      const scopeErr = [];
      auditCollectorConfigObject(missingScopeMeta, scopeErr);
      assert.ok(scopeErr.some(e => e.includes('redact_scope_name')), `${listName} missing redact_scope_name`);
      assert.ok(scopeErr.some(e => e.includes('clear_scope_version')), `${listName} missing clear_scope_version`);
      assert.ok(scopeErr.some(e => e.includes('clear_scope_schema_url')), `${listName} missing clear_scope_schema_url`);
    }

    // 2. Legacy prefixed metric.name / metric.unit / metric.description must be rejected (invalid in Collector v0.118 ottlmetric).
    const prefixedMetricCfg = buildValidCollectorConfig();
    prefixedMetricCfg.processors['filter/drop_noncompliant_metrics'].metrics.metric = [
      'resource.attributes["kty.resource_overflow"] == "drop"',
      'instrumentation_scope.attributes["kty.scope_overflow"] == "drop"',
      'metric.name != "calls" and metric.name != "duration" and metric.name != "traces.span.metrics.calls" and metric.name != "traces.span.metrics.duration"',
      '(metric.name == "duration" or metric.name == "traces.span.metrics.duration") and metric.unit != "ms" and metric.unit != "s"',
      '(metric.name == "calls" or metric.name == "traces.span.metrics.calls") and metric.unit != "" and metric.unit != "1" and metric.unit != "{call}" and metric.unit != "{calls}"',
    ];
    prefixedMetricCfg.processors.transform.metric_statements[2].statements = [
      'set(metric.description, "") where metric.description != ""',
    ];
    const prefixedErr = [];
    auditCollectorConfigObject(prefixedMetricCfg, prefixedErr);
    assert.ok(prefixedErr.some(e => e.includes('metrics.metric [name, duration unit, calls unit]')));
    assert.ok(prefixedErr.some(e => e.includes('clear non-empty description')));

    // 3. Burn script without --max-time or ignoring docker restart errors must be rejected.
    const noTimeoutOrRestartFailBurn = `#!/usr/bin/env bash
set -e
prom_rc=0
echo "Flushing and purging in-memory traces from Jaeger..."
docker restart kty-jaeger || true
echo "Flushing and resetting OpenTelemetry Collector buffers..."
docker restart kty-otel-collector || true
if ! curl --noproxy '*' -fsS -X POST "http://127.0.0.1:9090/api/v1/admin/tsdb/delete_series" -d 'match[]={__name__=~".+"}'; then
  prom_rc=1
fi
if ! curl --noproxy '*' -fsS -X POST "http://127.0.0.1:9090/api/v1/admin/tsdb/clean_tombstones"; then
  prom_rc=1
fi
exit "$prom_rc"
`;
    const burnTimeoutErr = [];
    auditBurnTelemetryScript(noTimeoutOrRestartFailBurn, burnTimeoutErr);
    assert.ok(burnTimeoutErr.some(e => e.includes('--max-time')));
    assert.ok(burnTimeoutErr.some(e => e.includes('kty-jaeger')));
    assert.ok(burnTimeoutErr.some(e => e.includes('kty-otel-collector')));
  });

  it('R12 Hardening: enforces resource schema_url, span trace_state, strict rule_ids list, path scrubbing, and burn curl args/URLs', () => {
    // 1. Missing resource schema_url clearing in preflight / trace / metric / log must fail.
    const missingPreflightResSchema = buildValidCollectorConfig();
    missingPreflightResSchema.processors['transform/metrics_preflight'].metric_statements[0].statements.pop();
    const preflightSchemaErr = [];
    auditCollectorConfigObject(missingPreflightResSchema, preflightSchemaErr);
    assert.ok(preflightSchemaErr.some(e => e.includes('clear_resource_schema_url')));

    for (const listName of ['trace_statements', 'metric_statements', 'log_statements']) {
      const missingResSchema = buildValidCollectorConfig();
      missingResSchema.processors.transform[listName][0].statements = [
        'keep_keys(attributes, ["service.name", "service.namespace", "telemetry.sdk.version"])',
      ];
      const schemaErr = [];
      auditCollectorConfigObject(missingResSchema, schemaErr);
      assert.ok(schemaErr.some(e => e.includes('clear_resource_schema_url')), `${listName} missing clear_resource_schema_url`);
    }

    // 2. Missing span trace_state clearing must fail.
    const missingTraceState = buildValidCollectorConfig();
    missingTraceState.processors.transform.trace_statements[2].statements =
      missingTraceState.processors.transform.trace_statements[2].statements.filter(s => !s.includes('trace_state'));
    const traceStateErr = [];
    auditCollectorConfigObject(missingTraceState, traceStateErr);
    assert.ok(traceStateErr.some(e => e.includes('trace_state')));

    // 3. rule_ids valid bounded list guard succeeds, while scalar-only or unbounded IsList fails.
    const buildWithExtraKeys = (includePathStmts = true, includePreflightDrops = true) => {
      const cfg = buildValidCollectorConfig();
      const keys = ['status', 'jurisdiction', 'rule_id', 'rule_ids', 'adapter_path', 'dataset_relative_path'];
      const keepStmt = `keep_keys(attributes, [${keys.map(k => `"${k}"`).join(', ')}])`;
      const adapterPredicate = `attributes["adapter_path"] != nil and (not IsString(attributes["adapter_path"]) or (attributes["adapter_path"] != "" and attributes["adapter_path"] != "[REDACTED_SENSITIVE_VALUE]" and not IsMatch(attributes["adapter_path"], "${APPROVED_ADAPTER_PATH_OTTL_PATTERN}")))`;
      const datasetPredicate = `attributes["dataset_relative_path"] != nil and (not IsString(attributes["dataset_relative_path"]) or IsMatch(attributes["dataset_relative_path"], "${DATASET_NUMERIC_STEM_REJECT_PATTERN}") or (attributes["dataset_relative_path"] != "" and attributes["dataset_relative_path"] != "[REDACTED_SENSITIVE_VALUE]" and not IsMatch(attributes["dataset_relative_path"], "${APPROVED_DATASET_RELATIVE_PATH_OTTL_PATTERN}")))`;
      const dimStmts = [
        buildBoundedDimStmt('status', APPROVED_STATUS_OTTL_PATTERN),
        buildBoundedDimStmt('jurisdiction', APPROVED_JURISDICTION_OTTL_PATTERN),
        buildBoundedDimStmt('rule_id', APPROVED_SCALAR_RULE_ID_OTTL_PATTERN),
      ];
      const pathOnlyStmts = includePathStmts
        ? [
            `set(attributes["adapter_path"], "[REDACTED_PATH]") where ${adapterPredicate}`,
            `set(attributes["dataset_relative_path"], "[REDACTED_PATH]") where ${datasetPredicate}`,
          ]
        : [];
      const pathAndDimStmts = [...pathOnlyStmts, ...dimStmts];
      const preflightDropStmts = includePreflightDrops
        ? [
            `set(attributes["kty.scrubbed_overflow"], "drop") where ${adapterPredicate}`,
            `set(attributes["kty.scrubbed_overflow"], "drop") where ${datasetPredicate}`,
            buildBoundedDimPreflightDropStmt('status', APPROVED_STATUS_OTTL_PATTERN),
            buildBoundedDimPreflightDropStmt('jurisdiction', APPROVED_JURISDICTION_OTTL_PATTERN),
            buildBoundedDimPreflightDropStmt('rule_id', APPROVED_SCALAR_RULE_ID_OTTL_PATTERN),
          ]
        : [];
      const dpClauses = buildNonScalarAttributeClauses(keys, 'attributes');
      cfg.processors['transform/metrics_preflight'].metric_statements[2].statements = [
        'set(cache["kty_raw_len"], Len(attributes))',
        keepStmt,
        'set(cache["kty_scrubbed_len"], Len(attributes))',
        'set(attributes["kty.scrubbed_overflow"], "drop") where cache["kty_scrubbed_len"] < cache["kty_raw_len"]',
        ...dpClauses.map(c => `set(attributes["kty.scrubbed_overflow"], "drop") where ${c}`),
        ...preflightDropStmts,
      ];
      cfg.processors['filter/drop_noncompliant_traces'].traces.span = [
        'Len(links) > 0',
        ...buildNonScalarAttributeClauses(['service.name', 'service.namespace', 'telemetry.sdk.version'], 'resource.attributes'),
        ...dpClauses,
      ];
      cfg.processors['filter/drop_noncompliant_traces'].traces.spanevent = [...dpClauses];
      cfg.processors.transform.trace_statements[2].statements = [
        'set(status.message, "[REDACTED_STATUS_MESSAGE]") where status.message != ""',
        `set(name, "[REDACTED_SPAN_NAME]") where not IsMatch(name, "${APPROVED_SPAN_NAME_OTTL_PATTERN}")`,
        'set(trace_state, "") where trace_state != ""',
        keepStmt,
        ...pathAndDimStmts,
      ];
      cfg.processors.transform.trace_statements[3].statements = [
        `set(name, "[REDACTED_EVENT_NAME]") where not IsMatch(name, "${APPROVED_EVENT_NAME_OTTL_PATTERN}")`,
        keepStmt,
        ...pathAndDimStmts,
      ];
      cfg.processors.transform.metric_statements[3].statements = [keepStmt, ...pathOnlyStmts];
      cfg.processors.transform.log_statements[2].statements = [
        keepStmt,
        ...pathAndDimStmts,
        buildLogTypeRedactStmt('rule_ids'),
        'set(body, "[REDACTED_LOG_BODY]") where body != nil',
      ];
      return cfg;
    };

    const validExtraErr = [];
    auditCollectorConfigObject(buildWithExtraKeys(true, true), validExtraErr);
    assert.deepEqual(validExtraErr, []);

    const missingPreflightPathDropErr = [];
    auditCollectorConfigObject(buildWithExtraKeys(true, false), missingPreflightPathDropErr);
    assert.ok(missingPreflightPathDropErr.some(e => e.includes('drop_invalid_adapter_path')));
    assert.ok(missingPreflightPathDropErr.some(e => e.includes('drop_invalid_dataset_relative_path')));
    assert.ok(missingPreflightPathDropErr.some(e => e.includes('drop_invalid_status')));

    const mutatingMetricDimCfg = buildValidCollectorConfig();
    mutatingMetricDimCfg.processors.transform.metric_statements[3].statements.push(
      buildBoundedDimStmt('status', APPROVED_STATUS_OTTL_PATTERN)
    );
    const mutatingMetricDimErr = [];
    auditCollectorConfigObject(mutatingMetricDimCfg, mutatingMetricDimErr);
    assert.ok(mutatingMetricDimErr.some(e => e.includes('must not mutate cumulative series identity')));

    const missingPathScrubErr = [];
    auditCollectorConfigObject(buildWithExtraKeys(false, true), missingPathScrubErr);
    assert.ok(missingPathScrubErr.some(e => e.includes('redact_adapter_path')));
    assert.ok(missingPathScrubErr.some(e => e.includes('redact_dataset_relative_path')));

    // Check Go RE2 bounded pattern & dataset_relative_path PII rejection semantics
    assert.ok(APPROVED_RULE_ID_OTTL_PATTERN.includes('\\\\x22'));
    assert.ok(!APPROVED_RULE_ID_OTTL_PATTERN.includes('{0,49}') && !APPROVED_RULE_ID_OTTL_PATTERN.includes('{1,64}'));
    assert.ok(!APPROVED_RULE_IDS_CSV_OTTL_PATTERN.includes('{0,49}') && !APPROVED_RULE_IDS_CSV_OTTL_PATTERN.includes('{1,64}'));

    const unescapeYamlDouble = p => p.replace(/\\\\/g, '\\');
    const ruleIdsCsvRegex = new RegExp(APPROVED_RULE_IDS_CSV_OTTL_PATTERN);
    assert.equal(ruleIdsCsvRegex.test('AR-001,CA_CIV_1950_5,state_daily_overtime_CA'), true);
    assert.equal(ruleIdsCsvRegex.test(`hmac:0123456789abcdef,sha256:${'a'.repeat(64)}`), true);
    assert.equal(ruleIdsCsvRegex.test('patient@example.test'), false);
    assert.equal(ruleIdsCsvRegex.test('john_doe'), false); // closed rule_id set rejects uncataloged slugs
    assert.equal(ruleIdsCsvRegex.test('PATIENT_HAS_HIV'), false);
    assert.equal(ruleIdsCsvRegex.test('arbitrary free text'), false);

    const scalarRuleIdRegex = new RegExp(APPROVED_SCALAR_RULE_ID_OTTL_PATTERN);
    assert.equal(scalarRuleIdRegex.test('state_implied_override_TX'), true);
    assert.equal(scalarRuleIdRegex.test('state_implied_override_XX'), false);
    assert.equal(scalarRuleIdRegex.test('PATIENT_HAS_HIV'), false);

    const baseModelRegex = new RegExp(unescapeYamlDouble(APPROVED_BASE_MODEL_OTTL_PATTERN));
    assert.equal(baseModelRegex.test('HuggingFaceTB/SmolLM2-135M'), true);
    assert.equal(baseModelRegex.test('google/gemma-2-2b-it'), true);
    assert.equal(baseModelRegex.test('microsoft/BitNet-b1.58-2B-4T'), true);
    assert.equal(baseModelRegex.test(`sha256:${'a'.repeat(64)}`), true);
    assert.equal(baseModelRegex.test('Tenant_Acme'), false);

    const datasetAllowRegex = new RegExp(unescapeYamlDouble(APPROVED_DATASET_RELATIVE_PATH_OTTL_PATTERN));
    const datasetNumericRejectRegex = new RegExp(unescapeYamlDouble(DATASET_NUMERIC_STEM_REJECT_PATTERN));
    const isDatasetPathAccepted = val => !datasetNumericRejectRegex.test(val) && datasetAllowRegex.test(val);
    assert.equal(isDatasetPathAccepted('d290f1ee6c544b0190e6d701748f0851.jsonl'), true);
    assert.equal(isDatasetPathAccepted('d290f1ee-6c54-4b01-90e6-d701748f0851.jsonl'), true);
    assert.equal(isDatasetPathAccepted('job-123.jsonl'), true);
    assert.equal(isDatasetPathAccepted('Alice.Smith.medical.pdf'), false);
    assert.equal(isDatasetPathAccepted('Jane_Doe_medical.csv'), false);
    assert.equal(isDatasetPathAccepted('patient_john_doe.jsonl'), false);
    assert.equal(isDatasetPathAccepted('1234567890123.jsonl'), false);

    const unboundedRuleIdsCfg = buildWithExtraKeys(true);
    unboundedRuleIdsCfg.processors['filter/drop_noncompliant_traces'].traces.span = [
      'Len(links) > 0',
      ...buildNonScalarAttributeClauses(['service.name', 'service.namespace', 'telemetry.sdk.version'], 'resource.attributes'),
      ...buildNonScalarAttributeClauses(['status', 'rule_id', 'adapter_path', 'dataset_relative_path'], 'attributes'),
      '(attributes["rule_ids"] != nil and not IsString(attributes["rule_ids"]) and not IsBool(attributes["rule_ids"]) and not IsInt(attributes["rule_ids"]) and not IsDouble(attributes["rule_ids"]) and not (IsList(attributes["rule_ids"]) and Len(attributes["rule_ids"]) <= 50 and IsMatch(attributes["rule_ids"], "' +
        APPROVED_RULE_ID_OTTL_PATTERN +
        '")))',
    ];
    const ruleIdsErr = [];
    auditCollectorConfigObject(unboundedRuleIdsCfg, ruleIdsErr);
    assert.ok(ruleIdsErr.some(e => e.includes('unreviewed condition') || e.includes('rule_ids')));

    // List branch missing per-element byte bound ([^\x22]{72}) must also be rejected
    const unboundedListElemCfg = buildWithExtraKeys(true);
    unboundedListElemCfg.processors['filter/drop_noncompliant_traces'].traces.span = [
      'Len(links) > 0',
      ...buildNonScalarAttributeClauses(['service.name', 'service.namespace', 'telemetry.sdk.version'], 'resource.attributes'),
      ...buildNonScalarAttributeClauses(['status', 'rule_id', 'adapter_path', 'dataset_relative_path'], 'attributes'),
      '(attributes["rule_ids"] != nil and not (IsString(attributes["rule_ids"]) and (attributes["rule_ids"] == "" or attributes["rule_ids"] == "[REDACTED_SENSITIVE_VALUE]" or (Len(attributes["rule_ids"]) <= 3600 and not IsMatch(attributes["rule_ids"], "^(?:[^,]*,){50}") and not IsMatch(attributes["rule_ids"], "[^,]{72}") and IsMatch(attributes["rule_ids"], "' +
        APPROVED_RULE_IDS_CSV_OTTL_PATTERN +
        '")))) and not (IsList(attributes["rule_ids"]) and Len(attributes["rule_ids"]) <= 50 and IsMatch(attributes["rule_ids"], "' +
        APPROVED_RULE_ID_OTTL_PATTERN +
        '")))',
    ];
    const unboundedListElemErr = [];
    auditCollectorConfigObject(unboundedListElemCfg, unboundedListElemErr);
    assert.ok(unboundedListElemErr.some(e => e.includes('unreviewed condition') || e.includes('rule_ids')));

    const missingSpanmetricsCacheCfg = buildValidCollectorConfig();
    delete missingSpanmetricsCacheCfg.connectors.spanmetrics.dimensions_cache_size;
    const spanmetricsCacheErr = [];
    auditCollectorConfigObject(missingSpanmetricsCacheCfg, spanmetricsCacheErr);
    assert.ok(spanmetricsCacheErr.some(e => e.includes('dimensions_cache_size')));

    const badSpanmetricsExpCfg = buildValidCollectorConfig();
    badSpanmetricsExpCfg.connectors.spanmetrics.metrics_expiration = '0m';
    const spanmetricsExpErr = [];
    auditCollectorConfigObject(badSpanmetricsExpCfg, spanmetricsExpErr);
    assert.ok(spanmetricsExpErr.some(e => e.includes('metrics_expiration')));

    const deprecatedCardLimitCfg = buildValidCollectorConfig();
    deprecatedCardLimitCfg.connectors.spanmetrics.aggregation_cardinality_limit = 1000;
    const deprecatedCardLimitErr = [];
    auditCollectorConfigObject(deprecatedCardLimitCfg, deprecatedCardLimitErr);
    assert.ok(deprecatedCardLimitErr.some(e => e.includes('aggregation_cardinality_limit')));

    const unboundedDimSpanmetricsCfg = buildValidCollectorConfig();
    unboundedDimSpanmetricsCfg.connectors.spanmetrics.dimensions.push({ name: 'rule_id' });
    const unboundedDimErr = [];
    auditCollectorConfigObject(unboundedDimSpanmetricsCfg, unboundedDimErr);
    assert.ok(unboundedDimErr.some(e => e.includes('rule_id') && e.includes('unbounded domain')));

    for (const reservedDim of ['service.name', 'span.kind', 'status.code']) {
      const reservedDimCfg = buildValidCollectorConfig();
      reservedDimCfg.connectors.spanmetrics.dimensions.push({ name: reservedDim });
      const reservedDimErr = [];
      auditCollectorConfigObject(reservedDimCfg, reservedDimErr);
      assert.ok(reservedDimErr.some(e => e.includes(reservedDim) && e.includes('OTel-reserved')));
    }

    const missingDimGuardCfg = buildValidCollectorConfig();
    missingDimGuardCfg.processors.transform.trace_statements[2].statements =
      missingDimGuardCfg.processors.transform.trace_statements[2].statements.filter(s => !s.includes('attributes["status"]'));
    const dimGuardErr = [];
    auditCollectorConfigObject(missingDimGuardCfg, dimGuardErr);
    assert.ok(dimGuardErr.some(e => e.includes('redact_status')));

    // 4. Burn script: caller env precedence over .env, EXIT trap collector restoration, barrier order, stdin auth (-K -), effective --noproxy/--max-time/-X/--fail.
    const makeBurn = ({
      deleteUrl = 'http://127.0.0.1:9090/api/v1/admin/tsdb/delete_series',
      deleteFlag = '--data-urlencode \'match[]={__name__=~".+"}\'',
      timeoutFlag = '--max-time 10',
      noproxyFlag = "--noproxy '*'",
      failFlag = '-fsS',
      barrierMode = 'stop_start',
      genesisAuthMode = 'stdin',
      preserveCallerEnv = true,
      restoreCollectorOnFailure = true,
      genesisMethodFlag = '-X DELETE',
    } = {}) => `#!/usr/bin/env bash
set -e
${
  preserveCallerEnv
    ? `_env_set=\${GENESIS_AUTH_TOKEN+set}
_env_val=\${GENESIS_AUTH_TOKEN-}
if [ -f .env ]; then source .env; fi
if [ "$_env_set" = "set" ]; then GENESIS_AUTH_TOKEN="$_env_val"; export GENESIS_AUTH_TOKEN; fi`
    : `if [ -f .env ]; then source .env; fi`
}
GENESIS_TOKEN="\${GENESIS_AUTH_TOKEN:?}"
case "$GENESIS_TOKEN" in
  *[$'\\r\\n']*|*'"'*|*\\\\*)
    exit 1
    ;;
esac
validate_tcp_port() {
  case "$2" in
    0*|*[!0-9]*|''|??????*) return 1 ;;
  esac
  [ "$2" -ge 1 ] && [ "$2" -le 65535 ]
}
validate_tcp_port "GENESIS_PORT" "\${GENESIS_PORT:-9002}" || exit 1
validate_tcp_port "PROMETHEUS_PORT" "\${PROMETHEUS_PORT:-9090}" || exit 1
prom_rc=0
purge_rc=0
if [ -n "\${KTY_BURN_STATE_DIR:-}" ]; then
  BURN_STATE_DIR="$KTY_BURN_STATE_DIR"
elif [ -n "\${XDG_STATE_HOME:-}" ]; then
  BURN_STATE_DIR="\${XDG_STATE_HOME%/}/knowthankyew/burn"
elif [ -n "\${HOME:-}" ]; then
  BURN_STATE_DIR="\${HOME%/}/.local/state/knowthankyew/burn"
else
  exit 1
fi
[ ! -L "$BURN_STATE_DIR" ] || exit 1
ensure_safe_dir_strict() {
  local dir="$1"
  [ ! -L "$dir" ] && [ -d "$dir" ] && [ -O "$dir" ] || return 1
  local perm_bits
  perm_bits="$(ls -ld "$dir" 2>/dev/null | awk '{print $1}')"
  case "$perm_bits" in
    d????w*|d???????w*) return 1 ;;
    d*) ;;
    *) return 1 ;;
  esac
  local real_dir anc anc_perms anc_owner
  real_dir="$(cd -P "$dir" 2>/dev/null && pwd -P)" || return 1
  anc="$real_dir"
  while [ "$anc" != "/" ] && [ -n "$anc" ]; do
    anc_perms="$(ls -ld "$anc" 2>/dev/null | awk '{print $1}')"
    case "$anc_perms" in
      d????w*) return 1 ;;
      d???????w*)
        case "$anc_perms" in
          d????????[tT]*)
            if [ ! -O "$anc" ]; then
              anc_owner="$(ls -ld "$anc" 2>/dev/null | awk '{print $3}')"
              [ "$anc_owner" = "root" ] || return 1
            fi
            ;;
          *) return 1 ;;
        esac
        ;;
    esac
    anc="$(dirname "$anc")"
  done
}
_kty_base_check="$BURN_STATE_DIR"
while [ ! -e "$_kty_base_check" ] && [ "$_kty_base_check" != "/" ] && [ "$_kty_base_check" != "." ]; do
  [ ! -L "$_kty_base_check" ] || exit 1
  _kty_base_check="$(dirname "$_kty_base_check")"
done
ensure_safe_dir_strict "$_kty_base_check" || exit 1
umask 077
mkdir -p -m 0700 "$BURN_STATE_DIR"
chmod 0700 "$BURN_STATE_DIR"
ensure_safe_dir_strict "$BURN_STATE_DIR" || exit 1
LOCK_FILE="\${KTY_BURN_LOCK_FILE:-$BURN_STATE_DIR/burn.lock}"
COLLECTOR_STATE_FILE="\${KTY_BURN_STATE_FILE:-$BURN_STATE_DIR/collector-running}"
PROM_STATE_FILE="\${KTY_BURN_PROM_STATE_FILE:-$BURN_STATE_DIR/prometheus-stopped}"
ensure_safe_target_file() {
  local target="$1"
  local parent_dir
  parent_dir="$(dirname "$target")"
  ensure_safe_dir_strict "$parent_dir" || return 1
  [ ! -L "$target" ] || return 1
  if [ -e "$target" ]; then
    [ -f "$target" ] && [ -O "$target" ] || return 1
  fi
}
ensure_safe_target_file "$LOCK_FILE" || exit 1
ensure_safe_target_file "$COLLECTOR_STATE_FILE" || exit 1
ensure_safe_target_file "$PROM_STATE_FILE" || exit 1
wait_prom_ready() {
  local prom_ready_max="\${KTY_PROM_READY_MAX_WAIT:-60}"
  local prom_wait=0
  while [ "$prom_wait" -lt "$prom_ready_max" ]; do
    if curl ${noproxyFlag} --connect-timeout 2 --max-time 2 -fsS "http://127.0.0.1:9090/-/ready" >/dev/null 9>&-; then
      return 0
    fi
    prom_wait=$((prom_wait + 1))
    sleep 0.25 9>&-
  done
  return 1
}
LOCK_BACKEND=""
if command -v flock >/dev/null 2>&1; then
  LOCK_BACKEND="flock"
elif command -v perl >/dev/null 2>&1; then
  LOCK_BACKEND="perl"
elif command -v python3 >/dev/null 2>&1; then
  LOCK_BACKEND="python3"
else
  exit 1
fi
try_flock_fd9() {
  case "$LOCK_BACKEND" in
    flock) flock -n 9 2>/dev/null ;;
    perl) perl -e 'use Fcntl qw(:flock); open(my $fh, ">&=", 9) or exit 2; flock($fh, LOCK_EX | LOCK_NB) or exit 1;' 2>/dev/null ;;
    python3) python3 -c 'import fcntl; fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)' 2>/dev/null ;;
  esac
}
LOCK_FD_OPEN=0
LOCK_ACQUIRED=0
collector_was_running=0
prom_was_stopped=0
prom_wal_wiped=0
${
  restoreCollectorOnFailure
    ? `restore_collector() {
  local rc=$?
  if [ "$prom_was_stopped" -eq 1 ]; then
    if ! docker start kty-prometheus 9>&-; then
      rc=1
    elif [ "$prom_wal_wiped" -eq 1 ] && wait_prom_ready; then
      [ -L "$PROM_STATE_FILE" ] || rm -f "$PROM_STATE_FILE" 2>/dev/null || true
    fi
    prom_was_stopped=0
  fi
  if [ "$collector_was_running" -eq 1 ]; then
    if ! docker start kty-otel-collector 9>&-; then
      rc=1
    else
      [ -L "$COLLECTOR_STATE_FILE" ] || rm -f "$COLLECTOR_STATE_FILE" 2>/dev/null || true
    fi
    collector_was_running=0
  fi
  if [ "$LOCK_FD_OPEN" -eq 1 ]; then
    exec 9>&-
    LOCK_FD_OPEN=0
    LOCK_ACQUIRED=0
  fi
  exit "$rc"
}
trap restore_collector EXIT`
    : `release_lock() {
  if [ "$LOCK_FD_OPEN" -eq 1 ]; then
    exec 9>&-
    LOCK_FD_OPEN=0
    LOCK_ACQUIRED=0
  fi
}
trap release_lock EXIT`
}
exec 9>>"$LOCK_FILE"
LOCK_FD_OPEN=1
lock_max_wait="\${KTY_BURN_LOCK_MAX_WAIT:-300}"
case "$lock_max_wait" in
  *[!0-9]*|''|0) lock_max_wait=300 ;;
esac
lock_wait=0
while true; do
  lock_rc=0
  try_flock_fd9 || lock_rc=$?
  if [ "$lock_rc" -eq 0 ]; then
    LOCK_ACQUIRED=1
    break
  fi
  [ "$lock_rc" -ne 2 ] || exit 1
  lock_wait=$((lock_wait + 1))
  [ "$lock_wait" -lt "$lock_max_wait" ] || exit 1
  sleep 0.1 9>&-
done
if ! running_containers="$(docker ps --format '{{.Names}}' 9>&-)"; then
  echo "ERROR: Failed to query running Docker containers" >&2
  exit 1
fi
if [ -f "$COLLECTOR_STATE_FILE" ]; then
  collector_was_running=1
fi
${
  barrierMode === 'stop_start'
    ? `if printf '%s\\n' "$running_containers" | grep -qx "kty-otel-collector"; then
  echo "Flushing and resetting OpenTelemetry Collector buffers..."
  collector_was_running=1
  ensure_safe_target_file "$COLLECTOR_STATE_FILE" || exit 1
  tmp_state="$(mktemp "\${BURN_STATE_DIR}/.collector-running.XXXXXX")" || exit 1
  printf '%s\\n' "$$" > "$tmp_state" && mv -f "$tmp_state" "$COLLECTOR_STATE_FILE"
  docker stop kty-otel-collector 9>&- || exit 1
fi
for producer_svc in kty-gradcast kty-mail-stripper kty-ftaas-api kty-ftaas-worker kty-surprisal; do
  if printf '%s\\n' "$running_containers" | grep -qx "$producer_svc"; then
    docker restart "$producer_svc" 9>&- || exit 1
  fi
done
echo "Flushing and purging in-memory traces from Jaeger..."
docker restart kty-jaeger 9>&- || exit 1
wipe_prom_wal_and_restart() {
  local should_stop="\${1:-1}"
  local prom_image
  prom_image="$(docker inspect -f '{{.Config.Image}}' kty-prometheus 9>&- || true)"
  [ -n "$prom_image" ] || prom_image="prom/prometheus:v3.1.0"
  if [ "$should_stop" -eq 1 ]; then
    ensure_safe_target_file "$PROM_STATE_FILE" || { prom_rc=1; return 0; }
    local tmp_prom_state
    tmp_prom_state="$(mktemp "\${BURN_STATE_DIR}/.prometheus-stopped.XXXXXX")" || { prom_rc=1; return 0; }
    printf '%s\\n' "$$" > "$tmp_prom_state" && mv -f "$tmp_prom_state" "$PROM_STATE_FILE" || { rm -f "$tmp_prom_state" 2>/dev/null || true; prom_rc=1; return 0; }
    prom_wal_wiped=0
    prom_was_stopped=1
    docker stop kty-prometheus 9>&- || exit 1
  else
    prom_wal_wiped=0
    prom_was_stopped=1
  fi
  docker run --rm --volumes-from kty-prometheus --network none --cap-drop ALL --security-opt no-new-privileges --entrypoint /bin/sh "$prom_image" -c 'find /prometheus -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +' 9>&- || exit 1
  prom_wal_wiped=1
  docker start kty-prometheus 9>&- || exit 1
  prom_was_stopped=0
  if ! wait_prom_ready; then
    prom_rc=1
    return 0
  fi
  [ -L "$PROM_STATE_FILE" ] || rm -f "$PROM_STATE_FILE" 2>/dev/null || true
}
if printf '%s\\n' "$running_containers" | grep -qx "kty-prometheus"; then
  docker restart kty-prometheus 9>&- || exit 1
  if ! wait_prom_ready; then
    prom_rc=1
  else
    if ! curl ${noproxyFlag} --connect-timeout 3 ${timeoutFlag} ${failFlag} -X POST "${deleteUrl}" ${deleteFlag} 9>&-; then
      prom_rc=1
    fi
    if ! curl ${noproxyFlag} --connect-timeout 3 ${timeoutFlag} ${failFlag} -X POST "http://127.0.0.1:9090/api/v1/admin/tsdb/clean_tombstones" 9>&-; then
      prom_rc=1
    fi
    wipe_prom_wal_and_restart 1
  fi
elif [ -f "$PROM_STATE_FILE" ]; then
  wipe_prom_wal_and_restart 0
fi`
    : barrierMode === 'restart_first'
      ? `echo "Flushing and resetting OpenTelemetry Collector buffers..."
docker restart kty-otel-collector 9>&- || exit 1
echo "Flushing and purging in-memory traces from Jaeger..."
docker restart kty-jaeger 9>&- || exit 1
docker restart kty-prometheus 9>&- || exit 1
curl ${noproxyFlag} --connect-timeout 2 --max-time 2 -fsS "http://127.0.0.1:9090/-/ready" >/dev/null 9>&- || prom_rc=1
curl ${noproxyFlag} --connect-timeout 3 ${timeoutFlag} ${failFlag} -X POST "${deleteUrl}" ${deleteFlag} 9>&- || prom_rc=1
curl ${noproxyFlag} --connect-timeout 3 ${timeoutFlag} ${failFlag} -X POST "http://127.0.0.1:9090/api/v1/admin/tsdb/clean_tombstones" 9>&- || prom_rc=1
docker stop kty-prometheus 9>&- || exit 1
docker run --rm --volumes-from kty-prometheus --entrypoint /bin/sh prom/prometheus:v3.1.0 -c 'find /prometheus -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +' 9>&- || exit 1
docker start kty-prometheus 9>&- || exit 1
curl ${noproxyFlag} --connect-timeout 2 --max-time 2 -fsS "http://127.0.0.1:9090/-/ready" >/dev/null 9>&- || prom_rc=1`
      : `echo "Flushing and purging in-memory traces from Jaeger..."
docker restart kty-jaeger 9>&- || exit 1
echo "Flushing and resetting OpenTelemetry Collector buffers..."
collector_was_running=1
docker stop kty-otel-collector 9>&- || exit 1
docker restart kty-prometheus 9>&- || exit 1
curl ${noproxyFlag} --connect-timeout 2 --max-time 2 -fsS "http://127.0.0.1:9090/-/ready" >/dev/null 9>&- || prom_rc=1
curl ${noproxyFlag} --connect-timeout 3 ${timeoutFlag} ${failFlag} -X POST "${deleteUrl}" ${deleteFlag} 9>&- || prom_rc=1
curl ${noproxyFlag} --connect-timeout 3 ${timeoutFlag} ${failFlag} -X POST "http://127.0.0.1:9090/api/v1/admin/tsdb/clean_tombstones" 9>&- || prom_rc=1
docker stop kty-prometheus 9>&- || exit 1
docker run --rm --volumes-from kty-prometheus --entrypoint /bin/sh prom/prometheus:v3.1.0 -c 'find /prometheus -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +' 9>&- || exit 1
docker start kty-prometheus 9>&- || exit 1
curl ${noproxyFlag} --connect-timeout 2 --max-time 2 -fsS "http://127.0.0.1:9090/-/ready" >/dev/null 9>&- || prom_rc=1`
}
${
  genesisAuthMode === 'stdin'
    ? `printf 'header = "Authorization: Bearer %s"\\n' "\${GENESIS_TOKEN}" | curl ${noproxyFlag} --connect-timeout 3 ${timeoutFlag} ${failFlag} ${genesisMethodFlag} -K - "http://127.0.0.1:9002/logs" 9>&- || purge_rc=$?`
    : `curl ${noproxyFlag} --connect-timeout 3 ${timeoutFlag} ${failFlag} ${genesisMethodFlag} -H "Authorization: Bearer \${GENESIS_TOKEN}" "http://127.0.0.1:9002/logs" 9>&- || purge_rc=$?`
}
${
  barrierMode === 'stop_start'
    ? `if [ "$collector_was_running" -eq 1 ]; then docker start kty-otel-collector 9>&- || exit 1; rm -f "$COLLECTOR_STATE_FILE" 2>/dev/null || true; collector_was_running=0; fi`
    : ''
}
if [ "$purge_rc" -ne 0 ]; then
  exit "$purge_rc"
fi
exit "$prom_rc"
`;

    const validBurnErr = [];
    auditBurnTelemetryScript(makeBurn(), validBurnErr);
    assert.deepEqual(validBurnErr, []);

    const staleDotenvOverrideErr = [];
    auditBurnTelemetryScript(makeBurn({ preserveCallerEnv: false }), staleDotenvOverrideErr);
    assert.ok(staleDotenvOverrideErr.some(e => e.includes('.env file must not override caller-exported GENESIS_AUTH_TOKEN')));

    const missingTrapRestoreErr = [];
    auditBurnTelemetryScript(makeBurn({ restoreCollectorOnFailure: false }), missingTrapRestoreErr);
    assert.ok(missingTrapRestoreErr.some(e => e.includes('restore kty-otel-collector')));

    const conflictingMethodErr = [];
    auditBurnTelemetryScript(makeBurn({ genesisMethodFlag: '-X DELETE -X GET' }), conflictingMethodErr);
    assert.ok(conflictingMethodErr.some(e => e.includes('-X DELETE')));

    const zeroTimeoutErr = [];
    auditBurnTelemetryScript(makeBurn({ timeoutFlag: '--max-time 10 --max-time 0' }), zeroTimeoutErr);
    assert.ok(zeroTimeoutErr.some(e => e.includes('--max-time')));

    const conflictingNoproxyErr = [];
    auditBurnTelemetryScript(makeBurn({ noproxyFlag: "--noproxy '*' --noproxy ''" }), conflictingNoproxyErr);
    assert.ok(conflictingNoproxyErr.some(e => e.includes('--noproxy')));

    const rawPlusErr = [];
    auditBurnTelemetryScript(makeBurn({ deleteFlag: '-d \'match[]={__name__=~".+"}\'' }), rawPlusErr);
    assert.ok(rawPlusErr.some(e => e.includes('--data-urlencode')));

    const typoPathErr = [];
    auditBurnTelemetryScript(makeBurn({ deleteUrl: 'http://127.0.0.1:9090/api/v1/admin/tsdb/delete_series_typo' }), typoPathErr);
    assert.ok(typoPathErr.some(e => e.includes('delete_series')));

    const restartBeforeJaegerErr = [];
    auditBurnTelemetryScript(makeBurn({ barrierMode: 'restart_first' }), restartBeforeJaegerErr);
    assert.ok(restartBeforeJaegerErr.some(e => e.includes('kty-otel-collector')));

    const jaegerBeforeCollectorErr = [];
    auditBurnTelemetryScript(makeBurn({ barrierMode: 'jaeger_first' }), jaegerBeforeCollectorErr);
    assert.ok(jaegerBeforeCollectorErr.some(e => e.includes('kty-otel-collector')));

    const cliTokenLeakErr = [];
    auditBurnTelemetryScript(makeBurn({ genesisAuthMode: 'cli' }), cliTokenLeakErr);
    assert.ok(cliTokenLeakErr.some(e => e.includes('CLI header flags') || e.includes('leaked Genesis bearer token')));

    const noFailOverrideErr = [];
    auditBurnTelemetryScript(makeBurn({ failFlag: '-fsS --no-fail' }), noFailOverrideErr);
    assert.ok(noFailOverrideErr.some(e => e.includes('--no-fail')));

    // 5. Genesis sibling auth enforcement negative fixture check.
    const tmpGenesisDir = mkdtempSync(resolve(tmpdir(), 'kty-genesis-auth-test-'));
    const validSecurityGo = `func AuthMiddleware(expectedToken string, next http.Handler) http.Handler {
  if expectedToken == "" { return next }
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    authHeader := r.Header.Get("Authorization")
    if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") { w.WriteHeader(http.StatusUnauthorized); return }
    token := strings.TrimSpace(authHeader[len("Bearer "):])
    if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
      w.WriteHeader(http.StatusUnauthorized)
      return
    }
    next.ServeHTTP(w, r)
  })
}
`;
    try {
      mkdirSync(resolve(tmpGenesisDir, 'internal/config'), { recursive: true });
      mkdirSync(resolve(tmpGenesisDir, 'internal/cli'), { recursive: true });
      mkdirSync(resolve(tmpGenesisDir, 'internal/security'), { recursive: true });
      writeFileSync(resolve(tmpGenesisDir, 'Dockerfile'), 'RUN go build -o /genesis ./cmd/server\nENTRYPOINT ["/genesis"]\n', 'utf-8');
      writeFileSync(resolve(tmpGenesisDir, 'internal/config/config.go'), 'if v := os.Getenv("GENESIS_AUTH_TOKEN"); v != "" { cfg.AuthToken = v }\n', 'utf-8');
      writeFileSync(
        resolve(tmpGenesisDir, 'internal/cli/server.go'),
        'httpMux.Handle("/", ui)\nhttpMux.HandleFunc("/query", q)\nhttpMux.HandleFunc("/stats", s)\nhttpMux.HandleFunc("/tail", t)\nhttpMux.HandleFunc("/logs", b)\nhttpMux.HandleFunc("/burn", b)\nauthenticatedHandler := security.AuthMiddleware(cfg.AuthToken, httpMux)\n&http.Server{Handler: authenticatedHandler}\n',
        'utf-8'
      );
      writeFileSync(resolve(tmpGenesisDir, 'internal/security/security.go'), validSecurityGo, 'utf-8');
      const validGenesisErr = [];
      auditGenesisAuthEnforcement(tmpGenesisDir, validGenesisErr);
      assert.deepEqual(validGenesisErr, []);

      // Self-comparison `token := expectedToken` before ConstantTimeCompare must fail.
      writeFileSync(
        resolve(tmpGenesisDir, 'internal/security/security.go'),
        `func AuthMiddleware(expectedToken string, next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    authHeader := r.Header.Get("Authorization")
    _ = strings.HasPrefix(strings.ToLower(authHeader), "bearer ")
    token := expectedToken
    if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
      w.WriteHeader(http.StatusUnauthorized)
      return
    }
    next.ServeHTTP(w, r)
  })
}
`,
        'utf-8'
      );
      const selfCompareGenesisErr = [];
      auditGenesisAuthEnforcement(tmpGenesisDir, selfCompareGenesisErr);
      assert.ok(selfCompareGenesisErr.some(e => e.includes('AuthMiddleware')));

      // Compound empty-token bypass `token != "" && subtle.ConstantTimeCompare(...) != 1` must fail.
      writeFileSync(
        resolve(tmpGenesisDir, 'internal/security/security.go'),
        `func AuthMiddleware(expectedToken string, next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    authHeader := r.Header.Get("Authorization")
    _ = strings.HasPrefix(strings.ToLower(authHeader), "bearer ")
    token := strings.TrimSpace(authHeader[len("Bearer "):])
    if token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
      w.WriteHeader(http.StatusUnauthorized)
      return
    }
    next.ServeHTTP(w, r)
  })
}
`,
        'utf-8'
      );
      const emptyTokenBypassErr = [];
      auditGenesisAuthEnforcement(tmpGenesisDir, emptyTokenBypassErr);
      assert.ok(emptyTokenBypassErr.some(e => e.includes('AuthMiddleware')));

      // Trailing condition bypass `subtle.ConstantTimeCompare(...) != 1 && token != ""` must fail.
      writeFileSync(
        resolve(tmpGenesisDir, 'internal/security/security.go'),
        `func AuthMiddleware(expectedToken string, next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    authHeader := r.Header.Get("Authorization")
    _ = strings.HasPrefix(strings.ToLower(authHeader), "bearer ")
    token := strings.TrimSpace(authHeader[len("Bearer "):])
    if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 && token != "" {
      w.WriteHeader(http.StatusUnauthorized)
      return
    }
    next.ServeHTTP(w, r)
  })
}
`,
        'utf-8'
      );
      const trailingBypassErr = [];
      auditGenesisAuthEnforcement(tmpGenesisDir, trailingBypassErr);
      assert.ok(trailingBypassErr.some(e => e.includes('AuthMiddleware')));

      // Nested `if ... { WriteHeader(401); return }` inside rejectBlock must fail (falls through when condition false).
      writeFileSync(
        resolve(tmpGenesisDir, 'internal/security/security.go'),
        `func AuthMiddleware(expectedToken string, next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    authHeader := r.Header.Get("Authorization")
    _ = strings.HasPrefix(strings.ToLower(authHeader), "bearer ")
    token := strings.TrimSpace(authHeader[len("Bearer "):])
    if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
      if token != "" {
        w.WriteHeader(http.StatusUnauthorized)
        return
      }
    }
    next.ServeHTTP(w, r)
  })
}
`,
        'utf-8'
      );
      const nestedReturnGenesisErr = [];
      auditGenesisAuthEnforcement(tmpGenesisDir, nestedReturnGenesisErr);
      assert.ok(nestedReturnGenesisErr.some(e => e.includes('AuthMiddleware')));

      // Missing return inside reject branch (falls through to next.ServeHTTP) must fail.
      writeFileSync(
        resolve(tmpGenesisDir, 'internal/security/security.go'),
        `func AuthMiddleware(expectedToken string, next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    authHeader := r.Header.Get("Authorization")
    _ = strings.HasPrefix(strings.ToLower(authHeader), "bearer ")
    token := strings.TrimSpace(authHeader[len("Bearer "):])
    if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
      w.WriteHeader(http.StatusUnauthorized)
    }
    next.ServeHTTP(w, r)
  })
}
`,
        'utf-8'
      );
      const fallthroughGenesisErr = [];
      auditGenesisAuthEnforcement(tmpGenesisDir, fallthroughGenesisErr);
      assert.ok(fallthroughGenesisErr.some(e => e.includes('AuthMiddleware')));

      // Isolated unwrapped httpMux test (valid security.go restored first).
      writeFileSync(resolve(tmpGenesisDir, 'internal/security/security.go'), validSecurityGo, 'utf-8');
      writeFileSync(
        resolve(tmpGenesisDir, 'internal/cli/server.go'),
        'httpMux.Handle("/", ui)\nhttpMux.HandleFunc("/query", q)\nhttpMux.HandleFunc("/stats", s)\nhttpMux.HandleFunc("/tail", t)\nhttpMux.HandleFunc("/logs", b)\nhttpMux.HandleFunc("/burn", b)\n&http.Server{Handler: httpMux}\n',
        'utf-8'
      );
      const unwrappedGenesisErr = [];
      auditGenesisAuthEnforcement(tmpGenesisDir, unwrappedGenesisErr);
      assert.ok(unwrappedGenesisErr.some(e => e.includes('wrap the entire httpMux')));
    } finally {
      rmSync(tmpGenesisDir, { recursive: true, force: true });
    }
  });

  it('CR-A7 Hardening: enforces 82-key & 8-resource-key partitions, strict numeric/bool/bounded-string schemas, burn docker ps failure, and Go ENOENT policy', () => {
    // 1. Canonical 82-key & 8-resource-key partitions must be disjoint and complete.
    const groups = [
      ['numeric', [...NUMERIC_COLLECTOR_KEYS]],
      ['boolean', [...BOOLEAN_COLLECTOR_KEYS]],
      ['audit_flag', [...AUDIT_FLAG_COLLECTOR_KEYS]],
      ['rule_ids', ['rule_ids']],
      ['path', Object.keys(PATH_COLLECTOR_SCHEMAS)],
      ['bounded_scalar_string', Object.keys(BOUNDED_SCALAR_STRING_SCHEMAS)],
    ];
    const seen = new Map();
    for (const [groupName, keys] of groups) {
      for (const k of keys) {
        assert.equal(seen.has(k), false, `Duplicate key "${k}" across schema groups (${seen.get(k)} and ${groupName})`);
        seen.set(k, groupName);
      }
    }
    assert.equal(seen.size, 82);
    assert.deepEqual(new Set(seen.keys()), CANONICAL_COLLECTOR_ALLOWED_KEYS);
    assert.equal(Object.keys(BOUNDED_RESOURCE_STRING_SCHEMAS).length, 8);
    assert.deepEqual(new Set(Object.keys(BOUNDED_RESOURCE_STRING_SCHEMAS)), CANONICAL_COLLECTOR_RESOURCE_KEYS);

    // 2. Helper to build a valid config for arbitrary allowlisted attribute keys + default resource keys.
    const buildConfigForKeys = (extraKeys = []) => {
      const cfg = buildValidCollectorConfig();
      const resKeys = ['service.name', 'service.namespace', 'telemetry.sdk.version'];
      const keys = ['status', 'rule_id', ...extraKeys];
      const keepStmt = `keep_keys(attributes, [${keys.map(k => `"${k}"`).join(', ')}])`;
      const dpDropStmts = [];
      const scalarRedactStmts = [];
      const pathOnlyRedactStmts = [];
      const logTypeStmts = [];
      for (const k of keys) {
        if (Object.hasOwn(PATH_COLLECTOR_SCHEMAS, k)) {
          dpDropStmts.push(buildScalarSchemaPreflightDropStmt(k, PATH_COLLECTOR_SCHEMAS[k], 'kty.scrubbed_overflow'));
          scalarRedactStmts.push(buildScalarSchemaRedactStmt(k, PATH_COLLECTOR_SCHEMAS[k]));
          pathOnlyRedactStmts.push(buildScalarSchemaRedactStmt(k, PATH_COLLECTOR_SCHEMAS[k]));
        } else if (Object.hasOwn(BOUNDED_SCALAR_STRING_SCHEMAS, k)) {
          dpDropStmts.push(buildScalarSchemaPreflightDropStmt(k, BOUNDED_SCALAR_STRING_SCHEMAS[k], 'kty.scrubbed_overflow'));
          scalarRedactStmts.push(buildScalarSchemaRedactStmt(k, BOUNDED_SCALAR_STRING_SCHEMAS[k]));
        } else {
          logTypeStmts.push(buildLogTypeRedactStmt(k));
        }
      }
      const dpClauses = buildNonScalarAttributeClauses(keys, 'attributes');
      cfg.processors['transform/metrics_preflight'].metric_statements[2].statements = [
        'set(cache["kty_raw_len"], Len(attributes))',
        keepStmt,
        'set(cache["kty_scrubbed_len"], Len(attributes))',
        'set(attributes["kty.scrubbed_overflow"], "drop") where cache["kty_scrubbed_len"] < cache["kty_raw_len"]',
        ...dpClauses.map(c => `set(attributes["kty.scrubbed_overflow"], "drop") where ${c}`),
        ...dpDropStmts,
      ];
      cfg.processors['filter/drop_noncompliant_traces'].traces.span = [
        'Len(links) > 0',
        ...buildNonScalarAttributeClauses(resKeys, 'resource.attributes'),
        ...dpClauses,
      ];
      cfg.processors['filter/drop_noncompliant_traces'].traces.spanevent = [...dpClauses];
      cfg.processors.transform.trace_statements[2].statements = [
        'set(status.message, "[REDACTED_STATUS_MESSAGE]") where status.message != ""',
        `set(name, "[REDACTED_SPAN_NAME]") where not IsMatch(name, "${APPROVED_SPAN_NAME_OTTL_PATTERN}")`,
        'set(trace_state, "") where trace_state != ""',
        keepStmt,
        ...scalarRedactStmts,
      ];
      cfg.processors.transform.trace_statements[3].statements = [
        `set(name, "[REDACTED_EVENT_NAME]") where not IsMatch(name, "${APPROVED_EVENT_NAME_OTTL_PATTERN}")`,
        keepStmt,
        ...scalarRedactStmts,
      ];
      cfg.processors.transform.metric_statements[3].statements = [keepStmt, ...pathOnlyRedactStmts];
      cfg.processors.transform.log_statements[2].statements = [
        keepStmt,
        ...scalarRedactStmts,
        ...logTypeStmts,
        'set(body, "[REDACTED_LOG_BODY]") where body != nil',
      ];
      return cfg;
    };

    const typedCleanErr = [];
    const typedKeys = ['char_count', 'flagged_clauses', 'is_compliant', 'loss', 'base_model', 'product_type', 'statute_code', 'job_id', 'error_code'];
    auditCollectorConfigObject(buildConfigForKeys(typedKeys), typedCleanErr);
    assert.deepEqual(typedCleanErr, []);

    // 3. String smuggling into numeric/boolean keys via permissive IsString clause must be REJECTED.
    for (const typedKey of ['char_count', 'flagged_clauses', 'is_compliant', 'loss']) {
      const cfg = buildConfigForKeys([typedKey]);
      cfg.processors['filter/drop_noncompliant_traces'].traces.span = cfg.processors['filter/drop_noncompliant_traces'].traces.span.map(s =>
        s.includes(`attributes["${typedKey}"]`)
          ? `(attributes["${typedKey}"] != nil and not IsString(attributes["${typedKey}"]) and not IsBool(attributes["${typedKey}"]) and not IsInt(attributes["${typedKey}"]) and not IsDouble(attributes["${typedKey}"]))`
          : s
      );
      const err = [];
      auditCollectorConfigObject(cfg, err);
      assert.ok(err.some(e => e.includes(`"${typedKey}"`)), `expected rejection for string-smuggling key "${typedKey}"`);

      const missingLogTypeCfg = buildConfigForKeys([typedKey]);
      missingLogTypeCfg.processors.transform.log_statements[2].statements =
        missingLogTypeCfg.processors.transform.log_statements[2].statements.filter(s => !s.includes(`attributes["${typedKey}"],`));
      const logErr = [];
      auditCollectorConfigObject(missingLogTypeCfg, logErr);
      assert.ok(logErr.some(e => e.includes(`redact_type_${typedKey}`)), `expected missing redact_type_${typedKey} rejection`);
    }

    // 4. Missing bounded string / resource redaction or preflight drop guards must be REJECTED.
    for (const strKey of ['base_model', 'product_type', 'statute_code', 'job_id', 'error_code']) {
      const missingRedactCfg = buildConfigForKeys([strKey]);
      missingRedactCfg.processors.transform.trace_statements[2].statements =
        missingRedactCfg.processors.transform.trace_statements[2].statements.filter(s => !s.includes(`attributes["${strKey}"],`));
      const redactErr = [];
      auditCollectorConfigObject(missingRedactCfg, redactErr);
      assert.ok(redactErr.some(e => e.includes(`redact_${strKey}`)), `expected missing redact_${strKey} rejection`);

      const missingDropCfg = buildConfigForKeys([strKey]);
      missingDropCfg.processors['transform/metrics_preflight'].metric_statements[2].statements =
        missingDropCfg.processors['transform/metrics_preflight'].metric_statements[2].statements.filter(
          s => !(s.includes('"kty.scrubbed_overflow"') && s.includes(`attributes["${strKey}"]`) && s.includes('IsMatch'))
        );
      const dropErr = [];
      auditCollectorConfigObject(missingDropCfg, dropErr);
      assert.ok(dropErr.some(e => e.includes(`drop_invalid_${strKey}`)), `expected missing drop_invalid_${strKey} rejection`);
    }

    const mutatingResCfg = buildValidCollectorConfig();
    mutatingResCfg.processors.transform.metric_statements[0].statements.push(
      buildScalarSchemaRedactStmt('service.name', BOUNDED_RESOURCE_STRING_SCHEMAS['service.name'])
    );
    const mutatingResErr = [];
    auditCollectorConfigObject(mutatingResCfg, mutatingResErr);
    assert.ok(mutatingResErr.some(e => e.includes('must not mutate cumulative series identity attribute "service.name"')));

    // 5. Masking docker ps failure with `|| true` in burn-telemetry.sh must fail behaviorally.
    const maskedDockerPsBurn = `#!/usr/bin/env bash
set -euo pipefail
docker ps --format '{{.Names}}' || true
exit 0
`;
    const maskedDockerPsErr = [];
    auditBurnTelemetryScript(maskedDockerPsBurn, maskedDockerPsErr);
    assert.ok(maskedDockerPsErr.some(e => e.includes('when \`docker ps\` fails')));

    // 6. Go ENOENT warns+skips when requireGo is false, and fails closed when requireGo is true (using isolated fixture).
    const tmpEnoentDir = mkdtempSync(resolve(tmpdir(), 'kty-genesis-enoent-'));
    try {
      mkdirSync(resolve(tmpEnoentDir, 'internal/cli'), { recursive: true });
      mkdirSync(resolve(tmpEnoentDir, 'internal/config'), { recursive: true });
      mkdirSync(resolve(tmpEnoentDir, 'internal/security'), { recursive: true });
      writeFileSync(resolve(tmpEnoentDir, 'Dockerfile'), 'RUN go build -o /genesis ./cmd/server\nENTRYPOINT ["/genesis"]\n', 'utf-8');
      writeFileSync(
        resolve(tmpEnoentDir, 'internal/config/config.go'),
        'if v := os.Getenv("GENESIS_AUTH_TOKEN"); v != "" { cfg.AuthToken = v }\n',
        'utf-8'
      );
      writeFileSync(
        resolve(tmpEnoentDir, 'internal/cli/server.go'),
        'httpMux.Handle("/", ui)\nhttpMux.HandleFunc("/query", q)\nhttpMux.HandleFunc("/stats", s)\nhttpMux.HandleFunc("/tail", t)\nhttpMux.HandleFunc("/logs", b)\nhttpMux.HandleFunc("/burn", b)\nauthenticatedHandler := security.AuthMiddleware(cfg.AuthToken, httpMux)\n&http.Server{Handler: authenticatedHandler}\n',
        'utf-8'
      );
      writeFileSync(
        resolve(tmpEnoentDir, 'internal/security/security.go'),
        `package security
func AuthMiddleware(expectedToken string, next http.Handler) http.Handler {
  if expectedToken == "" { return next }
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    authHeader := r.Header.Get("Authorization")
    var token string
    if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
      token = strings.TrimSpace(authHeader[7:])
    }
    if token == "" {
      token = r.URL.Query().Get("token")
    }
    if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
      w.WriteHeader(http.StatusUnauthorized)
      return
    }
    next.ServeHTTP(w, r)
  })
}
`,
        'utf-8'
      );
      writeFileSync(resolve(tmpEnoentDir, 'internal/security/security_test.go'), 'package security\n', 'utf-8');

      const skipGoErr = [];
      auditGenesisAuthEnforcement(tmpEnoentDir, skipGoErr, {
        requireGo: false,
        goCmd: 'nonexistent-go-binary-kty-test',
      });
      assert.deepEqual(skipGoErr, []);

      const requireGoErr = [];
      auditGenesisAuthEnforcement(tmpEnoentDir, requireGoErr, {
        requireGo: true,
        goCmd: 'nonexistent-go-binary-kty-test',
      });
      assert.ok(requireGoErr.some(e => e.includes('binary not found in PATH while KTY_REQUIRE_GO_TESTS=1')));

      // 7. Captured-token reassignment bypass (`configuredToken := expectedToken; ... token = configuredToken`) must fail.
      writeFileSync(
        resolve(tmpEnoentDir, 'internal/security/security.go'),
        `package security
func AuthMiddleware(expectedToken string, next http.Handler) http.Handler {
  configuredToken := expectedToken
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    authHeader := r.Header.Get("Authorization")
    var token string
    if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
      token = strings.TrimSpace(authHeader[7:])
    }
    token = configuredToken
    if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
      w.WriteHeader(http.StatusUnauthorized)
      return
    }
    next.ServeHTTP(w, r)
  })
}
`,
        'utf-8'
      );
      const capturedReassignErr = [];
      auditGenesisAuthEnforcement(tmpEnoentDir, capturedReassignErr, {
        requireGo: false,
        goCmd: 'nonexistent-go-binary-kty-test',
      });
      assert.ok(capturedReassignErr.some(e => e.includes('AuthMiddleware')));

      // 8. Dead-branch AuthMiddleware guard (`if false { if subtle.ConstantTimeCompare(...) }`) must fail.
      writeFileSync(
        resolve(tmpEnoentDir, 'internal/security/security.go'),
        `package security
func AuthMiddleware(expectedToken string, next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    authHeader := r.Header.Get("Authorization")
    var token string
    if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
      token = strings.TrimSpace(authHeader[7:])
    }
    if false {
      if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
        w.WriteHeader(http.StatusUnauthorized)
        return
      }
    }
    next.ServeHTTP(w, r)
  })
}
`,
        'utf-8'
      );
      const deadBranchErr = [];
      auditGenesisAuthEnforcement(tmpEnoentDir, deadBranchErr, {
        requireGo: false,
        goCmd: 'nonexistent-go-binary-kty-test',
      });
      assert.ok(deadBranchErr.some(e => e.includes('AuthMiddleware')));

      // Commented-out middleware wiring in server.go must not satisfy auditGenesisAuthEnforcement.
      writeFileSync(
        resolve(tmpEnoentDir, 'internal/security/security.go'),
        `package security
func AuthMiddleware(expectedToken string, next http.Handler) http.Handler {
  if expectedToken == "" { return next }
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    authHeader := r.Header.Get("Authorization")
    var token string
    if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
      token = strings.TrimSpace(authHeader[7:])
    }
    if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
      w.WriteHeader(http.StatusUnauthorized)
      return
    }
    next.ServeHTTP(w, r)
  })
}
`,
        'utf-8'
      );
      writeFileSync(
        resolve(tmpEnoentDir, 'internal/cli/server.go'),
        `httpMux.Handle("/", ui)
httpMux.HandleFunc("/query", q)
httpMux.HandleFunc("/stats", s)
httpMux.HandleFunc("/tail", t)
httpMux.HandleFunc("/logs", b)
httpMux.HandleFunc("/burn", b)
// authenticatedHandler := security.AuthMiddleware(cfg.AuthToken, httpMux)
/*
Handler: authenticatedHandler
*/
&http.Server{Handler: httpMux}
`,
        'utf-8'
      );
      const commentedWiringErr = [];
      auditGenesisAuthEnforcement(tmpEnoentDir, commentedWiringErr, {
        requireGo: false,
        goCmd: 'nonexistent-go-binary-kty-test',
      });
      assert.ok(commentedWiringErr.some(e => e.includes('wrap the entire httpMux with security.AuthMiddleware')));

      // Unused/discarded closure (`_ = http.HandlerFunc(...)`) returning `next` must fail AuthMiddleware audit.
      writeFileSync(
        resolve(tmpEnoentDir, 'internal/cli/server.go'),
        'httpMux.Handle("/", ui)\nhttpMux.HandleFunc("/query", q)\nhttpMux.HandleFunc("/stats", s)\nhttpMux.HandleFunc("/tail", t)\nhttpMux.HandleFunc("/logs", b)\nhttpMux.HandleFunc("/burn", b)\nauthenticatedHandler := security.AuthMiddleware(cfg.AuthToken, httpMux)\n&http.Server{Handler: authenticatedHandler}\n',
        'utf-8'
      );
      writeFileSync(
        resolve(tmpEnoentDir, 'internal/security/security.go'),
        `package security
func AuthMiddleware(expectedToken string, next http.Handler) http.Handler {
  if expectedToken == "" { return next }
  _ = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    authHeader := r.Header.Get("Authorization")
    var token string
    if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
      token = strings.TrimSpace(authHeader[7:])
    }
    if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
      w.WriteHeader(http.StatusUnauthorized)
      return
    }
    next.ServeHTTP(w, r)
  })
  return next
}
`,
        'utf-8'
      );
      const discardedClosureErr = [];
      auditGenesisAuthEnforcement(tmpEnoentDir, discardedClosureErr, {
        requireGo: false,
        goCmd: 'nonexistent-go-binary-kty-test',
      });
      assert.ok(discardedClosureErr.some(e => e.includes('AuthMiddleware')));

      // Unauthenticated outer guard (`if true { return next }`) before http.HandlerFunc must fail AuthMiddleware audit.
      writeFileSync(
        resolve(tmpEnoentDir, 'internal/security/security.go'),
        `package security
func AuthMiddleware(expectedToken string, next http.Handler) http.Handler {
  if true { return next }
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    authHeader := r.Header.Get("Authorization")
    var token string
    if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
      token = strings.TrimSpace(authHeader[7:])
    }
    if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
      w.WriteHeader(http.StatusUnauthorized)
      return
    }
    next.ServeHTTP(w, r)
  })
}
`,
        'utf-8'
      );
      const outerBypassErr = [];
      auditGenesisAuthEnforcement(tmpEnoentDir, outerBypassErr, {
        requireGo: false,
        goCmd: 'nonexistent-go-binary-kty-test',
      });
      assert.ok(outerBypassErr.some(e => e.includes('AuthMiddleware')));

      // Control-flow jump (`goto authorized` around ConstantTimeCompare) must fail AuthMiddleware audit even without security_test.go.
      writeFileSync(
        resolve(tmpEnoentDir, 'internal/security/security.go'),
        `package security
func AuthMiddleware(expectedToken string, next http.Handler) http.Handler {
  if expectedToken == "" { return next }
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    authHeader := r.Header.Get("Authorization")
    var token string
    if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
      token = strings.TrimSpace(authHeader[7:])
    }
    if token != "" {
      goto authorized
    }
    if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
      w.WriteHeader(http.StatusUnauthorized)
      return
    }
  authorized:
    next.ServeHTTP(w, r)
  })
}
`,
        'utf-8'
      );
      const gotoBypassErr = [];
      auditGenesisAuthEnforcement(tmpEnoentDir, gotoBypassErr, {
        requireGo: false,
        goCmd: 'nonexistent-go-binary-kty-test',
      });
      assert.ok(gotoBypassErr.some(e => e.includes('AuthMiddleware')));
    } finally {
      rmSync(tmpEnoentDir, { recursive: true, force: true });
    }

    // 9. Collector exporter destination & unreviewed exporter validation must reject external/exfil endpoints.
    const badJaegerCfg = buildValidCollectorConfig();
    badJaegerCfg.exporters['otlp/jaeger'].endpoint = 'exfil.example.com:4317';
    const badJaegerErr = [];
    auditCollectorConfigObject(badJaegerCfg, badJaegerErr);
    assert.ok(badJaegerErr.some(e => e.includes('exporters.otlp/jaeger.endpoint')));

    const extraExporterCfg = buildValidCollectorConfig();
    extraExporterCfg.exporters['otlp/exfil'] = { endpoint: 'evil.example.com:4317' };
    extraExporterCfg.service.pipelines.traces.exporters.push('otlp/exfil');
    const extraExporterErr = [];
    auditCollectorConfigObject(extraExporterCfg, extraExporterErr);
    assert.ok(extraExporterErr.some(e => e.includes('otlp/exfil')));

    // 10. Ignoring docker start kty-otel-collector failure must be caught by KTY_MOCK_DOCKER_FAIL_ACTION='start'.
    const liveBurn = readFileSync(resolve(REPO_ROOT, 'burn-telemetry.sh'), 'utf-8');
    const brokenStartBurn = liveBurn.replaceAll('docker start kty-otel-collector', 'docker start kty-otel-collector || true');
    assert.notEqual(brokenStartBurn, liveBurn);
    const brokenStartErr = [];
    auditBurnTelemetryScript(brokenStartBurn, brokenStartErr);
    assert.ok(brokenStartErr.some(e => e.includes('docker start on kty-otel-collector failed')));

    // 11. Helm .helmignore glob audit must catch wildcard and Go filepath.Match exclusions without blocking unrelated rules.
    const helmIgnoreErr = [];
    auditHelmIgnoreContent('files/*.yaml\n', helmIgnoreErr);
    assert.equal(helmIgnoreErr.length, 1);
    const helmBangLiteralErr = [];
    auditHelmIgnoreContent('files/otel-collector-config.yam[!l]\n', helmBangLiteralErr);
    assert.equal(helmBangLiteralErr.length, 1);
    const helmIgnoreOk = [];
    auditHelmIgnoreContent('*.tmp\ntemplates/*.yaml\n', helmIgnoreOk);
    assert.equal(helmIgnoreOk.length, 0);

    // 12. service.instance.id schema must reject employee-derived hostname slugs while accepting UUIDs, container hex IDs, and keyed digests.
    const instanceIdRe = new RegExp(APPROVED_SERVICE_INSTANCE_ID_OTTL_PATTERN);
    assert.equal(instanceIdRe.test('alice-smith'), false);
    assert.equal(instanceIdRe.test('alice-macbook-1a2b'), false);
    assert.equal(instanceIdRe.test('550e8400-e29b-41d4-a716-446655440000'), true);
    assert.equal(instanceIdRe.test('0123456789abcdef0123456789abcdef'), true);
    assert.equal(instanceIdRe.test('hmac:0123456789abcdef'), true);

    // 13. burn-telemetry.sh missing producer restart while collector is stopped must fail auditBurnTelemetryScript.
    const noProducerBurn = liveBurn.replace('docker restart "$producer_svc"', 'true "$producer_svc"');
    assert.notEqual(noProducerBurn, liveBurn);
    const noProducerErr = [];
    auditBurnTelemetryScript(noProducerBurn, noProducerErr);
    assert.ok(noProducerErr.some(e => e.includes('must restart running producer kty-ftaas-api')));

    // 14. Normalizing invalid metric scopes to [REDACTED_SCOPE_NAME] instead of rejecting via kty.scope_overflow must fail.
    const mergedScopeCfg = buildValidCollectorConfig();
    mergedScopeCfg.processors['transform/metrics_preflight'].metric_statements[1].statements[3] =
      `set(name, "[REDACTED_SCOPE_NAME]") where name != "" and not IsMatch(name, "${APPROVED_SCOPE_NAME_OTTL_PATTERN}")`;
    const mergedScopeErr = [];
    auditCollectorConfigObject(mergedScopeCfg, mergedScopeErr);
    assert.ok(mergedScopeErr.some(e => e.includes('drop_invalid_scope_name')));

    // 15. Removing concurrent kernel flock mutual exclusion must fail auditBurnTelemetryScript concurrency test.
    const unlockedBurn = liveBurn.replace('try_flock_fd9 || lock_rc=$?', 'lock_rc=0');
    assert.notEqual(unlockedBurn, liveBurn);
    const unlockedErr = [];
    auditBurnTelemetryScript(unlockedBurn, unlockedErr);
    assert.ok(unlockedErr.some(e => e.includes('mutual exclusion')));

    // 16. Falling back to shared /tmp when HOME, XDG_STATE_HOME, and KTY_BURN_STATE_DIR are unset must fail closed.
    const tmpFallbackBurn = liveBurn.replace(
      'echo "❌ Unable to resolve private burn state directory (set KTY_BURN_STATE_DIR, XDG_STATE_HOME, or HOME)." >&2\n    exit 1',
      'BURN_STATE_DIR="${TMPDIR:-/tmp}/kty-burn-unsafe"'
    );
    assert.notEqual(tmpFallbackBurn, liveBurn);
    const tmpFallbackErr = [];
    auditBurnTelemetryScript(tmpFallbackBurn, tmpFallbackErr);
    assert.ok(tmpFallbackErr.some(e => e.includes('shared /tmp')));

    // 17. Removing port validation before curl URL construction must fail auditBurnTelemetryScript on malformed/out-of-range ports.
    const unvalidatedPortBurn = liveBurn.replace('validate_tcp_port "GENESIS_PORT" "$GENESIS_PORT_VALIDATED" || exit 1', 'true');
    assert.notEqual(unvalidatedPortBurn, liveBurn);
    const unvalidatedPortErr = [];
    auditBurnTelemetryScript(unvalidatedPortBurn, unvalidatedPortErr);
    assert.ok(unvalidatedPortErr.some(e => e.includes('GENESIS_PORT="9002@outside.example"')));

    // 18. Prometheus TSDB purge executed BEFORE stopping kty-otel-collector must fail unified event barrier ordering.
    const preStopPromBurn = liveBurn.replace(
      'if printf \'%s\\n\' "$running_containers" | grep -qx "kty-otel-collector"; then',
      'curl --noproxy \'*\' --connect-timeout 3 --max-time 10 -fsS -X POST "http://127.0.0.1:${PROMETHEUS_PORT_VALIDATED}/api/v1/admin/tsdb/delete_series" --data-urlencode \'match[]={__name__=~".+"}\' || true\nif printf \'%s\\n\' "$running_containers" | grep -qx "kty-otel-collector"; then'
    );
    assert.notEqual(preStopPromBurn, liveBurn);
    const preStopPromErr = [];
    auditBurnTelemetryScript(preStopPromBurn, preStopPromErr);
    assert.ok(preStopPromErr.some(e => e.includes('strict barrier order')));

    // 19. Omitting pre-purge Prometheus scrape-drain restart before delete_series must fail unified event barrier ordering.
    const noPromDrainBurn = liveBurn.replace('    docker restart kty-prometheus 9>&-\n', '    :\n');
    assert.notEqual(noPromDrainBurn, liveBurn);
    const noPromDrainErr = [];
    auditBurnTelemetryScript(noPromDrainBurn, noPromDrainErr);
    assert.ok(noPromDrainErr.some(e => e.includes('strict barrier order')));

    // 20. Dropping Collector state reconciliation across interrupted burns must fail auditBurnTelemetryScript.
    const noStateRestoreBurn = liveBurn.replace(
      'if [ -f "$COLLECTOR_STATE_FILE" ]; then\n    # Reconcile interrupted previous burn that stopped Collector before receiving SIGKILL\n    collector_was_running=1\nfi',
      'collector_was_running=0'
    );
    assert.notEqual(noStateRestoreBurn, liveBurn);
    const noStateRestoreErr = [];
    auditBurnTelemetryScript(noStateRestoreBurn, noStateRestoreErr);
    assert.ok(noStateRestoreErr.some(e => e.includes('persisted Collector recovery state')));

    // 21. Bypassing symlink guard on COLLECTOR_STATE_FILE must fail auditBurnTelemetryScript symlink check.
    const symBypassBurn = liveBurn.replace('ensure_safe_target_file "$COLLECTOR_STATE_FILE" "collector recovery state file" || exit 1', 'true');
    assert.notEqual(symBypassBurn, liveBurn);
    const symBypassErr = [];
    auditBurnTelemetryScript(symBypassBurn, symBypassErr);
    assert.ok(symBypassErr.some(e => e.includes('symlinked KTY_BURN_STATE_FILE')));

    // 22. Leaking FD 9 into long-running docker child must fail SIGKILL immediate lock-release test.
    const leakedFdBurn = liveBurn.replace('docker restart kty-jaeger 9>&-', 'docker restart kty-jaeger');
    assert.notEqual(leakedFdBurn, liveBurn);
    const leakedFdErr = [];
    auditBurnTelemetryScript(leakedFdBurn, leakedFdErr);
    assert.ok(leakedFdErr.some(e => e.includes('SIGKILL')));

    // 23. Omitting Prometheus WAL/chunk wipe (stopping Prometheus and clearing /prometheus) must fail strict barrier ordering.
    const noPromWalWipeBurn = liveBurn.replace(
      'docker run --rm --volumes-from kty-prometheus --network none --cap-drop ALL --security-opt no-new-privileges --entrypoint /bin/sh "$prom_image" -c \'find /prometheus -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +\' 9>&-',
      'true'
    );
    assert.notEqual(noPromWalWipeBurn, liveBurn);
    const noPromWalWipeErr = [];
    auditBurnTelemetryScript(noPromWalWipeBurn, noPromWalWipeErr);
    assert.ok(noPromWalWipeErr.some(e => e.includes('erase /prometheus WAL/chunks')));

    // 24. Bypassing group/world-writable parent directory checks must fail unsafe-0777 override audit.
    const noDirPermBurn = liveBurn
      .replace('d????w*|d???????w*)', '__never_match_perm__)')
      .replace('d????w*)', '__never_match_group_w__)')
      .replace('d???????w*)', '__never_match_world_w__)');
    assert.notEqual(noDirPermBurn, liveBurn);
    const noDirPermErr = [];
    auditBurnTelemetryScript(noDirPermBurn, noDirPermErr);
    assert.ok(noDirPermErr.some(e => e.includes('0777 KTY_BURN_LOCK_FILE parent')));
    assert.ok(noDirPermErr.some(e => e.includes('0777 KTY_BURN_PROM_STATE_FILE parent')));
    assert.ok(noDirPermErr.some(e => e.includes('0777 ancestor of KTY_BURN_LOCK_FILE')));

    // 25. Dropping Prometheus WAL recovery state reconciliation across stopped crashes must fail auditBurnTelemetryScript.
    const noPromStateRestoreBurn = liveBurn.replace('elif [ -f "$PROM_STATE_FILE" ]; then', 'elif false; then');
    assert.notEqual(noPromStateRestoreBurn, liveBurn);
    const noPromStateRestoreErr = [];
    auditBurnTelemetryScript(noPromStateRestoreBurn, noPromStateRestoreErr);
    assert.ok(noPromStateRestoreErr.some(e => e.includes('persisted Prometheus WAL purge recovery state')));

    // 26. Bypassing symlink guard on PROM_STATE_FILE must fail auditBurnTelemetryScript symlink check.
    const promSymBypassBurn = liveBurn.replace('ensure_safe_target_file "$PROM_STATE_FILE" "prometheus recovery state file" || exit 1', 'true');
    assert.notEqual(promSymBypassBurn, liveBurn);
    const promSymBypassErr = [];
    auditBurnTelemetryScript(promSymBypassBurn, promSymBypassErr);
    assert.ok(promSymBypassErr.some(e => e.includes('symlinked KTY_BURN_PROM_STATE_FILE')));

    // 27. Clearing PROM_STATE_FILE in restore_collector when WAL purge failed (ignoring prom_wal_wiped guard) must fail.
    const unguardedPromStateCleanBurn = liveBurn.replace('elif [ "$prom_wal_wiped" -eq 1 ] && wait_prom_ready; then', 'else');
    assert.notEqual(unguardedPromStateCleanBurn, liveBurn);
    const unguardedPromStateCleanErr = [];
    auditBurnTelemetryScript(unguardedPromStateCleanBurn, unguardedPromStateCleanErr);
    assert.ok(unguardedPromStateCleanErr.some(e => e.includes('deleted prometheus-stopped state even though WAL purge failed')));
  });
});
