# Configuration Reference

This is the current public configuration reference for NarrowCTI Community
Edition.

Versioned configuration files remain available as release history. Use this
document for the active configuration surface.

## Configuration Model

```text
visible configuration
  -> source scope, thresholds, limits, dry-run, deduplication and graph policy

automatic curation engine
  -> normalize, score, decide, deduplicate, quarantine, audit and export
```

Operators configure the boundaries. NarrowCTI applies those boundaries and
records the reason for every `ingest`, `drop`, `quarantine`, `skip`,
`dry-run` or `export` decision.

## Required Connection Variables

| Variable | Scope | Default | Effect |
| --- | --- | --- | --- |
| `OPENCTI_URL` | OpenCTI | Required | OpenCTI base URL used by export, lookup and relationship audit. |
| `OPENCTI_TOKEN` | OpenCTI | Required | OpenCTI API token. Must never be committed. |
| `OTX_API_KEY` | OTX | Required for OTX | OTX API key used by OTX search/enrichment. |
| `MISP_URL` | MISP | Required for MISP | MISP base URL used by the MISP adapter. |
| `MISP_KEY` | MISP | Required for MISP | MISP API key. Must never be committed. |

## Compose Deployment Variables

| Variable | Default | Effect |
| --- | --- | --- |
| `NARROWCTI_GATEWAY_IMAGE` | `narrowcti/gateway:local` | Image tag used by all Compose services. Use `ghcr.io/narrowcti/narrowcti-gateway:<version>` for release deployments. |
| `NARROWCTI_GATEWAY_CONTAINER` | `narrowcti-gateway` | Container name for the gateway runtime service. |
| `NARROWCTI_GATEWAY_ENV_FILE` | `./gateway.env.example` | Env file consumed by Compose. Set to `./gateway.env` for real local secrets. |
| `NARROWCTI_GATEWAY_RESTART` | `no` | Restart policy for the gateway runtime. Keep `no` during validation. |
| `NARROWCTI_DOCKER_NETWORK` | `opencti_default` | External Docker network used to reach OpenCTI. |
| `CONNECTOR_NAME` | `NarrowCTI Gateway` | Logical connector name used in runtime metadata and audit naming. Keep it stable across deployments. |

## Gateway Runtime

| Variable | Default | Test posture | Production-like posture | Effect |
| --- | --- | --- | --- | --- |
| `NARROWCTI_MODE` | `gateway` | `gateway` | `gateway` | Runtime mode reported by preflight. |
| `NARROWCTI_ENABLED_SOURCES` | `otx` | One source first | Enable only validated sources | Comma-separated source list such as `otx,misp`. |
| `NARROWCTI_DRY_RUN` | `false` in code, `true` in templates | `true` | `false` only after evidence review | Gateway-level default for non-exporting runs. |
| `NARROWCTI_RUN_ONCE` | `false` in code, `true` in templates | `true` | `false` only after validation | Runs one bounded cycle and exits. |
| `NARROWCTI_SOURCE_INTERVAL_SECONDS` | `CONNECTOR_RUN_INTERVAL` or `3600` | Any safe value | Match operational cadence | Delay between source runs in continuous mode. |
| `CONNECTOR_RUN_INTERVAL` | `3600` | Optional legacy interval | Optional legacy interval | Legacy interval fallback used by source runtimes. |
| `NARROWCTI_STATE_DIR` | `/app/state` | Default | Persistent volume | Base state directory. |
| `NARROWCTI_DECISION_AUDIT_DIR` | `/app/state/audit` | Required for review | Required | Derived decision audit directory for sources. |
| `NARROWCTI_RUN_SUMMARY_FILE` | Empty unless configured | `/app/state/gateway_runs.jsonl` | Required for reports | Aggregate gateway run JSONL. |

## Scoring and Policy

| Variable | Default | Effect on decision |
| --- | --- | --- |
| `NARROWCTI_MIN_SCORE_TO_INGEST` | `60` | Candidates below this score are dropped unless they fall below the quarantine threshold first. Legacy `MIN_SCORE_TO_INGEST` overrides source-specific runtimes. |
| `NARROWCTI_QUARANTINE_SCORE_THRESHOLD` | `50` | Candidates below this score become `quarantine` when quarantine is enabled, otherwise `drop`. Legacy `QUARANTINE_SCORE_THRESHOLD` overrides source-specific runtimes. |
| `NARROWCTI_ENABLE_QUARANTINE` | `true` | Enables `quarantine` for very low scores instead of immediate `drop`. Legacy `ENABLE_QUARANTINE` overrides source-specific runtimes. |
| `NARROWCTI_MAX_DAYS_OLD` | `1095` | Old candidates need `MIN_SCORE_FOR_OLD_PULSE` or `MIN_SCORE_FOR_OLD_EVENT` to pass. Legacy `MAX_DAYS_OLD` overrides source-specific runtimes. |
| `NARROWCTI_CONTEXTUAL_SCORING_MODE` | `shadow` | `off` disables contextual adjustments, `shadow` calculates and audits them without changing decisions, and `enforce` uses the contextual score for score-threshold decisions. |
| `NARROWCTI_CONTEXTUAL_SCORING_MAX_IMPACT` | `100` | Caps the combined contextual impact ratio. Valid range is `0..100`. A lower value limits how far context can lift the base score. |
| `NARROWCTI_CONTEXTUAL_SCORING_IMPACTS` | Built-in category defaults | Comma-separated `category:points` overrides for `threat`, `toolbox`, `ttp`, `sector`, `location`, `vulnerability`, `author` and `graph_state`. Each value must be `0..100`. |
| `MAX_DAYS_HARD_FILTER` | `0` | `0` disables hard cutoff. Positive values drop candidates older than this many days regardless of score. |
| `MIN_SCORE_FOR_OLD_PULSE` | `80` | OTX score required when an old pulse exceeds `MAX_DAYS_OLD`. |
| `MIN_SCORE_FOR_OLD_EVENT` | `80` | MISP score required when an old event exceeds `MAX_DAYS_OLD`. |
| `NARROWCTI_ALLOWED_TLP` | Empty in code, `white,green` in templates | Candidates tagged with disallowed TLP are dropped before export. Empty means no TLP allow-list. TLP 2.0 `clear` and legacy `white` are policy-equivalent while the source value remains unchanged in evidence. |
| `NARROWCTI_ALLOWED_INDICATOR_TYPES` | Empty in code | Filters exportable indicator types. If all indicators are removed, the candidate is skipped. |

See `curation-decision-reference.md` for the decision matrix.

Contextual scoring is forward-only: it can preserve or increase the base score,
never reduce it. `enforce` can change outcomes controlled by score thresholds,
including minimum-score and quarantine boundaries. It cannot override a denied
TLP, the positive `MAX_DAYS_HARD_FILTER`, an explicit graph hold or an
indicator-type filter that removes every exportable indicator. Start with
`shadow`, compare decision evidence, then activate `enforce` deliberately.

## Deduplication

| Variable | Default | Effect |
| --- | --- | --- |
| `NARROWCTI_DEDUP_MODE` | `source` in code, `hybrid` in templates | `off`, `source`, `artifact` or `hybrid`. `hybrid` keeps source state and artifact correlation. |
| `NARROWCTI_DEDUP_STATE_FILE` | `/app/state/dedup_index.json` | Local artifact fingerprint and source-sighting index. |
| `NARROWCTI_OPENCTI_DEDUP_LOOKUP` | `false` | Optional OpenCTI Indicator pattern lookup before export. Lookup errors fail open. |
| `STATE_FILE` | `/app/state/state.json` | OTX processed pulse state. |
| `MISP_STATE_FILE` | `/app/state/misp_state.json` | MISP processed event state. |

## Quarantine and Review

| Variable | Default | Effect |
| --- | --- | --- |
| `NARROWCTI_QUARANTINE_REPOSITORY` | `/app/state/quarantine.jsonl` when derived by gateway | Shared quarantine JSONL repository. |
| `OTX_QUARANTINE_REPOSITORY` | Falls back to gateway value | OTX-specific quarantine repository override. |
| `MISP_QUARANTINE_REPOSITORY` | Falls back to gateway value | MISP-specific quarantine repository override. |
| `NARROWCTI_RELEASE_AUDIT_FILE` | `/app/state/audit/releases.jsonl` | Analyst release/reject/export audit file. |
| `NARROWCTI_RELEASE_QUARANTINE_REQUIRES_REASON` | `true` | Requires a reviewer reason for release, partial release or rejection. |
| `NARROWCTI_REVIEWER` | `operator` | Default reviewer identity for CLI actions. |
| `NARROWCTI_QUARANTINE_RAW_SNAPSHOT_MAX_BYTES` | `65536` | Maximum raw snapshot retained in quarantine evidence. |

### Analyst Review API

| Variable | Default | Effect |
| --- | --- | --- |
| `NARROWCTI_REVIEW_API_CREDENTIALS_FILE` | Required by the API process | Container path to the JSON file containing hashed API credentials. |
| `NARROWCTI_REVIEW_API_CREDENTIALS_SOURCE` | Example file in Compose | Compose host interpolation for the path mounted read-only as credentials. Set it in the shell or Compose interpolation env, not only the service `env_file`. |
| `NARROWCTI_REVIEW_API_HOST` | `127.0.0.1`; Compose uses `0.0.0.0` inside the container | API listen address. Compose still publishes only to host loopback. |
| `NARROWCTI_REVIEW_API_PORT` | `8081` | API listen port inside the runtime. |
| `NARROWCTI_REVIEW_API_PUBLISHED_PORT` | `8081` | Compose host interpolation for the loopback port. Set it before invoking Compose. |
| `NARROWCTI_REVIEW_API_DOCS_ENABLED` | `false` | Enables `/docs` and `/openapi.json`. Keep disabled unless needed in a controlled environment. |
| `NARROWCTI_REVIEW_API_ALLOW_EXPORT` | `false` | Allows `exporter` or `admin` credentials to perform real OpenCTI export. Preview remains available while false. |
| `NARROWCTI_REVIEW_API_IDENTITY_NAME` | `NarrowCTI Gateway` | STIX identity name used by API-triggered quarantine export. |
| `NARROWCTI_REVIEW_API_ALLOWED_HOSTS` | `127.0.0.1,localhost,testserver` in code | Comma-separated accepted HTTP Host values. Add the reverse-proxy hostname explicitly. |
| `NARROWCTI_REVIEW_API_MAX_BODY_BYTES` | `16384` | Rejects requests with a larger declared body before model parsing. Must be at least `1024`. |

Credential format, roles and endpoint behavior are documented in
`analyst-review-api.md`.

## OTX Source

| Variable | Default | Effect |
| --- | --- | --- |
| `OTX_QUERIES` | Required | Comma-separated OTX searches. |
| `OTX_DRY_RUN` | Falls back to `NARROWCTI_DRY_RUN`, default `false` | Non-exporting OTX execution. |
| `OTX_TIMEOUT` | `60` | OTX enrichment timeout. |
| `OTX_SEARCH_TIMEOUT` | `45` | OTX search timeout. |
| `OTX_RETRIES` | `3` | OTX retry count; must be greater than zero. |
| `OTX_RETRY_BACKOFF_SECONDS` | `3` | Delay between OTX retries. |
| `OTX_RETRY_JITTER_SECONDS` | `1` | Maximum random delay added to each OTX retry backoff. Set `0` only for deterministic tests. |
| `OTX_SOURCE_CONFIDENCE` | `50` | Source confidence adjustment. `50` is neutral. |
| `MAX_SEARCH_RESULTS_PER_QUERY` | At least `MAX_PULSES_PER_QUERY` or `10` | Search candidates reviewed per query. |
| `MAX_PULSES_PER_QUERY` | `5` | Accepted OTX pulses per query. |
| `MAX_IOCS_PER_PULSE` | `2000` | Max indicators exported per pulse. |
| `DECISION_AUDIT_FILE` | Empty | OTX decision audit override. |
| `INGEST_PAUSE_SECONDS` | `2` | Pause after successful source ingest. |
| `NARROWCTI_ENABLE_OTX_ENTITY_EXTRACTION` | `true` | Extracts OTX adversary, malware, ATT&CK, sector, country, TLP and references as evidence. |

## MISP Source

| Variable | Default | Effect |
| --- | --- | --- |
| `MISP_QUERIES` | Required | `*`, search terms, `event:<id>`, `event-id:<id>`, `id:<id>` or `uuid:<uuid>`. |
| `MISP_DRY_RUN` | `true` | Non-exporting MISP execution. |
| `MISP_RUN_ONCE` | `false` in code, `true` in templates | Runs one bounded MISP cycle and exits. |
| `MISP_VERIFY_TLS` | `false` | TLS verification for MISP HTTP calls. Use `true` in production-like deployments with valid TLS. |
| `MISP_SEARCH_TIMEOUT` | `45` | MISP search timeout. |
| `MISP_ENRICH_TIMEOUT` | `60` | MISP event enrichment timeout. |
| `MISP_RETRIES` | `3` | MISP retry count; must be greater than zero. |
| `MISP_RETRY_BACKOFF_SECONDS` | `3` | Delay between MISP retries. |
| `MISP_RETRY_JITTER_SECONDS` | `1` | Maximum random delay added to each MISP retry backoff. Set `0` only for deterministic tests. |
| `MISP_FROM_DATE` | Empty | Lower date bound for MISP search/backfill. |
| `MISP_TO_DATE` | Empty | Upper date bound for MISP search/backfill. |
| `MISP_TAGS` | Empty in code, `tlp:green` in templates | Tag filter for MISP search. |
| `MISP_PUBLISHED_ONLY` | `false` in code, `true` in templates | Restricts to published events. |
| `MISP_MAX_EVENTS_PER_RUN` | `10` in code, `1` in templates | Events processed per run. |
| `MISP_MAX_ATTRIBUTES_PER_EVENT` | `1000` | Metadata-first guardrail for event size. |
| `MISP_MAX_IOCS_PER_EVENT` | `1000` | Max indicators exported from one event. |
| `MISP_OVERSIZED_EVENT_ACTION` | `skip` | `skip` oversized events or `truncate` in controlled tests. |
| `MISP_SOURCE_CONFIDENCE` | `50` | Source confidence adjustment. `50` is neutral. |
| `MISP_DECISION_AUDIT_FILE` | Empty | MISP decision audit override. |
| `MISP_GRAPH_REPLAY_ON_ARTIFACT_DEDUP` | Falls back to global, default `false` | Allows MISP graph-only replay when indicators are already known. |

## MITRE and Enrichment

| Variable | Default | Effect |
| --- | --- | --- |
| `NARROWCTI_ENABLE_MITRE_ATTACK_RESOLUTION` | `true` | Resolves ATT&CK ids using a local cache when available. |
| `NARROWCTI_MITRE_CACHE_FILE` | Empty | Local ATT&CK cache path. Missing cache is warning evidence, not a blocker. |
| `NARROWCTI_MITRE_STIX_URL` | Enterprise ATT&CK STIX URL | Source URL for cache refresh tooling. |
| `NARROWCTI_IP_ASN_ENRICHMENT_FILE` | Empty | Optional offline IP-to-ASN mapping file for infrastructure enrichment. |

## Graph Promotion

| Variable | Default | Effect |
| --- | --- | --- |
| `NARROWCTI_MIN_ENTITY_CONFIDENCE` | `0` | Minimum confidence for graph entity candidates. |
| `NARROWCTI_MIN_RELATIONSHIP_CONFIDENCE` | `0` | Minimum confidence for graph relationship candidates. |
| `NARROWCTI_REQUIRE_RELATIONSHIP_PROVENANCE` | `false` | Requires source provenance before accepting relationships. |
| `NARROWCTI_ALLOWED_GRAPH_ENTITY_TYPES` | Empty | In audit/dry-run, empty keeps candidates visible. In export, empty uses safe defaults. |
| `NARROWCTI_ALLOWED_GRAPH_STIX_OBJECT_TYPES` | Empty | Optional STIX/OpenCTI object allow-list. In export, empty uses safe defaults. |
| `NARROWCTI_GRAPH_EXPORT_MODE` | `audit` | `audit`, `dry-run` or `export`. Controls graph promotion behavior. |
| `NARROWCTI_GRAPH_DEDUP_STATE_FILE` | Empty | Local graph known-key index. |
| `NARROWCTI_GRAPH_REPLAY_ON_ARTIFACT_DEDUP` | `false` | Allows graph-only replay when indicators are already known, subject to graph policy and source evidence. Source-specific `MISP_GRAPH_REPLAY_ON_ARTIFACT_DEDUP` can override it. |
| `NARROWCTI_OPENCTI_GRAPH_LOOKUP` | `false` | Read-only canonical lookup before creation. Existing entities are reused; relationships are deduplicated only after exact source, target, direction and relationship-type confirmation. Errors fail open and are logged. |
| `NARROWCTI_ENABLE_INFRASTRUCTURE_VICTIMOLOGY_EXPORT` | `false` | Explicitly promotes a same-event MISP `Infrastructure -> targets -> victimology` candidate whose source evidence and inference are exact. Keep disabled until OpenCTI API/UI validation confirms the expected Diamond victimology behavior. It does not approve unrelated or unvalidated relationships. |

Detection-rule mappings do not require a separate environment variable. They
use the same `NARROWCTI_GRAPH_EXPORT_MODE` gate above: only explicit ATT&CK ids
found in Sigma `tags`/`references` or in the associated MISP tags can produce
`Indicator --detects--> Attack-Pattern`. `audit` and `dry-run` remain
non-mutating; `export` promotes the idempotent relationship. Rules without an
explicit ATT&CK reference are retained without a semantic detection link.

Infrastructure victimology promotion is intentionally opt-in. With the default
`false`, NarrowCTI keeps the candidate in audit evidence with
`relationship_requires_opencti_validation`. Setting it to `true` only changes
that exact source-backed candidate; TLP, age, score, provenance and all other
graph policy controls remain active. Enable it for a bounded validation run,
inspect the resulting OpenCTI relationship and Diamond view, then retain the
decision and evidence in the operational report.

## Reporting and Validation

| Variable | Default | Effect |
| --- | --- | --- |
| `NARROWCTI_CAPABILITIES` | Empty | Declared capability inventory. Unknown values are warnings; no feature blocking in Community Edition. |
| `NARROWCTI_OPERATIONAL_VALIDATION_SOURCES` | `otx,misp` in Compose | Sources required by operational validation. |
| `NARROWCTI_OPERATIONAL_VALIDATION_EVIDENCE_FILE` | `/app/state/operational-validation-evidence.json` in Compose | Manual validation evidence file. |
| `NARROWCTI_OPENCTI_RELATIONSHIP_AUDIT_FILE` | `/app/state/opencti-relationship-audit.json` in Compose | Relationship audit evidence consumed by reports/validation. |
| `NARROWCTI_OPENCTI_AUDIT_TYPE` | Empty | Target OpenCTI object type for relationship audit. |
| `NARROWCTI_OPENCTI_AUDIT_SEARCH` | Empty | Target search value for relationship audit. |
| `NARROWCTI_OPENCTI_AUDIT_FIRST` | `100` | Max relationship audit page size. |
| `NARROWCTI_OPENCTI_AUDIT_OUTPUT_FILE` | `/app/state/opencti-relationship-audit.json` | Output file for audit evidence. |
| `NARROWCTI_OPENCTI_AUDIT_EXPECTED_QUADRANTS` | Empty | Expected Diamond quadrants such as `adversary,capability,infrastructure,victimology`. |
| `NARROWCTI_OPENCTI_AUDIT_REQUIRE_KILL_CHAIN` | `false` | Marks kill chain context as required for audit coverage. |

## Community Edition Posture

NarrowCTI Community Edition does not use commercial feature blocking. Capability
inventory exists for transparency and support diagnostics, not licensing.
