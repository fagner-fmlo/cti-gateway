# NarrowCTI Product Reference

This is the canonical public reference for NarrowCTI Community Edition
behavior. It connects the operator workflow, configuration, source adapters,
graph promotion, evidence and release gates. Versioned documents remain
historical snapshots; this document describes the current v1.1 behavior.

## Version Status

| Label | Meaning | Current value |
| --- | --- | --- |
| Latest published release | Latest immutable GitHub Release and stable tag | `v1.1.0`, published 2026-09-06 |
| Previous stable release | Previous GitHub Release and immutable tag | `v1.0.1`, published 2026-08-15 |
| v1.1.0 publication | GitHub Release, tag and image publication | Complete |
| Historical tags | Earlier implementation snapshots | `v0.2.0` through `v0.9.0` |

A Git tag without a GitHub Release is historical version evidence, not a
complete public release. The v1.1.0 tag, GitHub Release, release notes, image
publication and final evidence all refer to the same `main` release commit.

## Product Boundary

NarrowCTI is a pre-ingestion CTI decision gateway. It normalizes source data,
preserves provenance, scores and filters candidates, deduplicates artifacts,
builds graph-aware STIX and sends only governed output to OpenCTI.

```text
source payload
  -> source adapter and normalization
  -> metadata and provenance evidence
  -> base and contextual scoring
  -> TLP, age, type and policy controls
  -> source, artifact and OpenCTI deduplication
  -> quarantine or governed export
  -> STIX graph objects and relationships
  -> OpenCTI graph, audit records and operator reports
```

The boundary is deliberate:

- NarrowCTI decides what is safe and justified to ingest.
- OpenCTI stores, correlates, visualizes and investigates the curated graph.
- The official MITRE connector remains the canonical ATT&CK baseline loader.
- Official OpenCTI connectors such as MITRE or CVE remain external ingestion
  paths unless a source is explicitly enabled through NarrowCTI.
- NarrowCTI never claims an actor, target, sector, infrastructure or relation
  that the source does not support or a governed policy does not permit.

## Supported Ingestion Paths

| Path | NarrowCTI role | Query and scope | Primary evidence |
| --- | --- | --- | --- |
| OTX direct | Search and enrich OTX pulses, extract entities and export curated STIX | `OTX_QUERIES`, pulse limits and IOC guardrails | OTX state, decision audit, graph plan, report and OpenCTI audit |
| MISP direct | Search or replay MISP events, preserve event/object/attribute provenance and export curated STIX | `MISP_QUERIES`, dates, tags, publication and event guardrails | MISP state, decision audit, quarantine, graph plan, report and OpenCTI audit |
| MITRE official connector | Canonical ATT&CK baseline in OpenCTI | Controlled by the OpenCTI deployment | OpenCTI connector logs and ATT&CK objects |
| CVE or other official connectors | External OpenCTI source ingestion unless routed through NarrowCTI | Controlled by the corresponding connector | Connector evidence and OpenCTI objects |

The v1.0 NarrowCTI contract is OTX and MISP. Additional direct adapters are
outside the current product contract and must follow
`source-adapter-onboarding-v0.7.md` before they can be considered.

## Configuration Contract

Configuration is visible and deterministic. Operators set boundaries; the
engine applies them automatically and records the reason.

| Area | Main controls | What the operator must verify |
| --- | --- | --- |
| Connections | `OPENCTI_URL`, `OPENCTI_TOKEN`, `OTX_API_KEY`, `MISP_URL`, `MISP_KEY` | Credentials are local, valid and never committed |
| Runtime | `NARROWCTI_ENABLED_SOURCES`, `NARROWCTI_DRY_RUN`, `NARROWCTI_RUN_ONCE`, interval and state paths | First runs are bounded, dry-run and auditable |
| Score and policy | score thresholds, age limits, quarantine, contextual scoring and TLP | Decision score and policy reason match the intended risk posture |
| Source filters | OTX queries; MISP query, date, tag and publication filters | Query is narrow enough for available resources |
| Guardrails | maximum events, attributes, pulses and IoCs | A large feed cannot exhaust OpenCTI, Elasticsearch or local storage |
| Deduplication | source state, artifact index and optional OpenCTI lookup | Replays skip known work and do not create duplicate graph noise |
| Graph | export mode, graph allow-lists, confidence, provenance and lookup | Only source-backed graph objects and relations are promoted |
| Review | quarantine repository, review API credentials and release audit | Human decisions require identity and reason; export remains controlled |
| Evidence | decision audit, run summary, reports and relationship audit | Every result can be explained after the run |

The complete variable-by-variable table is in `configuration-reference.md`.
Code defaults describe the engine, while `.env.example` defaults describe a
safe operator profile. The effective value must be visible in preflight output.

## Decision Contract

| Decision | Meaning | OpenCTI mutation | Evidence to inspect |
| --- | --- | --- | --- |
| `ingest` | Candidate passed policy and deduplication | Yes, when export is enabled | Decision audit and importer result |
| `export` | Graph export completed for an accepted candidate | Yes | Graph plan and OpenCTI import result |
| `quarantine` | Candidate is held for analyst review | No | Quarantine record and score details |
| `drop` | Policy rejected the candidate | No | Decision reason and policy inputs |
| `skip` | No work was necessary, commonly state or artifact deduplication | No | State/artifact dedup reason |
| `dry-run` | Candidate would be accepted but mutation is disabled | No | Dry-run decision and graph preview |
| `error` | Processing or export failed and must not advance state | No reliable mutation is assumed | Error, retry and source summary |

The decision order is significant: source validation, TLP, age, score,
indicator type, deduplication, dry-run and export must not be silently
reordered. `shadow` contextual scoring is visible but does not change the
decision; `enforce` can change only score-dependent outcomes and cannot bypass
TLP, hard age or explicit holds.

## Query Contract

### OTX

`OTX_QUERIES` is a comma-separated list of search terms. Bound the run with
`MAX_SEARCH_RESULTS_PER_QUERY`, `MAX_PULSES_PER_QUERY` and
`MAX_IOCS_PER_PULSE`. Use `OTX_DRY_RUN=true` and `OTX_RUN_ONCE=true` for the
first run. A repeated pulse is expected to produce `skip`, not a second Report
or Indicator set.

### MISP

`MISP_QUERIES` accepts `*`, a search term, `event:<id>`, `event-id:<id>`,
`id:<id>` or `uuid:<uuid>`. For controlled validation prefer one direct event:

```text
MISP_QUERIES=event:1649
MISP_MAX_EVENTS_PER_RUN=1
MISP_MAX_ATTRIBUTES_PER_EVENT=500
MISP_MAX_IOCS_PER_EVENT=5
MISP_RUN_ONCE=true
```

Use `MISP_FROM_DATE`, `MISP_TO_DATE`, `MISP_TAGS` and
`MISP_PUBLISHED_ONLY` for bounded backfill. Oversized events are skipped by
default. `truncate` is for controlled experiments only and must appear in the
audit evidence.

## Graph Context Contract

Graph context is source-backed and same-event scoped. For MISP, the engine can
relate explicit campaign records to one unambiguous actor, capabilities,
infrastructure and victimology. It can also relate infrastructure to an
explicit actor or campaign and to explicit victimology. Every inferred edge
stores its source value, source field, scope and inference name.

The propagation rules are intentionally conservative:

- A campaign is not created from a Report title alone.
- A campaign is attributed to an actor only when one explicit actor candidate
  is unambiguous in the same event.
- Multiple explicit actors suppress inferred attribution rather than choosing
  one arbitrarily.
- Infrastructure victimology remains opt-in through
  `NARROWCTI_ENABLE_INFRASTRUCTURE_VICTIMOLOGY_EXPORT` until the target
  OpenCTI instance is validated.
- A source event containing only `campaign-name=Dust Storm` produces a
  campaign record and Report relation, but no invented actor, infrastructure,
  sector or country relation.

Use the OpenCTI relationship auditor to distinguish missing source evidence
from a failed export. See `opencti-coverage-matrix.md`.

## Validation Contract

| Validation | Command or workflow | Expected success |
| --- | --- | --- |
| Preflight | Compose `narrowcti-preflight` | Required variables valid; warnings are explainable |
| Unit suite | `python -m unittest discover -s tests -p test_*.py` | All tests pass |
| Quality and SAST | GitHub `Security and Quality` | Ruff, Bandit and strict dependency audit pass |
| DAST | GitHub `DAST` | Disposable review API and OWASP ZAP pass |
| Image | GitHub `Container Image` | Build, smoke test and Trivy pass |
| SBOM | `Container Image` workflow | CycloneDX artifact exists for the exact candidate |
| OTX real run | One bounded query, then repeat | First run ingests; repeat skips or deduplicates |
| MISP real run | One bounded event, then repeat | Valid event ingests; invalid or low-score event quarantines; repeat skips |
| Graph audit | `narrowcti-opencti-relationship-audit` | Relationships and Diamond/Kill Chain claims match evidence |
| Release | `release-process.md` | Same commit is merged, tagged, released and documented |

The v1.1.0 evidence record is maintained in `release-v1.1.0.md`. A green unit
test does not replace a real-feed or
OpenCTI-relationship validation.

## Error Contract

| Failure | Expected behavior | State safety |
| --- | --- | --- |
| Missing required variable | Preflight/runtime failure with variable name | No source checkpoint advances |
| Source timeout or 5xx | Bounded retries with backoff and jitter, then source error | Existing checkpoint remains |
| Source authentication or 4xx | Explicit source error; no false success | No source checkpoint advances |
| Malformed or incomplete candidate | `skip`, `drop` or `quarantine` according to reason | Candidate is auditable |
| OpenCTI rejected object or relationship | Export fails closed and reports worker error | Candidate is not marked imported |
| Duplicate source item | `skip` | Existing state is reused |
| Duplicate artifact | `skip` or graph-only replay when explicitly enabled | No duplicate Indicator is created |
| Review API unauthorized | `401` or `403` | No review transition occurs |
| Review transition conflict | `404` or `409` | Repository remains consistent |

## Evidence Files

The operational report should connect these artifacts by run:

- source state files;
- decision audit JSONL;
- gateway run summary JSONL;
- quarantine repository and release audit;
- graph export plan and graph dedup state;
- OpenCTI relationship audit JSON;
- text, JSON or HTML curation report;
- CI artifacts such as DAST evidence and SBOM.

Do not commit secrets, raw customer data or unbounded feed payloads. Local
validation evidence may remain in ignored state; public release notes should
contain summarized, reproducible facts and links, not private lab dumps.

## Data Contract Versions

Data contract versions are not release labels. They identify the shape of an
evidence or report payload and may remain stable across product releases for
consumer compatibility:

| Contract | Current value | Meaning |
| --- | --- | --- |
| Graph evidence and graph candidate payload | `v1.0.0` | Stable v1.0 shape for source-backed graph evidence. |
| Operational validation checklist | `operational-validation/v1.0` | Active checklist shape used by the v1.0 release gate. |
| Curation report | `curation-report/v0.8` | Stable report schema retained for compatibility; it does not mean the product is on v0.8. |
| Support diagnostics | `support-diagnostics/v0.8` | Stable support bundle schema retained for compatibility; it does not mean the product is on v0.8. |

When a contract changes incompatibly, introduce a new schema value and document
the migration. Do not infer the current product release from a payload schema.
