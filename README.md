<p align="center">
  <img src="docs/assets/narrowcti-banner.png" alt="NarrowCTI banner" width="760">
</p>

<p align="center">
  <strong>OpenCTI-native CTI curation gateway for governed, explainable and graph-ready intelligence.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
  <a href="https://github.com/NarrowCTI/narrowcti/actions/workflows/ci.yml"><img src="https://github.com/NarrowCTI/narrowcti/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="docs/README.md"><img src="https://img.shields.io/badge/docs-current-brightgreen.svg" alt="Documentation"></a>
  <a href="docs/container-images.md"><img src="https://img.shields.io/badge/container-GHCR-blue.svg" alt="Container image"></a>
  <a href="SECURITY.md"><img src="https://img.shields.io/badge/security-policy-informational.svg" alt="Security policy"></a>
</p>

NarrowCTI is an OpenCTI-native threat intelligence gateway designed to curate,
score, deduplicate and govern threat intelligence before it reaches the OpenCTI
graph.

NarrowCTI Gateway turns raw feed data into controlled ingestion candidates with
explainable decisions, source provenance, guardrails and operational evidence for
CTI, hunting and SOC teams.

## Current Version

```text
v1.0.1
```

`v1.0.1` is the current backward-compatible Community Edition patch release. It
preserves MISP source dates through STIX/OpenCTI timestamps while retaining the
production-ready v1.0.0 contract.

`v1.0.0` is the first production-ready Community Edition release. It hardens
the validated OTX and MISP gateway paths, integrates governed contextual
scoring, closes priority graph-quality gaps and validates installation,
upgrade, recovery and release gates. New source adapters are outside the
current release scope.

The latest published release is `v1.0.1` (2026-08-15). `v1.0.0`, `v0.9.0` and
`v0.8.0` remain available as historical release milestones, while `v0.2.0` through
`v0.7.0` remain historical tags without GitHub Release pages.

The release sequence is `v0.8.0` -> `v0.9.0` -> `v1.0.0` -> `v1.0.1`. The
`v1.0.1` release is the current patch milestone for the first Community
Edition.

Release history is summarized in `CHANGELOG.md`; detailed operator-facing
release notes are maintained under `docs/release-v*.md`.

## Quick Start

For a first safe evaluation, start with the current operator guide:

```text
docs/getting-started.md
```

The default deployment posture is dry-run, run-once and audit-first. Build the
gateway image, run preflight, then execute one bounded run before enabling real
OpenCTI graph export:

```powershell
docker compose -f deployment\docker-compose.narrowcti-gateway.yml build narrowcti-gateway
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile ops run --rm narrowcti-preflight
docker compose -f deployment\docker-compose.narrowcti-gateway.yml run --rm narrowcti-gateway
```

Use `docs/deployment-operations.md` for the authoritative deployment and
upgrade procedure.

## Product Identity

The v0.2 line was the modular OTX connector foundation. The v0.3 line is the
transition from an OTX-specific connector into NarrowCTI Gateway, an OpenCTI-native
pre-ingestion intelligence gateway. OTX remains the first source adapter; it is no
longer the product identity. The v0.4 release validated the gateway model with a
second real feed, and v0.5 introduced the unified gateway runtime model. The
current gateway shapes source-backed actor, arsenal, TTP, victimology,
infrastructure and quarantine/release context before OpenCTI ingestion.

## What It Does

- Searches OTX pulses using configurable threat intelligence queries.
- Enriches candidate pulses through the OTX API.
- Calculates contextual scores in `shadow` mode by default and supports
  explicit, audited `enforce` mode after operator validation.
- Applies ingestion policy for drop, quarantine and export decisions.
- Optionally writes structured decision audit records for operational review.
- Logs per-query operational summaries for reviewed, ingested, dropped,
  quarantined, skipped and failed candidates.
- Deduplicates processed pulses with persistent local state.
- Provides a MISP adapter foundation with independent state, dry-run mode,
  run-once execution and safe backfill filters.
- Maps source-backed actor, arsenal, MITRE ATT&CK, victimology, quarantine,
  release and graph-enrichment context.
- Builds STIX bundles for OpenCTI ingestion.
- Runs as a Dockerized connector inside an OpenCTI lab environment.

## Architecture

```text
External and internal intelligence sources
  -> source adapters such as OTX and MISP
  -> shared feed contract
  -> scoring, policy and decision audit
  -> source-scoped state and guardrails
  -> STIX builder
  -> OpenCTI exporter
```

Main modules:

```text
connectors/otx/      OTX connector runtime, feed adapter, settings and processor
connectors/misp/     MISP client, feed adapter, settings and processor foundation
core/                Feed contracts, scoring, policy and persistent state handling
exporters/           OpenCTI export and STIX bundle construction
tests/               Unit coverage for the processor and shared pipeline logic
docs/                Product, operations, architecture and release documentation
```

## Product Role

NarrowCTI is designed as a pre-ingestion intelligence decision layer for
OpenCTI. Its role is to reduce feed noise before data reaches the OpenCTI graph
by applying source-specific enrichment, scoring, deduplication and policy.

The gateway serves analysts, hunters, SOC and platform teams that need curated
intelligence, explainable decisions and auditable feed governance instead of raw
IoC forwarding. OTX, MISP and other approved source adapters use the same
explainable ingestion model. Source-backed actors, arsenal, MITRE tactics and
techniques, victimology, infrastructure, campaigns, vulnerabilities and
detection context are exported when the evidence supports them. The public
product boundary is tracked in `docs/product-reference.md`.

MITRE ATT&CK is treated as reference and curation context. The official MITRE
connector should populate OpenCTI with the canonical ATT&CK baseline, while
NarrowCTI uses ATT&CK ids found in OTX and MISP to enrich, score, filter,
deduplicate, audit and relate curated intelligence to the OpenCTI graph. This
decision is tracked in
`docs/mitre-curation-architecture-v0.7.md`.

## Deduplication Posture

NarrowCTI should protect OpenCTI graph hygiene instead of forwarding the same
artifact repeatedly. The current implementation deduplicates processed source
items with local state, deduplicates repeated STIX patterns inside each bundle
and can keep a local artifact index with provenance sightings for cross-source
correlation. The v0.5 gateway design extends this into layered pre-export
deduplication:

- Source-item deduplication prevents the same OTX pulse or MISP event from being
  processed repeatedly.
- Artifact deduplication normalizes indicator type and value before export.
- The local artifact index records source sightings so repeated OTX/MISP
  evidence can become correlation context instead of duplicate imports.
- Optional OpenCTI lookup can check existing STIX Indicator patterns before
  import when enabled.
- Cross-source matches should become provenance and confidence evidence, not
  duplicate graph noise.

## v0.4 Release

The v0.4 release starts the multi-feed expansion. OTX remains the reference
adapter, while MISP becomes the likely second adapter because many operations
use MISP as the central IoC and event hub.

The intended flow for MISP-backed environments is:

```text
AlienVault OTX and other feeds
  -> MISP
  -> NarrowCTI Gateway
  -> OpenCTI
```

NarrowCTI should preserve both the collector context, such as MISP, and the
original intelligence source, such as AlienVault OTX, when that information is
available.

A 2026-06-21 local validation confirmed that one MISP event can contain tens
of thousands of attributes, and that `opencti/connector-misp:6.9.4` does not
support `MISP_IMPORT_LIMIT`. NarrowCTI therefore needs first-class per-run and
per-event safety controls instead of relying on the official connector for
controlled backfill.

The MISP adapter foundation now includes explicit guardrails for maximum events
per run, maximum attributes per event and maximum exported IoCs per event.
Oversized events are skipped by default, with an explicit truncate mode available
for controlled experiments.
The adapter also supports dry-run validation, one-shot execution and bounded
historical backfill filters for date ranges, tags and published-only imports.
The adapter has dedicated settings, MISP event state and a processor foundation
so it can evolve without sharing OTX pulse processing state.

## v0.5 Release

The v0.5 release introduces the first unified NarrowCTI Gateway runtime.
Instead of treating each source container as the product shape, the gateway
runtime should orchestrate enabled sources such as OTX and MISP through a source
registry while keeping source-level state, audit evidence, guardrails and failure
isolation intact.

The source-specific OTX and MISP runtimes should remain available for debugging,
validation and bounded backfill. MISP should stay opt-in and guarded until local
OpenCTI, queue and Elasticsearch behavior remains stable across repeated bounded
runs. The runtime design is tracked in `docs/gateway-runtime-v0.5.md`, and the
product/architecture continuity validation is tracked in
`docs/product-architecture-validation-v0.5.md`.

## v0.6 Release Track

The v0.6 track is the quarantine and enrichment foundation. The goal is to
turn quarantine from a decision outcome into a reviewable, auditable operator
workflow while beginning structured enrichment from OTX and MITRE ATT&CK.

The current v0.6 implementation provides a local quarantine repository and CLI
workflow for listing, showing, rejecting and releasing held candidates with
reviewer reason and release audit evidence. OTX and MISP quarantine decisions
write pending records into the local repository with scoring metadata, source
provenance, indicators and a bounded raw snapshot. Released records can be
replayed through the existing OpenCTI export path with dry-run as the default.

The enrichment foundation extracts OTX adversary, malware family, ATT&CK,
industry, country, TLP and reference fields, then resolves ATT&CK technique and
tactic context through a local MITRE cache when configured. Gateway preflight
checks and operational reporting now include quarantine/release and MITRE cache
posture for operator readiness.

The detailed v0.6 design is tracked in
`docs/quarantine-enrichment-v0.6.md`, and the release notes are
tracked in `docs/release-v0.6.0.md`.

Initial quarantine CLI commands:

```powershell
python -m gateway.quarantine --repository state\quarantine.jsonl list --status pending
python -m gateway.quarantine --repository state\quarantine.jsonl show --id <quarantine-id>
python -m gateway.quarantine --repository state\quarantine.jsonl --release-audit-file state\audit\releases.jsonl reject --id <quarantine-id> --reason "Out of scope"
python -m gateway.quarantine --repository state\quarantine.jsonl --release-audit-file state\audit\releases.jsonl release --id <quarantine-id> --reason "Relevant to monitored actor"
python -m gateway.quarantine --repository state\quarantine.jsonl --release-audit-file state\audit\releases.jsonl release-indicators --id <quarantine-id> --type filehash-sha256,url --reason "High-value indicators"
python -m gateway.quarantine --repository state\quarantine.jsonl export-released --id <quarantine-id>
python -m gateway.quarantine --repository state\quarantine.jsonl export-released --id <quarantine-id> --execute --dedup-state-file state\dedup_index.json
python -m gateway.quarantine --release-audit-file state\audit\releases.jsonl audit
```

The initial v0.6 CLI records review state and release audit evidence locally.
The source processors automatically enqueue policy-quarantined OTX pulses and
MISP events when `NARROWCTI_QUARANTINE_REPOSITORY` is configured. Released
records can be replayed through the same OpenCTI export path with a dry-run
default; `--execute` is required for real export. The `audit` command summarizes
release, reject and export audit events without requiring manual JSONL parsing.

OTX entity extraction is controlled by
`NARROWCTI_ENABLE_OTX_ENTITY_EXTRACTION=true`. In v0.6 this extraction is
metadata-only: adversary, malware family, ATT&CK ids, industries, targeted
countries, TLP, references and tags are preserved as structured graph evidence.

## v0.7 Release

The v0.7 release turns the enrichment evidence from v0.6 into graph-aware
STIX/OpenCTI planning and preview output. The objective is to validate source
metadata more deeply, map supported evidence into actors, intrusion sets,
malware, tools, infrastructure, vulnerabilities, campaigns, sectors, locations,
ATT&CK techniques and relationships, and keep those relationships explainable
before they affect the OpenCTI graph.

The current operator contract is tracked in `docs/product-reference.md`, the
active architecture in `docs/architecture-v1.0.md`, and current OpenCTI
coverage in `docs/opencti-coverage-matrix.md`. Historical v0.7 source,
MITRE, MISP and OTX mapping documents remain available through
`docs/documentation-map.md`; they explain evolution but do not override the
current product contract.

## v0.8 Release

The v0.8 release starts the controlled promotion gate after v0.7. It adds
read-only OpenCTI graph lookup so NarrowCTI can detect canonical ATT&CK objects,
such as existing `attack-pattern` entries loaded by the official MITRE
connector, before controlled graph promotion is enabled.

The graph promotion design is tracked in `docs/graph-promotion-v0.8.md`, and
the release notes are tracked in `docs/release-v0.8.0.md`. Deployment, analyst
review, curation reporting and support diagnostics are tracked in the dedicated
v0.8 documents under `docs/`.

The relationship between NarrowCTI curation and OpenCTI post-ingestion
inference rules is documented in `docs/opencti-rules-engine-v0.8.md`.
NarrowCTI owns source-backed pre-ingestion decisions; OpenCTI Rules Engine can
optionally infer additional relationships after the curated graph exists.
OpenCTI tab coverage, current export status and backlog boundaries are tracked
in `docs/opencti-coverage-matrix-v0.8.md`.

## v0.9 Release

The published v0.9 release turns the v0.8 graph and analyst foundations into a
governed operator workflow. It adds the authenticated review API, exact
relationship deduplication, OpenCTI compatibility boundaries, public
contributor governance and blocking CI/CD security gates.

The authoritative notes are in `docs/release-v0.9.0.md`. The published image
and tag policy are in `docs/container-images.md`.

## v1.0 Release

The v1.0 release hardens the existing OTX and MISP gateway paths for Community
Edition. It covers deterministic contextual scoring,
source-backed actor, campaign, infrastructure and victimology propagation,
Diamond, Timeline and Kill Chain evidence, restart-safe operations, complete
documentation and reproducible security, image and OpenCTI validation. It does
not expand the source catalog. New direct adapters are outside the current
release scope.

The current product contract is `docs/product-reference.md`, the current
OpenCTI coverage matrix is `docs/opencti-coverage-matrix.md`, and the current
release evidence is `docs/release-v1.0.1.md`.

## Curation Configuration

Curation controls must be visible in configuration and then applied
automatically by the gateway. Current source runtimes expose score thresholds,
age limits, quarantine behavior, gateway-level allowed TLP, exportable
indicator types, MISP date ranges, MISP tag filters and volume guardrails
through environment variables. The v0.5 track adds gateway-level `NARROWCTI_*`
controls for shared policy, deduplication and source selection. Unsupported
policy dimensions remain explicit and are not silently inferred by the gateway.

The graph layer records `graph_candidate_policy` and `graph_export_plan`
metadata. `NARROWCTI_GRAPH_EXPORT_MODE=audit` keeps the plan audit-only, while
`dry-run` records what graph objects and relationships would be attempted. In
v0.8, `NARROWCTI_GRAPH_EXPORT_MODE=export` enables the first controlled graph
promotion gate: OTX and MISP still export the legacy report and indicators, but
also add accepted graph entities and relationships to the same STIX bundle.
This can feed OpenCTI areas such as Threats, Arsenal, Techniques, Sectors,
Locations and Observations when source metadata supports those entities. The
local graph deduplication state can be read with
`NARROWCTI_GRAPH_DEDUP_STATE_FILE` so OTX and MISP export plans can mark known
local graph keys as deduplicated. Dry-run plans are not marked as exported
knowledge, and export state is marked only after the OpenCTI import call
succeeds. In v0.8,
`NARROWCTI_OPENCTI_GRAPH_LOOKUP=true` can also be enabled so OTX and MISP
planning query OpenCTI for canonical graph objects, starting with ATT&CK
attack-patterns, malware, tools, infrastructure, CVE vulnerabilities, threat
actors and intrusion sets, and controlled locations/countries, before promotion
creates new graph knowledge. Canonical matches are exposed as bounded
`graph_export_plan_lookup_matches` metadata for bounded audit reporting. When a
canonical match includes a valid STIX `standard_id`, the
export gate references that existing OpenCTI object in the curated STIX bundle
instead of duplicating it. Graph SDOs created by NarrowCTI also use
deterministic STIX ids so repeated exports of the same curated object converge
on the same OpenCTI `standard_id`.

For bounded MISP curation replay,
`NARROWCTI_GRAPH_REPLAY_ON_ARTIFACT_DEDUP=true` can be combined with
`NARROWCTI_GRAPH_EXPORT_MODE=export` so events whose indicators are already
known still export accepted graph context without replaying indicator objects.

When real graph export is enabled without an explicit allow-list, NarrowCTI
uses a safe default allow-list. It promotes source-backed CTI objects such as
infrastructure, ASN, observables, sectors, locations, arsenal, ATT&CK,
vulnerabilities and reports, while keeping feed bookkeeping such as collector,
source identity, labels and markings in author/audit metadata unless the
operator explicitly opts into those graph candidate types.

The v0.8 graph bundle also activates richer export targets when they are
resolvable: MITRE data-source context can travel as a curated Data Source
anchored to the ATT&CK technique; detection guidance and MISP EventReports
travel as Notes; YARA/Sigma/Snort/Suricata/PCRE rules travel as pattern-aware
Indicators; MISP ObjectReferences become STIX Relationships when both UUID
endpoints resolve to graph objects; and MISP sightings become STIX Sightings
when the sighted value resolves to an Indicator. MITRE tactic and platform
values remain preserved as curated context/evidence and are not part of the
default export gate until OpenCTI import behavior is validated for those as
first-class objects. Unresolved relationship-only evidence stays out of the
bundle instead of creating unsafe OpenCTI edges.

Infrastructure promotion is intentionally conservative: raw domains, IPs and
URLs continue to be handled as Indicators or Observables unless source metadata
or review policy explicitly supports a STIX `infrastructure` candidate. This
keeps `Observations / Infrastructures` useful for curated threat infrastructure
instead of turning it into another raw IOC bucket.

For audit visibility, exported STIX bundles now use a source-aware OpenCTI
Author naming convention:

```text
<logical upstream source> via NarrowCTI
```

OTX exports appear as `OTX AlienVault via NarrowCTI`, MISP exports appear as
`MISP via NarrowCTI`, and additional adapters should define their own source
identity mapping with the same suffix. NarrowCTI also remains visible through
decision audit records, curation reports, export plans and `x_narrowcti_*`
graph metadata.

The full current configuration reference is tracked in
`docs/configuration-reference.md`. Versioned configuration references remain
available as release snapshots when a release note needs exact historical
behavior.

## NarrowCTI Gateway Runtime

The NarrowCTI Gateway runtime is configured through environment variables. The
current stable runtime uses the OTX adapter, and a safe template is provided at:

```text
connectors/otx/.env.example
```

The MISP adapter foundation has its own configuration template for controlled
local validation:

```text
connectors/misp/.env.example
```

Real runtime files must be created locally as needed:

```text
connectors/otx/.env
connectors/misp/.env
```

Do not commit real `.env` files. They contain OpenCTI, OTX or MISP credentials.

Required OTX variables:

```text
OPENCTI_URL
OPENCTI_TOKEN
OTX_API_KEY
OTX_QUERIES
```

Required MISP foundation variables:

```text
OPENCTI_URL
OPENCTI_TOKEN
MISP_URL
MISP_KEY
MISP_QUERIES
```

Recommended safe MISP validation controls for limited local machines:

```text
MISP_DRY_RUN=true
MISP_RUN_ONCE=true
MISP_MAX_EVENTS_PER_RUN=1
MISP_MAX_ATTRIBUTES_PER_EVENT=1000
MISP_MAX_IOCS_PER_EVENT=1000
MISP_QUERIES=*
MISP_FROM_DATE=YYYY-MM-DD
MISP_TO_DATE=YYYY-MM-DD
MISP_TAGS=tlp:green
MISP_PUBLISHED_ONLY=true
MISP_OVERSIZED_EVENT_ACTION=skip
```

For precise replay of a known MISP event during validation, use
`MISP_QUERIES=event:<id>` or `MISP_QUERIES=uuid:<uuid>` instead of a broad
search.


Initial v0.5 gateway runtime command for development validation:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\NarrowCTI"
docker run --rm --env-file config\.env.example -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m gateway.connector
```

The example keeps `NARROWCTI_DRY_RUN=true` and `OTX_DRY_RUN=true` for safe local validation.

Before running ingestion, operators can validate the gateway runtime posture
without calling feed APIs or OpenCTI:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\NarrowCTI"
docker run --rm --env-file config\.env.example -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m gateway.preflight
docker run --rm --env-file config\.env.example -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m gateway.preflight --json
```

The preflight reports enabled sources, deduplication posture, OpenCTI lookup,
aggregate summary output, source dry-run controls and local evidence paths for
source state, decision audit, release audit, quarantine repository, MITRE cache
and artifact deduplication. Unknown sources fail the check; weaker
graph-hygiene, missing MITRE cache and operational settings are reported as
warnings.

After one or more gateway runs, operators can summarize the aggregate JSONL
evidence written by `NARROWCTI_RUN_SUMMARY_FILE`:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\NarrowCTI"
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m gateway.report --file state\gateway_runs.jsonl
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m gateway.report --file state\gateway_runs.jsonl --json
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m gateway.report --file state\gateway_runs.jsonl --quarantine-file state\quarantine.jsonl --output-file state\gateway-operational-report.txt
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m gateway.decisions --dir state\audit
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m gateway.correlation --file state\dedup_index.json
```

The report aggregates run count, time range, total outcomes and per-source
outcomes for reviewed, ingested, dropped, quarantined, skipped, error and
dry-run candidates. It also reports directional value metrics such as accepted
items, filtered items, acceptance rate, filter rate and error rate, and it lists
source failures captured during gateway runs. Per-query rollups show which
searches produced reviewed, handled, accepted and filtered candidates. The
decision audit report aggregates ingest, drop, quarantine, skip, dry-run and
error reasons from source audit JSONL files, plus score ranges, averages and
per-query decision rollups for operator review. It also lists recent
quarantined candidates. When v0.7 `graph_export_plan` metadata is present, it
also aggregates graph export modes, statuses, actions, held reasons,
source/query rollups, deduplicated entity/relationship counts and dry-run
would-create object/relationship counts. The correlation report summarizes the
local artifact index, including cross-source fingerprints and source sighting
counts.

The unified gateway entrypoint composes enabled source runtimes and isolates
source failures. Keep source-specific runtimes available for debugging and
bounded backfills while the v0.5 gateway matures.

## Deployment

The authoritative current deployment and upgrade procedure is centralized in:

```text
docs/deployment-operations.md
```

The deployment assets are:

```text
deployment/docker-compose.narrowcti-gateway.yml
deployment/gateway.env.example
```

The v0.8 template is dry-run/run-once by default, joins an existing OpenCTI
Docker network and must be validated with `gateway.preflight` before any source
execution. Its `ops` profile can run preflight, curation reporting,
decision audit reporting, artifact correlation reporting, operational
validation and support diagnostics without starting continuous ingestion. The
curation report service persists text, JSON and HTML artifacts under the
gateway state volume, while support diagnostics can produce a redacted HTML
snapshot and support bundle for review. Older deployment snippets in
release-specific documents are
historical context; use `docs/deployment-operations.md` for the current
procedure.

Source-specific OTX and MISP runtimes remain available for debugging and
bounded backfill investigations, but they are not the current deployment source
of truth. Use `docs/deployment-operations.md` for deployment and upgrade
steps, and `scripts/misp-backfill-window.ps1 -Preview` only for controlled MISP
backfill command inspection.

## Validation

Run validation from the repository root after building the Docker image:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\NarrowCTI"
.\scripts\validate-release.ps1
```

The helper runs the same Docker-based syntax and unit validation commands used
for the release. To inspect commands without executing Docker:

```powershell
.\scripts\validate-release.ps1 -Preview
```

Manual equivalent:

```powershell
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m py_compile connectors/otx/connector.py connectors/otx/entity_extraction.py connectors/otx/feed_adapter.py connectors/otx/models.py connectors/otx/processor.py connectors/otx/runtime.py connectors/otx/settings.py connectors/otx/otx_client.py connectors/misp/client.py connectors/misp/connector.py connectors/misp/feed_adapter.py connectors/misp/models.py connectors/misp/processor.py connectors/misp/runtime.py connectors/misp/settings.py core/decision_audit.py core/feed_contract.py core/graph_candidates.py core/graph_evidence.py core/indicator_policy.py core/mitre_attack.py core/quarantine.py core/scoring.py core/policy.py core/state_repository.py core/tlp.py exporters/opencti.py exporters/stix_builder.py
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m py_compile gateway/preflight.py gateway/report.py gateway/decisions.py gateway/correlation.py gateway/mitre.py gateway/quarantine.py gateway/quarantine_export.py
docker run --rm -v "${LAB_ROOT}\NarrowCTI:/repo" -w /repo opencti-connector-narrowcti python -m unittest discover -s tests -v
```

## Release Flow

The project uses `dev` as the integration branch and `main` as the stable branch.
Official versions should be published from `main` with both a Git tag and a
GitHub Release containing curated release notes.

```text
feature/* -> dev -> main -> version tag -> GitHub Release
```

Current release:

```text
Latest published: v1.0.1
Previous stable milestone: v1.0.0
```

## Documentation

The documentation index is available in:

```text
docs/README.md
```

Recommended starting points:

```text
docs/getting-started.md
docs/deployment-operations.md
docs/configuration-reference.md
docs/architecture.md
docs/curation-decision-reference.md
docs/environment-profiles.md
docs/product-reference.md
docs/opencti-coverage-matrix.md
docs/analyst-review-api.md
docs/container-images.md
docs/opencti-compatibility.md
docs/security-quality-gates.md
docs/community-standards.md
docs/documentation-map.md
docs/architecture-v0.9.md
docs/graph-promotion-v0.8.md
docs/opencti-coverage-matrix-v0.8.md
docs/repository-structure.md
docs/development-guide.md
docs/community-issue-triage.md
docs/release-v1.0.1.md
docs/release-v0.9.0.md
docs/release-v0.8.0.md
docs/release-v1.0.0.md
docs/release-process.md
```

Development evidence and lab validation notes are retained only where they help
maintainers reproduce supported behavior. Release source archives are curated
through `.gitattributes` so operators receive product-focused documentation.

## Contributing

NarrowCTI is open to community contributions. Start with:

```text
CONTRIBUTING.md
docs/development-guide.md
docs/community-issue-triage.md
CODE_OF_CONDUCT.md
SUPPORT.md
SECURITY.md
docs/community-governance.md
```

Issues and pull requests should avoid secrets, `.env` files, local `state/`
artifacts, raw customer data and private feed payloads.

## About NarrowCTI

<p align="center">
  <img src="docs/assets/cybersysbr-logo.png" alt="CybersysBR logo" width="140">
</p>

NarrowCTI is a product designed and developed by **CybersysBR**, the
cybersecurity identity used by Fagner Mendes Leite de Oliveira. CybersysBR is
the authorship identity associated with the project; NarrowCTI Community
Edition remains distributed under the Apache-2.0 license.

## Security Notes

- Never commit real `.env` files or API tokens.
- Do not commit local machine paths, usernames or lab-specific secrets.
- Preserve `state/state.json` unless reprocessing old pulses is intentional.
- Avoid destructive Docker cleanup commands against persistent OpenCTI or MISP
  volumes unless backups are confirmed.
- Report vulnerabilities privately when possible. See `SECURITY.md`.

## License

NarrowCTI core is open source under Apache-2.0. See:

```text
LICENSE
THIRD_PARTY_NOTICES.md
```
