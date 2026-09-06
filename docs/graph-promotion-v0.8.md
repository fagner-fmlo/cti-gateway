# Graph Promotion - v0.8.0

## Purpose

This document defines the v0.8 graph promotion direction.

v0.7 proved that NarrowCTI can extract source metadata, normalize graph
evidence, build graph candidates, apply graph policy and preview STIX graph
objects without importing them into OpenCTI. v0.8 starts the controlled path
from preview to promotion.

## Product Rule

OpenCTI remains the protected intelligence graph. NarrowCTI must not create
graph entities or relationships until the candidate passes:

- Source metadata validation.
- Graph candidate policy.
- TLP and sharing controls.
- Local graph deduplication.
- OpenCTI graph lookup.
- Canonical MITRE lookup when ATT&CK evidence is present.
- Operator-visible audit evidence.

## Promotion Pipeline

```text
source metadata
  -> graph evidence
  -> graph candidates
  -> graph candidate policy
  -> local graph deduplication
  -> OpenCTI graph lookup
  -> graph export dry-run evidence
  -> OpenCTI lab import validation
  -> controlled graph promotion
  -> post-export local graph state marking
```

## v0.8 First Cut

The first v0.8 implementation started as read-only:

- `core/opencti_graph_lookup.py` provides an OpenCTI graph lookup adapter.
- ATT&CK attack-pattern candidates can be looked up by `x_mitre_id`.
- ATT&CK attack-pattern candidates can fall back to STIX `standard_id` lookup.
- The lookup implements the same `known_keys_for_plan` interface already used
  by local graph deduplication.
- Lookup errors fail open and are logged, preserving the current audit/dry-run
  behavior.
- `NARROWCTI_OPENCTI_GRAPH_LOOKUP=false` keeps the runtime read-only lookup
  disabled by default. When set to `true`, OTX and MISP planning combine local
  graph deduplication state with OpenCTI canonical graph lookup.
- Lookup matches are retained as bounded audit evidence in
  `graph_export_plan_lookup_matches` so analysts can inspect which canonical
  OpenCTI object was matched before future promotion logic creates anything.

This lets NarrowCTI mark a candidate such as `T1059` as already known by
OpenCTI before graph promotion tries to create anything.

## Controlled Export Gate

v0.8 now includes the first guarded graph promotion path. The default remains
safe:

- `NARROWCTI_GRAPH_EXPORT_MODE=audit`: records policy and graph evidence only.
- `NARROWCTI_GRAPH_EXPORT_MODE=dry-run`: records what would be created.
- `NARROWCTI_GRAPH_EXPORT_MODE=export`: imports the curated STIX bundle after
  source policy, graph candidate policy and graph deduplication planning pass.

In export mode, OTX and MISP use the same `graph_candidate_policy` and
`graph_export_plan` recorded in the decision audit. The exporter sends the
legacy `Report + Indicators` objects and appends accepted graph entities and
relationships to the same bundle. Local graph deduplication state is marked
only after the OpenCTI import call succeeds.

### Explicit detection-rule relationships

MISP detection rules are promoted as semantic relationships only when the rule
contains an explicit ATT&CK reference. For Sigma, NarrowCTI reads ATT&CK ids
(including the `/T1234/001/` URL form) from the rule's `tags` or `references`
fields and from MISP event, object or attribute tags. Each confirmed mapping
produces:

`Indicator (Sigma/YARA/etc.) --detects--> Attack-Pattern`

The relationship carries the source field, the exact ATT&CK id and the
`explicit-detection-rule-attack-reference` inference marker. A rule without an
explicit id remains an indicator (or note when incompatible) and is never
linked merely because it occurs in the same event as an ATT&CK object. Multiple
ids create multiple idempotent relationship candidates for the same rule.

The existing graph gate controls the lifecycle: `audit` records the candidate,
`dry-run` reports the would-create relationship, and `export` sends it to
OpenCTI. The report generator consumes the persisted `detects` relationship;
it does not infer or create this link itself.

MISP also has an explicit graph-only replay gate for curation improvements.
When `NARROWCTI_GRAPH_REPLAY_ON_ARTIFACT_DEDUP=true` or
`MISP_GRAPH_REPLAY_ON_ARTIFACT_DEDUP=true`, and
`NARROWCTI_GRAPH_EXPORT_MODE=export`, a MISP event skipped by artifact
deduplication because every indicator is already known can still export its
accepted graph context. The replay sends an empty indicator list, records the
decision reason as `all indicators already known; graph replay only`, and
preserves the same graph policy, lookup and local graph deduplication gates.
This is intended for bounded lab replay when mappings improve and existing
reports need missing semantic relationships, not for broad production
backfills.

Known graph keys returned by local state or OpenCTI lookup are not re-created
by the export gate. This protects canonical objects loaded by official
connectors, especially MITRE ATT&CK attack-patterns and existing Arsenal
objects. When OpenCTI lookup returns a valid canonical STIX `standard_id`, the
curated STIX bundle references that existing object and can create report links
or semantic relationships to it instead of creating a duplicate object.

The same guarded lookup now covers Vulnerability objects by CVE id. A candidate
such as `CVE-2019-13939` is looked up by canonical STIX id when present and then
by OpenCTI Vulnerability `name`. When a match is found, the export bundle
references the existing Vulnerability instead of creating a duplicate CVE
object.

Threat Actor and Intrusion Set lookup is enabled with the same conservative
posture. NarrowCTI prefers canonical `standard_id`, then exact OpenCTI name, and
can use exact OpenCTI alias matches when the canonical object exposes aliases.
This lets source evidence such as `Palmerworm` reference existing Intrusion Set
`BlackTech` without creating a second actor object.

Location lookup is enabled for country and location-style graph candidates.
NarrowCTI prefers canonical `standard_id`, then exact OpenCTI location name.
When a match is found, the export bundle references the existing OpenCTI
`Country`, `Region`, `Administrative-Area`, `City` or other `Location`
specialization returned by OpenCTI instead of creating a second location
object. Region, city and position normalization still require source-specific
metadata validation before broad export.

Promoted graph SDOs created by NarrowCTI use deterministic STIX ids derived
from object type, identity class and normalized value/name. This gives OpenCTI
the same `standard_id` across repeated exports and reduces duplicate graph
entities even before a live OpenCTI lookup match is available.

Infrastructure promotion is enabled as a controlled STIX `infrastructure`
mapping. This is not the same as promoting every domain, URL or IP observable
as infrastructure. A source must provide explicit infrastructure evidence or a
curated candidate must be released by policy before NarrowCTI populates
`Observations / Infrastructures`. Lookup prefers canonical `standard_id`, then
exact OpenCTI name, with alias search available only when OpenCTI returns exact
aliases.

## Source Identity And Author Hygiene

OpenCTI Author should represent the logical upstream intelligence source and
make the NarrowCTI curation path explicit. The product naming convention for
new exported bundles is:

```text
<logical upstream source> via NarrowCTI
```

This gives analysts both signals at once: which feed/collector supplied the
intelligence and that NarrowCTI curated the payload before OpenCTI ingestion.
In v0.8, OTX and MISP exports use these source-aware STIX identities:

| Source key | OpenCTI Author / STIX Identity |
| --- | --- |
| `alienvault:otx` | `OTX AlienVault via NarrowCTI` |
| `alienvault:otx-premium` | `OTX AlienVault Premium via NarrowCTI` |
| `misp:misp` | `MISP via NarrowCTI` |
| Future source adapters | `<Source display name> via NarrowCTI` |

NarrowCTI remains the curation layer. Its decisions stay visible through the
decision audit, graph export plan, curation reports and `x_narrowcti_*` custom
properties on promoted graph objects. Source identities use deterministic STIX
IDs so repeated exports reuse the same author identity instead of creating
duplicate author objects in OpenCTI.

This mapping is applied to new exported STIX bundles. It is not a historical
rewrite mechanism: when OpenCTI already has a Report, Indicator or graph object,
the import path should preserve the existing object and its original author
instead of changing provenance retroactively.

## OpenCTI Tab Mapping

The first controlled export can populate these OpenCTI areas when the source
metadata supports them and the candidate passes policy:

| OpenCTI area | Current NarrowCTI mapping | Notes |
| --- | --- | --- |
| Observations / Indicators | IOC indicators and detection-rule candidates as STIX `indicator` objects | IOC behavior remains active in every mode. Detection rules stay as native Indicators but use canonical names, labels, source references and descriptions for analyst discoverability. |
| Observations / Observables | Domain, URL, IPv4, IPv6, email and file-hash observables from graph candidates | Artifact-specific promotion is still pending. |
| Threats / Campaigns | STIX `campaign` | Created from MISP Galaxy Campaign evidence, explicit MISP campaign/operation Attribute or Object evidence, or explicit OTX campaign/operation fields. Report titles and feed names are not treated as campaigns. |
| Threats / Threat actors | STIX `threat-actor` for group actors; native OpenCTI `ThreatActorIndividual` for individual actors | Created only from explicit supported metadata such as OTX adversary or MISP galaxy evidence. Individual actors use native GraphQL export so they materialize in the correct OpenCTI tab. |
| Threats / Intrusion sets | STIX `intrusion-set` | Depends on source metadata or galaxy mapping. |
| Arsenal / Malware | STIX `malware` | Useful for malware families and actor arsenal enrichment. |
| Arsenal / Channels | OpenCTI custom SDO `channel` | Created only from explicit source-backed channel fields, including MISP Galaxy meta such as `c2-channel`, `communication-channel`, `delivery-channel` or `marketplace`, and explicit OTX fields such as `c2_channels`, `communication_channels`, `delivery_channels` or `marketplaces`. |
| Arsenal / Tools | STIX `tool` | Depends on source metadata or galaxy mapping. |
| Arsenal / Vulnerabilities | STIX `vulnerability` with CVE external references when available | CVE evidence can come from MISP attributes, tags or OTX indicators. |
| Observations / Infrastructures | STIX `infrastructure` | Requires explicit infrastructure evidence; raw indicators alone are not automatically promoted as infrastructure. |
| Techniques / Attack patterns | STIX `attack-pattern` with MITRE external id when available | Canonical MITRE lookup should be enabled before broad export. |
| Techniques / Narratives | OpenCTI custom SDO `narrative`; STIX `note` for supported report text | First-class Narrative promotion is limited to explicit objective, motivation, theme, goal or intent fields from MISP metadata or OTX pulse fields. Free-form report text remains a Report/Note. |
| Entities / Sectors | STIX `identity` with `identity_class=class` for `target_sector` | This is the mapping expected to feed OpenCTI Sectors. |
| Entities / Events | OpenCTI custom SDO `event` | Created only from explicit event-level fields such as `incident-name`, `observed-event`, `incident_name` or `event_name`; MISP EventReports remain Reports/Notes by default. |
| Entities / Security platforms | Native OpenCTI `SecurityPlatform` export plus report linking | Created from explicit security platform, SIEM, EDR, NDR, XDR, scanner or sensor fields in MISP or OTX; not exported as Organization. |
| Entities / Systems | STIX `identity` with `identity_class=system` for `target_system` | Created from explicit affected system, platform, operating-system or target asset fields in MISP or OTX. |
| Entities / Individuals | STIX `identity` with `identity_class=individual` for `target_individual` | Created only from explicit victimology/person fields such as `targeted-person` or `victim-individual`; threat-actor individuals remain separate Threat objects. |
| Locations / Countries and deeper geography | STIX `location` with country, region, administrative area, city, latitude, longitude and precision when source-backed | Country export is validated. Region, administrative-area, city and coordinate support is implemented for MISP Galaxy meta and explicit OTX victimology fields, but still needs real OpenCTI UI validation with source payloads carrying those fields. |

OpenCTI tabs not listed above are not guaranteed by this version. They remain
part of the graph enrichment backlog and require broader source metadata
validation before NarrowCTI should promote them automatically.

For analyst usability, promoted objects should not be empty shells when
NarrowCTI has source provenance. If the source provides an explicit
description, summary or details field, that text is preserved. If it does not,
NarrowCTI can generate a conservative provenance description such as
`Source-backed channel observed by MISP via NarrowCTI at Galaxy.meta.channel:
Telegram C2.` This description is intentionally audit-focused: it explains why
the object exists without claiming context the source did not provide.

Timeline evidence follows the same conservative model. When a graph candidate
carries source-backed timestamps, NarrowCTI preserves them as `x_narrowcti_*`
custom properties on promoted objects and semantic relationships, including
`x_narrowcti_source_created`, `x_narrowcti_source_modified`,
`x_narrowcti_source_timestamp`, `x_narrowcti_source_date`,
`x_narrowcti_first_seen`, `x_narrowcti_last_seen`, `x_narrowcti_valid_from` and
`x_narrowcti_valid_until`. This keeps temporal provenance available for
OpenCTI inspection, reporting and future Timeline validation without forcing
native STIX lifecycle fields where object-type support has not been validated.

## Runtime Configuration

`NARROWCTI_OPENCTI_GRAPH_LOOKUP` controls the v0.8 OpenCTI graph lookup gate.

- `false`: default. NarrowCTI only uses local graph deduplication state when
  `NARROWCTI_GRAPH_DEDUP_STATE_FILE` is configured.
- `true`: NarrowCTI queries OpenCTI during graph export planning and treats
  canonical matches, such as existing ATT&CK attack-patterns, malware, tools,
  infrastructure, CVE vulnerabilities, threat actors, intrusion sets and
  locations/countries, as known graph entities before promotion logic creates
  new objects.

The lookup itself is read-only. In `audit` and `dry-run` modes it does not
create entities, relationships or state marks in OpenCTI. In `export` mode,
matches with valid `standard_id` values can be referenced by the curated STIX
bundle.

`NARROWCTI_GRAPH_REPLAY_ON_ARTIFACT_DEDUP` defaults to `false`. It currently
applies to MISP. Enable it only with `NARROWCTI_GRAPH_EXPORT_MODE=export`,
OpenCTI lookup and bounded `MISP_QUERIES=event:<id>` style validation when the
operator intentionally wants graph context replay without indicator replay.

For Arsenal objects, lookup is intentionally conservative. Exact
`standard_id` wins, exact name remains the default, and curated alias groups can
resolve known equivalences such as `LummaC2` to an existing canonical
`Lumma Stealer` object when the canonical object is present in OpenCTI. This is
not broad fuzzy matching: if no explicit alias evidence or curated alias group
exists, NarrowCTI does not guess.

For Vulnerability objects, lookup is intentionally CVE-id based. Exact
`standard_id` matches are preferred, and `CVE-*` values are then matched against
OpenCTI Vulnerability names. Broad vendor advisory aliases are outside the
current v0.8 safety boundary.

For Threat Actor and Intrusion Set objects, lookup is intentionally limited to
`standard_id`, exact name and exact alias matching returned by OpenCTI search.
This supports canonical actor naming without broad fuzzy matching.

Threat Actor lookup is split by OpenCTI UI taxonomy. Normal `threat_actor`
candidates are treated as group-style actors and use `threatActorsGroup`.
Explicit `threat_actor_individual` evidence uses `threatActorsIndividuals` and
native `threatActorIndividualAdd(update=true)` export. NarrowCTI deliberately
keeps these candidates out of the generic STIX `threat-actor` bundle path so an
individual actor does not become a group-style actor in OpenCTI.

For Infrastructure objects, lookup is intentionally limited to `standard_id`,
exact name and exact alias matching returned by OpenCTI search. NarrowCTI does
not infer Infrastructure from every observable because that would pollute the
OpenCTI graph with low-context network artifacts.

ASN/IP infrastructure correlation is tracked separately in
`docs/infrastructure-correlation-v0.8.md`. Local validation confirmed that
OpenCTI can ingest `Autonomous-System` as a cyber observable and can represent
`Infrastructure -> consists-of -> ASN/IP/CIDR` plus
`IP/CIDR -> belongs-to -> ASN` relationships. Native NarrowCTI export now
supports `autonomous-system` graph candidates and exact OpenCTI lookup for
supported `stixCyberObservable` values. The lookup uses `name` for ASN objects
in this lab and `value` for generic observables such as IPv4, IPv6, domain,
URL and email values. Broad source activation still requires source-backed
provenance, source-specific ASN/netblock payload validation and relationship
policy controls.

For Location objects, lookup is intentionally limited to `standard_id` and
exact OpenCTI name. This is enough to protect controlled country export, such
as `Argentina`, without guessing ambiguous geography from weak source text.

For target identity objects, lookup is intentionally scoped to victimology.
Target Organizations use `organizations`, target Sectors use `sectors`, target
Systems use `systems` and target Individuals use `individuals`.
Source identities, collectors, feed authors and provenance identities do not use
the Organization lookup path and remain outside automatic graph promotion.

For Technique context objects, lookup is intentionally exact. Courses of Action
use `coursesOfAction`, Data Components use `dataComponents` and Data Sources
use `dataSources`. NarrowCTI matches `standard_id` first and exact `name`
second. Local OpenCTI 6.9.4 materializes MITRE custom exports with canonical
`data-component--` and `data-source--` ids, so export planning accepts those
canonical references for NarrowCTI `x-mitre-data-component` and
`x-mitre-data-source` candidates.

When matches exist, decision metadata can include
`graph_export_plan_lookup_matches` with the NarrowCTI candidate key, candidate
type, candidate value and canonical OpenCTI match fields such as `opencti_id`,
`standard_id`, `entity_type`, `name`, `observable_value`, `x_mitre_id`,
`match_type` and `match_value`. The decision audit report also aggregates these
matches in the `graph_export` summary with counters by candidate object type,
canonical match type and canonical entity type.

## Canonical MITRE Linking

The intended MITRE behavior is:

```text
Official MITRE connector
  -> loads canonical ATT&CK attack-patterns into OpenCTI

NarrowCTI
  -> finds T1059 in OTX/MISP/source metadata
  -> resolves technique context locally
  -> checks OpenCTI for canonical T1059
  -> references the canonical STIX id in the curated bundle
  -> creates curated report links or semantic relationships to the existing
     object when source relationship provenance supports it
```

v0.8 must prefer linking to existing canonical ATT&CK objects over creating new
attack-pattern objects. If the canonical object is missing, the candidate can
still be held by policy, remain in dry-run, or be created only when the operator
explicitly allows that object type and the source evidence is strong enough.

## Current Non-Goals

The current v0.8 cut still does not:

- Query every possible STIX object type.
- Replace local graph deduplication.
- Guarantee population of every OpenCTI tab without source metadata support.

## Expansion Path

After ATT&CK, malware, tool and Technique-context lookup are validated, the
same pattern should expand to:

- Malware and tool lookup beyond exact `standard_id` or name, including aliases
  and source references.
- External-reference based threat actor and intrusion set lookup beyond exact
  name or alias.
- Sector and location lookup with controlled vocabulary normalization.
- ASN/IP/CIDR infrastructure correlation through `stixCyberObservables`, with
  exact lookup and source-backed relationship provenance.
- Relationship lookup before edge creation.
- Post-export graph state marking only after OpenCTI import succeeds.

`core.graph_deduplication.GraphDeduplicationIndex.mark_exported_plan` is the
safe post-export marking path for future promotion work. It only persists
actions marked as `exported`, so dry-run `would_create` plans remain evidence
and do not become exported graph knowledge.

## Validation

Validation must cover:

- Unit tests for lookup query construction and fail-open behavior.
- Dry-run graph export plans with OpenCTI-known entity keys.
- Lab comparison against OpenCTI with the official MITRE connector enabled.
- Evidence that duplicate ATT&CK attack-pattern objects are not created.
- Evidence that future curated relationships point to canonical OpenCTI objects.
