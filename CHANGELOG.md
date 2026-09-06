# Changelog

All notable NarrowCTI Community Edition changes are summarized here.

Detailed operator-facing release notes remain in `docs/release-v*.md`.

## Unreleased

- Add deterministic `Indicator --detects--> Attack-Pattern` graph candidates
  for MISP Sigma/YARA rules with explicit ATT&CK tags or references. The
  existing audit, dry-run and export gates remain authoritative, and rules
  without explicit mappings are not linked by co-occurrence.

## v1.0.1 - 2026-08-15

Timestamp provenance patch for MISP-to-OpenCTI ingestion.

- Preserve the source MISP `event.date` as the STIX report publication date and
  as an explicit `x_narrowcti_source_date` property.
- Use the source event date for indicator `valid_from` when available, while
  retaining the OpenCTI registration timestamp as the technical creation time.
- Expose source activity dates as native STIX relationship start times so
  reports can distinguish functional evidence from OpenCTI ingestion time.
- Keep compatibility with custom exporters that predate the optional
  `published_at` argument.

## v1.0.0 - 2026-07-12

Production-ready Community Edition release for the existing OTX and MISP
gateway paths. The release is published under Apache License 2.0 with the
validated image and GitHub Release created from the final `main` commit.

- Added contextual scoring with explicit `off`, `shadow` and `enforce` modes,
  visible configuration, preflight posture and decision audit evidence.
- Harden graph quality for Diamond, infrastructure victimology, Timeline and
  Kill Chain without promoting source-weak inference.
- Propagate explicit same-event Campaign context to one unambiguous actor,
  infrastructure, capability and victimology relationships, with named
  inference evidence and title-only inference prohibited.
- Consolidate product, OpenCTI coverage, API, configuration and release-status
  documentation.
- Harden runtime recovery, retries, checkpoints, resource controls and health
  reporting, with reproducible validation evidence.
- Validate clean installation, upgrade compatibility, backup/restore and the
  security and software-supply-chain release gates.
- Keep Community reporting concise and audit-ready. Advanced executive report
  packs remain outside the v1.0 Community scope.
- Keep additional source adapters outside the current v1.0 release scope.

See `docs/release-v1.0.0.md`.

## v0.9.0 - 2026-07-11

Analyst operations and graph-quality release. Tag `v0.9.0` points to release
commit `abe19e599ffec4c03755b96e7ae70ff1ada2b228`. Integration merge commit
`ab2f73a8cee7b94bac96c488c6aa837c94141d3f` records the traceability message
`NarrowCTI v0.9.0 - release anterior ao início do vínculo empregatício`.
NarrowCTI Community Edition is distributed under Apache License 2.0.

All required GitHub Actions workflows passed for the release commit, including
CI, code quality, security and dependency review, container image validation,
DAST and Graph Update.

- Formalizes the governed analyst review API, graph-quality hardening and the
  governed source-onboarding boundary. Post-release planning moved new direct
  adapters to v1.1 so v1.0 can focus on production hardening.
- Keeps Community reporting operational and concise while reserving advanced
  enterprise reporting for a future separately scoped capability.
- Makes SAST, applicable DAST, code quality, dependency review and container
  image scanning mandatory release gates.
- Pins `pycti 7.260710.0` and adds a centralized, fail-closed compatibility
  boundary for live-validated OpenCTI `6.9.x` ingestion.
- Adds an authenticated, role-governed analyst review API and isolated Compose
  profile with real export disabled by default.
- Adds a blocking, disposable OWASP ZAP OpenAPI DAST workflow for the review
  API.
- Separates OpenCTI entity reuse from directed relationship deduplication and
  requires an exact existing edge and relationship type before suppressing a
  graph relationship export.

See `docs/release-v0.9.0.md`.

## v0.8.0

Graph promotion, analyst review and product operations release.

- Adds read-only OpenCTI graph lookup for canonical object reuse before graph
  promotion.
- Adds controlled graph promotion readiness for ATT&CK, locations,
  infrastructure, autonomous systems and supported observables.
- Adds source-backed graph hygiene for OTX and MISP so enrichment can promote
  entities and relationships only when provenance supports them.
- Adds analyst review, curation reporting, support diagnostics and deployment
  operations documentation.
- Adds OpenCTI coverage matrix and rules-engine alignment for pre-ingestion
  curation versus post-ingestion inference.

See `docs/release-v0.8.0.md`.

## v0.7.0

Graph enrichment and enterprise-filter foundation.

- Adds graph evidence and graph candidate models.
- Adds audit-first graph planning for actors, intrusion sets, malware, tools,
  vulnerabilities, sectors, locations, techniques, infrastructure and
  relationships.
- Adds MITRE ATT&CK curation architecture: the official MITRE connector remains
  the canonical ATT&CK loader, while NarrowCTI uses ATT&CK as enrichment
  context for source-backed intelligence.
- Adds source metadata validation and official connector mapping references for
  MISP and OTX compatibility.
- Adds contextual scoring, source onboarding and ingestion mode documentation.

See `docs/release-v0.7.0.md`.

## v0.6.0

Quarantine and enrichment foundation.

- Adds reviewable quarantine storage and CLI workflows.
- Adds release, reject, partial-release and replay audit evidence.
- Adds OTX entity extraction and local MITRE ATT&CK cache resolution.
- Adds preflight and reporting coverage for quarantine, release audit and MITRE
  resolver posture.

See `docs/release-v0.6.0.md`.

## v0.5.0

Unified gateway runtime and decision engine release.

- Adds the `gateway.connector` runtime and source registry.
- Adds the `NARROWCTI_*` configuration namespace.
- Adds source failure isolation, aggregate run summaries and operational
  reporting.
- Adds gateway image support through `Dockerfile.gateway`.
- Adds local artifact correlation and optional OpenCTI indicator lookup
  posture.

See `docs/release-v0.5.0.md`.

## v0.4.0

Multi-feed expansion release.

- Adds the MISP adapter foundation alongside the OTX reference adapter.
- Adds MISP guardrails for event volume, attribute count, exported IoCs, date
  filters, tag filters and published-only imports.
- Adds dry-run and run-once execution for controlled MISP validation.
- Preserves collector and original-source provenance when available.

See `docs/release-v0.4.0.md`.
