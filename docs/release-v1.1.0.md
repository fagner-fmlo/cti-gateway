# NarrowCTI v1.1.0 Release Notes

## Status

Status: released.

NarrowCTI v1.1.0 was promoted through the protected `dev -> main` flow,
validated, tagged immutably and published as a GitHub Release on 2026-09-06.

## Release Theme

v1.1.0 adds evidence-driven detection relationships to the OpenCTI graph while
preserving analyst visibility when a rule cannot be mapped to ATT&CK. It also
includes the reviewed dependency maintenance batch already integrated into
`dev`.

## Highlights

- Create deterministic `Indicator --detects--> Attack-Pattern` candidates for
  MISP Sigma/YARA rules only when an explicit ATT&CK tag, reference or other
  trusted mapping is present.
- Keep audit, dry-run, export and idempotency controls authoritative for graph
  relationship promotion.
- Preserve detection-rule report context when no ATT&CK relationship can be
  resolved; absence of a mapping is reported as a coverage boundary, not a
  reason to discard the rule.
- Carry the reviewed Dependabot maintenance updates for the OpenCTI client,
  msgpack, Ruff and container build/SBOM actions.

## Evidence Boundary

The gateway does not relate a rule to every technique that merely co-occurs in
the same event. A relationship is eligible only when the source contains an
explicit, deterministic mapping. This keeps the graph explainable and avoids
manufacturing defensive coverage.

## Upgrade Guidance

The release does not require an environment-variable migration or state reset.
Existing graph objects are not rewritten automatically. Operators should keep
stable deployments pinned to the immutable release image after publication:

```text
NARROWCTI_GATEWAY_IMAGE=ghcr.io/narrowcti/narrowcti-gateway:1.1.0
```

The moving `latest` line points to the same approved image digest for the
published `main` build; production deployments should remain pinned to `1.1.0`.

## Validation Record

- Dependabot batch PR #65 was reviewed and integrated into `dev`.
- The existing local validation evidence for the integrated code passed 544
  unit tests, Ruff, Bandit and strict dependency audits.
- [CI run 34049175951](https://github.com/NarrowCTI/narrowcti/actions/runs/34049175951)
  passed on the final `main` promotion commit.
- [Security and Quality run 34049175956](https://github.com/NarrowCTI/narrowcti/actions/runs/34049175956)
  passed on the final `main` promotion commit.
- [DAST run 34049175962](https://github.com/NarrowCTI/narrowcti/actions/runs/34049175962)
  passed on the final `main` promotion commit.
- [Container Image run 34049176023](https://github.com/NarrowCTI/narrowcti/actions/runs/34049176023)
  built, scanned, generated the SBOM and published the approved image after
  release-environment approval. That pre-tag main build resolved to
  `sha256:3635d053b4d6b76d724ea055723d9325bab7ebe8d404d0af273aba8d1012b200`.
- [Versioned Container Image run 34049999281](https://github.com/NarrowCTI/narrowcti/actions/runs/34049999281)
  rebuilt the exact tagged commit, passed the same gates and published
  `1.1.0`, `1.1`, `1`, `latest` and `sha-ce2be22` to
  `sha256:479884b893475f1e1229dc2d5737846f1ed4356f8a6fa571676475c40b9c645d`.
- The versioned image artifact and CycloneDX SBOM were integrity-checked by
  the workflow (artifact IDs `9994257846` and `9994255245`). The SBOM is also
  attached to the [GitHub Release](https://github.com/NarrowCTI/narrowcti/releases/tag/v1.1.0).

## Traceability

- Source branch: `release/v1.1.0`, created from `dev`.
- Detection relationship feature: commit `2bc86be` / PR #62.
- Unmapped-rule context fix: commit `2a76e97` / PR #63.
- Dependency maintenance batch: commit `16ed640` / PR #65.
- Promotion PR to `dev`: [#67](https://github.com/NarrowCTI/narrowcti/pull/67).
- Promotion PR to `main`: [#68](https://github.com/NarrowCTI/narrowcti/pull/68).
- Git tag: `v1.1.0`.
- Release commit: `ce2be227391d6df1dd6c5c45b238cf43a8301ed5`.
- GitHub Release: [NarrowCTI v1.1.0](https://github.com/NarrowCTI/narrowcti/releases/tag/v1.1.0).
- Canonical image: `ghcr.io/narrowcti/narrowcti-gateway:1.1.0`.

The intended release path remains:

```text
release/v1.1.0 -> dev -> main -> v1.1.0 tag -> GitHub Release
```

## Known Boundaries

- Detection rules without an explicit ATT&CK mapping remain visible but are
  not assigned a fabricated `detects` relationship.
- This release does not add a Mitre D3FEND connector.
- Historical OpenCTI objects are not backfilled automatically; reprocessing is
  required when an existing object should receive the new relationship.

## License

NarrowCTI Community Edition remains distributed under the Apache License 2.0.
