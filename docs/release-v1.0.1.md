# NarrowCTI v1.0.1 Release Notes

## Status

Status: released.

NarrowCTI v1.0.1 is a backward-compatible patch release focused on preserving
source chronology when MISP intelligence is exported to OpenCTI.

## Summary

The MISP event date is now carried through the gateway as source evidence
instead of being represented only by the time at which OpenCTI received the
object. This keeps publication, activity and ingestion timelines distinct for
analyst review and reporting.

## Highlights

- Preserve a valid MISP `event.date` as the STIX Report `published` timestamp.
- Record the source value as `x_narrowcti_source_date` for explicit provenance.
- Use the source date for indicator `valid_from` when available.
- Use source activity dates for native STIX relationship `start_time` values.
- Fall back to MISP `event.created`, then the existing connector-time behavior,
  when the source date is absent or invalid.
- Keep compatibility with custom exporters that predate the optional
  `published_at` argument.

The patch does not change scoring, filtering, deduplication, quarantine policy,
source authentication or the OpenCTI export contract beyond the timestamp
provenance fields described above.

## Upgrade Guidance

Pin stable deployments to the immutable release image:

```text
NARROWCTI_GATEWAY_IMAGE=ghcr.io/narrowcti/narrowcti-gateway:1.0.1
```

No environment-variable migration or state reset is required. Existing
OpenCTI objects are not rewritten; the corrected source chronology applies to
new or reprocessed MISP exports. Operators that intentionally follow the
moving stable line may continue using `latest`, while production deployments
should remain pinned to `1.0.1`.

## Validation Evidence

The release candidate passed the repository's required checks before
publication:

- Full local test validation passed with 541 tests, and Ruff completed without
  findings.
- [CI run 31917415692](https://github.com/NarrowCTI/narrowcti/actions/runs/31917415692)
  passed.
- [Security and Quality run 31917415583](https://github.com/NarrowCTI/narrowcti/actions/runs/31917415583)
  passed.
- [CodeQL run 31917415313](https://github.com/NarrowCTI/narrowcti/actions/runs/31917415313)
  passed.
- [DAST run 31917415567](https://github.com/NarrowCTI/narrowcti/actions/runs/31917415567)
  passed.
- [Container Image run 31917415564](https://github.com/NarrowCTI/narrowcti/actions/runs/31917415564)
  passed on `main`.
- [Tag publication run 31917659437](https://github.com/NarrowCTI/narrowcti/actions/runs/31917659437)
  completed the build, scan, SBOM and protected registry publication.

## Traceability

- Pull request: [#41](https://github.com/NarrowCTI/narrowcti/pull/41)
- Release commit: `7e67abade90152eb9c69345d37d87cca7f490a3f`
- Git tag: `v1.0.1`
- Canonical image: `ghcr.io/narrowcti/narrowcti-gateway:1.0.1`
- Version aliases: `1.0`, `1`, and the moving `latest` line where applicable

The release follows the controlled project path:

```text
feature/fix -> dev -> main -> version tag -> GitHub Release
```

## Known Boundaries

- Historical STIX objects are not backfilled automatically; reprocessing is
  required when an older MISP event needs corrected chronology.
- Source dates remain source evidence. The gateway does not infer a date that
  is not present in the MISP event.
- No new direct source adapter is introduced in this patch release.

## License

NarrowCTI Community Edition remains distributed under the Apache License 2.0.
