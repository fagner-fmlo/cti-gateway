import json

from core.graph_export_plan import normalize_graph_export_mode
from core.opencti_graph_lookup import filter_eq, first_node
from exporters.stix_builder import (
    build_curated_report_bundle,
    build_report_bundle,
    detection_rule_indicator_compatible,
    detection_rule_labels,
    detection_rule_indicator_name,
    graph_accepted_candidates,
    graph_candidate_description,
    graph_description_hydration_requests,
)


DESCRIPTION_READ_QUERY = """
query ReadObjectDescription($id: String!) {
  stixDomainObject(id: $id) {
    id
    standard_id
    entity_type
    createdBy { ... on Identity { name } }
    ... on Sector { name description }
    ... on ThreatActorGroup { name description }
    ... on ThreatActorIndividual { name description }
    ... on IntrusionSet { name description }
    ... on Campaign { name description }
    ... on Malware { name description }
    ... on Tool { name description }
    ... on Vulnerability { name description }
    ... on AttackPattern { name description }
    ... on CourseOfAction { name description }
    ... on Indicator { name description }
    ... on Infrastructure { name description }
    ... on Organization { name description }
    ... on Individual { name description }
    ... on System { name description }
    ... on SecurityPlatform { name description }
    ... on Region { name description }
    ... on Country { name description }
    ... on AdministrativeArea { name description }
    ... on City { name description }
    ... on Position { name description }
  }
}
"""


DESCRIPTION_PATCH_MUTATION = """
mutation HydrateObjectDescription($id: ID!, $input: [EditInput]!) {
  stixDomainObjectEdit(id: $id) {
    fieldPatch(input: $input) {
      id
      standard_id
      entity_type
      ... on Sector { name description }
      ... on ThreatActorGroup { name description }
      ... on ThreatActorIndividual { name description }
      ... on IntrusionSet { name description }
      ... on Campaign { name description }
      ... on Malware { name description }
      ... on Tool { name description }
      ... on Vulnerability { name description }
      ... on AttackPattern { name description }
      ... on CourseOfAction { name description }
      ... on Indicator { name description }
      ... on Infrastructure { name description }
      ... on Organization { name description }
      ... on Individual { name description }
      ... on System { name description }
      ... on SecurityPlatform { name description }
      ... on Region { name description }
      ... on Country { name description }
      ... on AdministrativeArea { name description }
      ... on City { name description }
      ... on Position { name description }
    }
  }
}
"""


class OpenCTIImportRejectedError(RuntimeError):
    pass


class _PyCTIWorkerLoggerProxy:
    def __init__(self, delegate, errors):
        self.delegate = delegate
        self.errors = errors

    def error(self, *args, **kwargs):
        self.errors.append(args)
        return self.delegate.error(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self.delegate, name)


def capture_pycti_worker_errors(api_client):
    """Capture permanent worker errors swallowed by PyCTI's import retry loop."""
    errors = []
    stix2_client = getattr(api_client, "stix2", None)
    opencti_client = getattr(stix2_client, "opencti", None)
    logger_factory = getattr(opencti_client, "logger_class", None)
    if not callable(logger_factory):
        return errors, lambda: None

    def logger_factory_proxy(name):
        return _PyCTIWorkerLoggerProxy(logger_factory(name), errors)

    opencti_client.logger_class = logger_factory_proxy

    def restore():
        opencti_client.logger_class = logger_factory

    return errors, restore


SECURITY_PLATFORM_LOOKUP_QUERY = """
query NarrowCTISecurityPlatformExportLookup($filters: FilterGroup) {
  securityPlatforms(first: 1, filters: $filters) {
    edges {
      node {
        id
        standard_id
        entity_type
        name
        security_platform_type
      }
    }
  }
}
"""

SECURITY_PLATFORM_ADD_MUTATION = """
mutation NarrowCTISecurityPlatformAdd($input: SecurityPlatformAddInput!) {
  securityPlatformAdd(input: $input) {
    id
    standard_id
    entity_type
    name
    security_platform_type
  }
}
"""

THREAT_ACTOR_INDIVIDUAL_LOOKUP_QUERY = """
query NarrowCTIThreatActorIndividualExportLookup($filters: FilterGroup) {
  threatActorsIndividuals(first: 1, filters: $filters) {
    edges {
      node {
        id
        standard_id
        entity_type
        name
        aliases
        threat_actor_types
      }
    }
  }
}
"""

THREAT_ACTOR_INDIVIDUAL_ADD_MUTATION = """
mutation NarrowCTIThreatActorIndividualAdd(
  $input: ThreatActorIndividualAddInput!
) {
  threatActorIndividualAdd(input: $input) {
    id
    standard_id
    entity_type
    name
    aliases
    threat_actor_types
  }
}
"""

IDENTITY_LOOKUP_QUERY = """
query NarrowCTIIdentityLookup($filters: FilterGroup) {
  identities(first: 1, filters: $filters) {
    edges {
      node {
        id
        standard_id
        entity_type
        name
      }
    }
  }
}
"""

INDICATOR_LOOKUP_QUERY = """
query NarrowCTIIndicatorLookup($filters: FilterGroup) {
  indicators(first: 1, filters: $filters) {
    edges {
      node {
        id
        standard_id
        entity_type
        name
        pattern_type
      }
    }
  }
}
"""

INDICATOR_ADD_MUTATION = """
mutation NarrowCTIIndicatorAdd($input: IndicatorAddInput!) {
  indicatorAdd(input: $input) {
    id
    standard_id
    entity_type
    name
    pattern_type
  }
}
"""

LABEL_LOOKUP_QUERY = """
query NarrowCTILabelLookup($filters: FilterGroup) {
  labels(first: 1, filters: $filters) {
    edges {
      node {
        id
        standard_id
        entity_type
        value
        color
      }
    }
  }
}
"""

LABEL_ADD_MUTATION = """
mutation NarrowCTILabelAdd($input: LabelAddInput!) {
  labelAdd(input: $input) {
    id
    standard_id
    entity_type
    value
    color
  }
}
"""

REPORT_LOOKUP_QUERY = """
query NarrowCTIReportExportLookup($filters: FilterGroup) {
  reports(first: 1, filters: $filters) {
    edges {
      node {
        id
        standard_id
        entity_type
        name
      }
    }
  }
}
"""

REPORT_OBJECT_REF_ADD_MUTATION = """
mutation NarrowCTIReportObjectRefAdd(
  $id: ID!
  $input: StixRefRelationshipAddInput!
) {
  reportEdit(id: $id) {
    relationAdd(input: $input) {
      id
      entity_type
      relationship_type
    }
  }
}
"""


def send_bundle(
    api_client,
    name,
    description,
    score,
    indicators=None,
    identity_name="NarrowCTI Gateway",
    graph_candidate_policy=None,
    graph_export_mode="audit",
    published_at=None,
):
    export_enabled = normalize_graph_export_mode(graph_export_mode) == "export"
    if export_enabled:
        bundle, indicator_count, _ = build_curated_report_bundle(
            name,
            description,
            score,
            indicators,
            graph_candidate_policy=graph_candidate_policy,
            identity_name=identity_name,
            published_at=published_at,
        )
    else:
        bundle, indicator_count = build_report_bundle(
            name,
            description,
            score,
            indicators,
            identity_name=identity_name,
            published_at=published_at,
    )
    bundle_json = bundle.serialize()
    worker_errors, restore_worker_logger = capture_pycti_worker_errors(api_client)
    try:
        import_result = api_client.stix2.import_bundle_from_json(bundle_json, update=True)
    finally:
        restore_worker_logger()
    failed = (
        import_result[1]
        if isinstance(import_result, tuple) and len(import_result) > 1
        else []
    )
    if failed or worker_errors:
        rejection = import_rejection_message(failed)
        if worker_errors:
            rejection = (
                f"{rejection}; OpenCTI worker recorded "
                f"{len(worker_errors)} permanent import error(s): "
                f"{worker_errors[0]}"
            )
        raise OpenCTIImportRejectedError(rejection)
    if export_enabled:
        native_security_platforms = export_native_security_platforms(
            api_client,
            graph_candidate_policy,
        )
        native_threat_actor_individuals = export_native_threat_actor_individuals(
            api_client,
            graph_candidate_policy,
        )
        native_detection_rules = export_native_detection_rule_indicators(
            api_client,
            graph_candidate_policy,
            identity_name=identity_name,
            score=score,
        )
        link_native_objects_to_reports(
            api_client,
            bundle_json,
            [
                *native_security_platforms,
                *native_threat_actor_individuals,
                *native_detection_rules,
            ],
        )
        hydrate_existing_graph_descriptions(
            api_client,
            graph_description_hydration_requests(
                graph_candidate_policy,
                identity_name=identity_name,
            ),
        )
    return indicator_count


def import_rejection_message(failed):
    samples = []
    for failure in list(failed or [])[:3]:
        if isinstance(failure, dict):
            detail = (
                failure.get("error_message")
                or failure.get("message")
                or failure.get("error")
                or failure.get("name")
            )
            if not detail:
                detail = json.dumps(failure, sort_keys=True, default=str)
        else:
            detail = str(failure)
        samples.append(str(detail)[:300])
    suffix = f": {' | '.join(samples)}" if samples else ""
    return f"OpenCTI rejected {len(failed)} bundle object(s){suffix}"


def export_native_security_platforms(api_client, graph_candidate_policy):
    exported = []
    for candidate in native_security_platform_candidates(graph_candidate_policy):
        existing_id = candidate_existing_id(candidate)
        if existing_id:
            exported.append(
                {
                    "id": existing_id,
                    "standard_id": clean_string(
                        candidate_attributes(candidate).get("opencti_existing_ref")
                    ),
                    "entity_type": "SecurityPlatform",
                    "name": graph_candidate_name(candidate),
                }
            )
            continue
        name = graph_candidate_name(candidate)
        if not name:
            continue
        existing = find_security_platform(api_client, name)
        if existing:
            exported.append(existing)
            continue
        attributes = candidate_attributes(candidate)
        input_payload = {
            "name": name,
            "update": True,
        }
        description = clean_string(
            attributes.get("description")
            or graph_candidate_description(candidate, attributes)
        )
        platform_type = clean_string(
            attributes.get("security_platform_type")
            or attributes.get("platform_type")
            or attributes.get("type")
        )
        confidence = graph_candidate_confidence(candidate)
        if description:
            input_payload["description"] = description
        if platform_type:
            input_payload["security_platform_type"] = platform_type
        if confidence is not None:
            input_payload["confidence"] = confidence
        try:
            result = api_client.query(
                SECURITY_PLATFORM_ADD_MUTATION,
                {"input": input_payload},
            )
        except Exception:
            continue
        node = ((result.get("data") or {}).get("securityPlatformAdd")) or {}
        if node:
            exported.append(node)
    return exported


def export_native_detection_rule_indicators(
    api_client,
    graph_candidate_policy,
    identity_name="NarrowCTI Gateway",
    score=None,
):
    exported = []
    author = find_identity(api_client, identity_name)
    for candidate in native_detection_rule_indicator_candidates(graph_candidate_policy):
        attributes = candidate_attributes(candidate)
        name = detection_rule_indicator_name(graph_candidate_name(candidate), attributes)
        pattern = clean_multiline_string(attributes.get("pattern"))
        pattern_type = clean_string(
            attributes.get("pattern_type") or attributes.get("rule_type")
        ).lower()
        if not name or not pattern or not pattern_type:
            continue
        label_ids = resolve_label_ids(api_client, detection_rule_labels(attributes))
        existing_id = candidate_existing_id(candidate)
        if existing_id:
            exported.append(
                {
                    "id": existing_id,
                    "standard_id": clean_string(attributes.get("opencti_existing_ref")),
                    "entity_type": "Indicator",
                    "name": name,
                    "pattern_type": pattern_type,
                }
            )
            continue
        existing = find_indicator(api_client, name)
        if existing:
            exported.append(existing)
            continue
        input_payload = {
            "name": name,
            "pattern": pattern,
            "pattern_type": pattern_type,
            "update": True,
            "indicator_types": ["malicious-activity"],
            "x_opencti_detection": True,
        }
        if label_ids:
            input_payload["objectLabel"] = label_ids
        description = clean_string(
            attributes.get("description")
            or graph_candidate_description(candidate, attributes)
        )
        confidence = graph_candidate_confidence(candidate)
        if description:
            input_payload["description"] = description
        if confidence is not None:
            input_payload["confidence"] = confidence
        if score is not None:
            input_payload["x_opencti_score"] = score
        if author.get("id"):
            input_payload["createdBy"] = author["id"]
        try:
            result = api_client.query(
                INDICATOR_ADD_MUTATION,
                {"input": input_payload},
            )
        except Exception:
            existing = find_indicator(api_client, name)
            if existing:
                exported.append(existing)
            continue
        node = ((result.get("data") or {}).get("indicatorAdd")) or {}
        if node:
            exported.append(node)
            continue
        existing = find_indicator(api_client, name)
        if existing:
            exported.append(existing)
    return exported


def export_native_threat_actor_individuals(api_client, graph_candidate_policy):
    exported = []
    for candidate in native_threat_actor_individual_candidates(graph_candidate_policy):
        existing_id = candidate_existing_id(candidate)
        if existing_id:
            exported.append(
                {
                    "id": existing_id,
                    "standard_id": clean_string(
                        candidate_attributes(candidate).get("opencti_existing_ref")
                    ),
                    "entity_type": "Threat-Actor-Individual",
                    "name": graph_candidate_name(candidate),
                }
            )
            continue
        name = graph_candidate_name(candidate)
        if not name:
            continue
        existing = find_threat_actor_individual(api_client, name)
        if existing:
            exported.append(existing)
            continue
        attributes = candidate_attributes(candidate)
        input_payload = {
            "name": name,
            "update": True,
        }
        description = clean_string(
            attributes.get("description")
            or graph_candidate_description(candidate, attributes)
        )
        confidence = graph_candidate_confidence(candidate)
        aliases = clean_list_values(
            attributes.get("aliases"),
            attributes.get("alias"),
            attributes.get("x_opencti_aliases"),
        )
        threat_actor_types = clean_list_values(
            attributes.get("threat_actor_types"),
            attributes.get("threat_actor_type"),
            attributes.get("type"),
        )
        if description:
            input_payload["description"] = description
        if confidence is not None:
            input_payload["confidence"] = confidence
        if aliases:
            input_payload["aliases"] = aliases
        if threat_actor_types:
            input_payload["threat_actor_types"] = threat_actor_types
        for field in (
            "first_seen",
            "last_seen",
            "primary_motivation",
            "resource_level",
            "sophistication",
        ):
            value = clean_string(attributes.get(field))
            if value:
                input_payload[field] = value
        for field in ("goals", "personal_motivations", "secondary_motivations"):
            values = clean_list_values(attributes.get(field))
            if values:
                input_payload[field] = values
        try:
            result = api_client.query(
                THREAT_ACTOR_INDIVIDUAL_ADD_MUTATION,
                {"input": input_payload},
            )
        except Exception:
            continue
        node = ((result.get("data") or {}).get("threatActorIndividualAdd")) or {}
        if node:
            exported.append(node)
    return exported


def link_native_objects_to_reports(
    api_client,
    bundle_json,
    objects,
):
    if not objects:
        return []
    reports = report_nodes_for_bundle(api_client, bundle_json)
    linked = []
    for report in reports:
        report_id = clean_string(report.get("id"))
        if not report_id:
            continue
        for platform in objects:
            platform_id = clean_string(platform.get("id"))
            if not platform_id:
                continue
            try:
                result = api_client.query(
                    REPORT_OBJECT_REF_ADD_MUTATION,
                    {
                        "id": report_id,
                        "input": {
                            "toId": platform_id,
                            "relationship_type": "object",
                            "update": True,
                        },
                    },
                )
            except Exception:
                continue
            node = (((result.get("data") or {}).get("reportEdit") or {}).get(
                "relationAdd"
            )) or {}
            if node:
                linked.append(node)
    return linked


def link_native_security_platforms_to_reports(api_client, bundle_json, security_platforms):
    return link_native_objects_to_reports(api_client, bundle_json, security_platforms)


def report_nodes_for_bundle(api_client, bundle_json):
    reports = []
    for report_ref in report_refs_from_bundle_json(bundle_json):
        standard_id = clean_string(report_ref.get("standard_id"))
        name = clean_string(report_ref.get("name"))
        node = {}
        if standard_id:
            node = find_report(api_client, "standard_id", standard_id)
        if not node and name:
            node = find_report(api_client, "name", name)
        if node:
            reports.append(node)
    return reports


def report_refs_from_bundle_json(bundle_json):
    try:
        data = json.loads(bundle_json)
    except (TypeError, ValueError):
        return []
    reports = []
    for item in data.get("objects") or []:
        if item.get("type") != "report":
            continue
        reports.append(
            {
                "standard_id": clean_string(item.get("id")),
                "name": clean_edge_string(item.get("name")),
            }
        )
    return reports


def find_report(api_client, key, value):
    try:
        result = api_client.query(
            REPORT_LOOKUP_QUERY,
            {"filters": filter_eq(key, value)},
        )
    except Exception:
        return {}
    return first_node(result, "reports")


def native_security_platform_candidates(graph_candidate_policy):
    candidates = []
    for candidate in graph_accepted_candidates(graph_candidate_policy):
        if clean_string(candidate.get("stix_object_type")).lower() != "security-platform":
            continue
        if clean_string(candidate.get("entity_type")).lower() != "security_platform":
            continue
        candidates.append(candidate)
    return candidates


def native_threat_actor_individual_candidates(graph_candidate_policy):
    candidates = []
    for candidate in graph_accepted_candidates(graph_candidate_policy):
        if clean_string(candidate.get("stix_object_type")).lower() != "threat-actor":
            continue
        if clean_string(candidate.get("entity_type")).lower() != "threat_actor_individual":
            continue
        candidates.append(candidate)
    return candidates


def native_detection_rule_indicator_candidates(graph_candidate_policy):
    candidates = []
    native_pattern_types = {"sigma"}
    for candidate in graph_accepted_candidates(graph_candidate_policy):
        if clean_string(candidate.get("stix_object_type")).lower() != "indicator":
            continue
        if clean_string(candidate.get("entity_type")).lower() != "detection_rule":
            continue
        attributes = candidate_attributes(candidate)
        pattern_type = clean_string(
            attributes.get("pattern_type") or attributes.get("rule_type")
        ).lower()
        if not detection_rule_indicator_compatible(attributes):
            continue
        if pattern_type not in native_pattern_types:
            continue
        candidates.append(candidate)
    return candidates


def find_identity(api_client, name):
    try:
        result = api_client.query(
            IDENTITY_LOOKUP_QUERY,
            {"filters": filter_eq("name", name)},
        )
    except Exception:
        return {}
    return first_node(result, "identities")


def find_indicator(api_client, name):
    try:
        result = api_client.query(
            INDICATOR_LOOKUP_QUERY,
            {"filters": filter_eq("name", name)},
        )
    except Exception:
        return {}
    return first_node(result, "indicators")


def find_label(api_client, value):
    try:
        result = api_client.query(
            LABEL_LOOKUP_QUERY,
            {"filters": filter_eq("value", value)},
        )
    except Exception:
        return {}
    return first_node(result, "labels")


def add_label(api_client, value):
    try:
        result = api_client.query(
            LABEL_ADD_MUTATION,
            {"input": {"value": value, "update": True}},
        )
    except Exception:
        return {}
    return ((result.get("data") or {}).get("labelAdd")) or {}


def resolve_label_ids(api_client, values):
    label_ids = []
    for value in clean_list_values(values):
        label = find_label(api_client, value) or add_label(api_client, value)
        label_id = clean_string(label.get("id"))
        if label_id:
            label_ids.append(label_id)
    return label_ids


def find_security_platform(api_client, name):
    try:
        result = api_client.query(
            SECURITY_PLATFORM_LOOKUP_QUERY,
            {"filters": filter_eq("name", name)},
        )
    except Exception:
        return {}
    return first_node(result, "securityPlatforms")


def find_threat_actor_individual(api_client, name):
    try:
        result = api_client.query(
            THREAT_ACTOR_INDIVIDUAL_LOOKUP_QUERY,
            {"filters": filter_eq("name", name)},
        )
    except Exception:
        return {}
    return first_node(result, "threatActorsIndividuals")


def candidate_existing_id(candidate):
    return clean_string(candidate_attributes(candidate).get("opencti_existing_id"))


def hydrate_existing_graph_descriptions(api_client, requests):
    for request in requests or []:
        opencti_id = request.get("opencti_id")
        description = request.get("description")
        if not opencti_id or not description:
            continue
        try:
            current = api_client.query(
                DESCRIPTION_READ_QUERY,
                {"id": opencti_id},
            )
        except Exception:
            continue
        current_object = (current.get("data") or {}).get("stixDomainObject") or {}
        if current_object.get("description"):
            continue
        if not request.get("narrow_owned") and not has_narrowcti_author(current_object):
            continue
        try:
            api_client.query(
                DESCRIPTION_PATCH_MUTATION,
                {
                    "id": opencti_id,
                    "input": [{"key": "description", "value": [description]}],
                },
            )
        except Exception:
            continue


def has_narrowcti_author(opencti_object):
    author = opencti_object.get("createdBy") or {}
    return "narrowcti" in str(author.get("name") or "").lower()


def graph_candidate_name(candidate):
    return clean_string(candidate.get("name") or candidate.get("value"))


def graph_candidate_confidence(candidate):
    try:
        confidence = int(candidate.get("confidence"))
    except (TypeError, ValueError):
        return None
    return max(0, min(100, confidence))


def candidate_attributes(candidate):
    attributes = candidate.get("attributes")
    return attributes if isinstance(attributes, dict) else {}


def clean_string(value):
    return " ".join(str(value or "").strip().split())


def clean_multiline_string(value):
    return str(value or "").strip()


def clean_edge_string(value):
    return str(value or "").strip()


def clean_list_values(*values):
    cleaned = []
    seen = set()
    for value in values:
        if isinstance(value, (list, tuple, set)):
            items = value
        else:
            items = [value]
        for item in items:
            text = clean_string(item)
            key = text.casefold()
            if not text or key in seen:
                continue
            seen.add(key)
            cleaned.append(text)
    return cleaned
