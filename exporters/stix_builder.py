from collections import Counter
from datetime import datetime, timezone
import re
from uuid import NAMESPACE_URL, uuid5

from stix2 import (
    Artifact,
    AttackPattern,
    AutonomousSystem,
    Bundle,
    Campaign,
    CourseOfAction,
    CustomObject,
    DomainName,
    EmailAddress,
    ExtensionDefinition,
    File,
    IPv4Address,
    IPv6Address,
    Identity,
    Infrastructure,
    Indicator,
    IntrusionSet,
    Location,
    Malware,
    Note,
    Relationship,
    Report,
    Sighting,
    ThreatActor,
    Tool,
    URL,
    Vulnerability,
)
from stix2.properties import StringProperty
from stix2.registry import class_for_type


def registered_custom_object(type_name, properties):
    existing = class_for_type(type_name, "2.1")
    if existing is not None:
        return existing

    @CustomObject(type_name, properties)
    class NarrowCTICustomObject:
        pass

    return NarrowCTICustomObject


MitreDataSource = registered_custom_object(
    "x-mitre-data-source",
    [("name", StringProperty(required=True))],
)
MitreDataComponent = registered_custom_object(
    "x-mitre-data-component",
    [("name", StringProperty(required=True))],
)
SEMANTIC_RELATIONSHIP_TYPES = {
    "attributed-to",
    "based-on",
    "belongs-to",
    "consists-of",
    "detects",
    "indicates",
    "mitigates",
    "related-to",
    "targets",
    "uses",
}
REPORT_ID_NAMESPACE = "https://narrowcti.local/stix/report"
IDENTITY_ID_NAMESPACE = "https://narrowcti.local/stix/identity"
GRAPH_OBJECT_ID_NAMESPACE = "https://narrowcti.local/stix/graph-object"
OPENCTI_EXTENSION_DEFINITION_ID = (
    f"extension-definition--{uuid5(NAMESPACE_URL, 'opencti-extension-definition')}"
)
OPENCTI_CUSTOM_SDO_TYPES = {"channel", "event", "narrative"}
DETECTION_RULE_INDICATOR_PATTERN_TYPES = {"sigma", "yara"}
DETECTION_RULE_NOTE_PATTERN_TYPES = {"pcre", "snort", "suricata"}


def escape_pattern_value(value):
    return value.replace("\\", "\\\\").replace("'", "\\'")


def indicator_pattern(raw_indicator):
    value = raw_indicator.get("indicator")
    indicator_type = raw_indicator.get("type", "").lower()

    if not value:
        return None

    escaped = escape_pattern_value(value)
    pattern_by_type = {
        "domain": f"[domain-name:value = '{escaped}']",
        "hostname": f"[domain-name:value = '{escaped}']",
        "ipv4": f"[ipv4-addr:value = '{escaped}']",
        "ipv6": f"[ipv6-addr:value = '{escaped}']",
        "url": f"[url:value = '{escaped}']",
        "email": f"[email-addr:value = '{escaped}']",
        "filehash-md5": f"[file:hashes.MD5 = '{escaped}']",
        "filehash-sha1": f"[file:hashes.SHA1 = '{escaped}']",
        "filehash-sha256": f"[file:hashes.SHA256 = '{escaped}']",
    }
    return pattern_by_type.get(indicator_type)


def build_indicators(raw_indicators, identity_id, score, valid_from):
    objects = []
    seen_patterns = set()

    for raw_indicator in raw_indicators:
        pattern = indicator_pattern(raw_indicator)
        if not pattern or pattern in seen_patterns:
            continue

        seen_patterns.add(pattern)
        value = raw_indicator.get("indicator")
        objects.append(
            Indicator(
                name=value,
                pattern=pattern,
                pattern_type="stix",
                valid_from=valid_from,
                confidence=score,
                created_by_ref=identity_id,
            )
        )

    return objects


def build_report_bundle(
    name,
    description,
    score,
    indicators=None,
    identity_name="NarrowCTI Gateway",
    published_at=None,
):
    now = datetime.now(timezone.utc)
    publication_time = source_publication_time(published_at, now)
    identity = build_identity(identity_name)
    indicator_objects = build_indicators(
        indicators or [], identity.id, score, publication_time
    )
    object_refs = [indicator.id for indicator in indicator_objects] or [identity.id]

    report = build_stix_report(
        name,
        description,
        score,
        now,
        identity.id,
        object_refs,
        source_date=published_at,
        published=publication_time,
    )

    bundle = Bundle(objects=[identity, *indicator_objects, report], allow_custom=True)
    return bundle, len(indicator_objects)


def build_curated_report_bundle(
    name,
    description,
    score,
    indicators=None,
    graph_candidate_policy=None,
    identity_name="NarrowCTI Gateway",
    published_at=None,
):
    now = datetime.now(timezone.utc)
    publication_time = source_publication_time(published_at, now)
    identity = build_identity(identity_name)
    indicator_objects = build_indicators(
        indicators or [], identity.id, score, publication_time
    )
    accepted_candidates = graph_accepted_candidates(graph_candidate_policy)
    external_object_ids = indicator_object_ids(indicator_objects)
    graph_content = build_graph_content(
        accepted_candidates,
        identity.id,
        now,
        external_object_ids=external_object_ids,
    )

    object_refs = [
        *[indicator.id for indicator in indicator_objects],
        *graph_content["object_refs"],
    ] or [identity.id]
    report = build_stix_report(
        name,
        description,
        score,
        now,
        identity.id,
        object_refs,
        source_date=published_at,
        published=publication_time,
    )
    relationship_content = build_graph_relationships(
        accepted_candidates,
        graph_content["object_ids"],
        graph_content["alias_ids"],
        report.id,
        identity.id,
        now,
        external_object_ids=external_object_ids,
    )
    extension_objects = opencti_extension_objects(
        graph_content["objects"],
        identity.id,
        now,
    )

    bundle = Bundle(
        objects=[
            identity,
            *extension_objects,
            *indicator_objects,
            *graph_content["objects"],
            *relationship_content["relationships"],
            report,
        ],
        allow_custom=True,
    )
    summary = graph_bundle_summary(
        accepted_candidates,
        bundle,
        graph_content,
        relationship_content,
    )
    summary["indicator_count"] = len(indicator_objects)
    return bundle, len(indicator_objects), summary


def build_graph_report_bundle(
    name,
    description,
    score,
    graph_candidate_policy=None,
    identity_name="NarrowCTI Gateway",
    published_at=None,
):
    now = datetime.now(timezone.utc)
    publication_time = source_publication_time(published_at, now)
    identity = build_identity(identity_name)
    accepted_candidates = graph_accepted_candidates(graph_candidate_policy)
    graph_content = build_graph_content(accepted_candidates, identity.id, now)

    report_refs = graph_content["object_refs"] or [identity.id]
    report = build_stix_report(
        name,
        description,
        score,
        now,
        identity.id,
        report_refs,
        source_date=published_at,
        published=publication_time,
    )
    relationship_content = build_graph_relationships(
        accepted_candidates,
        graph_content["object_ids"],
        graph_content["alias_ids"],
        report.id,
        identity.id,
        now,
    )
    extension_objects = opencti_extension_objects(
        graph_content["objects"],
        identity.id,
        now,
    )

    bundle = Bundle(
        objects=[
            identity,
            *extension_objects,
            *graph_content["objects"],
            *relationship_content["relationships"],
            report,
        ],
        allow_custom=True,
    )
    summary = graph_bundle_summary(
        accepted_candidates,
        bundle,
        graph_content,
        relationship_content,
    )
    return bundle, summary


def build_stix_report(
    name,
    description,
    score,
    now,
    identity_id,
    object_refs,
    source_date=None,
    published=None,
):
    custom_properties = {}
    if clean_string(source_date):
        custom_properties["x_narrowcti_source_date"] = clean_string(source_date)
    return Report(
        id=deterministic_report_id(name, description),
        name=name,
        description=description or "",
        report_types=["threat-report"],
        confidence=score,
        created=now,
        modified=now,
        published=published or now,
        created_by_ref=identity_id,
        object_refs=object_refs,
        custom_properties=custom_properties,
        allow_custom=True,
    )


def opencti_extension_objects(graph_objects, identity_id, now):
    if not any(
        stix_object_field(item, "type").lower() in OPENCTI_CUSTOM_SDO_TYPES
        for item in graph_objects or []
    ):
        return []
    return [
        ExtensionDefinition(
            id=OPENCTI_EXTENSION_DEFINITION_ID,
            name="OpenCTI",
            description="OpenCTI native custom SDO extension.",
            created=now,
            modified=now,
            created_by_ref=identity_id,
            schema="https://www.filigran.io/opencti/schema",
            version="1.0",
            extension_types=["new-sdo"],
            allow_custom=True,
        )
    ]


def build_identity(identity_name, identity_class="organization"):
    return Identity(
        id=deterministic_identity_id(identity_name, identity_class),
        name=identity_name,
        identity_class=identity_class,
    )


def deterministic_identity_id(name, identity_class="organization"):
    material = "|".join(
        (
            IDENTITY_ID_NAMESPACE,
            clean_string(identity_class).casefold() or "organization",
            clean_string(name).casefold() or "unknown",
        )
    )
    return f"identity--{uuid5(NAMESPACE_URL, material)}"


def deterministic_graph_object_id(stix_object_type, name, value="", attributes=None):
    attributes = attributes if isinstance(attributes, dict) else {}
    object_type = clean_string(stix_object_type).lower()
    identity_class = clean_string(attributes.get("identity_class")).casefold()
    material = "|".join(
        (
            GRAPH_OBJECT_ID_NAMESPACE,
            object_type,
            identity_class,
            clean_string(value or name).casefold(),
            clean_string(name).casefold(),
        )
    )
    return f"{object_type}--{uuid5(NAMESPACE_URL, material)}"


def deterministic_report_id(name, description):
    material = "|".join(
        (
            "narrowcti-report",
            clean_string(name).casefold(),
            clean_string(description).casefold(),
        )
    )
    return f"report--{uuid5(NAMESPACE_URL, material)}"


def indicator_object_ids(indicator_objects):
    ids = {}
    for indicator in indicator_objects or []:
        name = clean_string(getattr(indicator, "name", ""))
        if name:
            ids[("indicator", name.lower())] = indicator.id
            ids[("value", name.lower())] = indicator.id
    return ids


def build_graph_content(accepted_candidates, identity_id, now, external_object_ids=None):
    graph_objects = []
    graph_object_ids = {}
    graph_alias_ids = dict(external_object_ids or {})
    skipped_candidates = []
    object_counts = Counter()
    existing_reference_counts = Counter()

    for candidate in accepted_candidates:
        if graph_candidate_is_relationship_only(candidate):
            continue
        object_key = graph_object_key(candidate)
        if object_key in graph_object_ids:
            continue
        try:
            stix_object = graph_candidate_to_stix_object(candidate, identity_id, now)
        except Exception:
            stix_object = None
        existing_ref = existing_opencti_ref(candidate)
        if existing_ref:
            graph_object_ids[object_key] = existing_ref
            register_graph_object_aliases(graph_alias_ids, candidate, existing_ref)
            existing_reference_counts[
                clean_string(candidate.get("stix_object_type")).lower()
            ] += 1
            if graph_candidate_hydrates_existing_ref(candidate, stix_object, existing_ref):
                graph_objects.append(stix_object)
                object_counts[stix_object_field(stix_object, "type")] += 1
            continue
        if not stix_object:
            skipped_candidates.append(candidate_summary(candidate))
            continue
        graph_object_ids[object_key] = stix_object_field(stix_object, "id")
        register_graph_object_aliases(
            graph_alias_ids,
            candidate,
            stix_object_field(stix_object, "id"),
        )
        graph_objects.append(stix_object)
        object_counts[stix_object_field(stix_object, "type")] += 1

    return {
        "objects": graph_objects,
        "object_ids": graph_object_ids,
        "alias_ids": graph_alias_ids,
        "object_refs": list(graph_object_ids.values()),
        "skipped_candidates": skipped_candidates,
        "object_counts": object_counts,
        "existing_reference_counts": existing_reference_counts,
    }


def build_graph_relationships(
    accepted_candidates,
    graph_object_ids,
    graph_alias_ids,
    report_id,
    identity_id,
    now,
    external_object_ids=None,
):
    graph_relationships = []
    relationship_keys = set()
    relationship_counts = Counter()
    proposed_relationship_counts = Counter()
    semantic_relationship_count = 0
    report_relationship_count = 0
    graph_alias_ids = graph_alias_ids or {}
    external_object_ids = external_object_ids or {}
    for candidate in accepted_candidates:
        relationship = graph_special_relationship(
            candidate,
            graph_object_ids,
            graph_alias_ids,
            identity_id,
            now,
            external_object_ids,
        )
        if relationship:
            relationship_type = graph_special_relationship_type(candidate, relationship)
            relationship_key = graph_special_relationship_key(relationship)
            if relationship_key in relationship_keys:
                continue
            relationship_keys.add(relationship_key)
            graph_relationships.append(relationship)
            relationship_counts[relationship_type] += 1
            proposed_relationship_counts[
                clean_string(candidate.get("relationship_type")) or relationship_type
            ] += 1
            semantic_relationship_count += 1
            continue
        target_ref = graph_object_ids.get(graph_object_key(candidate))
        if not target_ref:
            continue
        source_ref, relationship_type, relationship_mode = graph_relationship_endpoint(
            candidate,
            graph_object_ids,
            report_id,
            target_ref,
        )
        relationship_target_ref = graph_relationship_target_ref(
            candidate,
            source_ref,
            target_ref,
        )
        source_ref = graph_relationship_source_ref(candidate, source_ref, target_ref)
        relationship_key = (source_ref, relationship_type, relationship_target_ref)
        if relationship_key in relationship_keys:
            continue
        relationship_keys.add(relationship_key)
        relationship = Relationship(
            source_ref=source_ref,
            relationship_type=relationship_type,
            target_ref=relationship_target_ref,
            confidence=clamp_stix_confidence(
                candidate.get("relationship_confidence", candidate.get("confidence"))
            ),
            created_by_ref=identity_id,
            custom_properties=graph_relationship_custom_properties(
                candidate,
                relationship_mode,
            ),
            **graph_relationship_temporal_kwargs(candidate),
            allow_custom=True,
        )
        graph_relationships.append(relationship)
        relationship_counts[relationship_type] += 1
        proposed_relationship_counts[
            clean_string(candidate.get("relationship_type")) or "related-to"
        ] += 1
        if relationship_mode == "semantic":
            semantic_relationship_count += 1
        else:
            report_relationship_count += 1

    return {
        "relationships": graph_relationships,
        "relationship_counts": relationship_counts,
        "proposed_relationship_counts": proposed_relationship_counts,
        "semantic_relationship_count": semantic_relationship_count,
        "report_relationship_count": report_relationship_count,
    }


def graph_bundle_summary(
    accepted_candidates,
    bundle,
    graph_content,
    relationship_content,
):
    return {
        "accepted_candidate_count": len(accepted_candidates),
        "bundle_object_count": len(bundle.objects),
        "graph_object_count": len(graph_content["objects"]),
        "existing_reference_count": sum(
            graph_content["existing_reference_counts"].values()
        ),
        "graph_relationship_count": len(relationship_content["relationships"]),
        "skipped_candidate_count": len(graph_content["skipped_candidates"]),
        "object_counts": dict(sorted(graph_content["object_counts"].items())),
        "existing_reference_counts": dict(
            sorted(graph_content["existing_reference_counts"].items())
        ),
        "relationship_counts": dict(
            sorted(relationship_content["relationship_counts"].items())
        ),
        "proposed_relationship_counts": dict(
            sorted(relationship_content["proposed_relationship_counts"].items())
        ),
        "semantic_relationship_count": relationship_content[
            "semantic_relationship_count"
        ],
        "report_relationship_count": relationship_content[
            "report_relationship_count"
        ],
        "skipped_candidates": graph_content["skipped_candidates"],
    }


def graph_accepted_candidates(graph_candidate_policy):
    policy = graph_candidate_policy if isinstance(graph_candidate_policy, dict) else {}
    return [
        candidate
        for candidate in policy.get("accepted") or []
        if isinstance(candidate, dict)
    ]


def graph_description_hydration_requests(
    graph_candidate_policy,
    identity_name="NarrowCTI Gateway",
):
    identity = build_identity(identity_name)
    now = datetime.now(timezone.utc)
    requests = []
    for candidate in graph_accepted_candidates(graph_candidate_policy):
        attributes = candidate_attributes(candidate)
        existing_ref = existing_opencti_ref(candidate)
        existing_id = clean_string(attributes.get("opencti_existing_id"))
        if not existing_ref or not existing_id:
            continue
        try:
            stix_object = graph_candidate_to_stix_object(candidate, identity.id, now)
        except Exception:
            stix_object = None
        if not stix_object:
            continue
        description = stix_object_field(stix_object, "description")
        if not description:
            continue
        requests.append(
            {
                "opencti_id": existing_id,
                "standard_id": existing_ref,
                "narrow_owned": graph_candidate_hydrates_existing_ref(
                    candidate,
                    stix_object,
                    existing_ref,
                ),
                "stix_object_type": clean_string(candidate.get("stix_object_type")),
                "entity_type": clean_string(candidate.get("entity_type")),
                "name": clean_string(candidate.get("name") or candidate.get("value")),
                "description": description,
            }
        )
    return requests


def existing_opencti_ref(candidate):
    attributes = (
        candidate.get("attributes")
        if isinstance(candidate.get("attributes"), dict)
        else {}
    )
    existing_ref = clean_string(attributes.get("opencti_existing_ref"))
    if existing_ref and any(
        existing_ref.startswith(f"{prefix}--")
        for prefix in candidate_existing_ref_prefixes(candidate)
    ):
        return existing_ref
    return ""


def graph_candidate_hydrates_existing_ref(candidate, stix_object, existing_ref):
    if not stix_object or stix_object_field(stix_object, "id") != existing_ref:
        return False
    attributes = (
        candidate.get("attributes")
        if isinstance(candidate.get("attributes"), dict)
        else {}
    )
    return bool(graph_candidate_description(candidate, attributes))


def candidate_existing_ref_prefixes(candidate):
    stix_object_type = clean_string(candidate.get("stix_object_type")).lower()
    canonical_prefixes = {
        "security-platform": ["identity", "security-platform"],
    }
    if stix_object_type in canonical_prefixes:
        return canonical_prefixes[stix_object_type]
    if stix_object_type != "observable":
        return [stix_object_type] if stix_object_type else []

    attributes = (
        candidate.get("attributes")
        if isinstance(candidate.get("attributes"), dict)
        else {}
    )
    observable_type = clean_string(attributes.get("observable_type")).lower()
    supported = {
        "artifact",
        "domain-name",
        "email-addr",
        "file",
        "ipv4-addr",
        "ipv6-addr",
        "url",
    }
    return [observable_type] if observable_type in supported else []


def graph_candidate_to_stix_object(candidate, identity_id, now):
    stix_object_type = clean_string(candidate.get("stix_object_type")).lower()
    entity_type = clean_string(candidate.get("entity_type")).lower()
    name = clean_string(candidate.get("name") or candidate.get("value"))
    value = clean_string(candidate.get("value"))
    attributes = (
        candidate.get("attributes")
        if isinstance(candidate.get("attributes"), dict)
        else {}
    )
    effective_attributes = dict(attributes)
    if stix_object_type == "identity":
        effective_attributes["identity_class"] = graph_identity_class(
            candidate,
            attributes,
        )
    if entity_type == "detection_rule":
        name = detection_rule_indicator_name(name, attributes)
        stix_object_type = detection_rule_stix_object_type(
            stix_object_type,
            attributes,
        )
    confidence = clamp_stix_confidence(candidate.get("confidence"))
    custom_properties = graph_custom_properties(candidate)

    if not name or not stix_object_type:
        return None
    if stix_object_type == "threat-actor" and entity_type == "threat_actor_individual":
        return None

    common = {
        "id": deterministic_graph_object_id(
            stix_object_type,
            name,
            value,
            effective_attributes,
        ),
        "created_by_ref": identity_id,
        "confidence": confidence,
        "custom_properties": custom_properties,
        "allow_custom": True,
    }
    description = graph_candidate_description(candidate, attributes)
    described_common = dict(common)
    if description:
        described_common["description"] = description
    if stix_object_type == "attack-pattern":
        attack_pattern_kwargs = {}
        kill_chain_phases = attack_pattern_kill_chain_phases(attributes)
        if kill_chain_phases:
            attack_pattern_kwargs["kill_chain_phases"] = kill_chain_phases
        return AttackPattern(
            name=name,
            external_references=attack_pattern_references(value, attributes),
            **attack_pattern_kwargs,
            **described_common,
        )
    if stix_object_type == "campaign":
        return Campaign(name=name, **described_common)
    if stix_object_type == "course-of-action":
        return CourseOfAction(name=name, **described_common)
    if stix_object_type == "threat-actor":
        return ThreatActor(name=name, **described_common)
    if stix_object_type == "intrusion-set":
        return IntrusionSet(name=name, **described_common)
    if stix_object_type == "infrastructure":
        return Infrastructure(name=name, **described_common)
    if stix_object_type == "autonomous-system":
        return autonomous_system_candidate_to_stix(
            candidate,
            custom_properties,
        )
    if stix_object_type == "malware":
        return Malware(
            name=name,
            is_family=bool(attributes.get("is_family", True)),
            **described_common,
        )
    if stix_object_type == "tool":
        return Tool(name=name, **described_common)
    if stix_object_type == "vulnerability":
        return Vulnerability(
            name=name,
            external_references=vulnerability_references(value),
            **described_common,
        )
    if stix_object_type == "identity":
        return Identity(
            name=name,
            identity_class=effective_attributes["identity_class"],
            **described_common,
        )
    if stix_object_type == "location":
        return location_candidate_to_stix(
            candidate,
            effective_attributes,
            custom_properties,
            confidence,
            identity_id,
            description,
        )
    if stix_object_type in OPENCTI_CUSTOM_SDO_TYPES:
        return opencti_custom_sdo_candidate_to_stix(
            stix_object_type,
            name,
            attributes,
            described_common,
            now,
        )
    if stix_object_type == "indicator":
        pattern = (
            clean_multiline_string(attributes.get("pattern"))
            if entity_type == "detection_rule"
            else clean_string(attributes.get("pattern"))
        ) or value
        pattern_type = clean_string(attributes.get("pattern_type")) or "stix"
        if not pattern:
            return None
        indicator_kwargs = {}
        if entity_type == "detection_rule":
            indicator_kwargs.update(detection_rule_indicator_properties(candidate, attributes))
        return Indicator(
            name=name,
            pattern=pattern,
            pattern_type=pattern_type,
            valid_from=now,
            **indicator_kwargs,
            **described_common,
        )
    if stix_object_type in CUSTOM_GRAPH_OBJECTS:
        return CUSTOM_GRAPH_OBJECTS[stix_object_type](
            name=name,
            **described_common,
        )
    if stix_object_type == "note":
        if entity_type == "detection_rule":
            return detection_rule_candidate_to_note(
                name,
                candidate,
                attributes,
                common,
                identity_id,
            )
        content = clean_string(attributes.get("content")) or value
        if not content:
            return None
        return Note(
            abstract=name,
            content=content,
            object_refs=[identity_id],
            **common,
        )
    if stix_object_type == "observable":
        return observable_candidate_to_stix(candidate, custom_properties)
    return None


CUSTOM_GRAPH_OBJECTS = {
    "x-mitre-data-component": MitreDataComponent,
    "x-mitre-data-source": MitreDataSource,
}


def opencti_custom_sdo_candidate_to_stix(stix_object_type, name, attributes, common, now):
    properties = {
        "type": stix_object_type,
        "spec_version": "2.1",
        "id": common["id"],
        "created_by_ref": common["created_by_ref"],
        "created": stix_timestamp(now),
        "modified": stix_timestamp(now),
        "name": name,
        "confidence": common["confidence"],
        **dict(common.get("custom_properties") or {}),
    }
    description = clean_string(common.get("description"))
    if description:
        properties["description"] = description
    properties["extensions"] = {
        OPENCTI_EXTENSION_DEFINITION_ID: {"extension_type": "new-sdo"}
    }
    aliases = clean_list_values(
        attributes.get("aliases"),
        attributes.get("alias"),
        attributes.get("x_opencti_aliases"),
    )
    if aliases:
        properties["aliases"] = aliases

    if stix_object_type == "channel":
        channel_types = clean_list_values(
            attributes.get("channel_types"),
            attributes.get("channel_type"),
        )
        if channel_types:
            properties["channel_types"] = channel_types
    elif stix_object_type == "narrative":
        narrative_types = clean_list_values(
            attributes.get("narrative_types"),
            attributes.get("narrative_type"),
        )
        if narrative_types:
            properties["narrative_types"] = narrative_types
    elif stix_object_type == "event":
        event_types = clean_list_values(
            attributes.get("event_types"),
            attributes.get("event_type"),
        )
        if event_types:
            properties["event_types"] = event_types
        start_time = parse_timestamp(
            first_clean_value(attributes.get("start_time"), attributes.get("start"))
        )
        stop_time = parse_timestamp(
            first_clean_value(attributes.get("stop_time"), attributes.get("stop"))
        )
        if start_time:
            properties["start_time"] = stix_timestamp(start_time)
        if stop_time:
            properties["stop_time"] = stix_timestamp(stop_time)

    return properties


def graph_candidate_is_relationship_only(candidate):
    stix_object_type = clean_string(candidate.get("stix_object_type")).lower()
    return stix_object_type in {"relationship", "sighting"}


def graph_identity_class(candidate, attributes):
    explicit_class = clean_string(attributes.get("identity_class"))
    if explicit_class:
        return explicit_class
    entity_type = clean_string(candidate.get("entity_type")).lower()
    if entity_type in {"collector", "source_identity"}:
        return "organization"
    if entity_type == "target_organization":
        return "organization"
    if entity_type == "target_individual":
        return "individual"
    if entity_type == "target_system":
        return "system"
    return "class"


def autonomous_system_candidate_to_stix(candidate, custom_properties):
    attributes = (
        candidate.get("attributes")
        if isinstance(candidate.get("attributes"), dict)
        else {}
    )
    number = autonomous_system_number(candidate, attributes)
    if number is None:
        return None
    name = autonomous_system_name(
        number,
        attributes.get("as_name")
        or attributes.get("asn_name")
        or attributes.get("name")
        or candidate.get("name")
        or candidate.get("value"),
    )
    rir = clean_string(attributes.get("rir"))
    properties = {
        "id": deterministic_autonomous_system_id(number),
        "number": number,
        "custom_properties": custom_properties,
        "allow_custom": True,
    }
    if name:
        properties["name"] = name
    if rir:
        properties["rir"] = rir
    return AutonomousSystem(**properties)


def autonomous_system_number(candidate, attributes):
    for value in (
        attributes.get("number"),
        attributes.get("asn"),
        attributes.get("as_number"),
        attributes.get("autonomous_system_number"),
        candidate.get("value"),
        candidate.get("name"),
    ):
        parsed = parse_autonomous_system_number(value)
        if parsed is not None:
            return parsed
    return None


def autonomous_system_name(number, value):
    fallback = f"AS{number}"
    name = clean_string(value)
    if not name:
        return fallback
    if name.isdigit() and int(name) == int(number):
        return fallback
    if re.fullmatch(rf"AS\s*{int(number)}", name, re.IGNORECASE):
        return fallback
    return name


def parse_autonomous_system_number(value):
    text = clean_string(value)
    if not text:
        return None
    match = re.search(r"\bAS\s*([0-9]{1,10})\b", text, re.IGNORECASE)
    if not match and text.isdigit():
        match = re.match(r"^([0-9]{1,10})$", text)
    if not match:
        return None
    number = int(match.group(1))
    if number < 0 or number > 4294967295:
        return None
    return number


def deterministic_autonomous_system_id(number):
    material = "|".join(
        (
            GRAPH_OBJECT_ID_NAMESPACE,
            "autonomous-system",
            str(int(number)),
        )
    )
    return f"autonomous-system--{uuid5(NAMESPACE_URL, material)}"


def location_candidate_to_stix(
    candidate,
    attributes,
    custom_properties,
    confidence,
    identity_id,
    description="",
):
    entity_type = clean_string(candidate.get("entity_type")).lower()
    name = clean_string(candidate.get("name") or candidate.get("value"))
    value = clean_string(candidate.get("value"))
    custom_properties = dict(custom_properties or {})
    opencti_location_type = opencti_location_type_for_candidate(entity_type)
    if opencti_location_type:
        custom_properties["x_opencti_location_type"] = opencti_location_type
    location = {
        "id": deterministic_location_id(candidate, attributes),
        "created_by_ref": identity_id,
        "name": name,
        "confidence": confidence,
        "custom_properties": custom_properties,
        "allow_custom": True,
    }
    if description:
        location["description"] = description

    country = first_clean_value(attributes.get("country"), attributes.get("country_code"))
    region = clean_string(attributes.get("region"))
    administrative_area = first_clean_value(
        attributes.get("administrative_area"),
        attributes.get("state"),
        attributes.get("province"),
    )
    city = clean_string(attributes.get("city"))

    if entity_type == "target_country" and not country:
        country = value or name
    elif entity_type == "target_region" and not region:
        region = value or name
    elif entity_type == "target_administrative_area" and not administrative_area:
        administrative_area = value or name
    elif entity_type == "target_city" and not city:
        city = value or name

    optional_fields = {
        "region": region,
        "country": country,
        "administrative_area": administrative_area,
        "city": city,
        "street_address": clean_string(attributes.get("street_address")),
        "postal_code": clean_string(attributes.get("postal_code")),
    }
    location.update({key: value for key, value in optional_fields.items() if value})

    latitude = parse_float(attributes.get("latitude"))
    longitude = parse_float(attributes.get("longitude"))
    precision = parse_float(attributes.get("precision"))
    if latitude is None or longitude is None:
        latitude, longitude = parse_position(value)
    if latitude is not None and longitude is not None:
        location["latitude"] = latitude
        location["longitude"] = longitude
        if precision is not None:
            location["precision"] = precision

    return Location(**location)


def opencti_location_type_for_candidate(entity_type):
    return {
        "target_administrative_area": "Administrative-Area",
        "target_city": "City",
        "target_country": "Country",
        "target_position": "Position",
        "target_region": "Region",
    }.get(entity_type, "")


def graph_candidate_description(candidate, attributes):
    description = first_clean_value(
        attributes.get("description"),
        attributes.get("summary"),
        attributes.get("details"),
    )
    if description:
        return description

    entity_type = clean_string(candidate.get("entity_type")).lower()
    if entity_type == "detection_rule":
        rule_type = first_clean_value(
            attributes.get("rule_type"),
            attributes.get("pattern_type"),
        )
        source_name = first_clean_value(
            candidate.get("source_name"),
            candidate.get("source_key"),
        )
        source_field = clean_string(candidate.get("source_field"))
        label = f"{rule_type.upper()} detection rule" if rule_type else "Detection rule"
        if source_name and source_field:
            return f"Source-backed {label} observed by {source_name} at {source_field}."
        if source_name:
            return f"Source-backed {label} observed by {source_name}."
        return f"Source-backed {label}."
    if entity_type in OPERATIONAL_CONTEXT_ENTITY_TYPES:
        return source_backed_context_description(
            candidate,
            attributes,
            OPERATIONAL_CONTEXT_ENTITY_TYPES[entity_type],
        )
    if entity_type not in TARGET_CONTEXT_ENTITY_TYPES:
        return ""

    return source_backed_context_description(
        candidate,
        attributes,
        TARGET_CONTEXT_ENTITY_TYPES[entity_type],
    )


def source_backed_context_description(candidate, attributes, label):
    name = clean_string(candidate.get("name") or candidate.get("value"))
    source_name = first_clean_value(candidate.get("source_name"), candidate.get("source_key"))
    source_value = first_clean_value(
        attributes.get("relationship_source_value"),
        attributes.get("source_value"),
        attributes.get("parent_cluster_value"),
    )
    source_field = clean_string(candidate.get("source_field"))
    relationship_type = clean_string(candidate.get("relationship_type")) or "related-to"
    if name and source_name and source_value:
        return (
            f"Source-backed {label} observed by {source_name}: "
            f"{source_value} {relationship_type} {name}."
        )
    if name and source_name and source_field:
        return f"Source-backed {label} observed by {source_name} at {source_field}: {name}."
    if name and source_name:
        return f"Source-backed {label} observed by {source_name}: {name}."
    return ""


OPERATIONAL_CONTEXT_ENTITY_TYPES = {
    "campaign": "campaign",
    "channel": "channel",
    "course_of_action": "course of action",
    "attack_data_component": "MITRE data component",
    "attack_data_source": "MITRE data source",
    "event": "event",
    "infrastructure": "infrastructure",
    "intrusion_set": "intrusion set",
    "malware": "malware",
    "narrative": "narrative",
    "security_platform": "security platform",
    "threat_actor": "threat actor",
    "threat_actor_individual": "threat actor individual",
    "tool": "tool",
    "vulnerability": "vulnerability",
}


TARGET_CONTEXT_ENTITY_TYPES = {
    "target_administrative_area": "target administrative area",
    "target_city": "target city",
    "target_country": "target country",
    "target_individual": "target individual",
    "target_organization": "target organization",
    "target_position": "target position",
    "target_region": "target region",
    "target_sector": "target sector",
    "target_system": "target system",
}


def deterministic_location_id(candidate, attributes):
    entity_type = clean_string(candidate.get("entity_type")).lower()
    name = clean_string(candidate.get("name") or candidate.get("value"))
    value = clean_string(candidate.get("value"))
    material_parts = [
        GRAPH_OBJECT_ID_NAMESPACE,
        "location",
        entity_type,
        value.casefold(),
        name.casefold(),
    ]
    for field in (
        "region",
        "country",
        "country_code",
        "administrative_area",
        "state",
        "province",
        "city",
        "latitude",
        "longitude",
    ):
        material_parts.append(clean_string(attributes.get(field)).casefold())
    if entity_type in {"target_country", "target_region"} and not any(
        material_parts[5:]
    ):
        return deterministic_graph_object_id("location", name, value, attributes)
    material = "|".join(material_parts)
    return f"location--{uuid5(NAMESPACE_URL, material)}"


def parse_position(value):
    match = re.search(
        r"(-?\d+(?:\.\d+)?)\s*[,/ ]\s*(-?\d+(?:\.\d+)?)",
        clean_string(value),
    )
    if not match:
        return None, None
    return parse_float(match.group(1)), parse_float(match.group(2))


def parse_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def observable_candidate_to_stix(candidate, custom_properties):
    attributes = (
        candidate.get("attributes")
        if isinstance(candidate.get("attributes"), dict)
        else {}
    )
    observable_type = clean_string(attributes.get("observable_type")).lower()
    value = clean_string(candidate.get("value"))
    hash_algorithm = clean_string(attributes.get("hash_algorithm")).upper()
    if not value:
        return None
    if observable_type == "artifact" and hash_algorithm:
        artifact = {
            "hashes": {normalize_hash_algorithm(hash_algorithm): value},
            "custom_properties": custom_properties,
            "allow_custom": True,
        }
        artifact_url = clean_string(
            attributes.get("artifact_url") or attributes.get("url")
        )
        mime_type = clean_string(attributes.get("mime_type"))
        payload_bin = clean_string(attributes.get("payload_bin"))
        encryption_algorithm = clean_string(attributes.get("encryption_algorithm"))
        decryption_key = clean_string(attributes.get("decryption_key"))
        if artifact_url:
            artifact["url"] = artifact_url
        if mime_type:
            artifact["mime_type"] = mime_type
        if payload_bin:
            artifact["payload_bin"] = payload_bin
        if encryption_algorithm:
            artifact["encryption_algorithm"] = encryption_algorithm
        if decryption_key:
            artifact["decryption_key"] = decryption_key
        return Artifact(**artifact)
    if observable_type == "domain-name":
        return DomainName(
            value=value,
            custom_properties=custom_properties,
            allow_custom=True,
        )
    if observable_type == "url":
        return URL(value=value, custom_properties=custom_properties, allow_custom=True)
    if observable_type == "ipv4-addr":
        return IPv4Address(
            value=value,
            custom_properties=custom_properties,
            allow_custom=True,
        )
    if observable_type == "ipv6-addr":
        return IPv6Address(
            value=value,
            custom_properties=custom_properties,
            allow_custom=True,
        )
    if observable_type == "email-addr":
        return EmailAddress(
            value=value,
            custom_properties=custom_properties,
            allow_custom=True,
        )
    if observable_type == "file" and hash_algorithm:
        return File(
            hashes={normalize_hash_algorithm(hash_algorithm): value},
            custom_properties=custom_properties,
            allow_custom=True,
        )
    return None


def attack_pattern_references(value, attributes):
    stix_id = clean_string(attributes.get("stix_id"))
    references = []
    if value.upper().startswith("T"):
        references.append({"source_name": "mitre-attack", "external_id": value.upper()})
    if stix_id:
        references.append({"source_name": "mitre-attack", "url": stix_id})
    return references or None


def attack_pattern_kill_chain_phases(attributes):
    phases = attributes.get("kill_chain_phases")
    if not isinstance(phases, (list, tuple)):
        return None
    normalized = []
    seen = set()
    for phase in phases:
        if not isinstance(phase, dict):
            continue
        kill_chain_name = clean_string(phase.get("kill_chain_name"))
        phase_name = clean_string(phase.get("phase_name"))
        if not kill_chain_name or not phase_name:
            continue
        key = (kill_chain_name.casefold(), phase_name.casefold())
        if key in seen:
            continue
        seen.add(key)
        normalized.append(
            {
                "kill_chain_name": kill_chain_name,
                "phase_name": phase_name,
            }
        )
    return normalized or None


def vulnerability_references(value):
    normalized = value.upper()
    if not normalized.startswith("CVE-"):
        return None
    return [{"source_name": "cve", "external_id": normalized}]


def detection_rule_stix_object_type(stix_object_type, attributes):
    pattern_type = detection_rule_pattern_type(attributes)
    if not detection_rule_indicator_compatible(attributes):
        return "note"
    if pattern_type in DETECTION_RULE_INDICATOR_PATTERN_TYPES:
        return "indicator"
    if pattern_type in DETECTION_RULE_NOTE_PATTERN_TYPES:
        return "note"
    if stix_object_type == "indicator":
        return "note"
    return stix_object_type


def detection_rule_indicator_name(name, attributes):
    rule_type = detection_rule_pattern_type(attributes).upper()
    name = clean_string(name)
    if not rule_type or name.upper().startswith(f"{rule_type}:"):
        return name
    return f"{rule_type}: {name}"


def detection_rule_pattern_type(attributes):
    return first_clean_value(
        attributes.get("pattern_type"),
        attributes.get("rule_type"),
    ).lower()


def detection_rule_indicator_compatible(attributes):
    value = attributes.get("opencti_indicator_compatible")
    if isinstance(value, bool):
        return value
    normalized = clean_string(value).casefold()
    if normalized in {"0", "false", "no"}:
        return False
    return True


def detection_rule_candidate_to_note(name, candidate, attributes, common, identity_id):
    content = detection_rule_note_content(candidate, attributes)
    if not content:
        return None
    note_kwargs = dict(common)
    labels = detection_rule_labels(attributes)
    references = detection_rule_external_references(candidate, attributes)
    if labels:
        note_kwargs["labels"] = labels
    if references:
        note_kwargs["external_references"] = references
    return Note(
        abstract=name,
        content=content,
        object_refs=[identity_id],
        **note_kwargs,
    )


def detection_rule_note_content(candidate, attributes):
    rule_type = detection_rule_pattern_type(attributes)
    pattern = clean_multiline_string(attributes.get("pattern"))
    source_name = first_clean_value(
        candidate.get("source_name"),
        candidate.get("source_key"),
    )
    source_field = clean_string(candidate.get("source_field"))
    label = f"{rule_type.upper()} detection rule" if rule_type else "Detection rule"
    if detection_rule_indicator_compatible(attributes):
        lines = [
            (
                f"{label} preserved as analyst evidence because this pattern type is "
                "not exported as a native OpenCTI Indicator by the compatibility gate."
            )
        ]
    else:
        lines = [
            (
                f"{label} preserved as analyst evidence because it did not pass "
                "the OpenCTI Indicator compatibility gate."
            )
        ]
        reason = clean_string(attributes.get("opencti_indicator_compatibility_reason"))
        if reason:
            lines.append(f"Compatibility reason: {reason}.")
    if source_name and source_field:
        lines.append(f"Source: {source_name} at {source_field}.")
    elif source_name:
        lines.append(f"Source: {source_name}.")
    if pattern:
        lines.extend(["", pattern])
    return "\n".join(lines)


def detection_rule_indicator_properties(candidate, attributes):
    properties = {
        "labels": detection_rule_labels(attributes),
        "external_references": detection_rule_external_references(candidate, attributes),
        "indicator_types": ["malicious-activity"],
    }
    return {key: value for key, value in properties.items() if value}


def detection_rule_labels(attributes):
    labels = ["narrowcti:detection-rule"]
    rule_type = detection_rule_pattern_type(attributes)
    if rule_type:
        labels.append(f"rule-type:{rule_type}")
    return labels


def detection_rule_external_references(candidate, attributes):
    references = []
    for key in ("attribute_uuid", "indicator_id", "object_uuid"):
        value = clean_string(attributes.get(key))
        if value:
            references.append(
                {
                    "source_name": f"narrowcti-{key.replace('_', '-')}",
                    "external_id": value,
                }
            )
    source_name = first_clean_value(candidate.get("source_name"), candidate.get("source_key"))
    source_field = clean_string(candidate.get("source_field"))
    if source_name and source_field:
        references.append(
            {
                "source_name": source_name,
                "description": f"Detection rule source field: {source_field}",
            }
        )
    return references


def graph_custom_properties(candidate):
    attributes = (
        candidate.get("attributes")
        if isinstance(candidate.get("attributes"), dict)
        else {}
    )
    custom = {
        "x_narrowcti_candidate_fingerprint": clean_string(candidate.get("fingerprint")),
        "x_narrowcti_entity_type": clean_string(candidate.get("entity_type")),
        "x_narrowcti_source_key": clean_string(candidate.get("source_key")),
        "x_narrowcti_source_name": clean_string(candidate.get("source_name")),
        "x_narrowcti_source_field": clean_string(candidate.get("source_field")),
        "x_narrowcti_external_id": clean_string(candidate.get("external_id")),
        "x_narrowcti_proposed_relationship_type": clean_string(
            candidate.get("relationship_type")
        ),
        "x_narrowcti_relationship_source_type": first_clean_value(
            attributes.get("relationship_source_stix_object_type"),
            attributes.get("source_stix_object_type"),
            parent_cluster_stix_object_type(attributes),
        ),
        "x_narrowcti_relationship_source_value": first_clean_value(
            attributes.get("relationship_source_value"),
            attributes.get("source_value"),
            attributes.get("parent_cluster_value"),
        ),
        "x_narrowcti_relationship_source_field": first_clean_value(
            attributes.get("relationship_source_field"),
            attributes.get("parent_tag_name"),
            attributes.get("parent_cluster_uuid"),
        ),
        **graph_timeline_custom_properties(attributes),
    }
    return {key: value for key, value in custom.items() if value}


def graph_timeline_custom_properties(attributes):
    return {
        "x_narrowcti_source_created": first_clean_value(
            attributes.get("source_created"),
            attributes.get("created"),
        ),
        "x_narrowcti_source_modified": first_clean_value(
            attributes.get("source_modified"),
            attributes.get("modified"),
        ),
        "x_narrowcti_source_timestamp": first_clean_value(
            attributes.get("source_timestamp"),
            attributes.get("timestamp"),
            attributes.get("date_sighting"),
        ),
        "x_narrowcti_source_date": first_clean_value(
            attributes.get("source_date"),
            attributes.get("date"),
        ),
        "x_narrowcti_first_seen": first_clean_value(
            attributes.get("first_seen"),
            attributes.get("first_seen_min"),
        ),
        "x_narrowcti_last_seen": first_clean_value(
            attributes.get("last_seen"),
            attributes.get("last_seen_max"),
        ),
        "x_narrowcti_valid_from": first_clean_value(
            attributes.get("valid_from"),
            attributes.get("valid_start"),
        ),
        "x_narrowcti_valid_until": first_clean_value(
            attributes.get("valid_until"),
            attributes.get("valid_stop"),
            attributes.get("expiration"),
        ),
    }


def graph_relationship_custom_properties(candidate, relationship_mode):
    custom = graph_custom_properties(candidate)
    custom["x_narrowcti_relationship_mode"] = relationship_mode
    return custom


def graph_relationship_temporal_kwargs(candidate):
    """Expose source activity time as a native STIX relationship period."""
    attributes = candidate_attributes(candidate)
    source_time = first_clean_value(
        attributes.get("source_date"),
        attributes.get("source_created"),
        attributes.get("source_timestamp"),
    )
    parsed = parse_timestamp(source_time)
    if parsed is None:
        return {}
    return {"start_time": parsed}


def graph_special_relationship(
    candidate,
    graph_object_ids,
    graph_alias_ids,
    identity_id,
    now,
    external_object_ids,
):
    stix_object_type = clean_string(candidate.get("stix_object_type")).lower()
    if stix_object_type == "relationship":
        return object_reference_candidate_to_relationship(
            candidate,
            graph_alias_ids,
            identity_id,
        )
    if stix_object_type == "sighting":
        return sighting_candidate_to_stix(
            candidate,
            graph_object_ids,
            graph_alias_ids,
            identity_id,
            now,
            external_object_ids,
        )
    return None


def object_reference_candidate_to_relationship(candidate, graph_alias_ids, identity_id):
    attributes = candidate_attributes(candidate)
    source_ref = graph_alias_ids.get(alias_key(attributes.get("source_uuid")))
    target_ref = graph_alias_ids.get(alias_key(attributes.get("target_uuid")))
    relationship_type = clean_string(candidate.get("relationship_type")) or "related-to"
    if not source_ref or not target_ref or source_ref == target_ref:
        return None
    return Relationship(
        source_ref=source_ref,
        relationship_type=relationship_type,
        target_ref=target_ref,
        confidence=clamp_stix_confidence(
            candidate.get("relationship_confidence", candidate.get("confidence"))
        ),
        created_by_ref=identity_id,
        custom_properties=graph_relationship_custom_properties(candidate, "semantic"),
        **graph_relationship_temporal_kwargs(candidate),
        allow_custom=True,
    )


def sighting_candidate_to_stix(
    candidate,
    graph_object_ids,
    graph_alias_ids,
    identity_id,
    now,
    external_object_ids,
):
    attributes = candidate_attributes(candidate)
    target_ref = first_clean_value(
        external_object_ids.get(("indicator", clean_string(candidate.get("value")).lower())),
        external_object_ids.get(("value", clean_string(candidate.get("value")).lower())),
        graph_object_ids.get(("indicator", clean_string(candidate.get("value")).lower())),
        graph_alias_ids.get(alias_key(attributes.get("attribute_uuid"))),
    )
    if not target_ref or not sighting_target_is_sdo(target_ref):
        return None
    if not positive_sighting(attributes):
        return None
    first_seen = parse_sighting_time(attributes.get("date_sighting")) or now
    return Sighting(
        id=deterministic_sighting_id(candidate, target_ref),
        sighting_of_ref=target_ref,
        where_sighted_refs=[identity_id],
        first_seen=first_seen,
        last_seen=first_seen,
        count=1,
        confidence=clamp_stix_confidence(candidate.get("confidence")),
        created_by_ref=identity_id,
        custom_properties=graph_relationship_custom_properties(candidate, "semantic"),
        allow_custom=True,
    )


def graph_special_relationship_type(candidate, relationship):
    if getattr(relationship, "type", "") == "sighting":
        return clean_string(candidate.get("relationship_type")) or "sighting-of"
    return clean_string(getattr(relationship, "relationship_type", "")) or "related-to"


def graph_special_relationship_key(relationship):
    if getattr(relationship, "type", "") == "sighting":
        return (
            getattr(relationship, "type", ""),
            getattr(relationship, "sighting_of_ref", ""),
            getattr(relationship, "first_seen", ""),
            getattr(relationship, "id", ""),
        )
    return (
        getattr(relationship, "source_ref", ""),
        getattr(relationship, "relationship_type", ""),
        getattr(relationship, "target_ref", ""),
    )


def sighting_target_is_sdo(ref):
    prefix = clean_string(ref).split("--", 1)[0]
    return prefix in {
        "attack-pattern",
        "campaign",
        "course-of-action",
        "grouping",
        "identity",
        "indicator",
        "infrastructure",
        "intrusion-set",
        "malware",
        "malware-analysis",
        "note",
        "observed-data",
        "opinion",
        "report",
        "threat-actor",
        "tool",
        "vulnerability",
    }


def positive_sighting(attributes):
    sighting_type = clean_string(attributes.get("sighting_type")).lower()
    return sighting_type in {"", "0", "sighting", "positive"}


def deterministic_sighting_id(candidate, target_ref):
    attributes = candidate_attributes(candidate)
    material = "|".join(
        (
            "narrowcti-sighting",
            clean_string(candidate.get("source_key")).casefold(),
            clean_string(candidate.get("external_id")).casefold(),
            clean_string(target_ref).casefold(),
            first_clean_value(
                attributes.get("sighting_uuid"),
                attributes.get("sighting_id"),
                attributes.get("date_sighting"),
            ).casefold(),
        )
    )
    return f"sighting--{uuid5(NAMESPACE_URL, material)}"


def parse_sighting_time(value):
    text = clean_string(value)
    if not text:
        return None
    try:
        if text.isdigit():
            return datetime.fromtimestamp(int(text), timezone.utc)
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        return None


def parse_timestamp(value):
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    text = clean_string(value)
    if not text:
        return None
    try:
        if text.isdigit():
            return datetime.fromtimestamp(int(text), timezone.utc)
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        return None


def source_publication_time(value, fallback):
    """Return a valid source timestamp, falling back to connector time."""
    return parse_timestamp(value) or fallback


def stix_timestamp(value):
    if isinstance(value, datetime):
        normalized = value
        if normalized.tzinfo is None:
            normalized = normalized.replace(tzinfo=timezone.utc)
        return normalized.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return clean_string(value)


def graph_relationship_endpoint(candidate, graph_object_ids, report_id, target_ref):
    relationship_type = clean_string(candidate.get("relationship_type")) or "related-to"
    source_key = graph_relationship_source_key(candidate)
    source_ref = graph_object_ids.get(source_key) if source_key else ""
    if (
        source_ref
        and source_ref != target_ref
        and relationship_type in SEMANTIC_RELATIONSHIP_TYPES
    ):
        return source_ref, relationship_type, "semantic"
    return report_id, "related-to", "report-context"


def graph_relationship_source_ref(candidate, source_ref, target_ref):
    if graph_relationship_is_candidate_to_anchor(candidate, source_ref, target_ref):
        return target_ref
    return source_ref


def graph_relationship_target_ref(candidate, source_ref, target_ref):
    if graph_relationship_is_candidate_to_anchor(candidate, source_ref, target_ref):
        return source_ref
    return target_ref


def graph_relationship_is_candidate_to_anchor(candidate, source_ref, target_ref):
    entity_type = clean_string(candidate.get("entity_type"))
    relationship_type = clean_string(candidate.get("relationship_type"))
    candidate_to_anchor_relationships = {
        ("attack_data_source", "detects"),
        ("attack_data_component", "detects"),
        ("detection_rule", "detects"),
        ("course_of_action", "mitigates"),
    }
    return (
        (entity_type, relationship_type) in candidate_to_anchor_relationships
        and graph_relationship_source_key(candidate)
        and source_ref
        and target_ref
        and source_ref != target_ref
    )


def graph_relationship_source_key(candidate):
    attributes = candidate_attributes(candidate)
    source_type = first_clean_value(
        attributes.get("relationship_source_stix_object_type"),
        attributes.get("source_stix_object_type"),
        parent_cluster_stix_object_type(attributes),
    )
    source_value = first_clean_value(
        attributes.get("relationship_source_value"),
        attributes.get("source_value"),
        attributes.get("parent_cluster_value"),
    )
    if not source_type or not source_value:
        return None
    return (source_type.lower(), source_value.lower())


def register_graph_object_aliases(graph_alias_ids, candidate, object_id):
    for key in candidate_alias_keys(candidate):
        graph_alias_ids.setdefault(key, object_id)


def candidate_alias_keys(candidate):
    attributes = candidate_attributes(candidate)
    keys = []
    for field in (
        "object_uuid",
        "attribute_uuid",
        "event_report_uuid",
        "cluster_uuid",
        "indicator_id",
    ):
        key = alias_key(attributes.get(field))
        if key:
            keys.append(key)
    return keys


def alias_key(value):
    cleaned = clean_string(value).lower()
    if not cleaned:
        return None
    return ("uuid", cleaned)


def candidate_attributes(candidate):
    return (
        candidate.get("attributes")
        if isinstance(candidate.get("attributes"), dict)
        else {}
    )


def parent_cluster_stix_object_type(attributes):
    kind = " ".join(
        clean_string(attributes.get(field)).casefold()
        for field in (
            "parent_cluster_type",
            "parent_galaxy_type",
            "parent_galaxy_name",
        )
        if clean_string(attributes.get(field))
    )
    if "attack-pattern" in kind or "mitre-attack-pattern" in kind:
        return "attack-pattern"
    if "campaign" in kind:
        return "campaign"
    if "intrusion-set" in kind:
        return "intrusion-set"
    if "threat-actor" in kind or "threat actor" in kind:
        return "threat-actor"
    if "malpedia" in kind or "ransomware" in kind or "malware" in kind:
        return "malware"
    if "tool" in kind:
        return "tool"
    if "sector" in kind:
        return "identity"
    if "country" in kind or "region" in kind:
        return "location"
    return ""


def first_clean_value(*values):
    for value in values:
        cleaned = clean_string(value)
        if cleaned:
            return cleaned
    return ""


def clean_list_values(*values):
    cleaned = []
    seen = set()
    for value in values:
        if value in ("", None):
            continue
        if isinstance(value, (list, tuple, set)):
            items = value
        else:
            items = str(value).split(",")
        for item in items:
            text = clean_string(item)
            key = text.casefold()
            if text and key not in seen:
                cleaned.append(text)
                seen.add(key)
    return cleaned


def stix_object_field(stix_object, field):
    if isinstance(stix_object, dict):
        return clean_string(stix_object.get(field))
    return clean_string(getattr(stix_object, field, ""))


def graph_object_key(candidate):
    return (
        clean_string(candidate.get("stix_object_type")).lower(),
        clean_string(candidate.get("value") or candidate.get("name")).lower(),
    )


def candidate_summary(candidate):
    return {
        key: value
        for key, value in {
            "entity_type": candidate.get("entity_type"),
            "value": candidate.get("value"),
            "stix_object_type": candidate.get("stix_object_type"),
            "relationship_type": candidate.get("relationship_type"),
        }.items()
        if value
    }


def normalize_hash_algorithm(value):
    aliases = {
        "SHA1": "SHA-1",
        "SHA-1": "SHA-1",
        "SHA256": "SHA-256",
        "SHA-256": "SHA-256",
        "MD5": "MD5",
    }
    return aliases.get(value, value)


def clamp_stix_confidence(value):
    try:
        confidence = int(value)
    except (TypeError, ValueError):
        confidence = 50
    return max(0, min(100, confidence))


def clean_string(value):
    return " ".join(str(value or "").strip().split())


def clean_multiline_string(value):
    return str(value or "").strip()
