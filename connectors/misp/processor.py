import ipaddress
import re
import time
from collections.abc import Mapping
from dataclasses import replace
from inspect import Parameter, signature

try:
    import yaml
except Exception:
    yaml = None

try:
    from sigma.parser.collection import SigmaCollectionParser
except Exception:
    SigmaCollectionParser = None

from core.decision_audit import DecisionAuditLog, DecisionRecord
from core.contextual_scoring import (
    build_contextual_score_evidence,
    contextual_scoring_config_from_settings,
    finalize_contextual_score_evidence,
)
from core.feed_contract import FeedRunSummary
from core.graph_candidates import (
    apply_graph_candidate_policy,
    build_graph_candidates,
    safe_graph_export_allowed_entity_types,
    safe_graph_export_allowed_stix_object_types,
)
from core.graph_deduplication import GraphDeduplicationIndex
from core.graph_evidence import build_graph_evidence
from core.graph_export_plan import (
    build_graph_export_plan,
    build_graph_export_plan_with_known_keys,
    exportable_graph_candidate_policy,
)
from core.indicator_policy import filter_indicators_by_type
from core.ip_asn_enrichment import load_ip_asn_enricher
from core.opencti_graph_lookup import CompositeGraphLookup, OpenCTIGraphLookup
from core.policy import PolicyConfig, should_ingest
from core.quarantine import (
    QuarantineRecord,
    QuarantineRepository,
    bounded_raw_snapshot,
)
from core.scoring import age_days, calculate_score_details
from core.source_identity import feed_source_identity_name
from core.state_repository import MISPEventStateRepository
from core.tlp import tlp_is_allowed
from exporters.opencti import send_bundle
from exporters.stix_builder import build_graph_report_bundle

from connectors.misp.feed_adapter import MISPFeedAdapter, event_to_feed_candidate
from connectors.misp.models import MISPEventCandidate


CVE_ID_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
DETECTION_RULE_TYPES = {"yara", "sigma", "snort", "suricata", "pcre"}


def age_label(age):
    if age is None:
        return "unknown"
    return f"{age}d"


def compact_mapping(value):
    return dict(value) if isinstance(value, Mapping) else {}


def decision_metadata(
    candidate_ref,
    candidate=None,
    graph_candidate_policy=None,
    graph_export_mode="audit",
    graph_deduplication_index=None,
    ip_asn_enricher=None,
    contextual_scoring_config=None,
    include_export_plan=True,
):
    event = compact_mapping(candidate.event if candidate else {})
    reference = compact_mapping(candidate_ref.raw)
    source = event or reference
    provenance = compact_mapping(source.get("provenance"))
    controls = compact_mapping(source.get("narrowcti_controls"))
    tags = source.get("tags") or candidate_ref.tags or []

    metadata = {
        "collector": provenance.get("collector") or candidate_ref.source.name,
        "original_source": provenance.get("original_source", ""),
        "misp_event_id": provenance.get("misp_event_id") or source.get("id", ""),
        "misp_event_uuid": provenance.get("misp_event_uuid") or candidate_ref.external_id,
        "misp_event_created": source.get("created", ""),
        "misp_event_timestamp": source.get("timestamp")
        or source.get("publish_timestamp")
        or "",
        "misp_event_date": source.get("date", ""),
        "tags": list(tags),
    }
    misp_galaxies = extract_misp_galaxies(source)
    if misp_galaxies:
        metadata["misp_galaxies"] = misp_galaxies
    misp_vulnerabilities = extract_misp_vulnerabilities(source, tags)
    if misp_vulnerabilities:
        metadata["misp_vulnerabilities"] = misp_vulnerabilities
    misp_campaigns = extract_misp_campaigns(source)
    if misp_campaigns:
        metadata["misp_campaigns"] = misp_campaigns
    misp_victimology = extract_misp_victimology(source)
    if misp_victimology:
        metadata["misp_victimology"] = misp_victimology
    misp_event_reports = extract_misp_event_reports(source)
    if misp_event_reports:
        metadata["misp_event_reports"] = misp_event_reports
    misp_sightings = extract_misp_sightings(source)
    if misp_sightings:
        metadata["misp_sightings"] = misp_sightings
    misp_object_references = extract_misp_object_references(source)
    if misp_object_references:
        metadata["misp_object_references"] = misp_object_references
    misp_infrastructure = extract_misp_infrastructure(
        source,
        ip_asn_enricher=ip_asn_enricher,
    )
    if misp_infrastructure:
        metadata["misp_infrastructure"] = misp_infrastructure
    misp_detection_rules = extract_misp_detection_rules(source)
    if misp_detection_rules:
        metadata["misp_detection_rules"] = misp_detection_rules
    if controls:
        metadata["guardrails"] = controls
    score_details = getattr(candidate, "score_details", None)
    if score_details:
        metadata["scoring"] = dict(score_details)
    metadata["graph_evidence"] = build_graph_evidence(
        metadata,
        source_key=candidate_ref.source.key,
        external_id=candidate_ref.external_id,
        title=getattr(candidate, "name", "") or candidate_ref.title,
    )
    graph_candidates = build_graph_candidates(metadata["graph_evidence"])
    metadata["graph_candidates"] = graph_candidates.to_dict()
    graph_policy = apply_graph_candidate_policy(
        graph_candidates,
        **(graph_candidate_policy or {}),
    ).to_dict()
    metadata["graph_candidate_policy"] = graph_policy
    metadata["contextual_scoring"] = build_contextual_score_evidence(
        base_candidate_score(candidate),
        graph_policy,
        **(contextual_scoring_config or {}),
    )
    if not include_export_plan:
        return metadata
    graph_plan, known_keys, lookup_error = build_graph_export_plan_with_known_keys(
        graph_policy,
        mode=graph_export_mode,
        graph_deduplication_index=graph_deduplication_index,
    )
    metadata["graph_export_plan"] = graph_plan
    preview_policy = graph_policy
    if graph_plan.get("export_enabled"):
        preview_policy = exportable_graph_candidate_policy(
            graph_policy,
            graph_plan,
            known_keys,
        )
    metadata["graph_stix_preview"] = graph_stix_preview(
        candidate_ref,
        candidate,
        preview_policy,
        identity_name=feed_source_identity_name(candidate_ref.source),
        export_enabled=graph_plan.get("export_enabled", False),
    )
    if known_keys["entity_keys"] or known_keys["relationship_keys"]:
        metadata["graph_export_plan_known_keys"] = known_keys
    if known_keys.get("matches"):
        metadata["graph_export_plan_lookup_matches"] = known_keys["matches"]
    if lookup_error:
        metadata["graph_export_plan_lookup_error"] = lookup_error
    return metadata


def graph_stix_preview(
    candidate_ref,
    candidate,
    graph_policy,
    identity_name="NarrowCTI Gateway",
    export_enabled=False,
):
    event = compact_mapping(candidate.event if candidate else {})
    bundle, summary = build_graph_report_bundle(
        getattr(candidate, "name", "") or candidate_ref.title or "NarrowCTI graph preview",
        event.get("info", ""),
        candidate_score(candidate),
        graph_candidate_policy=graph_policy,
        identity_name=identity_name,
        published_at=event.get("date") or event.get("created"),
    )
    preview = dict(summary)
    preview["status"] = "preview"
    preview["export_enabled"] = bool(export_enabled)
    preview["bundle_type"] = bundle.type
    return preview


def candidate_score(candidate):
    return getattr(candidate, "score", base_candidate_score(candidate))


def base_candidate_score(candidate):
    score_details = getattr(candidate, "score_details", {}) or {}
    return score_details.get("final_score", getattr(candidate, "score", 50))


def extract_misp_galaxies(event):
    event = compact_mapping(event)
    clusters = []
    for container in misp_galaxy_containers(event):
        galaxy = compact_mapping(container.get("galaxy"))
        for cluster in container.get("clusters") or []:
            normalized = normalize_misp_galaxy_cluster(
                cluster,
                galaxy,
                container.get("source_field", "Galaxy"),
            )
            if normalized:
                clusters.append(normalized)
    return deduplicate_misp_galaxies(clusters)


def misp_galaxy_containers(event):
    containers = []
    containers.extend(galaxy_containers_from_mapping(event, "Galaxy"))
    for index, attribute in enumerate(list_values(event.get("Attribute"))):
        if isinstance(attribute, Mapping):
            containers.extend(
                galaxy_containers_from_mapping(attribute, f"Attribute[{index}].Galaxy")
            )
    for object_index, misp_object in enumerate(list_values(event.get("Object"))):
        if not isinstance(misp_object, Mapping):
            continue
        containers.extend(
            galaxy_containers_from_mapping(misp_object, f"Object[{object_index}].Galaxy")
        )
        for attribute_index, attribute in enumerate(
            list_values(misp_object.get("Attribute"))
        ):
            if isinstance(attribute, Mapping):
                containers.extend(
                    galaxy_containers_from_mapping(
                        attribute,
                        f"Object[{object_index}].Attribute[{attribute_index}].Galaxy",
                    )
                )
    return containers


def galaxy_containers_from_mapping(value, source_field):
    value = compact_mapping(value)
    containers = []
    for galaxy in list_values(value.get("Galaxy")):
        galaxy = compact_mapping(galaxy)
        clusters = list_values(
            galaxy.get("GalaxyCluster") or galaxy.get("GalaxyClusters")
        )
        if clusters:
            containers.append(
                {
                    "galaxy": galaxy,
                    "clusters": clusters,
                    "source_field": source_field,
                }
            )
    direct_clusters = list_values(
        value.get("GalaxyCluster") or value.get("GalaxyClusters")
    )
    if direct_clusters:
        containers.append(
            {
                "galaxy": {},
                "clusters": direct_clusters,
                "source_field": source_field.replace("Galaxy", "GalaxyCluster"),
            }
        )
    return containers


def list_values(value):
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple)):
        return list(value)
    return []


def normalize_misp_galaxy_cluster(cluster, galaxy, source_field):
    cluster = compact_mapping(cluster)
    if not cluster:
        return {}
    galaxy = compact_mapping(galaxy)
    meta = compact_mapping(cluster.get("meta"))
    value = (
        cluster.get("value")
        or cluster.get("name")
        or cluster.get("tag_name")
        or cluster.get("uuid")
        or ""
    )
    if not value:
        return {}
    return {
        "value": value,
        "type": cluster.get("type") or galaxy.get("type") or galaxy.get("name") or "",
        "description": cluster.get("description", ""),
        "uuid": cluster.get("uuid", ""),
        "tag_name": cluster.get("tag_name", ""),
        "galaxy_type": galaxy.get("type", ""),
        "galaxy_name": galaxy.get("name", ""),
        "source_field": source_field,
        "meta": meta,
    }


def deduplicate_misp_galaxies(clusters):
    seen = set()
    deduplicated = []
    for cluster in clusters:
        key = (
            str(cluster.get("type", "")).casefold(),
            str(cluster.get("value", "")).casefold(),
            str(cluster.get("uuid", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(cluster)
    return deduplicated


def extract_misp_vulnerabilities(event, tags=None):
    findings = []
    for source in misp_vulnerability_sources(event, tags or []):
        for cve_id in normalize_cve_ids(source.get("value")):
            findings.append(
                compact_mapping(
                    {
                        "value": cve_id,
                        "source_field": source.get("source_field"),
                        "source_type": source.get("source_type"),
                        "attribute_type": source.get("attribute_type"),
                        "attribute_category": source.get("attribute_category"),
                        "attribute_uuid": source.get("attribute_uuid"),
                        "first_seen": source.get("first_seen"),
                        "last_seen": source.get("last_seen"),
                        "object_name": source.get("object_name"),
                        "object_uuid": source.get("object_uuid"),
                        "tags": source.get("tags"),
                    }
                )
            )
    return deduplicate_misp_vulnerabilities(findings)


def extract_misp_campaigns(event):
    event = compact_mapping(event)
    campaigns = []
    for source in misp_campaign_sources(event):
        normalized = normalize_misp_campaign(source)
        if normalized:
            campaigns.append(normalized)
    return deduplicate_misp_campaigns(campaigns)


def misp_campaign_sources(event):
    event = compact_mapping(event)
    sources = []
    for index, attribute in enumerate(list_values(event.get("Attribute"))):
        attribute = compact_mapping(attribute)
        if not attribute:
            continue
        sources.append(
            {
                "source_field": f"Attribute[{index}]",
                "attribute": attribute,
                "object": {},
                "source_type": "attribute",
            }
        )
    for object_index, misp_object in enumerate(list_values(event.get("Object"))):
        misp_object = compact_mapping(misp_object)
        if not misp_object:
            continue
        for attribute_index, attribute in enumerate(
            list_values(misp_object.get("Attribute"))
        ):
            attribute = compact_mapping(attribute)
            if not attribute:
                continue
            sources.append(
                {
                    "source_field": (
                        f"Object[{object_index}].Attribute[{attribute_index}]"
                    ),
                    "attribute": attribute,
                    "object": misp_object,
                    "source_type": "object-attribute",
                }
            )
    return sources


def normalize_misp_campaign(source):
    source = compact_mapping(source)
    attribute = compact_mapping(source.get("attribute"))
    misp_object = compact_mapping(source.get("object"))
    if not is_explicit_misp_campaign_source(attribute, misp_object):
        return {}
    value = clean_text(
        attribute.get("value")
        or attribute.get("comment")
        or attribute.get("uuid")
    )
    if not is_safe_misp_campaign_value(value):
        return {}
    return compact_mapping(
        {
            "value": value,
            "source_type": source.get("source_type"),
            "source_field": source.get("source_field"),
            "attribute_type": attribute.get("type"),
            "attribute_category": attribute.get("category"),
            "attribute_uuid": attribute.get("uuid"),
            "attribute_relation": attribute.get("object_relation"),
            "first_seen": attribute.get("first_seen"),
            "last_seen": attribute.get("last_seen"),
            "object_name": misp_object.get("name"),
            "object_uuid": misp_object.get("uuid"),
            "object_meta_category": misp_object.get("meta-category"),
            "tags": [tag_name for tag_name in attribute_tags(attribute) if tag_name],
        }
    )


def is_explicit_misp_campaign_source(attribute, misp_object):
    attribute = compact_mapping(attribute)
    misp_object = compact_mapping(misp_object)
    object_name = clean_text(misp_object.get("name")).casefold()
    relation = clean_text(attribute.get("object_relation")).casefold()
    attribute_type = clean_text(attribute.get("type")).casefold()
    category = clean_text(attribute.get("category")).casefold()
    explicit_terms = {
        "campaign",
        "campaign-name",
        "operation",
        "operation-name",
        "threat-campaign",
    }
    object_is_campaign = object_name in explicit_terms or object_name.endswith(
        "-campaign"
    )
    relation_is_campaign = relation in explicit_terms or relation.endswith(
        "-campaign"
    )
    type_is_campaign = attribute_type in explicit_terms
    category_is_campaign = category in {"attribution", "external analysis"}
    return type_is_campaign or relation_is_campaign or (
        object_is_campaign and category_is_campaign
    )


def is_safe_misp_campaign_value(value):
    value = clean_text(value)
    lowered = value.casefold()
    if not value:
        return False
    if lowered.startswith(("http://", "https://", "ftp://", "tlp:")):
        return False
    if "@" in value and not any(char.isspace() for char in value):
        return False
    if CVE_ID_PATTERN.fullmatch(value):
        return False
    if re.fullmatch(r"\bT\d{4}(?:\.\d{3})?\b", value, re.IGNORECASE):
        return False
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", lowered):
        return False
    if re.fullmatch(r"\d+", value):
        return False
    return True


def deduplicate_misp_campaigns(campaigns):
    seen = set()
    deduplicated = []
    for campaign in campaigns:
        key = (
            str(campaign.get("value", "")).casefold(),
            str(campaign.get("attribute_uuid", "")).casefold(),
            str(campaign.get("object_uuid", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(campaign)
    return deduplicated


MISP_VICTIMOLOGY_ATTRIBUTE_TYPES = {
    "target-org": ("target_organization", 68),
    "target-machine": ("target_system", 65),
    "target-location": ("target_country", 70),
}


def extract_misp_victimology(event):
    event = compact_mapping(event)
    records = []
    for source in misp_attribute_sources(event):
        normalized = normalize_misp_victimology(source)
        if normalized:
            records.append(normalized)
    return deduplicate_misp_victimology(records)


def misp_attribute_sources(event):
    event = compact_mapping(event)
    sources = []
    for index, attribute in enumerate(list_values(event.get("Attribute"))):
        attribute = compact_mapping(attribute)
        if not attribute:
            continue
        sources.append(
            {
                "source_field": f"Attribute[{index}]",
                "attribute": attribute,
                "object": {},
                "source_type": "attribute",
            }
        )
    for object_index, misp_object in enumerate(list_values(event.get("Object"))):
        misp_object = compact_mapping(misp_object)
        if not misp_object:
            continue
        for attribute_index, attribute in enumerate(
            list_values(misp_object.get("Attribute"))
        ):
            attribute = compact_mapping(attribute)
            if not attribute:
                continue
            sources.append(
                {
                    "source_field": (
                        f"Object[{object_index}].Attribute[{attribute_index}]"
                    ),
                    "attribute": attribute,
                    "object": misp_object,
                    "source_type": "object-attribute",
                }
            )
    return sources


def normalize_misp_victimology(source):
    source = compact_mapping(source)
    attribute = compact_mapping(source.get("attribute"))
    misp_object = compact_mapping(source.get("object"))
    entity_type, confidence = misp_victimology_entity_type(attribute)
    if not entity_type:
        return {}
    value = clean_text(attribute.get("value") or attribute.get("comment"))
    if not value:
        return {}
    return compact_mapping(
        {
            "value": value,
            "entity_type": entity_type,
            "confidence": confidence,
            "source_type": source.get("source_type"),
            "source_field": source.get("source_field"),
            "attribute_type": attribute.get("type"),
            "attribute_category": attribute.get("category"),
            "attribute_uuid": attribute.get("uuid"),
            "attribute_relation": attribute.get("object_relation"),
            "first_seen": attribute.get("first_seen"),
            "last_seen": attribute.get("last_seen"),
            "object_name": misp_object.get("name"),
            "object_uuid": misp_object.get("uuid"),
            "object_meta_category": misp_object.get("meta-category"),
            "tags": [tag_name for tag_name in attribute_tags(attribute) if tag_name],
        }
    )


def misp_victimology_entity_type(attribute):
    attribute = compact_mapping(attribute)
    attribute_type = clean_text(attribute.get("type")).casefold()
    relation = clean_text(attribute.get("object_relation")).casefold()
    return (
        MISP_VICTIMOLOGY_ATTRIBUTE_TYPES.get(attribute_type)
        or MISP_VICTIMOLOGY_ATTRIBUTE_TYPES.get(relation)
        or ("", 0)
    )


def deduplicate_misp_victimology(records):
    seen = set()
    deduplicated = []
    for record in records:
        key = (
            str(record.get("entity_type", "")).casefold(),
            str(record.get("value", "")).casefold(),
            str(record.get("attribute_uuid", "")).casefold(),
            str(record.get("object_uuid", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(record)
    return deduplicated


def misp_vulnerability_sources(event, tags):
    event = compact_mapping(event)
    sources = []
    for index, tag in enumerate(tags or []):
        sources.append(
            {
                "value": tag,
                "source_field": f"tags[{index}]",
                "source_type": "tag",
            }
        )
    for field in ("info", "name", "description"):
        sources.append(
            {
                "value": event.get(field),
                "source_field": field,
                "source_type": "event",
            }
        )
    for index, attribute in enumerate(list_values(event.get("Attribute"))):
        if isinstance(attribute, Mapping):
            sources.append(
                misp_attribute_vulnerability_source(
                    attribute,
                    f"Attribute[{index}]",
                )
            )
    for object_index, misp_object in enumerate(list_values(event.get("Object"))):
        if not isinstance(misp_object, Mapping):
            continue
        for attribute_index, attribute in enumerate(
            list_values(misp_object.get("Attribute"))
        ):
            if isinstance(attribute, Mapping):
                sources.append(
                    misp_attribute_vulnerability_source(
                        attribute,
                        f"Object[{object_index}].Attribute[{attribute_index}]",
                        misp_object=misp_object,
                    )
                )
    return sources


def misp_attribute_vulnerability_source(attribute, source_field, misp_object=None):
    attribute = compact_mapping(attribute)
    misp_object = compact_mapping(misp_object)
    return compact_mapping(
        {
            "value": attribute.get("value"),
            "source_field": source_field,
            "source_type": "attribute",
            "attribute_type": attribute.get("type"),
            "attribute_category": attribute.get("category"),
            "attribute_uuid": attribute.get("uuid"),
            "first_seen": attribute.get("first_seen"),
            "last_seen": attribute.get("last_seen"),
            "object_name": misp_object.get("name"),
            "object_uuid": misp_object.get("uuid"),
            "tags": [tag_name for tag_name in attribute_tags(attribute) if tag_name],
        }
    )


def attribute_tags(attribute):
    tags = []
    for tag in list_values(attribute.get("Tag")):
        if isinstance(tag, Mapping):
            value = tag.get("name") or tag.get("Name")
        else:
            value = tag
        if value:
            tags.append(value)
    return tags


def normalize_cve_ids(value):
    cve_ids = []
    for item in flatten_text(value):
        for match in CVE_ID_PATTERN.findall(str(item or "")):
            normalized = match.upper()
            if normalized not in cve_ids:
                cve_ids.append(normalized)
    return cve_ids


def flatten_text(value):
    if value is None:
        return []
    if isinstance(value, Mapping):
        values = []
        for item in value.values():
            values.extend(flatten_text(item))
        return values
    if isinstance(value, (list, tuple, set)):
        values = []
        for item in value:
            values.extend(flatten_text(item))
        return values
    return [value]


def deduplicate_misp_vulnerabilities(findings):
    seen = set()
    deduplicated = []
    for finding in findings:
        key = str(finding.get("value", "")).casefold()
        if not key or key in seen:
            continue
        seen.add(key)
        deduplicated.append(finding)
    return deduplicated


def extract_misp_event_reports(event):
    event = compact_mapping(event)
    reports = []
    for index, report in enumerate(list_values(event.get("EventReport"))):
        normalized = normalize_misp_event_report(report, f"EventReport[{index}]")
        if normalized:
            reports.append(normalized)
    return deduplicate_misp_event_reports(reports)


def normalize_misp_event_report(report, source_field):
    report = compact_mapping(report)
    if not report or is_truthy(report.get("deleted")):
        return {}
    title = clean_text(
        report.get("name")
        or report.get("title")
        or report.get("event_report_title")
        or report.get("uuid")
    )
    content = clean_text(
        report.get("content")
        or report.get("text")
        or report.get("body")
        or report.get("value")
    )
    if not title and content:
        title = content[:120]
    if not title and not content:
        return {}
    return compact_mapping(
        {
            "title": title,
            "content": content,
            "uuid": report.get("uuid"),
            "timestamp": report.get("timestamp"),
            "created": report.get("created"),
            "modified": report.get("modified"),
            "source_field": source_field,
        }
    )


def deduplicate_misp_event_reports(reports):
    seen = set()
    deduplicated = []
    for report in reports:
        key = (
            str(report.get("uuid", "")).casefold(),
            str(report.get("title", "")).casefold(),
            str(report.get("content", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(report)
    return deduplicated


def extract_misp_sightings(event):
    event = compact_mapping(event)
    sightings = []
    for source in misp_sighting_sources(event):
        for index, sighting in enumerate(list_values(source.get("sightings"))):
            normalized = normalize_misp_sighting(
                sighting,
                source,
                f"{source.get('source_field')}.Sighting[{index}]",
            )
            if normalized:
                sightings.append(normalized)
    return deduplicate_misp_sightings(sightings)


def misp_sighting_sources(event):
    event = compact_mapping(event)
    sources = []
    for index, attribute in enumerate(list_values(event.get("Attribute"))):
        attribute = compact_mapping(attribute)
        if not attribute:
            continue
        sources.append(
            {
                "source_field": f"Attribute[{index}]",
                "sightings": attribute.get("Sighting"),
                "attribute_type": attribute.get("type"),
                "attribute_category": attribute.get("category"),
                "attribute_value": attribute.get("value"),
                "attribute_uuid": attribute.get("uuid"),
            }
        )
    for object_index, misp_object in enumerate(list_values(event.get("Object"))):
        misp_object = compact_mapping(misp_object)
        if not misp_object:
            continue
        for attribute_index, attribute in enumerate(
            list_values(misp_object.get("Attribute"))
        ):
            attribute = compact_mapping(attribute)
            if not attribute:
                continue
            sources.append(
                {
                    "source_field": (
                        f"Object[{object_index}].Attribute[{attribute_index}]"
                    ),
                    "sightings": attribute.get("Sighting"),
                    "attribute_type": attribute.get("type"),
                    "attribute_category": attribute.get("category"),
                    "attribute_value": attribute.get("value"),
                    "attribute_uuid": attribute.get("uuid"),
                    "object_name": misp_object.get("name"),
                    "object_uuid": misp_object.get("uuid"),
                }
            )
    return sources


def normalize_misp_sighting(sighting, source, source_field):
    sighting = compact_mapping(sighting)
    source = compact_mapping(source)
    if not sighting or is_truthy(sighting.get("deleted")):
        return {}
    observed_value = clean_text(
        source.get("attribute_value")
        or sighting.get("value")
        or sighting.get("uuid")
        or sighting.get("id")
    )
    if not observed_value:
        return {}
    organization = compact_mapping(
        sighting.get("Organisation") or sighting.get("Organization")
    )
    return compact_mapping(
        {
            "value": observed_value,
            "sighting_id": sighting.get("id"),
            "sighting_uuid": sighting.get("uuid"),
            "sighting_type": sighting.get("type"),
            "date_sighting": sighting.get("date_sighting"),
            "source": sighting.get("source"),
            "confidence": sighting.get("confidence"),
            "source_confidence": sighting.get("source_confidence"),
            "organization": organization.get("name") or organization.get("uuid"),
            "organization_uuid": organization.get("uuid"),
            "attribute_type": source.get("attribute_type"),
            "attribute_category": source.get("attribute_category"),
            "attribute_uuid": source.get("attribute_uuid"),
            "object_name": source.get("object_name"),
            "object_uuid": source.get("object_uuid"),
            "source_field": source_field,
        }
    )


def deduplicate_misp_sightings(sightings):
    seen = set()
    deduplicated = []
    for sighting in sightings:
        key = (
            str(sighting.get("sighting_uuid", "")).casefold(),
            str(sighting.get("sighting_id", "")).casefold(),
            str(sighting.get("value", "")).casefold(),
            str(sighting.get("date_sighting", "")).casefold(),
            str(sighting.get("source", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(sighting)
    return deduplicated


def extract_misp_object_references(event):
    event = compact_mapping(event)
    references = []
    for object_index, misp_object in enumerate(list_values(event.get("Object"))):
        misp_object = compact_mapping(misp_object)
        if not misp_object:
            continue
        for reference_index, reference in enumerate(
            list_values(misp_object.get("ObjectReference"))
        ):
            normalized = normalize_misp_object_reference(
                reference,
                misp_object,
                f"Object[{object_index}].ObjectReference[{reference_index}]",
            )
            if normalized:
                references.append(normalized)
    return deduplicate_misp_object_references(references)


def normalize_misp_object_reference(reference, misp_object, source_field):
    reference = compact_mapping(reference)
    misp_object = compact_mapping(misp_object)
    if not reference or is_truthy(reference.get("deleted")):
        return {}
    source_uuid = clean_text(
        reference.get("object_uuid") or misp_object.get("uuid")
    )
    target_uuid = clean_text(
        reference.get("referenced_uuid")
        or reference.get("referenced_object_uuid")
        or reference.get("referenced_attribute_uuid")
    )
    relationship_type = normalize_misp_relationship_type(
        reference.get("relationship_type")
    )
    if not source_uuid or not target_uuid:
        return {}
    value = f"{source_uuid} {relationship_type} {target_uuid}"
    return compact_mapping(
        {
            "value": value,
            "relationship_type": relationship_type,
            "reference_id": reference.get("id"),
            "reference_uuid": reference.get("uuid"),
            "source_uuid": source_uuid,
            "source_name": misp_object.get("name"),
            "source_meta_category": misp_object.get("meta-category"),
            "target_uuid": target_uuid,
            "target_type": reference.get("referenced_type"),
            "comment": reference.get("comment"),
            "source_field": source_field,
        }
    )


def normalize_misp_relationship_type(value):
    normalized = clean_text(value).casefold().replace(" ", "-")
    return normalized or "related-to"


def deduplicate_misp_object_references(references):
    seen = set()
    deduplicated = []
    for reference in references:
        key = (
            str(reference.get("reference_uuid", "")).casefold(),
            str(reference.get("source_uuid", "")).casefold(),
            str(reference.get("relationship_type", "")).casefold(),
            str(reference.get("target_uuid", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(reference)
    return deduplicated


def extract_misp_infrastructure(event, ip_asn_enricher=None):
    event = compact_mapping(event)
    records = []
    for attribute_index, attribute in enumerate(list_values(event.get("Attribute"))):
        attribute = compact_mapping(attribute)
        if not attribute:
            continue
        records.extend(
            normalize_misp_infrastructure_attribute(
                attribute,
                f"Attribute[{attribute_index}]",
                ip_asn_enricher=ip_asn_enricher,
            )
        )
    for object_index, misp_object in enumerate(list_values(event.get("Object"))):
        misp_object = compact_mapping(misp_object)
        if not misp_object:
            continue
        records.extend(
            normalize_misp_infrastructure_object(
                misp_object,
                f"Object[{object_index}]",
                ip_asn_enricher=ip_asn_enricher,
            )
        )
    return deduplicate_misp_infrastructure_records(
        canonicalize_misp_autonomous_system_values(records)
    )


MISP_INFRASTRUCTURE_OBJECT_NAMES = {
    "asn",
    "domain-ip",
    "ip-port",
    "netblock",
}


MISP_INFRASTRUCTURE_ATTRIBUTE_OBJECT_NAMES = {
    "as": "asn",
    "asn": "asn",
    "domain|ip": "domain-ip",
    "hostname|port": "ip-port",
    "ip-dst|port": "ip-port",
    "ip-src|port": "ip-port",
}


def normalize_misp_infrastructure_attribute(
    attribute,
    source_field,
    ip_asn_enricher=None,
):
    attribute = compact_mapping(attribute)
    if not attribute or is_truthy(attribute.get("deleted")):
        return []
    attribute_type = clean_text(attribute.get("type")).casefold()
    object_name = MISP_INFRASTRUCTURE_ATTRIBUTE_OBJECT_NAMES.get(attribute_type)
    if not object_name:
        return []
    pseudo_object = {
        "uuid": attribute.get("uuid"),
        "name": object_name,
        "meta-category": attribute.get("category") or "network",
        "Attribute": [attribute],
    }
    return normalize_misp_infrastructure_object(
        pseudo_object,
        source_field,
        ip_asn_enricher=ip_asn_enricher,
    )


def normalize_misp_infrastructure_object(
    misp_object,
    source_field,
    ip_asn_enricher=None,
):
    misp_object = compact_mapping(misp_object)
    object_name = clean_text(misp_object.get("name")).casefold()
    if object_name not in MISP_INFRASTRUCTURE_OBJECT_NAMES:
        return []

    attributes = misp_object_attribute_facts(misp_object, source_field)
    observables = infrastructure_observables(attributes)
    asn = infrastructure_asn(attributes)
    if not observables and not asn:
        return []

    records = []
    infrastructure_name = ""
    if object_name != "asn" and observables:
        infrastructure_name = misp_infrastructure_name(
            object_name,
            observables,
            asn,
            misp_object,
        )
        records.append(
            misp_infrastructure_record(
                "infrastructure",
                infrastructure_name,
                "infrastructure",
                "uses",
                source_field,
                misp_object,
                confidence=72,
            )
        )

    for observable in observables:
        observable_attributes = misp_infrastructure_record_attributes(
            misp_object,
            observable["source_field"],
        )
        observable_attributes.update(
            {
                "observable_type": observable["observable_type"],
                "attribute_type": observable.get("attribute_type"),
                "attribute_relation": observable.get("relation"),
                "attribute_uuid": observable.get("attribute_uuid"),
                "first_seen": observable.get("first_seen"),
                "last_seen": observable.get("last_seen"),
                "port": observable.get("port"),
            }
        )
        if infrastructure_name:
            observable_attributes.update(
                relationship_source_attributes(
                    "infrastructure",
                    infrastructure_name,
                    observable["source_field"],
                )
            )
        records.append(
            misp_infrastructure_record(
                "observable",
                observable["value"],
                "observable",
                "consists-of" if infrastructure_name else "related-to",
                observable["source_field"],
                misp_object,
                confidence=70,
                attributes=observable_attributes,
            )
        )

    if asn:
        asn_attributes = misp_infrastructure_record_attributes(
            misp_object,
            asn["source_field"],
        )
        asn_attributes.update(
            {
                "asn": asn["number"],
                "asn_name": asn.get("name"),
                "rir": asn.get("rir"),
                "attribute_type": asn.get("attribute_type"),
                "attribute_relation": asn.get("relation"),
                "attribute_uuid": asn.get("attribute_uuid"),
                "first_seen": asn.get("first_seen"),
                "last_seen": asn.get("last_seen"),
            }
        )
        if infrastructure_name:
            infra_asn_attributes = dict(asn_attributes)
            infra_asn_attributes.update(
                relationship_source_attributes(
                    "infrastructure",
                    infrastructure_name,
                    asn["source_field"],
                )
            )
            records.append(
                misp_infrastructure_record(
                    "autonomous_system",
                    autonomous_system_value(asn),
                    "autonomous-system",
                    "consists-of",
                    asn["source_field"],
                    misp_object,
                    confidence=72,
                    attributes=infra_asn_attributes,
                )
            )
        else:
            records.append(
                misp_infrastructure_record(
                    "autonomous_system",
                    autonomous_system_value(asn),
                    "autonomous-system",
                    "related-to",
                    asn["source_field"],
                    misp_object,
                    confidence=72,
                    attributes=asn_attributes,
                )
            )
        for observable in observables:
            if observable["observable_type"] not in {"ipv4-addr", "ipv6-addr"}:
                continue
            belongs_attributes = dict(asn_attributes)
            belongs_attributes.update(
                relationship_source_attributes(
                    "observable",
                    observable["value"],
                    observable["source_field"],
                )
            )
            records.append(
                misp_infrastructure_record(
                    "autonomous_system",
                    autonomous_system_value(asn),
                    "autonomous-system",
                    "belongs-to",
                    asn["source_field"],
                    misp_object,
                    confidence=72,
                    attributes=belongs_attributes,
                )
            )
    records.extend(
        offline_ip_asn_records(
            observables,
            ip_asn_enricher,
            source_field,
            misp_object,
            infrastructure_name,
        )
    )
    return records


def offline_ip_asn_records(
    observables,
    ip_asn_enricher,
    source_field,
    misp_object,
    infrastructure_name="",
):
    if not ip_asn_enricher:
        return []
    records = []
    for observable in observables:
        if observable.get("observable_type") not in {"ipv4-addr", "ipv6-addr"}:
            continue
        match = ip_asn_enricher.lookup(observable.get("value"))
        if not match:
            continue
        attributes = misp_infrastructure_record_attributes(
            misp_object,
            observable.get("source_field") or source_field,
        )
        attributes.update(
            {
                "asn": match.asn,
                "asn_name": match.as_name,
                "rir": match.rir,
                "enrichment_source": match.source or "offline-ip-asn",
                "enrichment_cidr": str(match.network),
            }
        )
        attributes.update(
            relationship_source_attributes(
                "observable",
                observable["value"],
                observable.get("source_field") or source_field,
            )
        )
        records.append(
            misp_infrastructure_record(
                "autonomous_system",
                match.value,
                "autonomous-system",
                "belongs-to",
                observable.get("source_field") or source_field,
                misp_object,
                confidence=60,
                attributes=attributes,
            )
        )
        if infrastructure_name:
            infra_attributes = dict(attributes)
            infra_attributes.update(
                relationship_source_attributes(
                    "infrastructure",
                    infrastructure_name,
                    observable.get("source_field") or source_field,
                )
            )
            records.append(
                misp_infrastructure_record(
                    "autonomous_system",
                    match.value,
                    "autonomous-system",
                    "consists-of",
                    observable.get("source_field") or source_field,
                    misp_object,
                    confidence=60,
                    attributes=infra_attributes,
                )
            )
    return records


def misp_object_attribute_facts(misp_object, object_source_field):
    facts = []
    for attribute_index, attribute in enumerate(
        list_values(compact_mapping(misp_object).get("Attribute"))
    ):
        attribute = compact_mapping(attribute)
        if not attribute or is_truthy(attribute.get("deleted")):
            continue
        if object_source_field.startswith("Attribute[") and attribute_index == 0:
            source_field = object_source_field
        else:
            source_field = f"{object_source_field}.Attribute[{attribute_index}]"
        relation = clean_text(
            attribute.get("object_relation")
            or attribute.get("relation")
            or attribute.get("type")
        ).casefold()
        attribute_type = clean_text(attribute.get("type")).casefold()
        value = clean_text(attribute.get("value"))
        if not value:
            continue
        facts.append(
            {
                "relation": relation,
                "attribute_type": attribute_type,
                "value": value,
                "uuid": attribute.get("uuid"),
                "comment": attribute.get("comment"),
                "first_seen": attribute.get("first_seen"),
                "last_seen": attribute.get("last_seen"),
                "source_field": source_field,
            }
        )
    return facts


def infrastructure_observables(attributes):
    observables = []
    for fact in attributes:
        relation = fact["relation"]
        attribute_type = fact["attribute_type"]
        value = fact["value"]
        values = infrastructure_observable_values(attribute_type, relation, value)
        for observable in values:
            observable["relation"] = relation
            observable["attribute_type"] = attribute_type
            observable["attribute_uuid"] = fact.get("uuid")
            observable["first_seen"] = fact.get("first_seen")
            observable["last_seen"] = fact.get("last_seen")
            observable["source_field"] = fact["source_field"]
            observables.append(observable)
    return deduplicate_observables(observables)


def infrastructure_observable_values(attribute_type, relation, value):
    values = []
    parts = [part.strip() for part in value.split("|") if part.strip()]
    relation_type = f"{attribute_type}|{relation}"
    if len(parts) >= 2 and (
        "domain|ip" in relation_type
        or "hostname|port" in relation_type
        or "ip-src|port" in relation_type
        or "ip-dst|port" in relation_type
    ):
        if "domain|ip" in relation_type:
            values.extend(observable_values_from_text(parts[0], preferred="domain-name"))
            values.extend(observable_values_from_text(parts[1], preferred="ip"))
            return values
        if "hostname|port" in relation_type:
            values.extend(observable_values_from_text(parts[0], preferred="domain-name"))
            attach_port(values, parts[1])
            return values
        values.extend(observable_values_from_text(parts[0], preferred="ip"))
        attach_port(values, parts[1])
        return values

    preferred = ""
    if relation in {"domain", "hostname", "host", "fqdn"} or attribute_type in {
        "domain",
        "hostname",
    }:
        preferred = "domain-name"
    elif relation in {"url"} or attribute_type == "url":
        preferred = "url"
    elif relation in {
        "cidr",
        "netblock",
        "subnet",
        "subnet-announced",
        "ip-subnet",
    }:
        preferred = "ip-network"
    elif relation in {
        "ip",
        "ip-src",
        "ip-dst",
        "src-ip",
        "dst-ip",
        "first-ip",
        "last-ip",
    } or attribute_type in {"ip-src", "ip-dst"}:
        preferred = "ip"
    return observable_values_from_text(value, preferred=preferred)


def observable_values_from_text(value, preferred=""):
    value = clean_text(value)
    if not value:
        return []
    if preferred in {"ip", "ip-network"} or "/" in value:
        parsed = parse_ip_observable(value)
        if parsed:
            return [parsed]
        if preferred in {"ip", "ip-network"}:
            return []
    if preferred == "url" or value.lower().startswith(("http://", "https://")):
        return [{"value": value, "observable_type": "url"}]
    if preferred == "domain-name" or is_domain_value(value):
        return [{"value": value.lower(), "observable_type": "domain-name"}]
    parsed = parse_ip_observable(value)
    if parsed:
        return [parsed]
    return []


def parse_ip_observable(value):
    value = clean_text(value)
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            observable_type = "ipv4-addr" if network.version == 4 else "ipv6-addr"
            return {"value": str(network), "observable_type": observable_type}
        address = ipaddress.ip_address(value)
        observable_type = "ipv4-addr" if address.version == 4 else "ipv6-addr"
        return {"value": str(address), "observable_type": observable_type}
    except ValueError:
        return {}


def is_domain_value(value):
    value = clean_text(value).lower()
    if not value or " " in value or "/" in value or ":" in value:
        return False
    if "." not in value:
        return False
    return bool(re.match(r"^[a-z0-9_.-]+$", value))


def attach_port(observables, port):
    port = clean_text(port)
    if not port:
        return
    for observable in observables:
        observable["port"] = port


def deduplicate_observables(observables):
    seen = set()
    deduplicated = []
    for observable in observables:
        key = (
            observable.get("observable_type", ""),
            observable.get("value", "").casefold(),
            observable.get("port", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(observable)
    return deduplicated


def infrastructure_asn(attributes):
    number = None
    asn_fact = {}
    as_name = ""
    rir = ""
    for fact in attributes:
        relation = fact["relation"]
        attribute_type = fact["attribute_type"]
        value = fact["value"]
        asn_field = relation in {
            "asn",
            "as",
            "number",
            "autonomous-system",
        } or attribute_type in {"as", "asn"}
        asn_literal = re.search(r"\bAS\s*[0-9]{1,10}\b", value, re.IGNORECASE)
        if number is None and (asn_field or asn_literal):
            parsed = parse_asn_number(value)
            if parsed is not None:
                number = parsed
                asn_fact = fact
                continue
        if relation in {
            "as-name",
            "asn-name",
            "description",
            "name",
            "org",
            "organization",
            "organisation",
        }:
            as_name = as_name or value
        if relation in {"rir", "registry"}:
            rir = rir or value
    if number is None:
        return {}
    return {
        "number": number,
        "name": as_name,
        "rir": rir,
        "relation": asn_fact.get("relation"),
        "attribute_type": asn_fact.get("attribute_type"),
        "attribute_uuid": asn_fact.get("uuid"),
        "first_seen": asn_fact.get("first_seen"),
        "last_seen": asn_fact.get("last_seen"),
        "source_field": asn_fact.get("source_field", "Attribute"),
    }


def parse_asn_number(value):
    text = clean_text(value)
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


def autonomous_system_value(asn):
    number = asn.get("number")
    name = clean_text(asn.get("name"))
    if name and name.casefold() != f"as{number}":
        return f"AS{number} {name}"
    return f"AS{number}"


def misp_infrastructure_name(object_name, observables, asn, misp_object):
    preferred = ""
    for observable in observables:
        if observable["observable_type"] in {"domain-name", "url"}:
            preferred = observable["value"]
            break
    if not preferred and observables:
        preferred = observables[0]["value"]
    if not preferred and asn:
        preferred = autonomous_system_value(asn)
    if not preferred:
        preferred = clean_text(misp_object.get("uuid")) or object_name
    return f"MISP {object_name} {preferred}"


def misp_infrastructure_record(
    entity_type,
    value,
    stix_object_type,
    relationship_type,
    source_field,
    misp_object,
    confidence=70,
    attributes=None,
):
    return compact_mapping(
        {
            "entity_type": entity_type,
            "value": value,
            "stix_object_type": stix_object_type,
            "relationship_type": relationship_type,
            "source_field": source_field,
            "confidence": confidence,
            "attributes": compact_mapping(attributes)
            or misp_infrastructure_record_attributes(misp_object, source_field),
        }
    )


def misp_infrastructure_record_attributes(misp_object, source_field):
    return compact_mapping(
        {
            "object_name": misp_object.get("name"),
            "object_uuid": misp_object.get("uuid"),
            "object_meta_category": misp_object.get("meta-category"),
            "source_field": source_field,
        }
    )


def relationship_source_attributes(stix_object_type, value, source_field):
    return {
        "relationship_source_stix_object_type": stix_object_type,
        "relationship_source_value": value,
        "relationship_source_field": source_field,
    }


def deduplicate_misp_infrastructure_records(records):
    seen = set()
    deduplicated = []
    for record in records:
        attributes = compact_mapping(record.get("attributes"))
        key = (
            str(record.get("entity_type", "")).casefold(),
            str(record.get("value", "")).casefold(),
            str(record.get("relationship_type", "")).casefold(),
            str(attributes.get("relationship_source_stix_object_type", "")).casefold(),
            str(attributes.get("relationship_source_value", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(record)
    return deduplicated


def canonicalize_misp_autonomous_system_values(records):
    canonical_by_asn = {}
    for record in records:
        if record.get("entity_type") != "autonomous_system":
            continue
        attributes = compact_mapping(record.get("attributes"))
        asn = attributes.get("asn")
        if asn in ("", None):
            continue
        value = clean_text(record.get("value"))
        current = canonical_by_asn.get(asn, "")
        if len(value) > len(current):
            canonical_by_asn[asn] = value

    canonicalized = []
    for record in records:
        if record.get("entity_type") != "autonomous_system":
            canonicalized.append(record)
            continue
        attributes = compact_mapping(record.get("attributes"))
        asn = attributes.get("asn")
        canonical = canonical_by_asn.get(asn)
        if not canonical:
            canonicalized.append(record)
            continue
        updated = dict(record)
        updated["value"] = canonical
        canonicalized.append(updated)
    return canonicalized


def extract_misp_detection_rules(event):
    event = compact_mapping(event)
    rules = []
    for source in misp_detection_rule_sources(event):
        normalized = normalize_misp_detection_rule(source)
        if normalized:
            rules.append(normalized)
    return deduplicate_misp_detection_rules(rules)


def misp_detection_rule_sources(event):
    event = compact_mapping(event)
    sources = []
    for index, attribute in enumerate(list_values(event.get("Attribute"))):
        attribute = compact_mapping(attribute)
        if not attribute:
            continue
        sources.append(
            {
                "source_field": f"Attribute[{index}]",
                "attribute": attribute,
                "object": {},
            }
        )
    for object_index, misp_object in enumerate(list_values(event.get("Object"))):
        misp_object = compact_mapping(misp_object)
        if not misp_object:
            continue
        for attribute_index, attribute in enumerate(
            list_values(misp_object.get("Attribute"))
        ):
            attribute = compact_mapping(attribute)
            if not attribute:
                continue
            sources.append(
                {
                    "source_field": (
                        f"Object[{object_index}].Attribute[{attribute_index}]"
                    ),
                    "attribute": attribute,
                    "object": misp_object,
                }
            )
    return sources


def normalize_misp_detection_rule(source):
    source = compact_mapping(source)
    attribute = compact_mapping(source.get("attribute"))
    misp_object = compact_mapping(source.get("object"))
    rule_type = misp_detection_rule_type(attribute, misp_object)
    raw_rule_content = str(attribute.get("value") or "").strip()
    rule_content = raw_rule_content.strip()
    if rule_type not in DETECTION_RULE_TYPES:
        return {}
    if not clean_text(rule_content) or is_truthy(attribute.get("deleted")):
        return {}
    opencti_indicator_compatible = True
    compatibility_reason = ""
    if rule_type == "sigma":
        (
            opencti_indicator_compatible,
            compatibility_reason,
        ) = sigma_rule_opencti_compatibility(rule_content)
    title = detection_rule_title(rule_type, raw_rule_content, attribute)
    return compact_mapping(
        {
            "value": title,
            "rule_type": rule_type,
            "pattern_type": rule_type,
            "pattern": rule_content,
            "opencti_indicator_compatible": opencti_indicator_compatible,
            "opencti_indicator_compatibility_reason": compatibility_reason,
            "attribute_category": attribute.get("category"),
            "attribute_uuid": attribute.get("uuid"),
            "object_name": misp_object.get("name"),
            "object_uuid": misp_object.get("uuid"),
            "first_seen": attribute.get("first_seen"),
            "last_seen": attribute.get("last_seen"),
            "tags": [tag_name for tag_name in attribute_tags(attribute) if tag_name],
            "source_field": source.get("source_field"),
        }
    )


def misp_detection_rule_type(attribute, misp_object):
    attribute = compact_mapping(attribute)
    misp_object = compact_mapping(misp_object)
    attribute_type = clean_text(attribute.get("type")).casefold()
    object_relation = clean_text(attribute.get("object_relation")).casefold()
    object_name = clean_text(misp_object.get("name")).casefold()
    if object_relation in DETECTION_RULE_TYPES:
        return object_relation
    if attribute_type not in DETECTION_RULE_TYPES:
        return ""
    if object_name in DETECTION_RULE_TYPES:
        return object_name
    return attribute_type


def detection_rule_title(rule_type, rule_content, attribute):
    comment = clean_text(attribute.get("comment"))
    if comment:
        return comment

    extracted = extract_detection_rule_name(rule_type, rule_content)
    if extracted:
        return extracted

    return "detection rule"


def extract_detection_rule_name(rule_type, rule_content):
    if rule_type == "sigma":
        match = re.search(r"(?im)^\s*title\s*:\s*(.+?)\s*$", rule_content)
        if match:
            return clean_text(match.group(1).strip("'\""))

    if rule_type == "yara":
        match = re.search(
            r"(?im)^\s*(?:private\s+)?rule\s+([A-Za-z0-9_.$-]+)",
            rule_content,
        )
        if match:
            return clean_text(match.group(1))

    if rule_type in {"snort", "suricata"}:
        match = re.search(r'msg\s*:\s*"([^"]+)"', rule_content, flags=re.IGNORECASE)
        if match:
            return clean_text(match.group(1))

    return ""


def sigma_rule_has_valid_shape(rule_content):
    compatible, _reason = sigma_rule_opencti_compatibility(rule_content)
    return compatible


def sigma_rule_opencti_compatibility(rule_content):
    content = str(rule_content or "").strip()
    if not content:
        return False, "empty sigma rule"
    if yaml:
        try:
            parsed = yaml.safe_load(content)
        except Exception:
            return False, "invalid sigma yaml"
        if not isinstance(parsed, Mapping):
            return False, "sigma yaml is not a mapping"
        if not clean_text(parsed.get("title")):
            return False, "missing title"
        logsource = parsed.get("logsource")
        if not isinstance(logsource, Mapping) or not compact_mapping(logsource):
            return False, "missing logsource"
        detection = parsed.get("detection")
        if not isinstance(detection, Mapping):
            return False, "missing detection mapping"
        if not clean_text(detection.get("condition")):
            return False, "missing detection condition"
        selections = [
            value
            for key, value in detection.items()
            if clean_text(key).casefold() != "condition"
            and value not in ("", None, [], {})
        ]
        if not selections:
            return False, "missing detection selection"
        return validate_sigma_with_opencti_parser(content)

    if not re.search(r"(?im)^\s*title\s*:", content):
        return False, "missing title"
    if not re.search(r"(?im)^\s*logsource\s*:", content):
        return False, "missing logsource"
    if not re.search(r"(?im)^\s*detection\s*:", content):
        return False, "missing detection"
    if not re.search(r"(?im)^\s*condition\s*:", content):
        return False, "missing detection condition"
    in_block_scalar = None
    for line in content.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if in_block_scalar is not None:
            if indent > in_block_scalar:
                continue
            in_block_scalar = None
        if stripped.startswith("- "):
            continue
        if ":" not in stripped:
            return False, "invalid yaml-like line"
        if stripped.endswith("|") or stripped.endswith(">"):
            in_block_scalar = indent
    return validate_sigma_with_opencti_parser(content)


def validate_sigma_with_opencti_parser(content):
    """Match the Sigma syntax gate used by the supported OpenCTI 6.9 runtime."""
    if SigmaCollectionParser is None:
        return False, "OpenCTI-compatible Sigma parser unavailable"
    try:
        SigmaCollectionParser(content)
    except Exception:
        return False, "rejected by OpenCTI-compatible Sigma parser"
    return True, ""


def deduplicate_misp_detection_rules(rules):
    seen = set()
    deduplicated = []
    for rule in rules:
        key = (
            str(rule.get("attribute_uuid", "")).casefold(),
            str(rule.get("rule_type", "")).casefold(),
            str(rule.get("pattern", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(rule)
    return deduplicated


def clean_text(value):
    return " ".join(str(value or "").strip().split())


def is_truthy(value):
    if value is True:
        return True
    return clean_text(value).casefold() in {"1", "true", "yes"}


class MISPProcessor:
    def __init__(
        self,
        settings,
        misp_client,
        api_client,
        logger,
        exporter=send_bundle,
        state_repository_factory=MISPEventStateRepository,
        sleeper=time.sleep,
        ingest_pause_seconds=2,
        feed_adapter=None,
        decision_audit=None,
        artifact_dedup=None,
        quarantine_repository=None,
        graph_deduplication_index=None,
    ):
        self.settings = settings
        self.misp_client = misp_client
        self.feed_adapter = feed_adapter or MISPFeedAdapter(
            misp_client,
            limits=settings.adapter_limits,
            logger=logger,
        )
        self.api_client = api_client
        self.log = logger
        self.exporter = exporter
        self.state_repository_factory = state_repository_factory
        self.sleeper = sleeper
        self.ingest_pause_seconds = ingest_pause_seconds
        self.decision_audit = decision_audit or DecisionAuditLog()
        self.artifact_dedup = artifact_dedup
        self.quarantine_repository = quarantine_repository or self.build_quarantine_repository(
            settings
        )
        self.graph_deduplication_index = (
            graph_deduplication_index or self.build_graph_deduplication_index(settings)
        )
        self.ip_asn_enricher = load_ip_asn_enricher(
            getattr(settings, "ip_asn_enrichment_file", "")
        )
        self.policy_config = PolicyConfig(
            quarantine_score_threshold=settings.quarantine_score_threshold,
            enable_quarantine=settings.enable_quarantine,
            min_score_to_ingest=settings.min_score_to_ingest,
            max_days_old=settings.max_days_old,
            min_score_for_old_pulse=settings.min_score_for_old_event,
            max_days_hard_filter=settings.max_days_hard_filter,
        )
        self.graph_candidate_policy = graph_candidate_policy_from_settings(settings)
        self.contextual_scoring_config = contextual_scoring_config_from_settings(
            settings
        )

    def build_quarantine_repository(self, settings):
        repository_file = getattr(settings, "quarantine_repository_file", "")
        if not repository_file:
            return None
        return QuarantineRepository(repository_file)

    def build_graph_deduplication_index(self, settings):
        lookups = []
        state_file = getattr(settings, "graph_dedup_state_file", "")
        if state_file:
            lookups.append(GraphDeduplicationIndex(state_file))
        if getattr(settings, "opencti_graph_lookup", False) and self.api_client:
            lookups.append(OpenCTIGraphLookup(self.api_client, logger=self.log))
        if not lookups:
            return None
        if len(lookups) == 1:
            return lookups[0]
        return CompositeGraphLookup(*lookups)

    def run_once(self):
        state = self.state_repository_factory(self.settings.state_file)
        summaries = []

        for query in self.settings.misp_queries:
            summaries.append(self.process_query(query, state))

        return summaries

    def process_query(self, query, state):
        self.log(f"MISP query: {query}")
        candidates = self.feed_adapter.search(query)
        adapter_available = getattr(self.feed_adapter, "last_search_available", len(candidates))
        adapter_skipped = getattr(self.feed_adapter, "last_search_skipped", 0)
        outcomes = {
            "ingest": 0,
            "drop": 0,
            "quarantine": 0,
            "skip": 0,
            "error": 0,
            "dry_run": 0,
        }
        reviewed = 0

        for candidate in candidates[: self.settings.max_events_per_run]:
            reviewed += 1
            action = self.process_event_outcome(query, candidate, state)
            if action in outcomes:
                outcomes[action] += 1

            if action == "ingest":
                self.sleeper(self.ingest_pause_seconds)

        summary = FeedRunSummary(
            source=self.feed_adapter.source,
            query=query,
            reviewed=reviewed,
            ingested=outcomes["ingest"],
            available=adapter_available,
            dropped=outcomes["drop"],
            quarantined=outcomes["quarantine"],
            skipped=outcomes["skip"] + adapter_skipped,
            errors=outcomes["error"],
            dry_run=outcomes["dry_run"],
        )
        self.log(
            f"MISP query summary: {summary.query} reviewed={summary.reviewed} "
            f"ingested={summary.ingested} dropped={summary.dropped} "
            f"quarantined={summary.quarantined} skipped={summary.skipped} "
            f"errors={summary.errors} dry_run={summary.dry_run} "
            f"available={summary.available}"
        )
        return summary

    def process_event(self, query, event, state):
        return self.process_event_outcome(query, event, state) == "ingest"

    def process_event_outcome(self, query, event, state):
        candidate_ref = self.normalize_feed_candidate(event)
        event_id = candidate_ref.external_id

        if not event_id:
            self.log(f"Skip MISP event without id: {candidate_ref.title}")
            self.record_decision(
                query,
                candidate_ref,
                action="skip",
                reason="missing external id",
            )
            return "skip"

        if state.has_event(event_id):
            self.log(f"Skip MISP state: {candidate_ref.title}")
            self.record_decision(
                query,
                candidate_ref,
                action="skip",
                reason="already processed",
            )
            return "skip"

        candidate = self.enrich_candidate(query, candidate_ref)
        if not candidate:
            self.record_decision(
                query,
                candidate_ref,
                action="skip",
                reason="enrichment failed",
            )
            return "skip"

        action, reason = self.candidate_tlp_decision(candidate)
        if action != "ingest":
            self.record_decision(query, candidate_ref, action, reason, candidate)
            return action

        candidate = self.apply_contextual_scoring(candidate_ref, candidate)
        action, reason = self.candidate_policy_decision(candidate)
        if action != "ingest":
            self.record_decision(query, candidate_ref, action, reason, candidate)
            return action

        candidate = self.apply_indicator_type_filter(query, candidate_ref, candidate)
        if not candidate:
            return "skip"

        candidate = self.apply_artifact_dedup(query, candidate_ref, candidate)
        if not candidate:
            return "skip"
        if self.is_graph_replay_only(candidate):
            reason = "all indicators already known; graph replay only"

        if self.settings.dry_run:
            self.log(
                f"MISP dry-run: {candidate.name} score={candidate.score} "
                f"reason={reason}"
            )
            self.record_decision(
                query,
                candidate_ref,
                action="dry_run",
                reason=reason,
                candidate=candidate,
            )
            return "dry_run"

        ingest_result = self.ingest_candidate(candidate_ref, candidate, reason)
        if not ingest_result:
            self.record_decision(
                query,
                candidate_ref,
                action="error",
                reason="export failed",
                candidate=candidate,
            )
            return "error"

        self.mark_artifacts(candidate_ref, candidate)
        state.mark_event(event_id)
        self.record_decision(query, candidate_ref, "ingest", reason, candidate)
        if isinstance(ingest_result, dict):
            self.mark_exported_graph_plan(candidate_ref, candidate, ingest_result)
        return "ingest"

    def normalize_feed_candidate(self, event):
        if hasattr(event, "external_id") and hasattr(event, "raw"):
            return event
        return event_to_feed_candidate(event)

    def enrich_candidate(self, query, candidate_ref):
        enriched = self.feed_adapter.enrich(candidate_ref)
        if not enriched:
            self.log(f"Skip MISP enrich failed: {candidate_ref.title}")
            return None

        candidate = self.prepare_candidate(query, enriched.raw)
        self.log(
            f"MISP candidate: {candidate.name} age={age_label(candidate.age)} "
            f"iocs={candidate.ioc_count} score={candidate.score}"
        )
        return candidate

    def evaluate_candidate_policy(self, candidate):
        action, reason = self.candidate_policy_decision(candidate)
        return action == "ingest", reason

    def apply_contextual_scoring(self, candidate_ref, candidate):
        metadata = decision_metadata(
            candidate_ref,
            candidate,
            graph_candidate_policy=self.graph_candidate_policy,
            ip_asn_enricher=self.ip_asn_enricher,
            contextual_scoring_config=self.contextual_scoring_config,
            include_export_plan=False,
        )
        evidence = metadata.get("contextual_scoring", {})
        decision_score = int(evidence.get("decision_score", candidate.score))
        if decision_score != candidate.score:
            self.log(
                f"MISP contextual score applied: {candidate.name} "
                f"base={candidate.score} decision={decision_score}"
            )
        return replace(candidate, score=decision_score)

    def candidate_policy_decision(self, candidate):
        decision, reason = should_ingest(
            candidate.event,
            candidate.score,
            self.policy_config,
        )

        if decision == "quarantine":
            self.log(
                f"MISP quarantine: {candidate.name} "
                f"score={candidate.score} reason={reason}"
            )
            return "quarantine", reason

        if decision is False:
            self.log(
                f"MISP drop: {candidate.name} score={candidate.score} reason={reason}"
            )
            return "drop", reason

        return "ingest", reason

    def candidate_tlp_decision(self, candidate):
        allowed, reason = tlp_is_allowed(
            candidate.event.get("tags", []),
            getattr(self.settings, "allowed_tlp", []),
        )
        if not allowed:
            self.log(f"MISP drop: {candidate.name} reason={reason}")
            return "drop", reason
        return "ingest", "ok"

    def record_decision(self, query, candidate_ref, action, reason, candidate=None):
        title = candidate.name if candidate and candidate.name else candidate_ref.title
        indicator_count = candidate.ioc_count if candidate else 0
        score = candidate.score if candidate else None
        candidate_age = candidate.age if candidate else None

        metadata = decision_metadata(
            candidate_ref,
            candidate,
            graph_candidate_policy=self.graph_candidate_policy,
            graph_export_mode=getattr(self.settings, "graph_export_mode", "audit"),
            graph_deduplication_index=self.graph_deduplication_index,
            ip_asn_enricher=self.ip_asn_enricher,
            contextual_scoring_config=self.contextual_scoring_config,
        )
        if metadata.get("contextual_scoring"):
            metadata["contextual_scoring"] = finalize_contextual_score_evidence(
                metadata["contextual_scoring"],
                score,
                action,
                reason,
            )

        decision = DecisionRecord(
            action=action,
            reason=reason,
            source_key=candidate_ref.source.key,
            external_id=candidate_ref.external_id,
            title=title,
            query=query,
            score=score,
            age_days=candidate_age,
            indicator_count=indicator_count,
            metadata=metadata,
        )

        try:
            self.decision_audit.record(decision)
        except Exception as exc:
            self.log(f"MISP decision audit failed: {title} error={exc}")

        if action == "quarantine":
            self.record_quarantine(query, candidate_ref, reason, candidate)

    def record_quarantine(self, query, candidate_ref, reason, candidate=None):
        if not self.quarantine_repository:
            return

        title = candidate.name if candidate and candidate.name else candidate_ref.title
        indicators = list(candidate.indicators if candidate else candidate_ref.indicators)
        raw_source = candidate.event if candidate else candidate_ref.raw
        raw_snapshot, truncated = bounded_raw_snapshot(
            raw_source,
            getattr(self.settings, "quarantine_raw_snapshot_max_bytes", 65536),
        )
        metadata = decision_metadata(
            candidate_ref,
            candidate,
            graph_candidate_policy=self.graph_candidate_policy,
            graph_export_mode=getattr(self.settings, "graph_export_mode", "audit"),
            graph_deduplication_index=self.graph_deduplication_index,
            ip_asn_enricher=self.ip_asn_enricher,
            contextual_scoring_config=self.contextual_scoring_config,
        )
        if metadata.get("contextual_scoring"):
            metadata["contextual_scoring"] = finalize_contextual_score_evidence(
                metadata["contextual_scoring"],
                candidate.score if candidate else None,
                "quarantine",
                reason,
            )
        if truncated:
            metadata["raw_snapshot_truncated"] = True

        record = QuarantineRecord(
            source_key=candidate_ref.source.key,
            external_id=candidate_ref.external_id,
            title=title,
            reason=reason,
            query=query,
            score=candidate.score if candidate else None,
            age_days=candidate.age if candidate else None,
            indicator_count=candidate.ioc_count if candidate else len(indicators),
            indicators=indicators,
            metadata=metadata,
            raw_snapshot=raw_snapshot,
        )

        try:
            queued = self.quarantine_repository.add(record)
            self.log(
                f"MISP quarantine queued: {title} "
                f"id={queued.get('quarantine_id')} status={queued.get('status')}"
            )
        except Exception as exc:
            self.log(f"MISP quarantine repository failed: {title} error={exc}")

    def apply_artifact_dedup(self, query, candidate_ref, candidate):
        if not self.artifact_dedup:
            return candidate

        indicators, duplicate_count = self.artifact_dedup.filter_new_indicators(
            candidate.indicators
        )
        if duplicate_count:
            self.log(
                f"MISP artifact dedup: {candidate.name} duplicates={duplicate_count}"
            )
        if not indicators:
            replay_candidate = self.artifact_dedup_graph_replay_candidate(
                candidate_ref,
                candidate,
            )
            if replay_candidate:
                return replay_candidate
            self.record_decision(
                query,
                candidate_ref,
                action="skip",
                reason="all indicators already known",
                candidate=candidate,
            )
            return None
        if len(indicators) == len(candidate.indicators):
            return candidate
        return MISPEventCandidate(
            event=candidate.event,
            name=candidate.name,
            description=candidate.description,
            indicators=indicators,
            ioc_count=len(indicators),
            age=candidate.age,
            score=candidate.score,
            score_details=candidate.score_details,
        )

    def artifact_dedup_graph_replay_candidate(self, candidate_ref, candidate):
        if not self.graph_replay_on_artifact_dedup_enabled():
            return None
        try:
            _, metadata = self.graph_policy_for_export(candidate_ref, candidate)
        except Exception as exc:
            self.log(
                f"MISP artifact dedup graph replay planning failed: "
                f"{candidate.name} error={exc}"
            )
            return None
        graph_plan = compact_mapping(metadata.get("graph_export_plan"))
        exported_objects = int(graph_plan.get("exported_object_count") or 0)
        exported_relationships = int(
            graph_plan.get("exported_relationship_count") or 0
        )
        if exported_objects < 1 and exported_relationships < 1:
            self.log(
                f"MISP artifact dedup graph replay skipped: "
                f"{candidate.name} no exportable graph context"
            )
            return None

        event = dict(candidate.event)
        controls = compact_mapping(event.get("narrowcti_controls"))
        controls.update(
            {
                "graph_replay_only": True,
                "graph_replay_reason": "all indicators already known",
                "graph_replay_exported_object_count": exported_objects,
                "graph_replay_exported_relationship_count": exported_relationships,
            }
        )
        event["narrowcti_controls"] = controls
        self.log(
            f"MISP artifact dedup graph replay: {candidate.name} "
            f"objects={exported_objects} relationships={exported_relationships}"
        )
        return MISPEventCandidate(
            event=event,
            name=candidate.name,
            description=candidate.description,
            indicators=[],
            ioc_count=0,
            age=candidate.age,
            score=candidate.score,
            score_details=candidate.score_details,
        )

    def graph_replay_on_artifact_dedup_enabled(self):
        return bool(
            getattr(self.settings, "graph_replay_on_artifact_dedup", False)
        ) and getattr(self.settings, "graph_export_mode", "audit") == "export"

    def is_graph_replay_only(self, candidate):
        controls = compact_mapping(candidate.event.get("narrowcti_controls"))
        return bool(controls.get("graph_replay_only"))

    def apply_indicator_type_filter(self, query, candidate_ref, candidate):
        indicators, dropped_count = filter_indicators_by_type(
            candidate.indicators,
            getattr(self.settings, "allowed_indicator_types", []),
        )
        if not dropped_count:
            return candidate
        self.log(
            f"MISP indicator type filter: {candidate.name} "
            f"dropped={dropped_count} kept={len(indicators)}"
        )
        if not indicators:
            self.record_decision(
                query,
                candidate_ref,
                action="skip",
                reason="all indicators disallowed by type",
                candidate=candidate,
            )
            return None
        return MISPEventCandidate(
            event=candidate.event,
            name=candidate.name,
            description=candidate.description,
            indicators=indicators,
            ioc_count=len(indicators),
            age=candidate.age,
            score=candidate.score,
            score_details=candidate.score_details,
        )

    def mark_artifacts(self, candidate_ref, candidate):
        if not self.artifact_dedup:
            return
        if not candidate.indicators:
            return
        try:
            added = self.artifact_dedup.mark_indicators(
                candidate.indicators,
                source_key=candidate_ref.source.key,
                external_id=candidate_ref.external_id,
                title=candidate.name or candidate_ref.title,
            )
        except Exception as exc:
            self.log(f"MISP artifact dedup mark failed: {candidate.name} error={exc}")
            return
        if added:
            self.log(f"MISP artifact dedup mark: {candidate.name} added={added}")

    def ingest_candidate(self, candidate_ref, candidate, reason):
        self.log(f"MISP ingest: {candidate.name} score={candidate.score} reason={reason}")
        try:
            graph_policy = None
            graph_metadata = None
            export_kwargs = {
                "identity_name": feed_source_identity_name(candidate_ref.source),
                "published_at": candidate.event.get("date")
                or candidate.event.get("created"),
            }
            try:
                exporter_parameters = signature(self.exporter).parameters.values()
                accepts_published_at = any(
                    parameter.name == "published_at"
                    or parameter.kind == Parameter.VAR_KEYWORD
                    for parameter in exporter_parameters
                )
            except (TypeError, ValueError):
                accepts_published_at = True
            if not accepts_published_at:
                export_kwargs.pop("published_at", None)
            if getattr(self.settings, "graph_export_mode", "audit") == "export":
                graph_policy, graph_metadata = self.graph_policy_for_export(
                    candidate_ref,
                    candidate,
                )
                export_kwargs.update(
                    {
                        "graph_candidate_policy": graph_policy,
                        "graph_export_mode": getattr(
                            self.settings,
                            "graph_export_mode",
                            "audit",
                        ),
                    }
                )
            imported_iocs = self.exporter(
                self.api_client,
                candidate.name,
                candidate.description,
                candidate.score,
                candidate.indicators,
                **export_kwargs,
            )
        except Exception as exc:
            self.log(f"MISP ingest failed: {candidate.name} error={exc}")
            return False

        self.log(f"MISP ingest complete: {candidate.name} indicators={imported_iocs}")
        return graph_metadata or True

    def graph_policy_for_export(self, candidate_ref, candidate):
        metadata = decision_metadata(
            candidate_ref,
            candidate,
            graph_candidate_policy=self.graph_candidate_policy,
            graph_export_mode=getattr(self.settings, "graph_export_mode", "audit"),
            graph_deduplication_index=self.graph_deduplication_index,
            ip_asn_enricher=self.ip_asn_enricher,
            contextual_scoring_config=self.contextual_scoring_config,
        )
        graph_policy = exportable_graph_candidate_policy(
            metadata.get("graph_candidate_policy", {}),
            metadata.get("graph_export_plan", {}),
            metadata.get("graph_export_plan_known_keys", {}),
        )
        metadata["graph_export_plan"] = build_graph_export_plan(
            graph_policy,
            mode="export",
        )
        return graph_policy, metadata

    def mark_exported_graph_plan(self, candidate_ref, candidate, metadata):
        if not self.graph_deduplication_index or not hasattr(
            self.graph_deduplication_index,
            "mark_exported_plan",
        ):
            return
        try:
            added = self.graph_deduplication_index.mark_exported_plan(
                metadata.get("graph_export_plan", {}),
                source_key=candidate_ref.source.key,
                external_id=candidate_ref.external_id,
                title=candidate.name or candidate_ref.title,
            )
        except Exception as exc:
            self.log(f"MISP graph dedup mark failed: {candidate.name} error={exc}")
            return
        if added.get("entities") or added.get("relationships"):
            self.log(
                f"MISP graph dedup mark: {candidate.name} "
                f"entities={added.get('entities', 0)} "
                f"relationships={added.get('relationships', 0)}"
            )

    def apply_ioc_guardrail(self, event, indicators):
        ioc_count = len(indicators)
        exported_ioc_count = min(ioc_count, self.settings.max_iocs_per_event)
        controls = compact_mapping(event.get("narrowcti_controls"))
        controls.update(
            {
                "indicator_count": ioc_count,
                "max_iocs_per_event": self.settings.max_iocs_per_event,
                "exported_indicator_count": exported_ioc_count,
                "iocs_truncated": ioc_count > self.settings.max_iocs_per_event,
            }
        )
        event["narrowcti_controls"] = controls

        if controls["iocs_truncated"]:
            self.log(
                "MISP event exceeds IOC guardrail: "
                f"event={event.get('id') or event.get('uuid')} "
                f"iocs={ioc_count} "
                f"limit={self.settings.max_iocs_per_event} "
                "action=truncate"
            )
            return indicators[: self.settings.max_iocs_per_event], ioc_count

        return indicators, ioc_count

    def prepare_candidate(self, query, event):
        indicators, ioc_count = self.apply_ioc_guardrail(
            event,
            list(event.get("indicators", [])),
        )
        score_details = calculate_score_details(
            event,
            query,
            source_confidence=getattr(self.settings, "source_confidence", 50),
        )

        return MISPEventCandidate(
            event=event,
            name=event.get("name"),
            description=event.get("description", ""),
            indicators=indicators,
            ioc_count=ioc_count,
            age=age_days(event.get("created")),
            score=score_details["final_score"],
            score_details=score_details,
        )


def graph_candidate_policy_from_settings(settings):
    graph_export_mode = getattr(settings, "graph_export_mode", "audit")
    return {
        "min_entity_confidence": getattr(settings, "graph_min_entity_confidence", 0),
        "min_relationship_confidence": getattr(
            settings,
            "graph_min_relationship_confidence",
            0,
        ),
        "allowed_entity_types": safe_graph_export_allowed_entity_types(
            graph_export_mode,
            getattr(settings, "graph_allowed_entity_types", []),
        ),
        "allowed_stix_object_types": safe_graph_export_allowed_stix_object_types(
            graph_export_mode,
            getattr(settings, "graph_allowed_stix_object_types", []),
        ),
        "require_relationship_provenance": getattr(
            settings,
            "graph_require_relationship_provenance",
            False,
        ),
        "allow_infrastructure_victimology_export": getattr(
            settings,
            "enable_infrastructure_victimology_export",
            False,
        ),
    }
