import re
from collections import Counter
from collections.abc import Mapping

from core.tlp import extract_tlp_values, normalize_tlp


GRAPH_EVIDENCE_VERSION = "v1.0.0"

ENTITY_TARGETS = {
    "campaign": ("campaign", "related-to"),
    "course_of_action": ("course-of-action", "related-to"),
    "threat_actor": ("threat-actor", "attributed-to"),
    "threat_actor_individual": ("threat-actor", "attributed-to"),
    "intrusion_set": ("intrusion-set", "attributed-to"),
    "infrastructure": ("infrastructure", "uses"),
    "autonomous_system": ("autonomous-system", "related-to"),
    "channel": ("channel", "uses"),
    "event": ("event", "related-to"),
    "malware": ("malware", "uses"),
    "narrative": ("narrative", "related-to"),
    "security_platform": ("security-platform", "related-to"),
    "tool": ("tool", "uses"),
    "vulnerability": ("vulnerability", "related-to"),
    "observable": ("observable", "based-on"),
    "attack_pattern": ("attack-pattern", "uses"),
    "attack_tactic": ("x-mitre-tactic", "uses"),
    "target_sector": ("identity", "targets"),
    "target_organization": ("identity", "targets"),
    "target_individual": ("identity", "targets"),
    "target_system": ("identity", "targets"),
    "target_administrative_area": ("location", "targets"),
    "target_city": ("location", "targets"),
    "target_country": ("location", "targets"),
    "target_position": ("location", "targets"),
    "target_region": ("location", "targets"),
    "source_identity": ("identity", "originated-from"),
    "collector": ("identity", "collected-by"),
    "tag": ("label", "labels"),
    "marking": ("marking-definition", "marked-with"),
    "external_reference": ("external-reference", "references"),
    "detection_rule": ("indicator", "detects"),
    "attack_platform": ("x-narrowcti-attack-platform", "applies-to"),
    "attack_data_source": ("x-mitre-data-source", "detects"),
    "attack_data_component": ("x-mitre-data-component", "detects"),
    "detection_guidance": ("note", "documents"),
    "event_report": ("note", "documents"),
    "sighting": ("sighting", "sighting-of"),
    "object_reference": ("relationship", "related-to"),
}

TARGET_SECTOR_ALIASES = {
    "aerospace and defense": "Defense",
    "banking": "Finance",
    "banking and finance": "Finance",
    "defence": "Defense",
    "defense industrial base": "Defense",
    "e-commerce": "Retail",
    "financial": "Finance",
    "financial sector": "Finance",
    "financial services": "Finance",
    "fintech": "Finance",
    "government and public sector": "Government",
    "health": "Healthcare",
    "health care": "Healthcare",
    "healthcare and public health": "Healthcare",
    "information technology": "Technology",
    "it": "Technology",
    "oil and gas": "Energy",
    "public sector": "Government",
    "telecom": "Telecommunications",
    "telecommunications": "Telecommunications",
    "transport": "Transportation",
}

TARGET_COUNTRY_ALIASES = {
    "ar": "Argentina",
    "arg": "Argentina",
    "br": "Brazil",
    "bra": "Brazil",
    "cn": "China",
    "de": "Germany",
    "fr": "France",
    "gb": "United Kingdom",
    "ir": "Iran",
    "iran, islamic republic of": "Iran",
    "kp": "North Korea",
    "kr": "South Korea",
    "ru": "Russia",
    "russian federation": "Russia",
    "uk": "United Kingdom",
    "us": "United States",
    "usa": "United States",
    "u.s.": "United States",
    "u.s.a.": "United States",
    "united states of america": "United States",
}

TARGET_REGION_ALIASES = {
    "apac": "Asia-Pacific",
    "asia pacific": "Asia-Pacific",
    "asia-pacific": "Asia-Pacific",
    "cis": "Commonwealth of Independent States",
    "emea": "Europe, Middle East and Africa",
    "eu": "Europe",
    "european union": "Europe",
    "latam": "Latin America",
    "latin america and caribbean": "Latin America",
    "mena": "Middle East and North Africa",
    "middle east": "Middle East",
    "north america": "North America",
    "south america": "South America",
}

INTRUSION_SET_ALIASES = {
    "hidden cobra": "Lazarus Group",
    "lazarus": "Lazarus Group",
    "lazarus group": "Lazarus Group",
    "palmerworm": "BlackTech",
}

MALWARE_ALIASES = {
    "lumma c2": "Lumma Stealer",
    "lummac2": "Lumma Stealer",
    "lumma stealer": "Lumma Stealer",
    "lummastealer": "Lumma Stealer",
}

ATTACK_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
CVE_ID_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
MISP_GALAXY_TAG_PATTERN = re.compile(
    r'^misp-galaxy:([^=]+)=(?:"([^"]+)"|(.+))$',
    re.IGNORECASE,
)
MISP_INFRA_CONTEXT_MAX_INFRASTRUCTURES = 50
MISP_INFRA_CONTEXT_MAX_PAIRINGS = 100
MISP_INFRA_CONTEXT_MAX_RECORDS = 200
MISP_INFRA_CAPABILITY_ENTITY_TYPES = {
    "malware",
    "tool",
    "channel",
}
MISP_INFRA_VICTIMOLOGY_ENTITY_TYPES = {
    "target_administrative_area",
    "target_city",
    "target_country",
    "target_individual",
    "target_organization",
    "target_position",
    "target_region",
    "target_sector",
    "target_system",
}

MISP_CAMPAIGN_CONTEXT_MAX_CAMPAIGNS = 50
MISP_CAMPAIGN_CONTEXT_MAX_PAIRINGS = 100
MISP_CAMPAIGN_CONTEXT_MAX_RECORDS = 200
MISP_CAMPAIGN_ADVERSARY_ENTITY_TYPES = {
    "intrusion_set",
    "threat_actor",
    "threat_actor_individual",
}
MISP_CAMPAIGN_CAPABILITY_ENTITY_TYPES = {
    "attack_pattern",
    "channel",
    "malware",
    "tool",
}


def build_graph_evidence(metadata, source_key="", external_id="", title=""):
    metadata = metadata if isinstance(metadata, Mapping) else {}
    records = []
    records.extend(otx_entity_evidence(metadata.get("otx_entities"), source_key))
    records.extend(mitre_attack_evidence(metadata.get("mitre_attack"), source_key))
    records.extend(misp_metadata_evidence(metadata, source_key))
    misp_timeline = misp_timeline_attributes(metadata)
    misp_context_anchor = single_misp_context_anchor(metadata)
    records.extend(
        with_default_timeline(
            misp_galaxy_evidence(
                metadata.get("misp_galaxies"),
                source_key,
                misp_context_anchor,
            ),
            misp_timeline,
        )
    )
    records.extend(
        with_default_timeline(
            misp_vulnerability_evidence(
                metadata.get("misp_vulnerabilities"),
                source_key,
            ),
            misp_timeline,
        )
    )
    records.extend(
        with_default_timeline(
            misp_campaign_evidence(metadata.get("misp_campaigns"), source_key),
            misp_timeline,
        )
    )
    records.extend(
        with_default_timeline(
            misp_victimology_evidence(
                metadata.get("misp_victimology"),
                source_key,
                misp_context_anchor,
            ),
            misp_timeline,
        )
    )
    records.extend(
        with_default_timeline(
            misp_event_report_evidence(
                metadata.get("misp_event_reports"),
                source_key,
            ),
            misp_timeline,
        )
    )
    records.extend(
        with_default_timeline(
            misp_sighting_evidence(metadata.get("misp_sightings"), source_key),
            misp_timeline,
        )
    )
    records.extend(
        with_default_timeline(
            misp_object_reference_evidence(
                metadata.get("misp_object_references"),
                source_key,
            ),
            misp_timeline,
        )
    )
    records.extend(
        with_default_timeline(
            misp_infrastructure_evidence(
                metadata.get("misp_infrastructure"),
                source_key,
            ),
            misp_timeline,
        )
    )
    records.extend(
        with_default_timeline(
            misp_detection_rule_evidence(
                metadata.get("misp_detection_rules"),
                source_key,
            ),
            misp_timeline,
        )
    )
    records.extend(
        misp_campaign_context_relationship_evidence(records, source_key)
    )
    records.extend(
        misp_infrastructure_context_relationship_evidence(records, source_key)
    )

    return {
        "version": GRAPH_EVIDENCE_VERSION,
        "source_key": clean_string(source_key),
        "external_id": clean_string(external_id),
        "title": clean_string(title),
        "record_count": len(records),
        "counts": dict(
            sorted(Counter(record["entity_type"] for record in records).items())
        ),
        "records": records,
    }


def with_default_timeline(records, timeline_attributes):
    timeline_attributes = compact_mapping(timeline_attributes)
    if not timeline_attributes:
        return list(records or [])
    enriched = []
    for record in records or []:
        if not isinstance(record, Mapping):
            continue
        merged = dict(record)
        attributes = {
            **timeline_attributes,
            **compact_mapping(record.get("attributes")),
        }
        if attributes:
            merged["attributes"] = attributes
        enriched.append(merged)
    return enriched


def misp_timeline_attributes(metadata):
    return compact_mapping(
        {
            "source_created": metadata.get("misp_event_created"),
            "source_timestamp": metadata.get("misp_event_timestamp"),
            "source_date": metadata.get("misp_event_date"),
        }
    )


def otx_entity_evidence(entities, source_key=""):
    if not isinstance(entities, Mapping):
        return []
    records = []
    timeline_attributes = otx_timeline_attributes(entities)
    for item in entities.get("records") or []:
        if not isinstance(item, Mapping):
            continue
        attributes = {
            **timeline_attributes,
            **compact_mapping(item.get("attributes")),
        }
        record = evidence_record(
            entity_type=item.get("entity_type"),
            value=item.get("value"),
            source_key=source_key,
            source_name="otx",
            source_field=item.get("source_field"),
            confidence=item.get("confidence"),
            display_name=item.get("display_name"),
            attributes=attributes,
            stix_object_type=item.get("stix_object_type"),
            relationship_type=item.get("relationship_type"),
        )
        if record:
            records.append(record)
    return records


def otx_timeline_attributes(entities):
    lifecycle = compact_mapping(entities.get("lifecycle"))
    observation_window = compact_mapping(entities.get("indicator_observation_window"))
    return compact_mapping(
        {
            "source_created": lifecycle.get("created"),
            "source_modified": lifecycle.get("modified"),
            "first_seen_min": observation_window.get("first_seen_min"),
            "last_seen_max": observation_window.get("last_seen_max"),
        }
    )


def mitre_attack_evidence(mitre_attack, source_key=""):
    if not isinstance(mitre_attack, Mapping) or not mitre_attack.get("available"):
        return []
    records = []
    for technique in mitre_attack.get("resolved") or []:
        if not isinstance(technique, Mapping) or not technique.get("found"):
            continue
        attack_id = clean_string(technique.get("attack_id"))
        name = clean_string(technique.get("name"))
        tactics = clean_values(technique.get("tactics"))
        platforms = clean_values(technique.get("platforms"))
        data_sources = clean_values(technique.get("data_sources"))
        domains = clean_values(technique.get("domains"))
        detection = clean_string(technique.get("detection"))
        url = clean_string(technique.get("url"))
        external_references = mitre_external_references(attack_id, url)
        attributes = {
            "name": name,
            "description": clean_string(technique.get("description")),
            "tactics": tactics,
            "stix_id": clean_string(technique.get("stix_id")),
            "url": url,
            "external_references": external_references,
            "kill_chain_phases": mitre_kill_chain_phases(tactics),
            "platforms": platforms,
            "data_sources": data_sources,
            "detection": detection,
            "domains": domains,
            "version": clean_string(technique.get("version")),
            "attack_spec_version": clean_string(
                technique.get("attack_spec_version")
            ),
            "created": clean_string(technique.get("created")),
            "modified": clean_string(technique.get("modified")),
            "is_subtechnique": bool(technique.get("is_subtechnique", False)),
            "revoked": bool(technique.get("revoked", False)),
            "deprecated": bool(technique.get("deprecated", False)),
        }
        record = evidence_record(
            entity_type="attack_pattern",
            value=attack_id,
            source_key=source_key,
            source_name=clean_string(technique.get("source_name")) or "mitre-attack",
            source_field="mitre_attack.resolved",
            confidence=90,
            display_name=name,
            attributes=attributes,
        )
        if record:
            records.append(record)
        if url:
            records.append(
                evidence_record(
                    entity_type="external_reference",
                    value=url,
                    source_key=source_key,
                    source_name="mitre-attack",
                    source_field="mitre_attack.resolved.url",
                    confidence=90,
                    display_name=f"MITRE ATT&CK {attack_id}",
                    attributes={
                        "source_name": "mitre-attack",
                        "external_id": attack_id,
                        "technique": attack_id,
                        "url": url,
                    },
                )
            )
        for tactic in tactics:
            tactic_record = evidence_record(
                entity_type="attack_tactic",
                value=tactic,
                source_key=source_key,
                source_name="mitre-attack",
                source_field="mitre_attack.resolved.tactics",
                confidence=85,
                attributes=mitre_context_attributes(
                    attack_id,
                    "mitre_attack.resolved.tactics",
                ),
            )
            if tactic_record:
                records.append(tactic_record)
        for platform in platforms:
            platform_record = evidence_record(
                entity_type="attack_platform",
                value=platform,
                source_key=source_key,
                source_name="mitre-attack",
                source_field="mitre_attack.resolved.platforms",
                confidence=75,
                attributes=mitre_context_attributes(
                    attack_id,
                    "mitre_attack.resolved.platforms",
                ),
            )
            if platform_record:
                records.append(platform_record)
        for data_source in data_sources:
            data_component = mitre_data_component_from_data_source(data_source)
            data_source_record = evidence_record(
                entity_type="attack_data_source",
                value=data_source,
                source_key=source_key,
                source_name="mitre-attack",
                source_field="mitre_attack.resolved.data_sources",
                confidence=80,
                attributes=mitre_context_attributes(
                    attack_id,
                    "mitre_attack.resolved.data_sources",
                ),
            )
            if data_source_record:
                records.append(data_source_record)
            if data_component:
                component_attributes = mitre_context_attributes(
                    attack_id,
                    "mitre_attack.resolved.data_sources",
                )
                component_attributes["data_source"] = data_component["data_source"]
                component_record = evidence_record(
                    entity_type="attack_data_component",
                    value=data_component["data_component"],
                    source_key=source_key,
                    source_name="mitre-attack",
                    source_field="mitre_attack.resolved.data_sources",
                    confidence=78,
                    attributes=component_attributes,
                )
                if component_record:
                    records.append(component_record)
        if detection:
            records.append(
                evidence_record(
                    entity_type="detection_guidance",
                    value=detection,
                    source_key=source_key,
                    source_name="mitre-attack",
                    source_field="mitre_attack.resolved.detection",
                    confidence=70,
                    display_name=f"Detection guidance for {attack_id}",
                    attributes=mitre_context_attributes(
                        attack_id,
                        "mitre_attack.resolved.detection",
                    ),
                )
            )
    return records


def misp_metadata_evidence(metadata, source_key=""):
    if not isinstance(metadata, Mapping):
        return []
    records = []
    collector = evidence_record(
        entity_type="collector",
        value=metadata.get("collector"),
        source_key=source_key,
        source_name="misp",
        source_field="provenance.collector",
        confidence=80,
    )
    if collector:
        records.append(collector)

    original_source = evidence_record(
        entity_type="source_identity",
        value=metadata.get("original_source"),
        source_key=source_key,
        source_name="misp",
        source_field="provenance.original_source",
        confidence=70,
    )
    if original_source:
        records.append(original_source)

    tags = list(metadata.get("tags") or [])
    tlp_values = set(extract_tlp_values(tags))
    for value in sorted(tlp_values):
        record = evidence_record(
            entity_type="marking",
            value=value,
            source_key=source_key,
            source_name="misp",
            source_field="tags",
            confidence=80,
        )
        if record:
            records.append(record)

    for tag in tags:
        normalized_tag = clean_string(tag).lower()
        is_tlp_tag = normalized_tag.startswith("tlp:")
        if is_tlp_tag and normalize_tlp(tag) in tlp_values:
            continue
        record = evidence_record(
            entity_type="tag",
            value=tag,
            source_key=source_key,
            source_name="misp",
            source_field="tags",
            confidence=35,
        )
        if record:
            records.append(record)

    records.extend(misp_galaxy_evidence(misp_galaxy_tag_clusters(tags), source_key))

    return records


def misp_galaxy_tag_clusters(tags):
    clusters = []
    for index, tag in enumerate(tags or []):
        tag = clean_string(tag)
        match = MISP_GALAXY_TAG_PATTERN.match(tag)
        if not match:
            continue
        galaxy_type = clean_string(match.group(1))
        value = clean_string(match.group(2) or match.group(3))
        if not galaxy_type or not value:
            continue
        clusters.append(
            {
                "type": galaxy_type,
                "galaxy_type": galaxy_type,
                "galaxy_name": galaxy_type,
                "tag_name": tag,
                "value": value,
                "source_field": f"tags[{index}]",
            }
        )
    return clusters


def misp_galaxy_evidence(clusters, source_key="", relationship_anchor=None):
    records = []
    for cluster in clusters or []:
        if not isinstance(cluster, Mapping):
            continue
        entity_type, confidence = classify_misp_galaxy(cluster)
        if not entity_type:
            continue
        value = misp_galaxy_value(entity_type, cluster)
        attributes = misp_galaxy_attributes(cluster, entity_type)
        if misp_galaxy_uses_context_anchor(entity_type, attributes):
            anchor = compact_mapping(relationship_anchor)
            if anchor:
                attributes.update(anchor)
        record = evidence_record(
            entity_type=entity_type,
            value=value,
            source_key=source_key,
            source_name="misp-galaxy",
            source_field=cluster.get("source_field") or "misp_galaxies",
            confidence=confidence,
            display_name=cluster.get("value"),
            relationship_type=misp_galaxy_relationship_type(entity_type, attributes),
            attributes=attributes,
        )
        if record:
            records.append(record)
        records.extend(
            misp_galaxy_meta_evidence(cluster, source_key, relationship_anchor)
        )
    return records


MISP_GALAXY_CONTEXT_ANCHOR_ENTITY_TYPES = {
    "attack_pattern",
    "channel",
    "infrastructure",
    "malware",
    "tool",
} | MISP_INFRA_VICTIMOLOGY_ENTITY_TYPES


def misp_galaxy_uses_context_anchor(entity_type, attributes):
    if entity_type not in MISP_GALAXY_CONTEXT_ANCHOR_ENTITY_TYPES:
        return False
    attributes = compact_mapping(attributes)
    return not clean_string(attributes.get("relationship_source_value"))


def misp_galaxy_meta_evidence(cluster, source_key="", relationship_anchor=None):
    cluster = compact_mapping(cluster)
    meta = compact_mapping(cluster.get("meta"))
    if not meta:
        return []

    records = []
    anchor = misp_galaxy_meta_relationship_anchor(cluster, relationship_anchor)
    for entity_type, field_names, confidence in MISP_GALAXY_META_ENTITY_FIELDS:
        seen = set()
        for field_name in field_names:
            values = flatten_values(meta.get(field_name))
            for value in values:
                source_value = clean_string(value)
                attributes = misp_galaxy_meta_attributes(
                    cluster,
                    field_name,
                    entity_type,
                )
                if (
                    anchor
                    and entity_type in MISP_INFRA_VICTIMOLOGY_ENTITY_TYPES
                    and not attributes.get("relationship_source_value")
                ):
                    attributes.update(anchor)
                normalized, attributes = normalize_evidence_value(
                    entity_type,
                    source_value,
                    attributes,
                )
                key = normalized.casefold()
                if not normalized or key in seen:
                    continue
                if not is_safe_misp_meta_graph_value(entity_type, normalized):
                    continue
                seen.add(key)
                record = evidence_record(
                    entity_type=entity_type,
                    value=normalized,
                    source_key=source_key,
                    source_name="misp-galaxy",
                    source_field=meta_source_field(cluster, field_name),
                    confidence=confidence,
                    attributes=attributes,
                )
                if record:
                    records.append(record)
    return records


def misp_galaxy_meta_relationship_anchor(cluster, relationship_anchor=None):
    cluster = compact_mapping(cluster)
    classified_entity_type, _ = classify_misp_galaxy(cluster)
    stix_object_type = {
        "campaign": "campaign",
        "intrusion_set": "intrusion-set",
        "threat_actor": "threat-actor",
    }.get(classified_entity_type)
    if stix_object_type:
        value = misp_galaxy_value(classified_entity_type, cluster)
        if value:
            return {
                "relationship_source_stix_object_type": stix_object_type,
                "relationship_source_value": value,
                "relationship_source_field": (
                    clean_string(cluster.get("source_field")) or "misp_galaxies"
                ),
            }
    return compact_mapping(relationship_anchor)


MISP_GALAXY_META_ENTITY_FIELDS = (
    (
        "target_sector",
        (
            "targeted-sector",
            "targeted-sectors",
            "targeted_sector",
            "targeted_sectors",
            "target-sector",
            "target-sectors",
            "target_sector",
            "target_sectors",
            "cfr-target-category",
            "cfr-target-categories",
            "cfr_target_category",
            "cfr_target_categories",
        ),
        70,
    ),
    (
        "target_country",
        (
            "targeted-country",
            "targeted-countries",
            "targeted_country",
            "targeted_countries",
            "target-country",
            "target-countries",
            "target_country",
            "target_countries",
            "cfr-suspected-victim",
            "cfr-suspected-victims",
            "cfr_suspected_victim",
            "cfr_suspected_victims",
        ),
        70,
    ),
    (
        "target_organization",
        (
            "targeted-organization",
            "targeted-organizations",
            "targeted_organization",
            "targeted_organizations",
            "targeted-org",
            "targeted-orgs",
            "target_org",
            "target_orgs",
            "targeted-company",
            "targeted-companies",
            "targeted_company",
            "targeted_companies",
            "targeted-entity",
            "targeted-entities",
            "targeted_entity",
            "targeted_entities",
            "target-organization",
            "target-organizations",
            "target_organization",
            "target_organizations",
            "target-company",
            "target-companies",
            "target_company",
            "target_companies",
            "target-entity",
            "target-entities",
            "target_entity",
            "target_entities",
            "victim-organization",
            "victim-organizations",
            "victim_organization",
            "victim_organizations",
            "victim-organization-name",
            "victim-organization-names",
            "victim_organization_name",
            "victim_organization_names",
            "victim-org",
            "victim-orgs",
            "victim_org",
            "victim_orgs",
            "victim-company",
            "victim-companies",
            "victim_company",
            "victim_companies",
            "victim-entity",
            "victim-entities",
            "victim_entity",
            "victim_entities",
            "victim",
            "victims",
            "victim-name",
            "victim-names",
            "victim_name",
            "victim_names",
            "affected-organization",
            "affected-organizations",
            "affected_organization",
            "affected_organizations",
            "affected-company",
            "affected-companies",
            "affected_company",
            "affected_companies",
            "impacted-organization",
            "impacted-organizations",
            "impacted_organization",
            "impacted_organizations",
            "impacted-company",
            "impacted-companies",
            "impacted_company",
            "impacted_companies",
        ),
        70,
    ),
    (
        "target_individual",
        (
            "targeted-individual",
            "targeted-individuals",
            "targeted_individual",
            "targeted_individuals",
            "target-individual",
            "target-individuals",
            "target_individual",
            "target_individuals",
            "targeted-person",
            "targeted-persons",
            "targeted_person",
            "targeted_persons",
            "target-person",
            "target-persons",
            "target_person",
            "target_persons",
            "victim-individual",
            "victim-individuals",
            "victim_individual",
            "victim_individuals",
            "victim-person",
            "victim-persons",
            "victim_person",
            "victim_persons",
            "affected-individual",
            "affected-individuals",
            "affected_individual",
            "affected_individuals",
            "affected-person",
            "affected-persons",
            "affected_person",
            "affected_persons",
            "impacted-individual",
            "impacted-individuals",
            "impacted_individual",
            "impacted_individuals",
            "impacted-person",
            "impacted-persons",
            "impacted_person",
            "impacted_persons",
        ),
        65,
    ),
    (
        "target_system",
        (
            "targeted-system",
            "targeted-systems",
            "targeted_system",
            "targeted_systems",
            "target-system",
            "target-systems",
            "target_system",
            "target_systems",
            "victim-system",
            "victim-systems",
            "victim_system",
            "victim_systems",
            "affected-system",
            "affected-systems",
            "affected_system",
            "affected_systems",
            "impacted-system",
            "impacted-systems",
            "impacted_system",
            "impacted_systems",
            "targeted-platform",
            "targeted-platforms",
            "targeted_platform",
            "targeted_platforms",
            "target-platform",
            "target-platforms",
            "target_platform",
            "target_platforms",
            "affected-platform",
            "affected-platforms",
            "affected_platform",
            "affected_platforms",
            "operating-system",
            "operating-systems",
            "operating_system",
            "operating_systems",
            "targeted-asset",
            "targeted-assets",
            "targeted_asset",
            "targeted_assets",
        ),
        65,
    ),
    (
        "security_platform",
        (
            "security-platform",
            "security-platforms",
            "security_platform",
            "security_platforms",
            "security-product",
            "security-products",
            "security_product",
            "security_products",
            "detection-platform",
            "detection-platforms",
            "detection_platform",
            "detection_platforms",
            "siem",
            "edr",
            "ndr",
            "xdr",
            "sensor",
            "sensors",
            "scanner",
            "scanners",
        ),
        65,
    ),
    (
        "channel",
        (
            "channel",
            "channels",
            "c2-channel",
            "c2-channels",
            "c2_channel",
            "c2_channels",
            "command-and-control-channel",
            "command-and-control-channels",
            "command_and_control_channel",
            "command_and_control_channels",
            "communication-channel",
            "communication-channels",
            "communication_channel",
            "communication_channels",
            "delivery-channel",
            "delivery-channels",
            "delivery_channel",
            "delivery_channels",
            "distribution-channel",
            "distribution-channels",
            "distribution_channel",
            "distribution_channels",
            "marketplace",
            "marketplaces",
        ),
        65,
    ),
    (
        "narrative",
        (
            "narrative",
            "narratives",
            "objective",
            "objectives",
            "campaign-objective",
            "campaign-objectives",
            "campaign_objective",
            "campaign_objectives",
            "operation-objective",
            "operation-objectives",
            "operation_objective",
            "operation_objectives",
            "observed-motivation",
            "observed-motivations",
            "observed_motivation",
            "observed_motivations",
            "cfr-type-of-incident",
            "cfr-types-of-incident",
            "cfr_type_of_incident",
            "cfr_types_of_incident",
            "type-of-incident",
            "types-of-incident",
            "type_of_incident",
            "types_of_incident",
            "motivation",
            "motivations",
            "theme",
            "themes",
            "goal",
            "goals",
            "intent",
            "intents",
        ),
        62,
    ),
    (
        "event",
        (
            "event",
            "events",
            "event-name",
            "event-names",
            "event_name",
            "event_names",
            "incident",
            "incidents",
            "incident-name",
            "incident-names",
            "incident_name",
            "incident_names",
            "observed-event",
            "observed-events",
            "observed_event",
            "observed_events",
            "activity-event",
            "activity-events",
            "activity_event",
            "activity_events",
        ),
        62,
    ),
    (
        "target_region",
        (
            "targeted-region",
            "targeted-regions",
            "targeted_region",
            "targeted_regions",
            "target-region",
            "target-regions",
            "target_region",
            "target_regions",
        ),
        65,
    ),
    (
        "target_administrative_area",
        (
            "targeted-administrative-area",
            "targeted-administrative-areas",
            "targeted_administrative_area",
            "targeted_administrative_areas",
            "target-administrative-area",
            "target-administrative-areas",
            "target_administrative_area",
            "target_administrative_areas",
            "targeted-state",
            "targeted-states",
            "targeted_state",
            "targeted_states",
            "target-state",
            "target-states",
            "target_state",
            "target_states",
            "targeted-province",
            "targeted-provinces",
            "targeted_province",
            "targeted_provinces",
            "target-province",
            "target-provinces",
            "target_province",
            "target_provinces",
        ),
        62,
    ),
    (
        "target_city",
        (
            "targeted-city",
            "targeted-cities",
            "targeted_city",
            "targeted_cities",
            "target-city",
            "target-cities",
            "target_city",
            "target_cities",
        ),
        62,
    ),
    (
        "target_position",
        (
            "targeted-position",
            "targeted-positions",
            "targeted_position",
            "targeted_positions",
            "target-position",
            "target-positions",
            "target_position",
            "target_positions",
            "targeted-coordinate",
            "targeted-coordinates",
            "targeted_coordinate",
            "targeted_coordinates",
            "target-coordinate",
            "target-coordinates",
            "target_coordinate",
            "target_coordinates",
        ),
        60,
    ),
)


TARGET_ORGANIZATION_VALUE_DENYLIST = {
    "alienvault",
    "alienvault otx",
    "misp",
    "narrowcti",
    "narrowcti gateway",
    "opencti",
    "otx",
    "the mitre corporation",
}

TARGET_INDIVIDUAL_VALUE_DENYLIST = TARGET_ORGANIZATION_VALUE_DENYLIST | {
    "admin",
    "administrator",
    "analyst",
    "author",
    "root",
    "user",
}


def is_target_organization_value(value):
    value = clean_string(value)
    lowered = value.casefold()
    if not value:
        return False
    if lowered in TARGET_ORGANIZATION_VALUE_DENYLIST:
        return False
    if lowered.startswith(("http://", "https://", "ftp://", "tlp:")):
        return False
    if "@" in value and not any(char.isspace() for char in value):
        return False
    if ATTACK_ID_PATTERN.fullmatch(value) or CVE_ID_PATTERN.fullmatch(value):
        return False
    if is_dotted_identifier_value(value):
        return False
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", lowered):
        return False
    return True


def is_dotted_identifier_value(value):
    value = clean_string(value)
    lowered = value.casefold()
    if not value or any(char.isspace() for char in value):
        return False
    if lowered.count(".") < 2:
        return False
    labels = lowered.split(".")
    return all(re.fullmatch(r"[a-z0-9_-]+", label or "") for label in labels)


def is_target_individual_value(value):
    value = clean_string(value)
    lowered = value.casefold()
    if not is_target_organization_value(value):
        return False
    if lowered in TARGET_INDIVIDUAL_VALUE_DENYLIST:
        return False
    if re.fullmatch(r"\d+", value):
        return False
    return True


def is_safe_misp_meta_graph_value(entity_type, value):
    if entity_type == "target_individual":
        return is_target_individual_value(value)
    if entity_type in {
        "channel",
        "event",
        "narrative",
        "security_platform",
        "target_organization",
        "target_system",
    }:
        value = clean_string(value)
        if not is_target_organization_value(value):
            return False
        if re.fullmatch(r"\d+", value):
            return False
        return True
    return bool(clean_string(value))


def meta_source_field(cluster, field_name):
    source_field = clean_string(cluster.get("source_field")) or "Galaxy"
    return f"{source_field}.meta.{field_name}"


def misp_galaxy_meta_attributes(cluster, field_name, entity_type=""):
    attributes = compact_mapping(
        {
            "meta_key": field_name,
            "parent_galaxy_type": cluster.get("galaxy_type"),
            "parent_galaxy_name": cluster.get("galaxy_name"),
            "parent_cluster_type": cluster.get("type"),
            "parent_cluster_value": cluster.get("value"),
            "parent_cluster_uuid": cluster.get("uuid"),
            "parent_tag_name": cluster.get("tag_name"),
        }
    )
    entity_type = clean_string(entity_type)
    normalized_field = field_name.replace("_", "-").casefold()
    if entity_type == "channel":
        attributes["channel_types"] = misp_meta_context_types(
            normalized_field,
            {
                "c2": ("c2", "command-and-control"),
                "delivery": ("delivery", "distribution"),
                "communication": ("communication",),
                "marketplace": ("marketplace",),
            },
        )
    elif entity_type == "narrative":
        attributes["narrative_types"] = misp_meta_context_types(
            normalized_field,
            {
                "objective": ("objective", "goal", "intent"),
                "motivation": ("motivation",),
                "theme": ("theme", "narrative"),
                "incident-type": ("type-of-incident",),
            },
        )
    elif entity_type == "event":
        attributes["event_types"] = misp_meta_context_types(
            normalized_field,
            {
                "incident": ("incident",),
                "activity": ("activity", "observed"),
                "cti-event": ("event",),
            },
        )
    elif entity_type == "security_platform":
        platform_types = misp_meta_context_types(
            normalized_field,
            {
                "SIEM": ("siem",),
                "EDR": ("edr",),
                "NDR": ("ndr",),
                "XDR": ("xdr",),
                "Scanner": ("scanner",),
                "Sensor": ("sensor",),
                "Detection Platform": ("detection-platform", "security-platform"),
                "Security Product": ("security-product",),
            },
        )
        if platform_types:
            attributes["security_platform_type"] = platform_types[0]
    return compact_mapping(attributes)


def misp_meta_context_types(field_name, mapping):
    values = []
    for output, tokens in mapping.items():
        if any(token in field_name for token in tokens):
            values.append(output)
    return values


def classify_misp_galaxy(cluster):
    kind = " ".join(
        clean_string(cluster.get(field)).casefold()
        for field in ("type", "galaxy_type", "galaxy_name", "tag_name")
        if clean_string(cluster.get(field))
    )
    if not kind:
        return "", 0
    if "attack-pattern" in kind or "mitre-attack-pattern" in kind:
        return "attack_pattern", 85
    if "intrusion-set" in kind:
        return "intrusion_set", 80
    if "vulnerability" in kind or "cve" in kind:
        return "vulnerability", 80
    if "campaign" in kind:
        return "campaign", 75
    if "course-of-action" in kind or "course of action" in kind:
        return "course_of_action", 75
    if misp_galaxy_is_threat_actor_individual(cluster, kind):
        return "threat_actor_individual", 65
    if "threat-actor" in kind or "threat actor" in kind:
        return "threat_actor", 80
    if "malpedia" in kind or "ransomware" in kind or "malware" in kind:
        return "malware", 80
    if "tool" in kind:
        return "tool", 75
    if "sector" in kind:
        return "target_sector", 70
    if "country" in kind:
        return "target_country", 70
    if "region" in kind:
        return "target_region", 65
    return "", 0


def misp_galaxy_value(entity_type, cluster):
    if entity_type == "attack_pattern":
        attack_id = first_attack_id_from_cluster(cluster)
        if attack_id:
            return attack_id
    if entity_type == "vulnerability":
        cve_id = first_cve_id_from_cluster(cluster)
        if cve_id:
            return cve_id
    return clean_string(cluster.get("value"))


def misp_galaxy_is_threat_actor_individual(cluster, kind=""):
    kind = kind or " ".join(
        clean_string(cluster.get(field)).casefold()
        for field in ("type", "galaxy_type", "galaxy_name", "tag_name")
        if clean_string(cluster.get(field))
    )
    normalized_kind = kind.replace("-", "").replace("_", "").replace(" ", "")
    explicit_values = []
    meta = compact_mapping(cluster.get("meta"))
    for key in (
        "actor-type",
        "actor_type",
        "threat-actor-type",
        "threat_actor_type",
        "threat-actor-class",
        "threat_actor_class",
        "type",
    ):
        explicit_values.extend(flatten_values(meta.get(key)))
    explicit = {
        clean_string(value).casefold()
        for value in explicit_values
        if clean_string(value)
    }
    return (
        "threatactorindividual" in normalized_kind
        or "threatactorsindividual" in normalized_kind
        or bool(explicit.intersection({"individual", "person", "human"}))
    )


def first_attack_id_from_cluster(cluster):
    values = [
        cluster.get("value"),
        cluster.get("tag_name"),
        cluster.get("description"),
    ]
    meta = compact_mapping(cluster.get("meta"))
    for key in ("external_id", "external-id", "mitre_id", "mitre-id", "id", "refs"):
        values.extend(flatten_values(meta.get(key)))
    for value in values:
        match = ATTACK_ID_PATTERN.search(clean_string(value))
        if match:
            return match.group(0).upper()
    return ""


def first_cve_id_from_cluster(cluster):
    values = [
        cluster.get("value"),
        cluster.get("tag_name"),
        cluster.get("description"),
    ]
    meta = compact_mapping(cluster.get("meta"))
    for key in ("external_id", "external-id", "cve", "cves", "id", "refs"):
        values.extend(flatten_values(meta.get(key)))
    for value in values:
        match = CVE_ID_PATTERN.search(clean_string(value))
        if match:
            return match.group(0).upper()
    return ""


def misp_galaxy_attributes(cluster, entity_type=""):
    meta = compact_mapping(cluster.get("meta"))
    attributes = {
        "galaxy_type": clean_string(cluster.get("galaxy_type")),
        "galaxy_name": clean_string(cluster.get("galaxy_name")),
        "cluster_type": clean_string(cluster.get("type")),
        "cluster_uuid": clean_string(cluster.get("uuid")),
        "tag_name": clean_string(cluster.get("tag_name")),
        "description": clean_string(cluster.get("description")),
        "meta": meta,
    }
    if entity_type == "threat_actor":
        attributes["threat_actor_class"] = "group"
    elif entity_type == "threat_actor_individual":
        attributes["threat_actor_class"] = "individual"
    attack_id = first_attack_id_from_cluster(cluster)
    if attack_id:
        attributes["external_id"] = attack_id
    cve_id = first_cve_id_from_cluster(cluster)
    if cve_id:
        attributes["external_id"] = cve_id
    if entity_type == "course_of_action":
        attack_id, attack_source_field = first_mitigated_attack_id_from_cluster(cluster)
        if attack_id:
            attributes.update(
                {
                    "relationship_source_stix_object_type": "attack-pattern",
                    "relationship_source_value": attack_id,
                    "relationship_source_field": attack_source_field,
                }
            )
    return compact_mapping(attributes)


def misp_galaxy_relationship_type(entity_type, attributes):
    if (
        entity_type == "course_of_action"
        and clean_string(attributes.get("relationship_source_stix_object_type")).lower()
        == "attack-pattern"
        and clean_string(attributes.get("relationship_source_value"))
    ):
        return "mitigates"
    return ""


def first_mitigated_attack_id_from_cluster(cluster):
    meta = compact_mapping(cluster.get("meta"))
    for key in (
        "mitigates",
        "mitigated",
        "attack_pattern",
        "attack-pattern",
        "attack_patterns",
        "attack-patterns",
        "technique",
        "techniques",
        "related_attack_pattern",
        "related-attack-pattern",
        "related_technique",
        "related-technique",
        "mitre_attack_id",
        "mitre-attack-id",
        "mitre_technique_id",
        "mitre-technique-id",
        "refs",
    ):
        for value in flatten_values(meta.get(key)):
            match = ATTACK_ID_PATTERN.search(clean_string(value))
            if match:
                return match.group(0).upper(), f"meta.{key}"
    return "", ""


def misp_vulnerability_evidence(vulnerabilities, source_key=""):
    records = []
    for vulnerability in vulnerabilities or []:
        vulnerability = compact_mapping(vulnerability)
        if not vulnerability:
            continue
        attributes = compact_mapping(
            {
                "source_type": vulnerability.get("source_type"),
                "attribute_type": vulnerability.get("attribute_type"),
                "attribute_category": vulnerability.get("attribute_category"),
                "attribute_uuid": vulnerability.get("attribute_uuid"),
                "first_seen": vulnerability.get("first_seen"),
                "last_seen": vulnerability.get("last_seen"),
                "object_name": vulnerability.get("object_name"),
                "object_uuid": vulnerability.get("object_uuid"),
                "tags": vulnerability.get("tags"),
            }
        )
        record = evidence_record(
            entity_type="vulnerability",
            value=vulnerability.get("value"),
            source_key=source_key,
            source_name="misp",
            source_field=vulnerability.get("source_field"),
            confidence=75,
            attributes=attributes,
        )
        if record:
            records.append(record)
    return records


def misp_campaign_evidence(campaigns, source_key=""):
    records = []
    for campaign in campaigns or []:
        campaign = compact_mapping(campaign)
        if not campaign:
            continue
        attributes = compact_mapping(
            {
                "source_type": campaign.get("source_type"),
                "attribute_type": campaign.get("attribute_type"),
                "attribute_category": campaign.get("attribute_category"),
                "attribute_uuid": campaign.get("attribute_uuid"),
                "attribute_relation": campaign.get("attribute_relation"),
                "first_seen": campaign.get("first_seen"),
                "last_seen": campaign.get("last_seen"),
                "object_name": campaign.get("object_name"),
                "object_uuid": campaign.get("object_uuid"),
                "object_meta_category": campaign.get("object_meta_category"),
                "tags": campaign.get("tags"),
            }
        )
        record = evidence_record(
            entity_type="campaign",
            value=campaign.get("value"),
            source_key=source_key,
            source_name="misp",
            source_field=campaign.get("source_field"),
            confidence=70,
            attributes=attributes,
        )
        if record:
            records.append(record)
    return records


def misp_victimology_evidence(victimology_records, source_key="", relationship_anchor=None):
    records = []
    for item in victimology_records or []:
        item = compact_mapping(item)
        entity_type = clean_string(item.get("entity_type"))
        value = clean_string(item.get("value"))
        if not entity_type or not value:
            continue
        attributes = compact_mapping(
            {
                "source_type": item.get("source_type"),
                "attribute_type": item.get("attribute_type"),
                "attribute_category": item.get("attribute_category"),
                "attribute_uuid": item.get("attribute_uuid"),
                "attribute_relation": item.get("attribute_relation"),
                "first_seen": item.get("first_seen"),
                "last_seen": item.get("last_seen"),
                "object_name": item.get("object_name"),
                "object_uuid": item.get("object_uuid"),
                "object_meta_category": item.get("object_meta_category"),
                "tags": item.get("tags"),
            }
        )
        anchor = compact_mapping(relationship_anchor)
        if anchor and not attributes.get("relationship_source_value"):
            attributes.update(anchor)
        normalized, attributes = normalize_evidence_value(
            entity_type,
            value,
            attributes,
        )
        if not normalized or not is_safe_misp_meta_graph_value(entity_type, normalized):
            continue
        record = evidence_record(
            entity_type=entity_type,
            value=normalized,
            source_key=source_key,
            source_name="misp-attribute",
            source_field=item.get("source_field") or "Attribute",
            confidence=item.get("confidence") or 65,
            attributes=attributes,
        )
        if record:
            records.append(record)
    return records


def single_misp_context_anchor(metadata):
    metadata = compact_mapping(metadata)
    anchors = misp_campaign_anchors(metadata.get("misp_campaigns"))
    galaxy_sources = list(metadata.get("misp_galaxies") or [])
    galaxy_sources.extend(misp_galaxy_tag_clusters(metadata.get("tags")))
    for entity_type, stix_object_type in (
        ("campaign", "campaign"),
        ("intrusion_set", "intrusion-set"),
        ("threat_actor", "threat-actor"),
    ):
        anchors.extend(
            misp_galaxy_anchors(
                galaxy_sources,
                entity_type,
                stix_object_type,
            )
        )
    return single_unique_anchor(anchors)


def misp_campaign_anchors(campaigns):
    anchors = []
    for campaign in campaigns or []:
        campaign = compact_mapping(campaign)
        value = clean_string(campaign.get("value"))
        if not value:
            continue
        anchors.append(
            {
                "relationship_source_stix_object_type": "campaign",
                "relationship_source_value": value,
                "relationship_source_field": (
                    clean_string(campaign.get("source_field")) or "misp_campaigns"
                ),
            }
        )
    return anchors


def misp_galaxy_anchors(clusters, entity_type, stix_object_type):
    anchors = []
    for cluster in clusters or []:
        cluster = compact_mapping(cluster)
        classified_entity_type, _ = classify_misp_galaxy(cluster)
        if classified_entity_type != entity_type:
            continue
        value = misp_galaxy_value(entity_type, cluster)
        if not value:
            continue
        anchors.append(
            {
                "relationship_source_stix_object_type": stix_object_type,
                "relationship_source_value": value,
                "relationship_source_field": (
                    clean_string(cluster.get("source_field")) or "misp_galaxies"
                ),
            }
        )
    return anchors


def single_unique_anchor(anchors):
    unique = {}
    for anchor in anchors:
        anchor = compact_mapping(anchor)
        key = (
            clean_string(anchor.get("relationship_source_stix_object_type")).casefold(),
            clean_string(anchor.get("relationship_source_value")).casefold(),
        )
        if not all(key):
            continue
        unique[key] = anchor
    if len(unique) != 1:
        return {}
    return next(iter(unique.values()))


def misp_event_report_evidence(event_reports, source_key=""):
    records = []
    for event_report in event_reports or []:
        event_report = compact_mapping(event_report)
        if not event_report:
            continue
        title = clean_string(event_report.get("title"))
        content = clean_string(event_report.get("content"))
        value = title or content[:120]
        attributes = compact_mapping(
            {
                "content": content,
                "event_report_uuid": event_report.get("uuid"),
                "timestamp": event_report.get("timestamp"),
                "created": event_report.get("created"),
                "modified": event_report.get("modified"),
            }
        )
        record = evidence_record(
            entity_type="event_report",
            value=value,
            source_key=source_key,
            source_name="misp",
            source_field=event_report.get("source_field") or "EventReport",
            confidence=70,
            display_name=title,
            attributes=attributes,
        )
        if record:
            records.append(record)
    return records


def misp_sighting_evidence(sightings, source_key=""):
    records = []
    for sighting in sightings or []:
        sighting = compact_mapping(sighting)
        if not sighting:
            continue
        attributes = compact_mapping(
            {
                "sighting_id": sighting.get("sighting_id"),
                "sighting_uuid": sighting.get("sighting_uuid"),
                "sighting_type": sighting.get("sighting_type"),
                "date_sighting": sighting.get("date_sighting"),
                "source": sighting.get("source"),
                "confidence": sighting.get("confidence"),
                "source_confidence": sighting.get("source_confidence"),
                "organization": sighting.get("organization"),
                "organization_uuid": sighting.get("organization_uuid"),
                "attribute_type": sighting.get("attribute_type"),
                "attribute_category": sighting.get("attribute_category"),
                "attribute_uuid": sighting.get("attribute_uuid"),
                "object_name": sighting.get("object_name"),
                "object_uuid": sighting.get("object_uuid"),
            }
        )
        record = evidence_record(
            entity_type="sighting",
            value=sighting.get("value"),
            source_key=source_key,
            source_name="misp",
            source_field=sighting.get("source_field") or "Sighting",
            confidence=misp_sighting_confidence(sighting),
            attributes=attributes,
        )
        if record:
            records.append(record)
    return records


def misp_sighting_confidence(sighting):
    return first_confidence_value(
        sighting.get("confidence"),
        sighting.get("source_confidence"),
        65,
    )


def misp_object_reference_evidence(object_references, source_key=""):
    records = []
    for object_reference in object_references or []:
        object_reference = compact_mapping(object_reference)
        if not object_reference:
            continue
        attributes = compact_mapping(
            {
                "reference_id": object_reference.get("reference_id"),
                "reference_uuid": object_reference.get("reference_uuid"),
                "source_uuid": object_reference.get("source_uuid"),
                "source_name": object_reference.get("source_name"),
                "source_meta_category": object_reference.get("source_meta_category"),
                "target_uuid": object_reference.get("target_uuid"),
                "target_type": object_reference.get("target_type"),
                "comment": object_reference.get("comment"),
            }
        )
        record = evidence_record(
            entity_type="object_reference",
            value=object_reference.get("value"),
            source_key=source_key,
            source_name="misp",
            source_field=object_reference.get("source_field") or "ObjectReference",
            confidence=60,
            attributes=attributes,
            relationship_type=object_reference.get("relationship_type"),
        )
        if record:
            records.append(record)
    return records


def misp_infrastructure_evidence(infrastructure_records, source_key=""):
    records = []
    for infrastructure_record in infrastructure_records or []:
        infrastructure_record = compact_mapping(infrastructure_record)
        if not infrastructure_record:
            continue
        record = evidence_record(
            entity_type=infrastructure_record.get("entity_type"),
            value=infrastructure_record.get("value"),
            source_key=source_key,
            source_name="misp-object",
            source_field=infrastructure_record.get("source_field") or "Object",
            confidence=infrastructure_record.get("confidence", 70),
            attributes=infrastructure_record.get("attributes"),
            stix_object_type=infrastructure_record.get("stix_object_type"),
            relationship_type=infrastructure_record.get("relationship_type"),
        )
        if record:
            records.append(record)
    return records


def misp_infrastructure_context_relationship_evidence(records, source_key=""):
    records = [record for record in records or [] if isinstance(record, Mapping)]
    infrastructures = unique_context_records(
        (
            record
            for record in records
            if record.get("entity_type") == "infrastructure"
            and record.get("stix_object_type") == "infrastructure"
            and clean_string(record.get("source_name")).startswith("misp")
        )
    )
    if (
        not infrastructures
        or len(infrastructures) > MISP_INFRA_CONTEXT_MAX_INFRASTRUCTURES
    ):
        return []

    context_records = []
    existing = semantic_relationship_keys(records)
    actors = unique_context_records(
        record
        for record in records
        if record.get("entity_type")
        in MISP_CAMPAIGN_ADVERSARY_ENTITY_TYPES
        and clean_string(record.get("source_name")).startswith("misp")
    )
    if len(actors) == 1:
        context_records.extend(
            infrastructure_anchor_relationship_records(
                infrastructures,
                actors,
                source_key,
                existing,
                "uses",
                "misp-event-infrastructure-adversary-context",
            )
        )

    campaigns = unique_context_records(
        record
        for record in records
        if record.get("entity_type") == "campaign"
        and clean_string(record.get("source_name")).startswith("misp")
    )
    if len(campaigns) == 1:
        context_records.extend(
            infrastructure_anchor_relationship_records(
                infrastructures,
                campaigns,
                source_key,
                existing,
                "uses",
                "misp-event-infrastructure-campaign-context",
            )
        )

    capabilities = unique_context_records(
        record
        for record in records
        if record.get("entity_type") in MISP_INFRA_CAPABILITY_ENTITY_TYPES
        and clean_string(record.get("source_name")).startswith("misp")
    )
    if len(infrastructures) * len(capabilities) <= MISP_INFRA_CONTEXT_MAX_PAIRINGS:
        context_records.extend(
            infrastructure_anchor_relationship_records(
                infrastructures,
                capabilities,
                source_key,
                existing,
                "uses",
                "misp-event-infrastructure-capability-context",
            )
        )

    attack_patterns = unique_context_records(
        record
        for record in records
        if record.get("entity_type") == "attack_pattern"
        and clean_string(record.get("source_name")).startswith("misp")
    )
    if len(infrastructures) * len(attack_patterns) <= MISP_INFRA_CONTEXT_MAX_PAIRINGS:
        context_records.extend(
            infrastructure_attack_pattern_relationship_records(
                infrastructures,
                attack_patterns,
                source_key,
                existing,
            )
        )

    victimology = unique_context_records(
        record
        for record in records
        if record.get("entity_type") in MISP_INFRA_VICTIMOLOGY_ENTITY_TYPES
        and clean_string(record.get("source_name")).startswith("misp")
    )
    if len(infrastructures) * len(victimology) <= MISP_INFRA_CONTEXT_MAX_PAIRINGS:
        context_records.extend(
            infrastructure_victimology_relationship_records(
                infrastructures,
                victimology,
                source_key,
                existing,
            )
        )

    return context_records[:MISP_INFRA_CONTEXT_MAX_RECORDS]


def misp_campaign_context_relationship_evidence(records, source_key=""):
    """Relate explicit same-event campaign context without title inference."""
    records = [record for record in records or [] if isinstance(record, Mapping)]
    campaigns = unique_context_records(
        record
        for record in records
        if record.get("entity_type") == "campaign"
        and record.get("stix_object_type") == "campaign"
        and clean_string(record.get("source_name")).startswith("misp")
    )
    if (
        not campaigns
        or len(campaigns) > MISP_CAMPAIGN_CONTEXT_MAX_CAMPAIGNS
    ):
        return []

    existing = semantic_relationship_keys(records)
    context_records = []
    actors = unique_context_records(
        record
        for record in records
        if record.get("entity_type") in MISP_CAMPAIGN_ADVERSARY_ENTITY_TYPES
        and clean_string(record.get("source_name")).startswith("misp")
    )
    if (
        len(actors) == 1
        and len(campaigns) * len(actors)
        <= MISP_CAMPAIGN_CONTEXT_MAX_PAIRINGS
    ):
        context_records.extend(
            context_anchor_relationship_records(
                actors,
                campaigns,
                source_key,
                existing,
                "attributed-to",
                "misp-event-campaign-adversary-context",
            )
        )

    capabilities = unique_context_records(
        record
        for record in records
        if record.get("entity_type") in MISP_CAMPAIGN_CAPABILITY_ENTITY_TYPES
        and clean_string(record.get("source_name")).startswith("misp")
    )
    if (
        len(campaigns) * len(capabilities)
        <= MISP_CAMPAIGN_CONTEXT_MAX_PAIRINGS
    ):
        context_records.extend(
            context_anchor_relationship_records(
                capabilities,
                campaigns,
                source_key,
                existing,
                "uses",
                "misp-event-campaign-capability-context",
            )
        )

    infrastructures = unique_context_records(
        record
        for record in records
        if record.get("entity_type") == "infrastructure"
        and record.get("stix_object_type") == "infrastructure"
        and clean_string(record.get("source_name")).startswith("misp")
    )
    if (
        len(campaigns) * len(infrastructures)
        <= MISP_CAMPAIGN_CONTEXT_MAX_PAIRINGS
    ):
        context_records.extend(
            context_anchor_relationship_records(
                infrastructures,
                campaigns,
                source_key,
                existing,
                "uses",
                "misp-event-campaign-infrastructure-context",
            )
        )

    victimology = unique_context_records(
        record
        for record in records
        if record.get("entity_type") in MISP_INFRA_VICTIMOLOGY_ENTITY_TYPES
        and clean_string(record.get("source_name")).startswith("misp")
    )
    if (
        len(campaigns) * len(victimology)
        <= MISP_CAMPAIGN_CONTEXT_MAX_PAIRINGS
    ):
        context_records.extend(
            context_anchor_relationship_records(
                victimology,
                campaigns,
                source_key,
                existing,
                "targets",
                "misp-event-campaign-victimology-context",
            )
        )

    return context_records[:MISP_CAMPAIGN_CONTEXT_MAX_RECORDS]


def infrastructure_anchor_relationship_records(
    infrastructures,
    anchors,
    source_key,
    existing,
    relationship_type,
    inference,
):
    return context_anchor_relationship_records(
        infrastructures,
        anchors,
        source_key,
        existing,
        relationship_type,
        inference,
    )


def context_anchor_relationship_records(
    targets,
    anchors,
    source_key,
    existing,
    relationship_type,
    inference,
):
    records = []
    for target in targets:
        for anchor in anchors:
            source_type = clean_string(anchor.get("stix_object_type"))
            source_value = clean_string(anchor.get("value"))
            if not source_type or not source_value:
                continue
            key = semantic_relationship_key(
                source_type,
                source_value,
                relationship_type,
                target.get("stix_object_type"),
                target.get("value"),
            )
            if key in existing:
                continue
            existing.add(key)
            attributes = {
                **compact_mapping(target.get("attributes")),
                "relationship_source_stix_object_type": source_type,
                "relationship_source_value": source_value,
                "relationship_source_field": anchor.get("source_field"),
                "relationship_inference": inference,
                "relationship_context_scope": "same-misp-event",
            }
            record = evidence_record(
                entity_type=target.get("entity_type"),
                value=target.get("value"),
                source_key=source_key,
                source_name="misp-context",
                source_field=target.get("source_field"),
                confidence=min(
                    clamp_confidence(target.get("confidence")),
                    clamp_confidence(anchor.get("confidence")),
                ),
                display_name=target.get("display_name"),
                attributes=attributes,
                stix_object_type=target.get("stix_object_type"),
                relationship_type=relationship_type,
            )
            if record:
                records.append(record)
    return records


def infrastructure_attack_pattern_relationship_records(
    infrastructures,
    attack_patterns,
    source_key,
    existing,
):
    records = []
    for infrastructure in infrastructures:
        for attack_pattern in attack_patterns:
            key = semantic_relationship_key(
                infrastructure.get("stix_object_type"),
                infrastructure.get("value"),
                "related-to",
                attack_pattern.get("stix_object_type"),
                attack_pattern.get("value"),
            )
            if key in existing:
                continue
            existing.add(key)
            attributes = {
                **compact_mapping(attack_pattern.get("attributes")),
                "relationship_source_stix_object_type": "infrastructure",
                "relationship_source_value": infrastructure.get("value"),
                "relationship_source_field": infrastructure.get("source_field"),
                "relationship_inference": "misp-event-infrastructure-ttp-context",
                "relationship_context_scope": "same-misp-event",
            }
            record = evidence_record(
                entity_type=attack_pattern.get("entity_type"),
                value=attack_pattern.get("value"),
                source_key=source_key,
                source_name="misp-context",
                source_field=attack_pattern.get("source_field"),
                confidence=min(
                    clamp_confidence(infrastructure.get("confidence")),
                    clamp_confidence(attack_pattern.get("confidence")),
                ),
                display_name=attack_pattern.get("display_name"),
                attributes=attributes,
                stix_object_type=attack_pattern.get("stix_object_type"),
                relationship_type="related-to",
            )
            if record:
                records.append(record)
    return records


def infrastructure_victimology_relationship_records(
    infrastructures,
    victimology,
    source_key,
    existing,
):
    records = []
    for infrastructure in infrastructures:
        for target in victimology:
            key = semantic_relationship_key(
                infrastructure.get("stix_object_type"),
                infrastructure.get("value"),
                "targets",
                target.get("stix_object_type"),
                target.get("value"),
            )
            if key in existing:
                continue
            existing.add(key)
            attributes = {
                **compact_mapping(target.get("attributes")),
                "relationship_source_stix_object_type": "infrastructure",
                "relationship_source_value": infrastructure.get("value"),
                "relationship_source_field": infrastructure.get("source_field"),
                "relationship_inference": "misp-event-infrastructure-victimology-context",
                "relationship_context_scope": "same-misp-event",
                "relationship_validation_state": "requires-opencti-validation",
            }
            record = evidence_record(
                entity_type=target.get("entity_type"),
                value=target.get("value"),
                source_key=source_key,
                source_name="misp-context",
                source_field=target.get("source_field"),
                confidence=min(
                    clamp_confidence(infrastructure.get("confidence")),
                    clamp_confidence(target.get("confidence")),
                ),
                display_name=target.get("display_name"),
                attributes=attributes,
                stix_object_type=target.get("stix_object_type"),
                relationship_type="targets",
            )
            if record:
                records.append(record)
    return records


def unique_context_records(records):
    unique = {}
    for record in records or []:
        record = compact_mapping(record)
        key = (
            clean_string(record.get("entity_type")).casefold(),
            clean_string(record.get("stix_object_type")).casefold(),
            clean_string(record.get("value")).casefold(),
        )
        if not all(key) or key in unique:
            continue
        unique[key] = record
    return list(unique.values())


def semantic_relationship_keys(records):
    keys = set()
    for record in records or []:
        record = compact_mapping(record)
        attributes = compact_mapping(record.get("attributes"))
        source_type = clean_string(
            attributes.get("relationship_source_stix_object_type")
        )
        source_value = clean_string(attributes.get("relationship_source_value"))
        key = semantic_relationship_key(
            source_type,
            source_value,
            record.get("relationship_type"),
            record.get("stix_object_type"),
            record.get("value"),
        )
        if key:
            keys.add(key)
    return keys


def semantic_relationship_key(
    source_type,
    source_value,
    relationship_type,
    target_type,
    target_value,
):
    values = (
        clean_string(source_type).casefold(),
        clean_string(source_value).casefold(),
        clean_string(relationship_type).casefold(),
        clean_string(target_type).casefold(),
        clean_string(target_value).casefold(),
    )
    if not all(values):
        return ()
    return values


def misp_detection_rule_evidence(detection_rules, source_key=""):
    records = []
    for detection_rule in detection_rules or []:
        detection_rule = compact_mapping(detection_rule)
        if not detection_rule:
            continue
        base_attributes = {
            "rule_type": detection_rule.get("rule_type"),
            "pattern_type": detection_rule.get("pattern_type"),
            "pattern": detection_rule.get("pattern"),
            "opencti_indicator_compatible": detection_rule.get(
                "opencti_indicator_compatible"
            ),
            "opencti_indicator_compatibility_reason": detection_rule.get(
                "opencti_indicator_compatibility_reason"
            ),
            "attribute_category": detection_rule.get("attribute_category"),
            "attribute_uuid": detection_rule.get("attribute_uuid"),
            "object_name": detection_rule.get("object_name"),
            "object_uuid": detection_rule.get("object_uuid"),
            "first_seen": detection_rule.get("first_seen"),
            "last_seen": detection_rule.get("last_seen"),
            "tags": detection_rule.get("tags"),
            "attack_pattern_ids": detection_rule.get("attack_pattern_ids"),
            "attack_id_source": detection_rule.get("attack_id_source"),
        }
        rule_type = clean_string(detection_rule.get("rule_type")).casefold()
        compatible = detection_rule.get("opencti_indicator_compatible")
        incompatible = compatible is False or clean_string(compatible).casefold() in {
            "false",
            "0",
            "no",
        }
        attack_pattern_ids = (
            clean_values(detection_rule.get("attack_pattern_ids"))
            if rule_type in {"sigma", "yara"} and not incompatible
            else []
        )
        records_to_build = attack_pattern_ids or [""]
        for attack_id in records_to_build:
            attributes = dict(base_attributes)
            confidence = 70
            relationship_type = ""
            if attack_id:
                relation_source_field = (
                    detection_rule.get("source_field") or "Attribute"
                )
                attack_id_source = clean_string(
                    detection_rule.get("attack_id_source")
                )
                if attack_id_source:
                    relation_source_field = (
                        f"{relation_source_field}.{attack_id_source}"
                    )
                attributes.update(
                    {
                        "relationship_source_stix_object_type": "attack-pattern",
                        "relationship_source_value": attack_id,
                        "relationship_source_field": relation_source_field,
                        "relationship_inference": "explicit-detection-rule-attack-reference",
                    }
                )
                confidence = 85
                relationship_type = "detects"
            record = evidence_record(
                entity_type="detection_rule",
                value=detection_rule.get("value"),
                source_key=source_key,
                source_name="misp",
                source_field=detection_rule.get("source_field") or "Attribute",
                confidence=confidence,
                relationship_type=relationship_type,
                attributes=attributes,
            )
            if record:
                records.append(record)
    return records


def evidence_record(
    entity_type,
    value,
    source_key="",
    source_name="",
    source_field="",
    confidence=50,
    display_name="",
    attributes=None,
    stix_object_type="",
    relationship_type="",
):
    entity_type = clean_string(entity_type)
    value = clean_string(value)
    compact_attributes = compact_mapping(attributes)
    value, compact_attributes = normalize_evidence_value(
        entity_type,
        value,
        compact_attributes,
    )
    if not entity_type or not value:
        return {}

    default_stix_object_type, default_relationship_type = ENTITY_TARGETS.get(
        entity_type,
        ("x-narrowcti-evidence", "related-to"),
    )
    stix_object_type = clean_string(stix_object_type) or default_stix_object_type
    relationship_type = clean_string(relationship_type) or default_relationship_type
    record = {
        "entity_type": entity_type,
        "value": value,
        "stix_object_type": stix_object_type,
        "relationship_type": relationship_type,
        "source_key": clean_string(source_key),
        "source_name": clean_string(source_name),
        "source_field": clean_string(source_field),
        "confidence": evidence_confidence(
            entity_type,
            confidence,
            source_name,
            source_field,
            compact_attributes,
        ),
    }
    display_name = clean_string(display_name)
    if display_name and display_name != value:
        record["display_name"] = display_name
    if compact_attributes:
        record["attributes"] = compact_attributes
    return record


def evidence_confidence(entity_type, confidence, source_name="", source_field="", attributes=None):
    confidence = clamp_confidence(confidence)
    if entity_type == "target_sector":
        return target_sector_confidence(confidence, source_name, source_field, attributes)
    if entity_type in TARGET_LOCATION_ENTITY_TYPES:
        return target_location_confidence(confidence, source_name, source_field)
    if entity_type == "intrusion_set":
        return intrusion_set_confidence(confidence, attributes)
    if entity_type == "malware":
        return malware_confidence(confidence, attributes)
    return confidence


TARGET_LOCATION_ENTITY_TYPES = {
    "target_administrative_area",
    "target_city",
    "target_country",
    "target_position",
    "target_region",
}


def target_sector_confidence(confidence, source_name="", source_field="", attributes=None):
    source_name = clean_string(source_name).casefold()
    source_field = clean_string(source_field).casefold()
    attributes = compact_mapping(attributes)
    if source_name == "misp-galaxy" and "targeted-sector" in source_field:
        return max(confidence, 75)
    if source_name == "otx" and source_field == "industries":
        return max(confidence, 60)
    if attributes.get("normalized_value"):
        return max(confidence, 60)
    return confidence


def target_location_confidence(confidence, source_name="", source_field=""):
    source_name = clean_string(source_name).casefold()
    source_field = clean_string(source_field).casefold()
    if source_name == "misp-galaxy" and "targeted-" in source_field:
        return max(confidence, 70)
    if source_name == "otx" and source_field.startswith("targeted_"):
        return max(confidence, 60)
    return confidence


def intrusion_set_confidence(confidence, attributes=None):
    attributes = compact_mapping(attributes)
    if attributes.get("normalized_value"):
        return max(confidence, 70)
    return confidence


def malware_confidence(confidence, attributes=None):
    attributes = compact_mapping(attributes)
    if attributes.get("normalized_value"):
        return max(confidence, 70)
    return confidence


def normalize_evidence_value(entity_type, value, attributes):
    if entity_type == "intrusion_set":
        return normalize_alias_value(
            value,
            attributes,
            INTRUSION_SET_ALIASES,
            "intrusion_set",
        )
    if entity_type == "malware":
        return normalize_alias_value(
            value,
            attributes,
            MALWARE_ALIASES,
            "malware",
        )
    if entity_type == "target_sector":
        return normalize_alias_value(
            value,
            attributes,
            TARGET_SECTOR_ALIASES,
            "target_sector",
        )
    if entity_type == "target_country":
        return normalize_alias_value(
            value,
            attributes,
            TARGET_COUNTRY_ALIASES,
            "target_country",
        )
    if entity_type == "target_region":
        return normalize_alias_value(
            value,
            attributes,
            TARGET_REGION_ALIASES,
            "target_region",
        )
    return value, attributes


def normalize_alias_value(value, attributes, aliases, scope):
    canonical = aliases.get(value.casefold(), value)
    if canonical == value:
        return value, attributes
    attributes = dict(attributes)
    attributes.setdefault("source_value", value)
    attributes["normalized_value"] = True
    attributes["normalization_scope"] = scope
    return canonical, compact_mapping(attributes)


def compact_mapping(value):
    if not isinstance(value, Mapping):
        return {}
    return {
        clean_string(key): item
        for key, item in value.items()
        if clean_string(key) and item not in ("", None, [], {})
    }


def clean_string(value):
    return " ".join(str(value or "").strip().split())


def clean_values(values):
    return [clean_string(value) for value in values or [] if clean_string(value)]


def flatten_values(value):
    if isinstance(value, Mapping):
        flattened = []
        for item in value.values():
            flattened.extend(flatten_values(item))
        return flattened
    if isinstance(value, (list, tuple, set)):
        flattened = []
        for item in value:
            flattened.extend(flatten_values(item))
        return flattened
    return [value] if value not in ("", None, [], {}) else []


def mitre_external_references(attack_id, url):
    if not attack_id and not url:
        return []
    reference = {"source_name": "mitre-attack"}
    if attack_id:
        reference["external_id"] = attack_id
    if url:
        reference["url"] = url
    return [reference]


def mitre_context_attributes(attack_id, source_field):
    return compact_mapping(
        {
            "technique": attack_id,
            "relationship_source_stix_object_type": "attack-pattern",
            "relationship_source_value": attack_id,
            "relationship_source_field": source_field,
        }
    )


def mitre_data_component_from_data_source(value):
    text = clean_string(value)
    if ":" not in text:
        return {}
    data_source, data_component = text.split(":", 1)
    data_source = clean_string(data_source)
    data_component = clean_string(data_component)
    if not data_source or not data_component:
        return {}
    return {
        "data_source": data_source,
        "data_component": data_component,
    }


def mitre_kill_chain_phases(tactics):
    return [
        {"kill_chain_name": "mitre-attack", "phase_name": tactic}
        for tactic in tactics or []
        if clean_string(tactic)
    ]


def clamp_confidence(value):
    try:
        confidence = int(value)
    except (TypeError, ValueError):
        confidence = 50
    return max(0, min(100, confidence))


def first_confidence_value(*values):
    for value in values:
        clean = clean_string(value)
        if clean:
            return clamp_confidence(clean)
    return 50
