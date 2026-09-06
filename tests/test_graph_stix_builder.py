import json
import unittest

from exporters.stix_builder import (
    build_curated_report_bundle,
    build_graph_report_bundle,
    deterministic_graph_object_id,
)


class GraphStixBuilderTests(unittest.TestCase):
    def test_builds_graph_report_bundle_from_accepted_candidates(self):
        bundle, summary = build_graph_report_bundle(
            "Curated graph report",
            "graph context",
            80,
            graph_candidate_policy={
                "accepted": [
                    attack_pattern_candidate(),
                    attack_pattern_candidate(),
                    threat_actor_candidate(),
                    infrastructure_candidate(),
                    vulnerability_candidate(),
                    observable_candidate(),
                    detection_rule_candidate(),
                    event_report_candidate(),
                ],
                "held": [
                    {
                        "candidate": unsupported_candidate(),
                        "reasons": ["entity_confidence_below_min"],
                    }
                ],
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        self.assertEqual(8, summary["accepted_candidate_count"])
        self.assertEqual(16, summary["bundle_object_count"])
        self.assertEqual(7, summary["graph_object_count"])
        self.assertEqual(7, summary["graph_relationship_count"])
        self.assertEqual(0, summary["skipped_candidate_count"])
        self.assertEqual(
            {
                "attack-pattern": 1,
                "domain-name": 1,
                "infrastructure": 1,
                "indicator": 1,
                "note": 1,
                "threat-actor": 1,
                "vulnerability": 1,
            },
            summary["object_counts"],
        )
        self.assertEqual(
            {"related-to": 6, "uses": 1},
            summary["relationship_counts"],
        )
        self.assertEqual(
            {
                "attributed-to": 1,
                "based-on": 1,
                "detects": 1,
                "documents": 1,
                "related-to": 1,
                "uses": 2,
            },
            summary["proposed_relationship_counts"],
        )
        self.assertEqual(1, summary["semantic_relationship_count"])
        self.assertEqual(6, summary["report_relationship_count"])
        self.assertEqual(1, len(objects_by_type["attack-pattern"]))
        self.assertEqual(1, len(objects_by_type["threat-actor"]))
        self.assertEqual(1, len(objects_by_type["infrastructure"]))
        self.assertEqual(1, len(objects_by_type["vulnerability"]))
        self.assertEqual(1, len(objects_by_type["domain-name"]))
        self.assertEqual(1, len(objects_by_type["indicator"]))
        self.assertEqual(1, len(objects_by_type["note"]))
        self.assertEqual(7, len(objects_by_type["relationship"]))
        detection_indicator = objects_by_type["indicator"][0]
        self.assertEqual("SIGMA: Suspicious PowerShell", detection_indicator["name"])
        self.assertEqual("sigma", detection_indicator["pattern_type"])
        self.assertIn("logsource:\n", detection_indicator["pattern"])
        self.assertIn("  condition: selection", detection_indicator["pattern"])
        self.assertEqual(["malicious-activity"], detection_indicator["indicator_types"])
        self.assertIn("narrowcti:detection-rule", detection_indicator["labels"])
        self.assertIn("rule-type:sigma", detection_indicator["labels"])
        self.assertEqual(
            "Source-backed SIGMA detection rule observed by misp at Attribute[0].",
            detection_indicator["description"],
        )
        self.assertIn(
            {
                "source_name": "narrowcti-attribute-uuid",
                "external_id": "attribute-rule-1",
            },
            detection_indicator["external_references"],
        )

        attack_pattern = objects_by_type["attack-pattern"][0]
        self.assertEqual("Command and Scripting Interpreter", attack_pattern["name"])
        self.assertIn(
            {"source_name": "mitre-attack", "external_id": "T1059"},
            attack_pattern["external_references"],
        )
        self.assertEqual(
            "uses",
            attack_pattern["x_narrowcti_proposed_relationship_type"],
        )
        note = objects_by_type["note"][0]
        self.assertEqual("Initial analyst report", note["abstract"])
        self.assertEqual(
            "The event describes exploitation activity.",
            note["content"],
        )
        self.assertIn(
            "identity--",
            note["object_refs"][0],
        )

        reports = objects_by_type["report"]
        self.assertEqual(1, len(reports))
        self.assertEqual(7, len(reports[0]["object_refs"]))
        report_context_relationships = [
            relationship
            for relationship in objects_by_type["relationship"]
            if relationship["x_narrowcti_relationship_mode"] == "report-context"
        ]
        semantic_relationships = [
            relationship
            for relationship in objects_by_type["relationship"]
            if relationship["x_narrowcti_relationship_mode"] == "semantic"
        ]
        self.assertEqual(6, len(report_context_relationships))
        self.assertTrue(
            all(
                relationship["source_ref"] == reports[0]["id"]
                and relationship["relationship_type"] == "related-to"
                for relationship in report_context_relationships
            )
        )
        self.assertEqual(
            ["uses"],
            [relationship["relationship_type"] for relationship in semantic_relationships],
        )

    def test_attack_pattern_preserves_kill_chain_phases(self):
        candidate = attack_pattern_candidate()
        candidate["attributes"] = {
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
                {"kill_chain_name": "", "phase_name": "ignored"},
                "ignored",
            ],
        }

        bundle, _summary = build_graph_report_bundle(
            "Curated graph report",
            "graph context",
            80,
            graph_candidate_policy={"accepted": [candidate]},
        )

        data = json.loads(bundle.serialize())
        attack_pattern = next(
            item for item in data["objects"] if item["type"] == "attack-pattern"
        )

        self.assertEqual(
            [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            attack_pattern["kill_chain_phases"],
        )

    def test_preserves_incompatible_detection_rule_as_note(self):
        bundle, summary = build_graph_report_bundle(
            "Curated graph report",
            "graph context",
            80,
            graph_candidate_policy={"accepted": [snort_detection_rule_candidate()]},
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        self.assertNotIn("indicator", objects_by_type)
        self.assertEqual(1, len(objects_by_type["note"]))
        self.assertEqual(1, summary["graph_object_count"])
        self.assertEqual({"note": 1}, summary["object_counts"])
        note = objects_by_type["note"][0]
        self.assertEqual("SNORT: Adobe Flash Exploit", note["abstract"])
        self.assertIn("rule-type:snort", note["labels"])
        self.assertIn("narrowcti:detection-rule", note["labels"])
        self.assertIn("alert tcp any any -> any any", note["content"])
        self.assertIn(
            {
                "source_name": "narrowcti-attribute-uuid",
                "external_id": "attribute-snort-1",
            },
            note["external_references"],
        )

    def test_preserves_incompatible_sigma_detection_rule_as_note(self):
        bundle, summary = build_graph_report_bundle(
            "Curated graph report",
            "graph context",
            80,
            graph_candidate_policy={
                "accepted": [incompatible_sigma_detection_rule_candidate()]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        self.assertNotIn("indicator", objects_by_type)
        self.assertEqual(1, len(objects_by_type["note"]))
        self.assertEqual(1, summary["graph_object_count"])
        self.assertEqual({"note": 1}, summary["object_counts"])
        note = objects_by_type["note"][0]
        self.assertEqual("SIGMA: Broken Sigma", note["abstract"])
        self.assertIn("rule-type:sigma", note["labels"])
        self.assertIn("missing detection selection", note["content"])
        self.assertIn("title: Broken Sigma", note["content"])

    def test_builds_detection_rule_detects_attack_pattern_relationship(self):
        bundle, summary = build_graph_report_bundle(
            "Sigma relationship report",
            "explicit Sigma ATT&CK mapping",
            85,
            graph_candidate_policy={
                "accepted": [
                    attack_pattern_candidate(),
                    detection_rule_attack_pattern_candidate(),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        attack_pattern = next(
            item for item in data["objects"] if item["type"] == "attack-pattern"
        )
        indicator = next(item for item in data["objects"] if item["type"] == "indicator")
        relationships = [
            item
            for item in data["objects"]
            if item["type"] == "relationship"
            and item["relationship_type"] == "detects"
        ]

        self.assertEqual(1, len(relationships))
        self.assertEqual(indicator["id"], relationships[0]["source_ref"])
        self.assertEqual(attack_pattern["id"], relationships[0]["target_ref"])
        self.assertEqual(1, summary["semantic_relationship_count"])
        self.assertEqual(1, summary["relationship_counts"]["detects"])

    def test_native_threat_actor_individual_is_not_exported_as_generic_stix_actor(self):
        bundle, summary = build_graph_report_bundle(
            "Curated graph report",
            "graph context",
            80,
            graph_candidate_policy={
                "accepted": [
                    threat_actor_individual_candidate(),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        self.assertNotIn("threat-actor", [item["type"] for item in data["objects"]])
        self.assertEqual(0, summary["graph_object_count"])
        self.assertEqual(1, summary["skipped_candidate_count"])

    def test_builds_semantic_relationship_when_source_anchor_is_trusted(self):
        bundle, summary = build_graph_report_bundle(
            "Curated graph report",
            "graph context",
            80,
            graph_candidate_policy={
                "accepted": [
                    threat_actor_candidate(),
                    target_sector_candidate(),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        actor = objects_by_type["threat-actor"][0]
        sector = next(
            item
            for item in objects_by_type["identity"]
            if item["name"] == "Finance"
        )
        target_relationship = next(
            relationship
            for relationship in objects_by_type["relationship"]
            if relationship["relationship_type"] == "targets"
        )

        self.assertEqual("class", sector["identity_class"])
        self.assertEqual(actor["id"], target_relationship["source_ref"])
        self.assertEqual(sector["id"], target_relationship["target_ref"])
        self.assertEqual(
            "semantic",
            target_relationship["x_narrowcti_relationship_mode"],
        )
        self.assertEqual(
            {
                "related-to": 1,
                "targets": 1,
            },
            summary["relationship_counts"],
        )
        self.assertEqual(
            {
                "attributed-to": 1,
                "targets": 1,
            },
            summary["proposed_relationship_counts"],
        )
        self.assertEqual(1, summary["semantic_relationship_count"])
        self.assertEqual(1, summary["report_relationship_count"])

    def test_graph_objects_preserve_source_backed_descriptions(self):
        bundle, _ = build_graph_report_bundle(
            "Curated graph report",
            "graph context",
            80,
            graph_candidate_policy={
                "accepted": [
                    described_threat_actor_candidate(),
                    target_sector_candidate(),
                    described_tool_candidate(),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        actor = objects_by_type["threat-actor"][0]
        sector = next(
            item
            for item in objects_by_type["identity"]
            if item["name"] == "Finance"
        )
        tool = objects_by_type["tool"][0]

        self.assertEqual(
            "APT Example is a source-described threat actor.",
            actor["description"],
        )
        self.assertEqual(
            "Source-backed target sector observed by misp-galaxy: "
            "APT Example targets Finance.",
            sector["description"],
        )
        self.assertEqual(
            "Turla is a source-described backdoor tool.",
            tool["description"],
        )

    def test_hydrates_existing_narrow_owned_graph_object_description(self):
        sector_candidate = target_sector_candidate()
        sector_candidate["attributes"] = {
            **sector_candidate["attributes"],
            "opencti_existing_ref": deterministic_graph_object_id(
                "identity",
                "Finance",
                "Finance",
                {"identity_class": "class"},
            ),
        }

        bundle, summary = build_graph_report_bundle(
            "Curated graph report",
            "graph context",
            80,
            graph_candidate_policy={"accepted": [sector_candidate]},
        )

        data = json.loads(bundle.serialize())
        identities = [
            item
            for item in data["objects"]
            if item["type"] == "identity" and item["name"] == "Finance"
        ]
        self.assertEqual(1, len(identities))
        self.assertEqual(1, summary["existing_reference_count"])
        self.assertEqual(1, summary["graph_object_count"])
        self.assertEqual(
            "Source-backed target sector observed by misp-galaxy: "
            "APT Example targets Finance.",
            identities[0]["description"],
        )

    def test_does_not_hydrate_external_existing_graph_object(self):
        sector_candidate = target_sector_candidate()
        sector_candidate["attributes"] = {
            **sector_candidate["attributes"],
            "opencti_existing_ref": "identity--11111111-1111-4111-8111-111111111111",
        }

        bundle, summary = build_graph_report_bundle(
            "Curated graph report",
            "graph context",
            80,
            graph_candidate_policy={"accepted": [sector_candidate]},
        )

        data = json.loads(bundle.serialize())
        self.assertFalse(
            any(
                item["type"] == "identity" and item["name"] == "Finance"
                for item in data["objects"]
            )
        )
        self.assertEqual(1, summary["existing_reference_count"])
        self.assertEqual(0, summary["graph_object_count"])

    def test_builds_campaign_and_campaign_targeting_relationship(self):
        bundle, summary = build_graph_report_bundle(
            "Curated graph report",
            "graph context",
            80,
            graph_candidate_policy={
                "accepted": [
                    campaign_candidate(),
                    campaign_target_sector_candidate(),
                    campaign_target_organization_candidate(),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        campaign = objects_by_type["campaign"][0]
        sector = next(
            item
            for item in objects_by_type["identity"]
            if item["name"] == "Energy"
        )
        organization = next(
            item
            for item in objects_by_type["identity"]
            if item["name"] == "Example Energy Co"
        )
        target_relationships = [
            relationship
            for relationship in objects_by_type["relationship"]
            if relationship["relationship_type"] == "targets"
        ]

        self.assertEqual("Operation Example", campaign["name"])
        self.assertEqual(
            "Source-backed campaign observed by misp-galaxy at Galaxy: "
            "Operation Example.",
            campaign["description"],
        )
        self.assertEqual("class", sector["identity_class"])
        self.assertEqual("organization", organization["identity_class"])
        self.assertEqual(
            [campaign["id"], campaign["id"]],
            sorted(relationship["source_ref"] for relationship in target_relationships),
        )
        self.assertEqual(
            sorted([sector["id"], organization["id"]]),
            sorted(relationship["target_ref"] for relationship in target_relationships),
        )
        self.assertEqual(
            ["semantic", "semantic"],
            sorted(
                relationship["x_narrowcti_relationship_mode"]
                for relationship in target_relationships
            ),
        )
        self.assertEqual(
            {
                "related-to": 1,
                "targets": 2,
            },
            summary["relationship_counts"],
        )
        self.assertEqual(
            {
                "related-to": 1,
                "targets": 2,
            },
            summary["proposed_relationship_counts"],
        )

    def test_builds_course_of_action_from_source_backed_candidate(self):
        bundle, summary = build_graph_report_bundle(
            "Curated mitigation report",
            "Course of action context",
            80,
            graph_candidate_policy={
                "accepted": [
                    course_of_action_candidate(),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        course = objects_by_type["course-of-action"][0]
        self.assertEqual("Disable or Remove Feature or Program", course["name"])
        self.assertEqual(
            "Source-backed course of action observed by misp-galaxy at Galaxy: "
            "Disable or Remove Feature or Program.",
            course["description"],
        )
        self.assertEqual(1, summary["graph_object_count"])
        self.assertEqual(
            {"course-of-action": 1},
            summary["object_counts"],
        )

    def test_builds_course_of_action_mitigates_attack_pattern_relationship(self):
        bundle, summary = build_graph_report_bundle(
            "Curated mitigation report",
            "Course of action context",
            80,
            graph_candidate_policy={
                "accepted": [
                    attack_pattern_candidate(),
                    mitigating_course_of_action_candidate(),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        course = objects_by_type["course-of-action"][0]
        attack_pattern = objects_by_type["attack-pattern"][0]
        semantic_relationships = [
            item
            for item in data["objects"]
            if item["type"] == "relationship"
            and item["relationship_type"] == "mitigates"
        ]

        self.assertEqual(1, len(semantic_relationships))
        self.assertEqual(course["id"], semantic_relationships[0]["source_ref"])
        self.assertEqual(attack_pattern["id"], semantic_relationships[0]["target_ref"])
        self.assertEqual(1, summary["semantic_relationship_count"])
        self.assertEqual(1, summary["relationship_counts"]["mitigates"])
        self.assertEqual(1, summary["proposed_relationship_counts"]["mitigates"])

    def test_builds_source_and_collector_identities_as_organizations(self):
        bundle, _summary = build_graph_report_bundle(
            "Curated graph report",
            "graph context",
            80,
            graph_candidate_policy={
                "accepted": [
                    source_identity_candidate(),
                    collector_candidate(),
                    target_sector_candidate(),
                    target_individual_candidate(),
                    target_system_candidate(),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        identities = {
            item["name"]: item
            for item in data["objects"]
            if item["type"] == "identity"
        }

        self.assertEqual("organization", identities["VK-Intel"]["identity_class"])
        self.assertEqual("organization", identities["misp"]["identity_class"])
        self.assertEqual("class", identities["Finance"]["identity_class"])
        self.assertEqual("individual", identities["Incident Responder"]["identity_class"])
        self.assertEqual("system", identities["SAP ERP"]["identity_class"])

    def test_builds_semantic_relationship_from_explicit_source_anchor(self):
        bundle, _ = build_graph_report_bundle(
            "Curated graph report",
            "graph context",
            80,
            graph_candidate_policy={
                "accepted": [
                    threat_actor_candidate(),
                    anchored_malware_candidate(),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        actor = objects_by_type["threat-actor"][0]
        malware = objects_by_type["malware"][0]
        relationship = next(
            relationship
            for relationship in objects_by_type["relationship"]
            if relationship["relationship_type"] == "uses"
        )

        self.assertEqual(actor["id"], relationship["source_ref"])
        self.assertEqual(malware["id"], relationship["target_ref"])
        self.assertEqual("semantic", relationship["x_narrowcti_relationship_mode"])
        self.assertEqual(
            "threat-actor",
            relationship["x_narrowcti_relationship_source_type"],
        )
        self.assertEqual(
            "APT Example",
            relationship["x_narrowcti_relationship_source_value"],
        )
        self.assertEqual(
            "adversary",
            relationship["x_narrowcti_relationship_source_field"],
        )

    def test_builds_infrastructure_asn_ip_relationships(self):
        bundle, summary = build_graph_report_bundle(
            "Curated infrastructure report",
            "ASN/IP context",
            80,
            graph_candidate_policy={
                "accepted": [
                    infrastructure_candidate(),
                    infrastructure_asn_candidate("consists-of"),
                    infrastructure_ip_candidate(),
                    infrastructure_asn_candidate(
                        "belongs-to",
                        source_type="observable",
                        source_value="203.0.113.10",
                    ),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        self.assertEqual(4, summary["accepted_candidate_count"])
        self.assertEqual(3, summary["graph_object_count"])
        self.assertEqual(
            {
                "autonomous-system": 1,
                "infrastructure": 1,
                "ipv4-addr": 1,
            },
            summary["object_counts"],
        )
        self.assertEqual(
            {"belongs-to": 1, "consists-of": 2, "related-to": 1},
            summary["relationship_counts"],
        )
        self.assertEqual(3, summary["semantic_relationship_count"])
        self.assertEqual(1, summary["report_relationship_count"])
        self.assertEqual(1, len(objects_by_type["autonomous-system"]))
        self.assertEqual(1, len(objects_by_type["ipv4-addr"]))

        infrastructure = objects_by_type["infrastructure"][0]
        autonomous_system = objects_by_type["autonomous-system"][0]
        ip_address = objects_by_type["ipv4-addr"][0]
        self.assertEqual(64512, autonomous_system["number"])
        self.assertEqual("AS64512 NarrowCTI Validation ASN", autonomous_system["name"])
        self.assertEqual("203.0.113.10", ip_address["value"])
        self.assertEqual(
            "2026-06-20T10:00:00Z",
            infrastructure["x_narrowcti_source_created"],
        )
        self.assertEqual(
            "2026-06-22T10:00:00Z",
            infrastructure["x_narrowcti_source_modified"],
        )
        self.assertEqual("2026-06-20", infrastructure["x_narrowcti_source_date"])
        self.assertEqual(
            "2026-06-20T10:05:00Z",
            infrastructure["x_narrowcti_first_seen"],
        )
        self.assertEqual(
            "2026-06-22T10:05:00Z",
            infrastructure["x_narrowcti_last_seen"],
        )

        relationships = objects_by_type["relationship"]
        self.assertTrue(
            any(
                relationship["source_ref"] == infrastructure["id"]
                and relationship["relationship_type"] == "consists-of"
                and relationship["target_ref"] == autonomous_system["id"]
                for relationship in relationships
            )
        )
        infrastructure_asn_relationship = next(
            relationship
            for relationship in relationships
            if relationship["source_ref"] == infrastructure["id"]
            and relationship["relationship_type"] == "consists-of"
            and relationship["target_ref"] == autonomous_system["id"]
        )
        self.assertEqual(
            "2026-06-20T10:00:00Z",
            infrastructure_asn_relationship["x_narrowcti_source_created"],
        )
        self.assertEqual(
            "2026-06-22T10:05:00Z",
            infrastructure_asn_relationship["x_narrowcti_last_seen"],
        )
        self.assertTrue(
            any(
                relationship["source_ref"] == infrastructure["id"]
                and relationship["relationship_type"] == "consists-of"
                and relationship["target_ref"] == ip_address["id"]
                for relationship in relationships
            )
        )
        self.assertTrue(
            any(
                relationship["source_ref"] == ip_address["id"]
                and relationship["relationship_type"] == "belongs-to"
                and relationship["target_ref"] == autonomous_system["id"]
                for relationship in relationships
            )
        )

    def test_autonomous_system_without_source_name_uses_as_number_as_name(self):
        bundle, summary = build_graph_report_bundle(
            "Curated ASN report",
            "ASN-only context",
            80,
            graph_candidate_policy={
                "accepted": [
                    {
                        "fingerprint": "asn-only",
                        "entity_type": "autonomous_system",
                        "value": "AS64513",
                        "stix_object_type": "autonomous-system",
                        "relationship_type": "related-to",
                        "source_key": "misp:misp",
                        "source_name": "misp-object",
                        "source_field": "Attribute[5]",
                        "confidence": 70,
                        "relationship_confidence": 70,
                        "attributes": {"asn": 64513},
                    }
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        autonomous_system = objects_by_type["autonomous-system"][0]
        self.assertEqual(1, summary["object_counts"]["autonomous-system"])
        self.assertEqual(64513, autonomous_system["number"])
        self.assertEqual("AS64513", autonomous_system["name"])

    def test_builds_ipv6_belongs_to_autonomous_system_relationship(self):
        bundle, summary = build_graph_report_bundle(
            "Curated IPv6 infrastructure report",
            "IPv6 ASN context",
            80,
            graph_candidate_policy={
                "accepted": [
                    infrastructure_candidate(),
                    infrastructure_ipv6_candidate(),
                    infrastructure_asn_candidate(
                        "belongs-to",
                        source_type="observable",
                        source_value="2001:db8::10",
                    ),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        ipv6 = objects_by_type["ipv6-addr"][0]
        autonomous_system = objects_by_type["autonomous-system"][0]
        relationships = objects_by_type["relationship"]

        self.assertEqual("2001:db8::10", ipv6["value"])
        self.assertEqual(1, summary["object_counts"]["ipv6-addr"])
        self.assertEqual(1, summary["relationship_counts"]["belongs-to"])
        self.assertTrue(
            any(
                relationship["source_ref"] == ipv6["id"]
                and relationship["relationship_type"] == "belongs-to"
                and relationship["target_ref"] == autonomous_system["id"]
                for relationship in relationships
            )
        )

    def test_builds_infrastructure_attack_pattern_related_relationship(self):
        bundle, summary = build_graph_report_bundle(
            "Curated infrastructure TTP report",
            "Infrastructure technique context",
            80,
            graph_candidate_policy={
                "accepted": [
                    infrastructure_candidate(),
                    infrastructure_attack_pattern_candidate(),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        infrastructure = objects_by_type["infrastructure"][0]
        attack_pattern = objects_by_type["attack-pattern"][0]
        relationship = next(
            relationship
            for relationship in objects_by_type["relationship"]
            if relationship["relationship_type"] == "related-to"
            and relationship["source_ref"] == infrastructure["id"]
            and relationship["target_ref"] == attack_pattern["id"]
        )

        self.assertEqual(2, summary["accepted_candidate_count"])
        self.assertEqual(
            {"related-to": 2},
            summary["relationship_counts"],
        )
        self.assertEqual(1, summary["semantic_relationship_count"])
        self.assertEqual(1, summary["report_relationship_count"])
        self.assertEqual("semantic", relationship["x_narrowcti_relationship_mode"])
        self.assertEqual(
            "infrastructure",
            relationship["x_narrowcti_relationship_source_type"],
        )
        self.assertEqual(
            "Validation C2 Infrastructure",
            relationship["x_narrowcti_relationship_source_value"],
        )

    def test_builds_infrastructure_victimology_targets_relationship(self):
        bundle, summary = build_graph_report_bundle(
            "Curated infrastructure victimology report",
            "Infrastructure target context",
            80,
            graph_candidate_policy={
                "accepted": [
                    infrastructure_candidate(),
                    infrastructure_victimology_candidate(),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        infrastructure = objects_by_type["infrastructure"][0]
        sector = next(
            item
            for item in objects_by_type["identity"]
            if item["name"] == "Finance"
        )
        relationship = next(
            relationship
            for relationship in objects_by_type["relationship"]
            if relationship["relationship_type"] == "targets"
            and relationship["source_ref"] == infrastructure["id"]
            and relationship["target_ref"] == sector["id"]
        )

        self.assertEqual(2, summary["accepted_candidate_count"])
        self.assertEqual(
            {"related-to": 1, "targets": 1},
            summary["relationship_counts"],
        )
        self.assertEqual(1, summary["semantic_relationship_count"])
        self.assertEqual(1, summary["report_relationship_count"])
        self.assertEqual("Finance", sector["name"])
        self.assertEqual("semantic", relationship["x_narrowcti_relationship_mode"])
        self.assertEqual(
            "infrastructure",
            relationship["x_narrowcti_relationship_source_type"],
        )
        self.assertEqual(
            "Validation C2 Infrastructure",
            relationship["x_narrowcti_relationship_source_value"],
        )

    def test_builds_mitre_data_source_and_skips_unimportable_context_objects(self):
        bundle, summary = build_graph_report_bundle(
            "Curated MITRE context report",
            "Technique context",
            80,
            graph_candidate_policy={
                "accepted": [
                    attack_pattern_candidate(),
                    attack_tactic_candidate(),
                    attack_platform_candidate(),
                    attack_data_source_candidate(),
                    attack_data_component_candidate(),
                    detection_guidance_candidate(),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        attack_pattern = objects_by_type["attack-pattern"][0]
        data_source = objects_by_type["x-mitre-data-source"][0]
        data_component = objects_by_type["x-mitre-data-component"][0]
        self.assertEqual(2, summary["skipped_candidate_count"])
        self.assertEqual(
            [
                {
                    "entity_type": "attack_tactic",
                    "value": "execution",
                    "stix_object_type": "x-mitre-tactic",
                    "relationship_type": "uses",
                },
                {
                    "entity_type": "attack_platform",
                    "value": "Windows",
                    "stix_object_type": "x-narrowcti-attack-platform",
                    "relationship_type": "applies-to",
                },
            ],
            summary["skipped_candidates"],
        )
        self.assertEqual(1, len(objects_by_type["x-mitre-data-source"]))
        self.assertEqual(1, len(objects_by_type["x-mitre-data-component"]))
        self.assertEqual(1, len(objects_by_type["note"]))
        self.assertEqual(
            "Source-backed MITRE data source observed by mitre-attack: "
            "T1059 detects Process: Process Creation.",
            data_source["description"],
        )
        self.assertEqual(
            "Source-backed MITRE data component observed by mitre-attack: "
            "T1059 detects Process Creation.",
            data_component["description"],
        )
        self.assertEqual(
            {
                "attack-pattern": 1,
                "note": 1,
                "x-mitre-data-component": 1,
                "x-mitre-data-source": 1,
            },
            summary["object_counts"],
        )
        self.assertTrue(
            any(
                relationship["source_ref"] == data_source["id"]
                and relationship["relationship_type"] == "detects"
                and relationship["target_ref"] == attack_pattern["id"]
                for relationship in objects_by_type["relationship"]
            )
        )
        self.assertTrue(
            any(
                relationship["source_ref"] == data_component["id"]
                and relationship["relationship_type"] == "detects"
                and relationship["target_ref"] == attack_pattern["id"]
                for relationship in objects_by_type["relationship"]
            )
        )

    def test_builds_object_reference_relationship_when_misp_uuids_resolve(self):
        bundle, summary = build_graph_report_bundle(
            "Curated object reference report",
            "MISP ObjectReference context",
            80,
            graph_candidate_policy={
                "accepted": [
                    misp_uuid_infrastructure_candidate(),
                    misp_uuid_malware_candidate(),
                    object_reference_candidate(),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        malware = objects_by_type["malware"][0]
        infrastructure = objects_by_type["infrastructure"][0]
        self.assertEqual(0, summary["skipped_candidate_count"])
        self.assertEqual(2, summary["graph_object_count"])
        self.assertEqual(3, summary["graph_relationship_count"])
        self.assertEqual(1, summary["semantic_relationship_count"])
        self.assertEqual(2, summary["report_relationship_count"])
        self.assertTrue(
            any(
                relationship["source_ref"] == malware["id"]
                and relationship["relationship_type"] == "uses"
                and relationship["target_ref"] == infrastructure["id"]
                for relationship in objects_by_type["relationship"]
            )
        )

    def test_builds_sighting_when_indicator_target_resolves(self):
        bundle, indicator_count, summary = build_curated_report_bundle(
            "Curated sighting report",
            "Sighting context",
            80,
            indicators=[{"type": "domain", "indicator": "evil.example"}],
            graph_candidate_policy={"accepted": [sighting_candidate()]},
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        indicator = objects_by_type["indicator"][0]
        sighting = objects_by_type["sighting"][0]
        self.assertEqual(1, indicator_count)
        self.assertEqual(0, summary["skipped_candidate_count"])
        self.assertEqual(0, summary["graph_object_count"])
        self.assertEqual(1, summary["graph_relationship_count"])
        self.assertEqual(indicator["id"], sighting["sighting_of_ref"])
        self.assertIn("identity--", sighting["where_sighted_refs"][0])
        self.assertEqual(65, sighting["confidence"])
        self.assertEqual("2026-06-21T01:21:40Z", sighting["first_seen"])
        self.assertEqual("2026-06-21T01:21:40Z", sighting["last_seen"])
        self.assertEqual(1, summary["relationship_counts"]["sighting-of"])

    def test_skips_non_positive_misp_sighting(self):
        candidate = sighting_candidate()
        candidate["attributes"]["sighting_type"] = "1"
        bundle, indicator_count, summary = build_curated_report_bundle(
            "Curated false-positive sighting report",
            "Sighting context",
            80,
            indicators=[{"type": "domain", "indicator": "evil.example"}],
            graph_candidate_policy={"accepted": [candidate]},
        )

        data = json.loads(bundle.serialize())
        self.assertEqual(1, indicator_count)
        self.assertNotIn("sighting", {item["type"] for item in data["objects"]})
        self.assertEqual(0, summary["graph_relationship_count"])
        self.assertEqual({}, summary["relationship_counts"])


    def test_builds_curated_bundle_with_indicators_and_graph_entities(self):
        bundle, indicator_count, summary = build_curated_report_bundle(
            "Curated ingest report",
            "graph context",
            80,
            indicators=[{"type": "domain", "indicator": "one.example"}],
            graph_candidate_policy={
                "accepted": [
                    threat_actor_candidate(),
                    infrastructure_candidate(),
                    target_sector_candidate(),
                    anchored_malware_candidate(),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        sector = next(
            item
            for item in objects_by_type["identity"]
            if item["name"] == "Finance"
        )
        report = objects_by_type["report"][0]

        self.assertEqual(1, indicator_count)
        self.assertEqual(1, summary["indicator_count"])
        self.assertEqual(4, summary["graph_object_count"])
        self.assertEqual("class", sector["identity_class"])
        self.assertEqual(1, len(objects_by_type["indicator"]))
        self.assertEqual(1, len(objects_by_type["infrastructure"]))
        self.assertEqual(1, len(objects_by_type["malware"]))
        self.assertEqual(1, len(objects_by_type["threat-actor"]))
        self.assertIn(sector["id"], report["object_refs"])
        self.assertIn(objects_by_type["indicator"][0]["id"], report["object_refs"])

    def test_graph_objects_use_stable_ids_for_repeated_exports(self):
        first_bundle, _ = build_graph_report_bundle(
            "Curated graph report",
            "graph context",
            80,
            graph_candidate_policy={
                "accepted": [
                    threat_actor_candidate(),
                    infrastructure_candidate(),
                    target_sector_candidate(),
                    target_country_candidate(),
                    vulnerability_candidate(),
                ]
            },
        )
        second_bundle, _ = build_graph_report_bundle(
            "Curated graph report",
            "graph context",
            80,
            graph_candidate_policy={
                "accepted": [
                    threat_actor_candidate(),
                    infrastructure_candidate(),
                    target_sector_candidate(),
                    target_country_candidate(),
                    vulnerability_candidate(),
                ]
            },
        )

        first_ids = graph_object_ids_by_name(first_bundle)
        second_ids = graph_object_ids_by_name(second_bundle)

        self.assertEqual(first_ids["APT Example"], second_ids["APT Example"])
        self.assertEqual(
            first_ids["Validation C2 Infrastructure"],
            second_ids["Validation C2 Infrastructure"],
        )
        self.assertEqual(first_ids["Finance"], second_ids["Finance"])
        self.assertEqual(first_ids["Argentina"], second_ids["Argentina"])
        self.assertEqual(first_ids["CVE-2026-0001"], second_ids["CVE-2026-0001"])

    def test_builds_deep_location_fields_from_source_backed_candidate(self):
        bundle, summary = build_graph_report_bundle(
            "Curated location report",
            "location context",
            80,
            graph_candidate_policy={
                "accepted": [
                    target_city_candidate(),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        location = objects_by_type["location"][0]
        self.assertEqual("Sao Paulo", location["name"])
        self.assertEqual("South America", location["region"])
        self.assertEqual("Brazil", location["country"])
        self.assertEqual("Sao Paulo", location["administrative_area"])
        self.assertEqual("Sao Paulo", location["city"])
        self.assertEqual(-23.5505, location["latitude"])
        self.assertEqual(-46.6333, location["longitude"])
        self.assertEqual(10.0, location["precision"])
        self.assertEqual("City", location["x_opencti_location_type"])
        self.assertEqual(1, summary["graph_object_count"])

    def test_builds_opencti_location_type_hints(self):
        bundle, _ = build_graph_report_bundle(
            "Curated location report",
            "location context",
            80,
            graph_candidate_policy={
                "accepted": [
                    target_country_candidate(),
                    target_region_candidate(),
                    target_administrative_area_candidate(),
                    target_city_candidate(),
                    target_position_candidate(),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        location_types_by_name = {
            item["name"]: item["x_opencti_location_type"]
            for item in data["objects"]
            if item["type"] == "location"
        }

        self.assertEqual("Country", location_types_by_name["Argentina"])
        self.assertEqual("Region", location_types_by_name["South America"])
        self.assertEqual("Administrative-Area", location_types_by_name["Sao Paulo State"])
        self.assertEqual("City", location_types_by_name["Sao Paulo"])
        self.assertEqual("Position", location_types_by_name["Sao Paulo Position"])

    def test_builds_opencti_custom_sdos_with_extension_definition(self):
        bundle, summary = build_graph_report_bundle(
            "Curated custom SDO report",
            "custom graph context",
            80,
            graph_candidate_policy={
                "accepted": [
                    channel_candidate(),
                    narrative_candidate(),
                    event_candidate(),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        self.assertEqual(3, summary["accepted_candidate_count"])
        self.assertEqual(9, summary["bundle_object_count"])
        self.assertEqual(3, summary["graph_object_count"])
        self.assertEqual(3, summary["graph_relationship_count"])
        self.assertEqual(
            {"channel": 1, "event": 1, "narrative": 1},
            summary["object_counts"],
        )
        self.assertEqual(1, len(objects_by_type["extension-definition"]))
        extension_id = objects_by_type["extension-definition"][0]["id"]

        channel = objects_by_type["channel"][0]
        self.assertEqual("Telegram C2", channel["name"])
        self.assertEqual(["c2", "delivery"], channel["channel_types"])
        self.assertEqual(["Telegram"], channel["aliases"])
        self.assertEqual(
            "Source-backed channel observed by MISP via NarrowCTI at "
            "Galaxy.meta.channel: Telegram C2.",
            channel["description"],
        )
        self.assertEqual(
            {"extension_type": "new-sdo"},
            channel["extensions"][extension_id],
        )

        narrative = objects_by_type["narrative"][0]
        self.assertEqual("Credential theft objective", narrative["name"])
        self.assertEqual(["objective"], narrative["narrative_types"])
        self.assertEqual(
            "Source-backed objective narrative.",
            narrative["description"],
        )
        self.assertEqual(
            {"extension_type": "new-sdo"},
            narrative["extensions"][extension_id],
        )

        event = objects_by_type["event"][0]
        self.assertEqual("Observed phishing wave", event["name"])
        self.assertEqual(["phishing"], event["event_types"])
        self.assertEqual(
            "Source-backed event observed by MISP via NarrowCTI at Event.info: "
            "Observed phishing wave.",
            event["description"],
        )
        self.assertTrue(event["start_time"].startswith("2026-06-25T10:00:00"))
        self.assertTrue(event["stop_time"].startswith("2026-06-25T12:00:00"))
        self.assertEqual(
            {"extension_type": "new-sdo"},
            event["extensions"][extension_id],
        )

    def test_curated_bundle_references_existing_opencti_objects(self):
        existing_attack_pattern_ref = (
            "attack-pattern--11111111-1111-4111-8111-111111111111"
        )
        bundle, _, summary = build_curated_report_bundle(
            "Curated ingest report",
            "graph context",
            80,
            graph_candidate_policy={
                "accepted": [
                    threat_actor_candidate(),
                    existing_attack_pattern_candidate(existing_attack_pattern_ref),
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        actor = objects_by_type["threat-actor"][0]
        report = objects_by_type["report"][0]
        relationship = next(
            item
            for item in objects_by_type["relationship"]
            if item["relationship_type"] == "uses"
        )

        self.assertNotIn("attack-pattern", objects_by_type)
        self.assertEqual(1, summary["existing_reference_count"])
        self.assertEqual(
            {"attack-pattern": 1},
            summary["existing_reference_counts"],
        )
        self.assertIn(existing_attack_pattern_ref, report["object_refs"])
        self.assertEqual(actor["id"], relationship["source_ref"])
        self.assertEqual(existing_attack_pattern_ref, relationship["target_ref"])
        self.assertEqual("semantic", relationship["x_narrowcti_relationship_mode"])

    def test_curated_bundle_references_existing_opencti_observables(self):
        existing_observable_ref = (
            "ipv4-addr--11111111-1111-4111-8111-111111111111"
        )
        bundle, _, summary = build_curated_report_bundle(
            "Curated observable report",
            "graph context",
            80,
            graph_candidate_policy={
                "accepted": [
                    existing_ipv4_observable_candidate(existing_observable_ref)
                ]
            },
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        report = objects_by_type["report"][0]
        relationship = objects_by_type["relationship"][0]

        self.assertNotIn("ipv4-addr", objects_by_type)
        self.assertEqual(1, summary["existing_reference_count"])
        self.assertEqual(
            {"observable": 1},
            summary["existing_reference_counts"],
        )
        self.assertIn(existing_observable_ref, report["object_refs"])
        self.assertEqual(existing_observable_ref, relationship["target_ref"])

    def test_builds_artifact_observable_from_explicit_metadata(self):
        bundle, summary = build_graph_report_bundle(
            "Curated artifact report",
            "artifact context",
            80,
            graph_candidate_policy={"accepted": [artifact_candidate()]},
        )

        data = json.loads(bundle.serialize())
        objects_by_type = {}
        for item in data["objects"]:
            objects_by_type.setdefault(item["type"], []).append(item)

        artifact = objects_by_type["artifact"][0]
        self.assertEqual(
            {
                "SHA-256": (
                    "0123456789abcdef0123456789abcdef"
                    "0123456789abcdef0123456789abcdef"
                )
            },
            artifact["hashes"],
        )
        self.assertEqual(
            "https://narrowcti.local/artifacts/sample.bin",
            artifact["url"],
        )
        self.assertEqual("application/octet-stream", artifact["mime_type"])
        self.assertEqual(1, summary["graph_object_count"])
        self.assertEqual({"artifact": 1}, summary["object_counts"])

    def test_skips_invalid_or_unsupported_graph_candidates(self):
        _, summary = build_graph_report_bundle(
            "Curated graph report",
            "graph context",
            80,
            graph_candidate_policy={
                "accepted": [
                    unsupported_candidate(),
                    {
                        "entity_type": "observable",
                        "value": "bad-hash",
                        "name": "bad-hash",
                        "stix_object_type": "observable",
                        "relationship_type": "based-on",
                        "confidence": 65,
                        "attributes": {
                            "observable_type": "file",
                            "hash_algorithm": "SHA-256",
                        },
                    },
                    {
                        "entity_type": "artifact",
                        "value": "bad-artifact",
                        "name": "bad-artifact",
                        "stix_object_type": "observable",
                        "relationship_type": "related-to",
                        "confidence": 65,
                        "attributes": {
                            "observable_type": "artifact",
                        },
                    },
                ]
            },
        )

        self.assertEqual(3, summary["accepted_candidate_count"])
        self.assertEqual(0, summary["graph_object_count"])
        self.assertEqual(0, summary["graph_relationship_count"])
        self.assertEqual(3, summary["skipped_candidate_count"])

    def test_graph_relationship_preserves_source_activity_date(self):
        bundle, _summary = build_graph_report_bundle(
            "Historical MISP graph report",
            "graph context",
            80,
            graph_candidate_policy={"accepted": [infrastructure_candidate()]},
            published_at="2017-02-18",
        )

        data = json.loads(bundle.serialize())
        report = next(item for item in data["objects"] if item["type"] == "report")
        relationship = next(
            item for item in data["objects"] if item["type"] == "relationship"
        )

        self.assertTrue(report["published"].startswith("2017-02-18T00:00:00"))
        self.assertTrue(relationship["start_time"].startswith("2026-06-20T00:00:00"))


def attack_pattern_candidate():
    return {
        "fingerprint": "attack-1",
        "entity_type": "attack_pattern",
        "value": "T1059",
        "name": "Command and Scripting Interpreter",
        "stix_object_type": "attack-pattern",
        "relationship_type": "uses",
        "source_key": "alienvault:otx",
        "source_name": "mitre-attack",
        "source_field": "mitre_attack.resolved",
        "confidence": 90,
        "relationship_confidence": 85,
    }


def threat_actor_candidate():
    return {
        "fingerprint": "actor-1",
        "entity_type": "threat_actor",
        "value": "APT Example",
        "name": "APT Example",
        "stix_object_type": "threat-actor",
        "relationship_type": "attributed-to",
        "source_key": "alienvault:otx",
        "source_name": "otx",
        "source_field": "adversary",
        "confidence": 70,
        "relationship_confidence": 65,
    }


def threat_actor_individual_candidate():
    return {
        "fingerprint": "actor-individual-1",
        "entity_type": "threat_actor_individual",
        "value": "Individual Actor",
        "name": "Individual Actor",
        "stix_object_type": "threat-actor",
        "relationship_type": "attributed-to",
        "source_key": "misp:misp",
        "source_name": "misp-galaxy",
        "source_field": "Galaxy.threat-actor-individual",
        "confidence": 65,
        "relationship_confidence": 65,
        "attributes": {"threat_actor_class": "individual"},
    }


def described_threat_actor_candidate():
    candidate = dict(threat_actor_candidate())
    candidate["attributes"] = {
        "description": "APT Example is a source-described threat actor."
    }
    return candidate


def campaign_candidate():
    return {
        "fingerprint": "campaign-1",
        "entity_type": "campaign",
        "value": "Operation Example",
        "name": "Operation Example",
        "stix_object_type": "campaign",
        "relationship_type": "related-to",
        "source_key": "misp:misp",
        "source_name": "misp-galaxy",
        "source_field": "Galaxy",
        "confidence": 75,
        "relationship_confidence": 70,
        "attributes": {
            "cluster_uuid": "cluster-campaign",
            "galaxy_type": "campaign",
            "galaxy_name": "Campaign",
        },
    }


def described_tool_candidate():
    return {
        "fingerprint": "tool-1",
        "entity_type": "tool",
        "value": "Turla",
        "name": "Turla",
        "stix_object_type": "tool",
        "relationship_type": "uses",
        "source_key": "misp:misp",
        "source_name": "misp-galaxy",
        "source_field": "Galaxy",
        "confidence": 75,
        "relationship_confidence": 75,
        "attributes": {
            "description": "Turla is a source-described backdoor tool.",
            "cluster_uuid": "cluster-tool",
            "galaxy_type": "tool",
            "galaxy_name": "Tool",
        },
    }


def infrastructure_candidate():
    return {
        "fingerprint": "infrastructure-1",
        "entity_type": "infrastructure",
        "value": "Validation C2 Infrastructure",
        "name": "Validation C2 Infrastructure",
        "stix_object_type": "infrastructure",
        "relationship_type": "uses",
        "source_key": "misp:misp",
        "source_name": "misp-object",
        "source_field": "ObjectReference",
        "confidence": 70,
        "relationship_confidence": 70,
        "attributes": {
            "relationship_source_stix_object_type": "threat-actor",
            "relationship_source_value": "APT Example",
            "relationship_source_field": "threat-actor",
            "created": "2026-06-20T10:00:00Z",
            "modified": "2026-06-22T10:00:00Z",
            "source_date": "2026-06-20",
            "first_seen": "2026-06-20T10:05:00Z",
            "last_seen": "2026-06-22T10:05:00Z",
        },
    }


def infrastructure_asn_candidate(
    relationship_type,
    source_type="infrastructure",
    source_value="Validation C2 Infrastructure",
):
    return {
        "fingerprint": f"asn-{relationship_type}-{source_type}",
        "entity_type": "autonomous_system",
        "value": "AS64512 NarrowCTI Validation ASN",
        "name": "AS64512 NarrowCTI Validation ASN",
        "stix_object_type": "autonomous-system",
        "relationship_type": relationship_type,
        "source_key": "misp:misp",
        "source_name": "misp-object",
        "source_field": "asn",
        "confidence": 70,
        "relationship_confidence": 70,
        "attributes": {
            "asn": 64512,
            "rir": "PRIVATE",
            "relationship_source_stix_object_type": source_type,
            "relationship_source_value": source_value,
            "relationship_source_field": "asn-enrichment",
            "created": "2026-06-20T10:00:00Z",
            "modified": "2026-06-22T10:00:00Z",
            "first_seen": "2026-06-20T10:05:00Z",
            "last_seen": "2026-06-22T10:05:00Z",
        },
    }


def infrastructure_ip_candidate():
    return {
        "fingerprint": "infra-ip-1",
        "entity_type": "observable",
        "value": "203.0.113.10",
        "name": "203.0.113.10",
        "stix_object_type": "observable",
        "relationship_type": "consists-of",
        "source_key": "misp:misp",
        "source_name": "misp-object",
        "source_field": "ip",
        "confidence": 70,
        "relationship_confidence": 70,
        "attributes": {
            "observable_type": "ipv4-addr",
            "relationship_source_stix_object_type": "infrastructure",
            "relationship_source_value": "Validation C2 Infrastructure",
            "relationship_source_field": "ip-enrichment",
        },
    }


def infrastructure_ipv6_candidate():
    candidate = infrastructure_ip_candidate()
    candidate["fingerprint"] = "infra-ipv6-1"
    candidate["value"] = "2001:db8::10"
    candidate["name"] = "2001:db8::10"
    candidate["attributes"] = {
        **candidate["attributes"],
        "observable_type": "ipv6-addr",
    }
    return candidate


def infrastructure_attack_pattern_candidate():
    candidate = attack_pattern_candidate()
    candidate["fingerprint"] = "infra-attack-1"
    candidate["relationship_type"] = "related-to"
    candidate["attributes"] = {
        "relationship_source_stix_object_type": "infrastructure",
        "relationship_source_value": "Validation C2 Infrastructure",
        "relationship_source_field": "infrastructures",
        "relationship_inference": "otx-single-adversary-infrastructure-ttp",
    }
    return candidate


def infrastructure_victimology_candidate():
    candidate = target_sector_candidate()
    candidate["fingerprint"] = "infra-victimology-1"
    candidate["source_field"] = "Galaxy.meta.targeted-sector"
    candidate["attributes"] = {
        **candidate["attributes"],
        "relationship_source_stix_object_type": "infrastructure",
        "relationship_source_value": "Validation C2 Infrastructure",
        "relationship_source_field": "infrastructure-victimology",
        "relationship_inference": "misp-event-infrastructure-victimology-context",
    }
    return candidate


def attack_tactic_candidate():
    return {
        "fingerprint": "attack-tactic-1",
        "entity_type": "attack_tactic",
        "value": "execution",
        "name": "execution",
        "stix_object_type": "x-mitre-tactic",
        "relationship_type": "uses",
        "source_key": "alienvault:otx",
        "source_name": "mitre-attack",
        "source_field": "mitre_attack.resolved.tactics",
        "confidence": 85,
        "relationship_confidence": 80,
        "attributes": {
            "relationship_source_stix_object_type": "attack-pattern",
            "relationship_source_value": "T1059",
            "relationship_source_field": "mitre_attack.resolved.tactics",
        },
    }


def attack_platform_candidate():
    return {
        "fingerprint": "attack-platform-1",
        "entity_type": "attack_platform",
        "value": "Windows",
        "name": "Windows",
        "stix_object_type": "x-narrowcti-attack-platform",
        "relationship_type": "applies-to",
        "source_key": "alienvault:otx",
        "source_name": "mitre-attack",
        "source_field": "mitre_attack.resolved.platforms",
        "confidence": 75,
        "relationship_confidence": 75,
        "attributes": {
            "relationship_source_stix_object_type": "attack-pattern",
            "relationship_source_value": "T1059",
            "relationship_source_field": "mitre_attack.resolved.platforms",
        },
    }


def attack_data_source_candidate():
    return {
        "fingerprint": "attack-data-source-1",
        "entity_type": "attack_data_source",
        "value": "Process: Process Creation",
        "name": "Process: Process Creation",
        "stix_object_type": "x-mitre-data-source",
        "relationship_type": "detects",
        "source_key": "alienvault:otx",
        "source_name": "mitre-attack",
        "source_field": "mitre_attack.resolved.data_sources",
        "confidence": 80,
        "relationship_confidence": 80,
        "attributes": {
            "relationship_source_stix_object_type": "attack-pattern",
            "relationship_source_value": "T1059",
            "relationship_source_field": "mitre_attack.resolved.data_sources",
        },
    }


def attack_data_component_candidate():
    return {
        "fingerprint": "attack-data-component-1",
        "entity_type": "attack_data_component",
        "value": "Process Creation",
        "name": "Process Creation",
        "stix_object_type": "x-mitre-data-component",
        "relationship_type": "detects",
        "source_key": "alienvault:otx",
        "source_name": "mitre-attack",
        "source_field": "mitre_attack.resolved.data_sources",
        "confidence": 78,
        "relationship_confidence": 78,
        "attributes": {
            "relationship_source_stix_object_type": "attack-pattern",
            "relationship_source_value": "T1059",
            "relationship_source_field": "mitre_attack.resolved.data_sources",
            "data_source": "Process",
        },
    }


def detection_guidance_candidate():
    return {
        "fingerprint": "detection-guidance-1",
        "entity_type": "detection_guidance",
        "value": "Monitor process execution.",
        "name": "Detection guidance for T1059",
        "stix_object_type": "note",
        "relationship_type": "documents",
        "source_key": "alienvault:otx",
        "source_name": "mitre-attack",
        "source_field": "mitre_attack.resolved.detection",
        "confidence": 70,
        "relationship_confidence": 70,
        "attributes": {
            "content": "Monitor process execution.",
            "relationship_source_stix_object_type": "attack-pattern",
            "relationship_source_value": "T1059",
            "relationship_source_field": "mitre_attack.resolved.detection",
        },
    }


def target_sector_candidate():
    return {
        "fingerprint": "sector-1",
        "entity_type": "target_sector",
        "value": "Finance",
        "name": "Finance",
        "stix_object_type": "identity",
        "relationship_type": "targets",
        "source_key": "misp:misp",
        "source_name": "misp-galaxy",
        "source_field": "Galaxy.meta.targeted-sector",
        "confidence": 70,
        "relationship_confidence": 70,
        "attributes": {
            "parent_cluster_type": "threat-actor",
            "parent_cluster_value": "APT Example",
            "parent_cluster_uuid": "cluster-actor",
        },
    }


def target_system_candidate():
    return {
        "fingerprint": "system-1",
        "entity_type": "target_system",
        "value": "SAP ERP",
        "name": "SAP ERP",
        "stix_object_type": "identity",
        "relationship_type": "targets",
        "source_key": "misp:misp",
        "source_name": "misp-galaxy",
        "source_field": "Galaxy.meta.targeted-system",
        "confidence": 62,
        "relationship_confidence": 62,
        "attributes": {
            "parent_cluster_type": "threat-actor",
            "parent_cluster_value": "APT Example",
            "parent_cluster_uuid": "cluster-actor",
        },
    }


def target_individual_candidate():
    return {
        "fingerprint": "individual-1",
        "entity_type": "target_individual",
        "value": "Incident Responder",
        "name": "Incident Responder",
        "stix_object_type": "identity",
        "relationship_type": "targets",
        "source_key": "misp:misp",
        "source_name": "misp-galaxy",
        "source_field": "Galaxy.meta.targeted-person",
        "confidence": 65,
        "relationship_confidence": 65,
        "attributes": {
            "parent_cluster_type": "threat-actor",
            "parent_cluster_value": "APT Example",
            "parent_cluster_uuid": "cluster-actor",
        },
    }


def campaign_target_sector_candidate():
    return {
        "fingerprint": "campaign-sector-1",
        "entity_type": "target_sector",
        "value": "Energy",
        "name": "Energy",
        "stix_object_type": "identity",
        "relationship_type": "targets",
        "source_key": "misp:misp",
        "source_name": "misp-galaxy",
        "source_field": "Galaxy.meta.targeted-sector",
        "confidence": 70,
        "relationship_confidence": 70,
        "attributes": {
            "parent_cluster_type": "campaign",
            "parent_cluster_value": "Operation Example",
            "parent_cluster_uuid": "cluster-campaign",
        },
    }


def campaign_target_organization_candidate():
    return {
        "fingerprint": "campaign-organization-1",
        "entity_type": "target_organization",
        "value": "Example Energy Co",
        "name": "Example Energy Co",
        "stix_object_type": "identity",
        "relationship_type": "targets",
        "source_key": "misp:misp",
        "source_name": "misp-galaxy",
        "source_field": "Galaxy.meta.victim-organization",
        "confidence": 70,
        "relationship_confidence": 70,
        "attributes": {
            "parent_cluster_type": "campaign",
            "parent_cluster_value": "Operation Example",
            "parent_cluster_uuid": "cluster-campaign",
        },
    }


def course_of_action_candidate():
    return {
        "fingerprint": "course-of-action-1",
        "entity_type": "course_of_action",
        "value": "Disable or Remove Feature or Program",
        "name": "Disable or Remove Feature or Program",
        "stix_object_type": "course-of-action",
        "relationship_type": "related-to",
        "source_key": "misp:misp",
        "source_name": "misp-galaxy",
        "source_field": "Galaxy",
        "confidence": 75,
        "relationship_confidence": 70,
        "attributes": {
            "cluster_uuid": "cluster-coa",
            "galaxy_type": "mitre-course-of-action",
            "galaxy_name": "MITRE Course of Action",
        },
    }


def mitigating_course_of_action_candidate():
    candidate = course_of_action_candidate()
    candidate["relationship_type"] = "mitigates"
    candidate["attributes"] = {
        **candidate["attributes"],
        "relationship_source_stix_object_type": "attack-pattern",
        "relationship_source_value": "T1059",
        "relationship_source_field": "meta.mitigates",
    }
    return candidate


def source_identity_candidate():
    return {
        "fingerprint": "source-identity-1",
        "entity_type": "source_identity",
        "value": "VK-Intel",
        "name": "VK-Intel",
        "stix_object_type": "identity",
        "relationship_type": "originated-from",
        "source_key": "misp:misp",
        "source_name": "misp",
        "source_field": "provenance.original_source",
        "confidence": 70,
        "relationship_confidence": 70,
    }


def collector_candidate():
    return {
        "fingerprint": "collector-1",
        "entity_type": "collector",
        "value": "misp",
        "name": "misp",
        "stix_object_type": "identity",
        "relationship_type": "collected-by",
        "source_key": "misp:misp",
        "source_name": "misp",
        "source_field": "provenance.collector",
        "confidence": 80,
        "relationship_confidence": 80,
    }


def target_country_candidate():
    return {
        "fingerprint": "country-1",
        "entity_type": "target_country",
        "value": "Argentina",
        "name": "Argentina",
        "stix_object_type": "location",
        "relationship_type": "targets",
        "source_key": "misp:misp",
        "source_name": "misp-galaxy",
        "source_field": "Galaxy.meta.targeted-country",
        "confidence": 70,
        "relationship_confidence": 70,
        "attributes": {
            "parent_cluster_type": "threat-actor",
            "parent_cluster_value": "APT Example",
            "parent_cluster_uuid": "cluster-actor",
        },
    }


def target_region_candidate():
    return {
        "fingerprint": "region-1",
        "entity_type": "target_region",
        "value": "South America",
        "name": "South America",
        "stix_object_type": "location",
        "relationship_type": "targets",
        "source_key": "misp:misp",
        "source_name": "misp-galaxy",
        "source_field": "Galaxy.meta.targeted-region",
        "confidence": 65,
        "relationship_confidence": 65,
        "attributes": {
            "parent_cluster_type": "threat-actor",
            "parent_cluster_value": "APT Example",
            "parent_cluster_uuid": "cluster-actor",
        },
    }


def target_administrative_area_candidate():
    return {
        "fingerprint": "administrative-area-1",
        "entity_type": "target_administrative_area",
        "value": "Sao Paulo State",
        "name": "Sao Paulo State",
        "stix_object_type": "location",
        "relationship_type": "targets",
        "source_key": "misp:misp",
        "source_name": "misp-galaxy",
        "source_field": "Galaxy.meta.targeted-state",
        "confidence": 62,
        "relationship_confidence": 62,
        "attributes": {
            "region": "South America",
            "country": "Brazil",
            "administrative_area": "Sao Paulo",
            "parent_cluster_type": "threat-actor",
            "parent_cluster_value": "APT Example",
            "parent_cluster_uuid": "cluster-actor",
        },
    }


def target_city_candidate():
    return {
        "fingerprint": "city-1",
        "entity_type": "target_city",
        "value": "Sao Paulo",
        "name": "Sao Paulo",
        "stix_object_type": "location",
        "relationship_type": "targets",
        "source_key": "misp:misp",
        "source_name": "misp-galaxy",
        "source_field": "Galaxy.meta.targeted-city",
        "confidence": 62,
        "relationship_confidence": 62,
        "attributes": {
            "region": "South America",
            "country": "Brazil",
            "administrative_area": "Sao Paulo",
            "city": "Sao Paulo",
            "latitude": "-23.5505",
            "longitude": "-46.6333",
            "precision": "10",
            "parent_cluster_type": "threat-actor",
            "parent_cluster_value": "APT Example",
            "parent_cluster_uuid": "cluster-actor",
        },
    }


def target_position_candidate():
    return {
        "fingerprint": "position-1",
        "entity_type": "target_position",
        "value": "-23.5505,-46.6333",
        "name": "Sao Paulo Position",
        "stix_object_type": "location",
        "relationship_type": "targets",
        "source_key": "misp:misp",
        "source_name": "misp-galaxy",
        "source_field": "Galaxy.meta.targeted-coordinate",
        "confidence": 60,
        "relationship_confidence": 60,
        "attributes": {
            "region": "South America",
            "country": "Brazil",
            "administrative_area": "Sao Paulo",
            "city": "Sao Paulo",
            "latitude": "-23.5505",
            "longitude": "-46.6333",
            "precision": "10",
            "parent_cluster_type": "threat-actor",
            "parent_cluster_value": "APT Example",
            "parent_cluster_uuid": "cluster-actor",
        },
    }


def channel_candidate():
    return {
        "fingerprint": "channel-1",
        "entity_type": "channel",
        "value": "Telegram C2",
        "name": "Telegram C2",
        "stix_object_type": "channel",
        "relationship_type": "uses",
        "source_key": "misp",
        "source_name": "MISP via NarrowCTI",
        "source_field": "Galaxy.meta.channel",
        "confidence": 70,
        "relationship_confidence": 70,
        "attributes": {
            "aliases": ["Telegram"],
            "channel_types": ["c2", "delivery"],
        },
    }


def narrative_candidate():
    return {
        "fingerprint": "narrative-1",
        "entity_type": "narrative",
        "value": "Credential theft objective",
        "name": "Credential theft objective",
        "stix_object_type": "narrative",
        "relationship_type": "related-to",
        "source_key": "misp",
        "source_name": "MISP via NarrowCTI",
        "source_field": "Galaxy.meta.objective",
        "confidence": 65,
        "relationship_confidence": 65,
        "attributes": {
            "description": "Source-backed objective narrative.",
            "narrative_types": ["objective"],
        },
    }


def event_candidate():
    return {
        "fingerprint": "event-1",
        "entity_type": "event",
        "value": "Observed phishing wave",
        "name": "Observed phishing wave",
        "stix_object_type": "event",
        "relationship_type": "related-to",
        "source_key": "misp",
        "source_name": "MISP via NarrowCTI",
        "source_field": "Event.info",
        "confidence": 60,
        "relationship_confidence": 60,
        "attributes": {
            "event_types": ["phishing"],
            "start_time": "2026-06-25T10:00:00Z",
            "stop_time": "2026-06-25T12:00:00Z",
        },
    }


def anchored_malware_candidate():
    return {
        "fingerprint": "malware-anchored-1",
        "entity_type": "malware",
        "value": "LummaC2",
        "name": "LummaC2",
        "stix_object_type": "malware",
        "relationship_type": "uses",
        "source_key": "alienvault:otx",
        "source_name": "otx",
        "source_field": "malware_families",
        "confidence": 55,
        "relationship_confidence": 55,
        "attributes": {
            "relationship_source_stix_object_type": "threat-actor",
            "relationship_source_value": "APT Example",
            "relationship_source_field": "adversary",
        },
    }


def misp_uuid_infrastructure_candidate():
    candidate = infrastructure_candidate()
    candidate["fingerprint"] = "uuid-infrastructure-1"
    candidate["value"] = "MISP domain-ip c2.example"
    candidate["name"] = "MISP domain-ip c2.example"
    candidate["attributes"] = {"object_uuid": "object-infra"}
    return candidate


def misp_uuid_malware_candidate():
    return {
        "fingerprint": "uuid-malware-1",
        "entity_type": "malware",
        "value": "Example Malware",
        "name": "Example Malware",
        "stix_object_type": "malware",
        "relationship_type": "related-to",
        "source_key": "misp:event",
        "source_name": "misp-galaxy",
        "source_field": "Galaxy[0]",
        "confidence": 80,
        "relationship_confidence": 80,
        "attributes": {"object_uuid": "object-malware"},
    }


def object_reference_candidate():
    return {
        "fingerprint": "object-reference-1",
        "entity_type": "object_reference",
        "value": "object-malware uses object-infra",
        "name": "object-malware uses object-infra",
        "stix_object_type": "relationship",
        "relationship_type": "uses",
        "source_key": "misp:event",
        "source_name": "misp",
        "source_field": "Object[0].ObjectReference[0]",
        "confidence": 60,
        "relationship_confidence": 60,
        "attributes": {
            "source_uuid": "object-malware",
            "target_uuid": "object-infra",
            "reference_uuid": "reference-1",
        },
    }


def sighting_candidate():
    return {
        "fingerprint": "sighting-1",
        "entity_type": "sighting",
        "value": "evil.example",
        "name": "evil.example",
        "stix_object_type": "sighting",
        "relationship_type": "sighting-of",
        "source_key": "misp:event",
        "source_name": "misp",
        "source_field": "Attribute[0].Sighting[0]",
        "confidence": 65,
        "relationship_confidence": 65,
        "attributes": {
            "sighting_id": "42",
            "date_sighting": "1782004900",
            "attribute_uuid": "attribute-domain",
            "source": "SOC",
        },
    }


def existing_attack_pattern_candidate(existing_ref):
    candidate = attack_pattern_candidate()
    candidate["attributes"] = {
        "relationship_source_stix_object_type": "threat-actor",
        "relationship_source_value": "APT Example",
        "relationship_source_field": "adversary",
        "opencti_existing_ref": existing_ref,
        "opencti_existing_id": "internal--1",
        "opencti_existing_entity_type": "Attack-Pattern",
        "opencti_match_type": "mitre_attack_id",
        "opencti_match_value": "T1059",
    }
    return candidate


def existing_ipv4_observable_candidate(existing_ref):
    candidate = infrastructure_ip_candidate()
    candidate["relationship_type"] = "related-to"
    candidate["attributes"] = {
        "observable_type": "ipv4-addr",
        "opencti_existing_ref": existing_ref,
    }
    return candidate


def vulnerability_candidate():
    return {
        "fingerprint": "vuln-1",
        "entity_type": "vulnerability",
        "value": "CVE-2026-0001",
        "name": "CVE-2026-0001",
        "stix_object_type": "vulnerability",
        "relationship_type": "related-to",
        "source_key": "alienvault:otx",
        "source_name": "otx",
        "source_field": "indicators",
        "confidence": 70,
        "relationship_confidence": 60,
    }


def observable_candidate():
    return {
        "fingerprint": "observable-1",
        "entity_type": "observable",
        "value": "one.example",
        "name": "one.example",
        "stix_object_type": "observable",
        "relationship_type": "based-on",
        "source_key": "alienvault:otx",
        "source_name": "otx",
        "source_field": "indicators",
        "confidence": 65,
        "relationship_confidence": 65,
        "attributes": {
            "observable_type": "domain-name",
            "indicator_type": "domain",
        },
    }


def artifact_candidate():
    return {
        "fingerprint": "artifact-1",
        "entity_type": "artifact",
        "value": (
            "0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef"
        ),
        "name": "NarrowCTI sample artifact",
        "stix_object_type": "observable",
        "relationship_type": "related-to",
        "source_key": "validation",
        "source_name": "NarrowCTI validation",
        "source_field": "artifact.metadata",
        "confidence": 70,
        "relationship_confidence": 70,
        "attributes": {
            "observable_type": "artifact",
            "hash_algorithm": "SHA-256",
            "artifact_url": "https://narrowcti.local/artifacts/sample.bin",
            "mime_type": "application/octet-stream",
        },
    }


def detection_rule_candidate():
    return {
        "fingerprint": "rule-1",
        "entity_type": "detection_rule",
        "value": "Suspicious PowerShell",
        "name": "Suspicious PowerShell",
        "stix_object_type": "indicator",
        "relationship_type": "detects",
        "source_key": "misp:event",
        "source_name": "misp",
        "source_field": "Attribute[0]",
        "confidence": 75,
        "relationship_confidence": 70,
        "attributes": {
            "pattern": (
                "title: Suspicious PowerShell\n"
                "logsource:\n"
                "  product: windows\n"
                "detection:\n"
                "  selection:\n"
                "    EventID: 1\n"
                "  condition: selection"
            ),
            "pattern_type": "sigma",
            "attribute_uuid": "attribute-rule-1",
        },
    }


def detection_rule_attack_pattern_candidate():
    candidate = detection_rule_candidate()
    candidate["fingerprint"] = "rule-attack-pattern-1"
    candidate["relationship_confidence"] = 85
    candidate["attributes"] = dict(candidate["attributes"])
    candidate["attributes"].update(
        {
            "relationship_source_stix_object_type": "attack-pattern",
            "relationship_source_value": "T1059",
            "relationship_source_field": "Attribute[0].Tag",
            "relationship_inference": "explicit-detection-rule-attack-reference",
            "attack_pattern_ids": ["T1059"],
            "attack_id_source": "misp-tags",
        }
    )
    return candidate


def incompatible_sigma_detection_rule_candidate():
    candidate = detection_rule_candidate()
    candidate["fingerprint"] = "rule-sigma-incompatible-1"
    candidate["value"] = "Broken Sigma"
    candidate["name"] = "Broken Sigma"
    candidate["attributes"] = dict(candidate["attributes"])
    candidate["attributes"].update(
        {
            "pattern": (
                "title: Broken Sigma\n"
                "logsource:\n"
                "  product: windows\n"
                "detection:\n"
                "  condition: selection"
            ),
            "opencti_indicator_compatible": False,
            "opencti_indicator_compatibility_reason": "missing detection selection",
            "attribute_uuid": "attribute-invalid-sigma",
        }
    )
    return candidate


def snort_detection_rule_candidate():
    return {
        "fingerprint": "rule-snort-1",
        "entity_type": "detection_rule",
        "value": "Adobe Flash Exploit",
        "name": "Adobe Flash Exploit",
        "stix_object_type": "indicator",
        "relationship_type": "detects",
        "source_key": "misp:event",
        "source_name": "misp",
        "source_field": "Attribute[2]",
        "confidence": 70,
        "relationship_confidence": 70,
        "attributes": {
            "pattern": 'alert tcp any any -> any any (msg:"Adobe Flash Exploit"; sid:1;)',
            "pattern_type": "snort",
            "attribute_uuid": "attribute-snort-1",
        },
    }


def event_report_candidate():
    return {
        "fingerprint": "event-report-1",
        "entity_type": "event_report",
        "value": "Initial analyst report",
        "name": "Initial analyst report",
        "stix_object_type": "note",
        "relationship_type": "documents",
        "source_key": "misp:event",
        "source_name": "misp",
        "source_field": "EventReport[0]",
        "confidence": 70,
        "relationship_confidence": 70,
        "attributes": {
            "content": "The event describes exploitation activity.",
            "event_report_uuid": "event-report-1",
        },
    }


def unsupported_candidate():
    return {
        "entity_type": "unknown",
        "value": "unknown",
        "name": "unknown",
        "stix_object_type": "x-unsupported",
        "relationship_type": "related-to",
        "confidence": 50,
        "relationship_confidence": 50,
    }


def graph_object_ids_by_name(bundle):
    data = json.loads(bundle.serialize())
    return {
        item["name"]: item["id"]
        for item in data["objects"]
        if item["type"]
        in {
            "attack-pattern",
            "autonomous-system",
            "channel",
            "event",
            "identity",
            "infrastructure",
            "intrusion-set",
            "location",
            "malware",
            "narrative",
            "threat-actor",
            "tool",
            "vulnerability",
        }
    }


if __name__ == "__main__":
    unittest.main()
