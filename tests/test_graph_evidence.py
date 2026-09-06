import unittest

from core.graph_evidence import build_graph_evidence


class GraphEvidenceTests(unittest.TestCase):
    def test_maps_explicit_infrastructure_evidence(self):
        evidence = build_graph_evidence(
            {
                "otx_entities": {
                    "records": [
                        {
                            "entity_type": "infrastructure",
                            "value": "Validation C2 Infrastructure",
                            "source_field": "infrastructure",
                            "confidence": 70,
                        }
                    ]
                }
            },
            source_key="alienvault:otx",
            external_id="pulse-1",
            title="Infrastructure pulse",
        )

        self.assertEqual(1, evidence["counts"]["infrastructure"])
        self.assertIn(
            {
                "entity_type": "infrastructure",
                "value": "Validation C2 Infrastructure",
                "stix_object_type": "infrastructure",
                "relationship_type": "uses",
                "source_key": "alienvault:otx",
                "source_name": "otx",
                "source_field": "infrastructure",
                "confidence": 70,
            },
            evidence["records"],
        )

    def test_maps_explicit_autonomous_system_evidence(self):
        evidence = build_graph_evidence(
            {
                "otx_entities": {
                    "records": [
                        {
                            "entity_type": "autonomous_system",
                            "value": "AS64512 NarrowCTI Validation ASN",
                            "source_field": "asn",
                            "confidence": 70,
                            "attributes": {"asn": 64512, "rir": "PRIVATE"},
                        }
                    ]
                }
            },
            source_key="alienvault:otx",
            external_id="pulse-1",
            title="ASN pulse",
        )

        self.assertEqual(1, evidence["counts"]["autonomous_system"])
        self.assertIn(
            {
                "entity_type": "autonomous_system",
                "value": "AS64512 NarrowCTI Validation ASN",
                "stix_object_type": "autonomous-system",
                "relationship_type": "related-to",
                "source_key": "alienvault:otx",
                "source_name": "otx",
                "source_field": "asn",
                "confidence": 70,
                "attributes": {"asn": 64512, "rir": "PRIVATE"},
            },
            evidence["records"],
        )

    def test_normalizes_intrusion_set_aliases(self):
        evidence = build_graph_evidence(
            {
                "otx_entities": {
                    "records": [
                        {
                            "entity_type": "intrusion_set",
                            "value": "Lazarus",
                            "source_field": "adversary",
                            "confidence": 60,
                        }
                    ]
                }
            },
            source_key="alienvault:otx",
            external_id="pulse-1",
            title="Actor pulse",
        )

        intrusion_set = evidence["records"][0]
        self.assertEqual("Lazarus Group", intrusion_set["value"])
        self.assertEqual(70, intrusion_set["confidence"])
        self.assertEqual("Lazarus", intrusion_set["attributes"]["source_value"])
        self.assertTrue(intrusion_set["attributes"]["normalized_value"])
        self.assertEqual(
            "intrusion_set",
            intrusion_set["attributes"]["normalization_scope"],
        )

    def test_normalizes_malware_aliases(self):
        evidence = build_graph_evidence(
            {
                "otx_entities": {
                    "records": [
                        {
                            "entity_type": "malware",
                            "value": "LummaC2",
                            "source_field": "malware_families",
                            "confidence": 55,
                        }
                    ]
                }
            },
            source_key="alienvault:otx",
            external_id="pulse-1",
            title="Malware pulse",
        )

        malware = evidence["records"][0]
        self.assertEqual("Lumma Stealer", malware["value"])
        self.assertEqual(70, malware["confidence"])
        self.assertEqual("LummaC2", malware["attributes"]["source_value"])
        self.assertTrue(malware["attributes"]["normalized_value"])
        self.assertEqual("malware", malware["attributes"]["normalization_scope"])

    def test_normalizes_otx_target_sector_aliases(self):
        evidence = build_graph_evidence(
            {
                "otx_entities": {
                    "records": [
                        {
                            "entity_type": "target_sector",
                            "value": "Defence",
                            "source_field": "industries",
                            "confidence": 50,
                        }
                    ]
                }
            },
            source_key="alienvault:otx",
            external_id="pulse-1",
            title="Sector pulse",
        )

        sector = evidence["records"][0]
        self.assertEqual("Defense", sector["value"])
        self.assertEqual(60, sector["confidence"])
        self.assertEqual("Defence", sector["attributes"]["source_value"])
        self.assertTrue(sector["attributes"]["normalized_value"])
        self.assertEqual("target_sector", sector["attributes"]["normalization_scope"])

    def test_normalizes_otx_target_country_aliases(self):
        evidence = build_graph_evidence(
            {
                "otx_entities": {
                    "records": [
                        {
                            "entity_type": "target_country",
                            "value": "BR",
                            "source_field": "targeted_countries",
                            "confidence": 50,
                        }
                    ]
                }
            },
            source_key="alienvault:otx",
            external_id="pulse-1",
            title="Country pulse",
        )

        country = evidence["records"][0]
        self.assertEqual("Brazil", country["value"])
        self.assertEqual(60, country["confidence"])
        self.assertEqual("BR", country["attributes"]["source_value"])
        self.assertTrue(country["attributes"]["normalized_value"])
        self.assertEqual("target_country", country["attributes"]["normalization_scope"])

    def test_builds_otx_and_mitre_graph_evidence_records(self):
        evidence = build_graph_evidence(
            {
                "otx_entities": {
                    "records": [
                        {
                            "entity_type": "threat_actor",
                            "value": "APT Example",
                            "source_field": "adversary",
                            "confidence": 60,
                        },
                        {
                            "entity_type": "attack_pattern",
                            "value": "T1059",
                            "source_field": "attack_ids",
                            "confidence": 70,
                        },
                        {
                            "entity_type": "vulnerability",
                            "value": "CVE-2024-12345",
                            "source_field": "vulnerabilities",
                            "confidence": 75,
                        },
                    ]
                },
                "mitre_attack": {
                    "available": True,
                    "resolved": [
                        {
                            "attack_id": "T1059",
                            "found": True,
                            "name": "Command and Scripting Interpreter",
                            "description": "Interpreters execute commands.",
                            "tactics": ["execution"],
                            "stix_id": "attack-pattern--1",
                            "source_name": "mitre-attack",
                            "url": "https://attack.mitre.org/techniques/T1059/",
                            "platforms": ["Windows"],
                            "data_sources": ["Process: Process Creation"],
                            "detection": "Monitor process execution.",
                            "domains": ["enterprise-attack"],
                            "version": "2.6",
                            "attack_spec_version": "3.3.0",
                            "created": "2020-01-01T00:00:00.000Z",
                            "modified": "2026-01-01T00:00:00.000Z",
                        }
                    ],
                },
            },
            source_key="alienvault:otx",
            external_id="pulse-1",
            title="Technique pulse",
        )

        self.assertEqual("v1.0.0", evidence["version"])
        self.assertEqual("alienvault:otx", evidence["source_key"])
        self.assertEqual(10, evidence["record_count"])
        self.assertEqual(2, evidence["counts"]["attack_pattern"])
        self.assertEqual(1, evidence["counts"]["vulnerability"])
        self.assertEqual(1, evidence["counts"]["attack_platform"])
        self.assertEqual(1, evidence["counts"]["attack_data_component"])
        self.assertEqual(1, evidence["counts"]["attack_data_source"])
        self.assertEqual(1, evidence["counts"]["detection_guidance"])
        self.assertEqual(1, evidence["counts"]["external_reference"])
        self.assertIn(
            {
                "entity_type": "threat_actor",
                "value": "APT Example",
                "stix_object_type": "threat-actor",
                "relationship_type": "attributed-to",
                "source_key": "alienvault:otx",
                "source_name": "otx",
                "source_field": "adversary",
                "confidence": 60,
            },
            evidence["records"],
        )
        self.assertIn(
            {
                "entity_type": "vulnerability",
                "value": "CVE-2024-12345",
                "stix_object_type": "vulnerability",
                "relationship_type": "related-to",
                "source_key": "alienvault:otx",
                "source_name": "otx",
                "source_field": "vulnerabilities",
                "confidence": 75,
            },
            evidence["records"],
        )
        self.assertIn(
            {
                "entity_type": "attack_tactic",
                "value": "execution",
                "stix_object_type": "x-mitre-tactic",
                "relationship_type": "uses",
                "source_key": "alienvault:otx",
                "source_name": "mitre-attack",
                "source_field": "mitre_attack.resolved.tactics",
                "confidence": 85,
                "attributes": {
                    "technique": "T1059",
                    "relationship_source_stix_object_type": "attack-pattern",
                    "relationship_source_value": "T1059",
                    "relationship_source_field": "mitre_attack.resolved.tactics",
                },
            },
            evidence["records"],
        )
        technique = next(
            record
            for record in evidence["records"]
            if record["entity_type"] == "attack_pattern"
            and record["source_field"] == "mitre_attack.resolved"
        )
        self.assertEqual(["Windows"], technique["attributes"]["platforms"])
        self.assertEqual(
            ["Process: Process Creation"],
            technique["attributes"]["data_sources"],
        )
        self.assertEqual(
            "Monitor process execution.",
            technique["attributes"]["detection"],
        )
        self.assertEqual(
            [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1059",
                    "url": "https://attack.mitre.org/techniques/T1059/",
                }
            ],
            technique["attributes"]["external_references"],
        )
        self.assertEqual(
            [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            technique["attributes"]["kill_chain_phases"],
        )
        self.assertIn(
            {
                "entity_type": "external_reference",
                "value": "https://attack.mitre.org/techniques/T1059/",
                "stix_object_type": "external-reference",
                "relationship_type": "references",
                "source_key": "alienvault:otx",
                "source_name": "mitre-attack",
                "source_field": "mitre_attack.resolved.url",
                "confidence": 90,
                "display_name": "MITRE ATT&CK T1059",
                "attributes": {
                    "source_name": "mitre-attack",
                    "external_id": "T1059",
                    "technique": "T1059",
                    "url": "https://attack.mitre.org/techniques/T1059/",
                },
            },
            evidence["records"],
        )
        self.assertIn(
            {
                "entity_type": "attack_platform",
                "value": "Windows",
                "stix_object_type": "x-narrowcti-attack-platform",
                "relationship_type": "applies-to",
                "source_key": "alienvault:otx",
                "source_name": "mitre-attack",
                "source_field": "mitre_attack.resolved.platforms",
                "confidence": 75,
                "attributes": {
                    "technique": "T1059",
                    "relationship_source_stix_object_type": "attack-pattern",
                    "relationship_source_value": "T1059",
                    "relationship_source_field": "mitre_attack.resolved.platforms",
                },
            },
            evidence["records"],
        )
        self.assertIn(
            {
                "entity_type": "attack_data_source",
                "value": "Process: Process Creation",
                "stix_object_type": "x-mitre-data-source",
                "relationship_type": "detects",
                "source_key": "alienvault:otx",
                "source_name": "mitre-attack",
                "source_field": "mitre_attack.resolved.data_sources",
                "confidence": 80,
                "attributes": {
                    "technique": "T1059",
                    "relationship_source_stix_object_type": "attack-pattern",
                    "relationship_source_value": "T1059",
                    "relationship_source_field": "mitre_attack.resolved.data_sources",
                },
            },
            evidence["records"],
        )
        self.assertIn(
            {
                "entity_type": "attack_data_component",
                "value": "Process Creation",
                "stix_object_type": "x-mitre-data-component",
                "relationship_type": "detects",
                "source_key": "alienvault:otx",
                "source_name": "mitre-attack",
                "source_field": "mitre_attack.resolved.data_sources",
                "confidence": 78,
                "attributes": {
                    "technique": "T1059",
                    "relationship_source_stix_object_type": "attack-pattern",
                    "relationship_source_value": "T1059",
                    "relationship_source_field": "mitre_attack.resolved.data_sources",
                    "data_source": "Process",
                },
            },
            evidence["records"],
        )
        self.assertTrue(
            any(
                record["entity_type"] == "detection_guidance"
                and record["display_name"] == "Detection guidance for T1059"
                and record["value"] == "Monitor process execution."
                for record in evidence["records"]
            )
        )

    def test_builds_otx_detection_rule_evidence(self):
        evidence = build_graph_evidence(
            {
                "otx_entities": {
                    "records": [
                        {
                            "entity_type": "detection_rule",
                            "value": "Suspicious YARA rule",
                            "source_field": "indicators",
                            "confidence": 70,
                            "attributes": {
                                "rule_type": "yara",
                                "pattern_type": "yara",
                                "pattern": "rule SuspiciousRule { condition: true }",
                                "indicator_type": "YARA",
                                "indicator_id": "indicator-yara-1",
                            },
                        }
                    ]
                }
            },
            source_key="alienvault:otx",
            external_id="pulse-1",
            title="OTX pulse",
        )

        self.assertEqual(1, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["detection_rule"])
        self.assertIn(
            {
                "entity_type": "detection_rule",
                "value": "Suspicious YARA rule",
                "stix_object_type": "indicator",
                "relationship_type": "detects",
                "source_key": "alienvault:otx",
                "source_name": "otx",
                "source_field": "indicators",
                "confidence": 70,
                "attributes": {
                    "rule_type": "yara",
                    "pattern_type": "yara",
                    "pattern": "rule SuspiciousRule { condition: true }",
                    "indicator_type": "YARA",
                    "indicator_id": "indicator-yara-1",
                },
            },
            evidence["records"],
        )

    def test_builds_otx_observable_evidence(self):
        evidence = build_graph_evidence(
            {
                "otx_entities": {
                    "records": [
                        {
                            "entity_type": "observable",
                            "value": "one.example",
                            "source_field": "indicators",
                            "confidence": 65,
                            "attributes": {
                                "observable_type": "domain-name",
                                "indicator_type": "domain",
                                "first_seen": "2026-04-01T10:00:00Z",
                                "last_seen": "2026-04-02T10:00:00Z",
                            },
                        }
                    ]
                }
            },
            source_key="alienvault:otx",
            external_id="pulse-1",
            title="OTX pulse",
        )

        self.assertEqual(1, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["observable"])
        self.assertIn(
            {
                "entity_type": "observable",
                "value": "one.example",
                "stix_object_type": "observable",
                "relationship_type": "based-on",
                "source_key": "alienvault:otx",
                "source_name": "otx",
                "source_field": "indicators",
                "confidence": 65,
                "attributes": {
                    "observable_type": "domain-name",
                    "indicator_type": "domain",
                    "first_seen": "2026-04-01T10:00:00Z",
                    "last_seen": "2026-04-02T10:00:00Z",
                },
            },
            evidence["records"],
        )

    def test_adds_otx_timeline_attributes_to_entity_evidence(self):
        evidence = build_graph_evidence(
            {
                "otx_entities": {
                    "lifecycle": {
                        "created": "2026-04-01T00:00:00Z",
                        "modified": "2026-04-03T00:00:00Z",
                    },
                    "indicator_observation_window": {
                        "first_seen_min": "2026-04-01T10:00:00Z",
                        "last_seen_max": "2026-04-05T10:00:00Z",
                    },
                    "records": [
                        {
                            "entity_type": "infrastructure",
                            "value": "APT Example OTX observed infrastructure",
                            "source_field": "infrastructures",
                            "confidence": 70,
                            "attributes": {
                                "first_seen": "2026-04-02T10:00:00Z",
                            },
                        }
                    ],
                }
            },
            source_key="alienvault:otx",
            external_id="pulse-1",
            title="OTX pulse",
        )

        self.assertEqual(1, evidence["record_count"])
        attributes = evidence["records"][0]["attributes"]
        self.assertEqual("2026-04-01T00:00:00Z", attributes["source_created"])
        self.assertEqual("2026-04-03T00:00:00Z", attributes["source_modified"])
        self.assertEqual("2026-04-02T10:00:00Z", attributes["first_seen"])
        self.assertEqual("2026-04-01T10:00:00Z", attributes["first_seen_min"])
        self.assertEqual("2026-04-05T10:00:00Z", attributes["last_seen_max"])

    def test_preserves_otx_relationship_override(self):
        evidence = build_graph_evidence(
            {
                "otx_entities": {
                    "records": [
                        {
                            "entity_type": "observable",
                            "value": "one.example",
                            "source_field": "indicators",
                            "confidence": 65,
                            "relationship_type": "consists-of",
                            "attributes": {
                                "observable_type": "domain-name",
                                "relationship_source_stix_object_type": "infrastructure",
                                "relationship_source_value": (
                                    "APT Example OTX observed infrastructure pulse-1"
                                ),
                                "relationship_source_field": "infrastructures",
                            },
                        }
                    ]
                }
            },
            source_key="alienvault:otx",
            external_id="pulse-1",
            title="OTX pulse",
        )

        self.assertIn(
            {
                "entity_type": "observable",
                "value": "one.example",
                "stix_object_type": "observable",
                "relationship_type": "consists-of",
                "source_key": "alienvault:otx",
                "source_name": "otx",
                "source_field": "indicators",
                "confidence": 65,
                "attributes": {
                    "observable_type": "domain-name",
                    "relationship_source_stix_object_type": "infrastructure",
                    "relationship_source_value": (
                        "APT Example OTX observed infrastructure pulse-1"
                    ),
                    "relationship_source_field": "infrastructures",
                },
            },
            evidence["records"],
        )

    def test_builds_misp_provenance_tags_and_marking_evidence(self):
        evidence = build_graph_evidence(
            {
                "collector": "misp",
                "original_source": "AlienVault",
                "tags": ["tlp:green", "ransomware"],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(4, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["marking"])
        self.assertIn(
            {
                "entity_type": "source_identity",
                "value": "AlienVault",
                "stix_object_type": "identity",
                "relationship_type": "originated-from",
                "source_key": "misp:misp",
                "source_name": "misp",
                "source_field": "provenance.original_source",
                "confidence": 70,
            },
            evidence["records"],
        )
        self.assertIn(
            {
                "entity_type": "marking",
                "value": "green",
                "stix_object_type": "marking-definition",
                "relationship_type": "marked-with",
                "source_key": "misp:misp",
                "source_name": "misp",
                "source_field": "tags",
                "confidence": 80,
            },
            evidence["records"],
        )

    def test_builds_misp_galaxy_graph_evidence(self):
        evidence = build_graph_evidence(
            {
                "collector": "misp",
                "misp_event_created": "2026-06-20T00:00:00Z",
                "misp_event_timestamp": "1782004900",
                "misp_event_date": "2026-06-20",
                "misp_galaxies": [
                    {
                        "type": "mitre-attack-pattern",
                        "value": "Command and Scripting Interpreter - T1059",
                        "uuid": "cluster-attack",
                        "tag_name": 'misp-galaxy:mitre-attack-pattern="T1059"',
                        "galaxy_type": "mitre-attack-pattern",
                        "galaxy_name": "MITRE ATT&CK",
                        "source_field": "Galaxy",
                        "meta": {
                            "external_id": ["T1059"],
                            "refs": ["https://attack.mitre.org/techniques/T1059/"],
                        },
                    },
                    {
                        "type": "threat-actor",
                        "value": "APT Example",
                        "uuid": "cluster-actor",
                        "galaxy_type": "threat-actor",
                        "galaxy_name": "Threat Actor",
                        "source_field": "Galaxy",
                        "meta": {
                            "synonyms": ["Example Group"],
                            "targeted-sector": ["Activists", "Journalist"],
                            "targeted-country": ["AR"],
                        },
                    },
                    {
                        "type": "sector",
                        "value": "Finance",
                        "galaxy_type": "sector",
                        "source_field": "Galaxy",
                    },
                ],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(7, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["attack_pattern"])
        self.assertEqual(1, evidence["counts"]["threat_actor"])
        self.assertEqual(3, evidence["counts"]["target_sector"])
        self.assertEqual(1, evidence["counts"]["target_country"])
        actor = next(
            record
            for record in evidence["records"]
            if record["entity_type"] == "threat_actor"
        )
        self.assertEqual("group", actor["attributes"]["threat_actor_class"])
        attack = next(
            record for record in evidence["records"] if record["entity_type"] == "attack_pattern"
        )
        self.assertEqual("T1059", attack["value"])
        self.assertEqual("attack-pattern", attack["stix_object_type"])
        self.assertEqual(
            "2026-06-20T00:00:00Z",
            attack["attributes"]["source_created"],
        )
        self.assertEqual("1782004900", attack["attributes"]["source_timestamp"])
        self.assertEqual("2026-06-20", attack["attributes"]["source_date"])
        self.assertEqual(
            "Command and Scripting Interpreter - T1059",
            attack["display_name"],
        )
        self.assertEqual("T1059", attack["attributes"]["external_id"])
        self.assertEqual(
            ["https://attack.mitre.org/techniques/T1059/"],
            attack["attributes"]["meta"]["refs"],
        )
        sector = next(
            record
            for record in evidence["records"]
            if record["entity_type"] == "target_sector"
            and record["value"] == "Activists"
        )
        self.assertEqual("Galaxy.meta.targeted-sector", sector["source_field"])
        self.assertEqual(75, sector["confidence"])
        self.assertEqual(
            "APT Example",
            sector["attributes"]["parent_cluster_value"],
        )
        country = next(
            record
            for record in evidence["records"]
            if record["entity_type"] == "target_country"
        )
        self.assertEqual("Argentina", country["value"])
        self.assertEqual("AR", country["attributes"]["source_value"])

    def test_normalizes_misp_target_sector_aliases_before_deduplication(self):
        evidence = build_graph_evidence(
            {
                "misp_galaxies": [
                    {
                        "type": "threat-actor",
                        "value": "APT Example",
                        "uuid": "cluster-actor",
                        "galaxy_type": "threat-actor",
                        "source_field": "Galaxy",
                        "meta": {
                            "targeted-sector": ["Financial Services", "Finance"],
                        },
                    }
                ],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        sectors = [
            record
            for record in evidence["records"]
            if record["entity_type"] == "target_sector"
        ]
        self.assertEqual(1, len(sectors))
        self.assertEqual("Finance", sectors[0]["value"])
        self.assertEqual(75, sectors[0]["confidence"])
        self.assertEqual("Financial Services", sectors[0]["attributes"]["source_value"])
        self.assertTrue(sectors[0]["attributes"]["normalized_value"])

    def test_builds_misp_cfr_victimology_meta_evidence(self):
        evidence = build_graph_evidence(
            {
                "misp_galaxies": [
                    {
                        "type": "threat-actor",
                        "value": "Equation Group",
                        "uuid": "cluster-actor",
                        "galaxy_type": "threat-actor",
                        "source_field": "Galaxy",
                        "meta": {
                            "cfr-target-category": ["Government", "Military"],
                            "cfr-suspected-victims": ["Iran", "Afghanistan"],
                            "cfr-type-of-incident": ["Espionage"],
                            "observed_motivations": ["Cyber Espionage"],
                        },
                    }
                ],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        sectors = [
            record
            for record in evidence["records"]
            if record["entity_type"] == "target_sector"
        ]
        countries = [
            record
            for record in evidence["records"]
            if record["entity_type"] == "target_country"
        ]
        self.assertEqual(["Government", "Military"], [record["value"] for record in sectors])
        self.assertEqual(["Iran", "Afghanistan"], [record["value"] for record in countries])
        narratives = [
            record
            for record in evidence["records"]
            if record["entity_type"] == "narrative"
        ]
        narrative_types = {
            record["value"]: record["attributes"]["narrative_types"]
            for record in narratives
        }
        self.assertEqual(["incident-type"], narrative_types["Espionage"])
        self.assertEqual(["motivation"], narrative_types["Cyber Espionage"])
        self.assertTrue(
            all(
                record["source_field"] == "Galaxy.meta.cfr-target-category"
                for record in sectors
            )
        )
        self.assertTrue(
            all(
                record["source_field"] == "Galaxy.meta.cfr-suspected-victims"
                for record in countries
            )
        )

    def test_builds_misp_threat_actor_individual_evidence_only_class(self):
        evidence = build_graph_evidence(
            {
                "misp_galaxies": [
                    {
                        "type": "threat-actor-individual",
                        "value": "Example Operator",
                        "uuid": "cluster-individual",
                        "galaxy_type": "threat-actor-individual",
                        "galaxy_name": "Threat Actor Individual",
                        "source_field": "Galaxy",
                        "meta": {"threat-actor-type": ["individual"]},
                    }
                ],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(1, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["threat_actor_individual"])
        actor = evidence["records"][0]
        self.assertEqual("threat_actor_individual", actor["entity_type"])
        self.assertEqual("threat-actor", actor["stix_object_type"])
        self.assertEqual("Example Operator", actor["value"])
        self.assertEqual("individual", actor["attributes"]["threat_actor_class"])
        self.assertEqual(65, actor["confidence"])

    def test_builds_misp_deep_location_meta_evidence(self):
        evidence = build_graph_evidence(
            {
                "misp_galaxies": [
                    {
                        "type": "threat-actor",
                        "value": "APT Example",
                        "uuid": "cluster-actor",
                        "galaxy_type": "threat-actor",
                        "galaxy_name": "Threat Actor",
                        "source_field": "Galaxy",
                        "meta": {
                            "targeted-region": ["APAC"],
                            "targeted-state": ["Sao Paulo"],
                            "targeted-city": ["Sao Paulo"],
                            "targeted-coordinate": ["-23.5505,-46.6333"],
                        },
                    }
                ],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(5, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["threat_actor"])
        self.assertEqual(1, evidence["counts"]["target_region"])
        self.assertEqual(1, evidence["counts"]["target_administrative_area"])
        self.assertEqual(1, evidence["counts"]["target_city"])
        self.assertEqual(1, evidence["counts"]["target_position"])
        region = next(
            record
            for record in evidence["records"]
            if record["entity_type"] == "target_region"
        )
        self.assertEqual("Asia-Pacific", region["value"])
        self.assertEqual(70, region["confidence"])
        self.assertEqual("APAC", region["attributes"]["source_value"])
        self.assertEqual("target_region", region["attributes"]["normalization_scope"])
        city = next(
            record
            for record in evidence["records"]
            if record["entity_type"] == "target_city"
        )
        self.assertEqual("Sao Paulo", city["value"])
        self.assertEqual("location", city["stix_object_type"])
        self.assertEqual("targets", city["relationship_type"])
        self.assertEqual("Galaxy.meta.targeted-city", city["source_field"])
        self.assertEqual(70, city["confidence"])
        self.assertEqual("APT Example", city["attributes"]["parent_cluster_value"])

    def test_builds_misp_campaign_galaxy_graph_evidence(self):
        evidence = build_graph_evidence(
            {
                "misp_galaxies": [
                    {
                        "type": "campaign",
                        "value": "Operation Example",
                        "uuid": "cluster-campaign",
                        "galaxy_type": "campaign",
                        "galaxy_name": "Campaign",
                        "source_field": "Galaxy",
                        "meta": {
                            "refs": ["https://example.test/campaign"],
                            "targeted-sector": ["Energy"],
                        },
                    }
                ],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(2, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["campaign"])
        self.assertEqual(1, evidence["counts"]["target_sector"])
        campaign = next(
            record
            for record in evidence["records"]
            if record["entity_type"] == "campaign"
        )
        self.assertEqual("Operation Example", campaign["value"])
        self.assertEqual("campaign", campaign["stix_object_type"])
        self.assertEqual("related-to", campaign["relationship_type"])
        self.assertEqual("cluster-campaign", campaign["attributes"]["cluster_uuid"])
        sector = next(
            record
            for record in evidence["records"]
            if record["entity_type"] == "target_sector"
        )
        self.assertEqual("Energy", sector["value"])
        self.assertEqual("Galaxy.meta.targeted-sector", sector["source_field"])
        self.assertEqual(
            "Operation Example",
            sector["attributes"]["parent_cluster_value"],
        )

    def test_builds_misp_explicit_campaign_evidence(self):
        evidence = build_graph_evidence(
            {
                "misp_campaigns": [
                    {
                        "value": "Operation Example",
                        "source_type": "attribute",
                        "source_field": "Attribute[0]",
                        "attribute_type": "campaign-name",
                        "attribute_category": "Attribution",
                        "attribute_uuid": "attribute-campaign-1",
                        "first_seen": "2026-06-20T10:00:00Z",
                        "last_seen": "2026-06-22T10:00:00Z",
                        "tags": ["tlp:green"],
                    }
                ],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(1, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["campaign"])
        campaign = evidence["records"][0]
        self.assertEqual("campaign", campaign["entity_type"])
        self.assertEqual("campaign", campaign["stix_object_type"])
        self.assertEqual("Operation Example", campaign["value"])
        self.assertEqual("Attribute[0]", campaign["source_field"])
        self.assertEqual("attribute-campaign-1", campaign["attributes"]["attribute_uuid"])
        self.assertEqual("campaign-name", campaign["attributes"]["attribute_type"])
        self.assertEqual("2026-06-20T10:00:00Z", campaign["attributes"]["first_seen"])
        self.assertEqual("2026-06-22T10:00:00Z", campaign["attributes"]["last_seen"])

    def test_builds_misp_target_organization_meta_evidence(self):
        evidence = build_graph_evidence(
            {
                "misp_galaxies": [
                    {
                        "type": "campaign",
                        "value": "Operation Example",
                        "uuid": "cluster-campaign",
                        "galaxy_type": "campaign",
                        "galaxy_name": "Campaign",
                        "source_field": "Galaxy",
                        "meta": {
                            "victim-organization": ["Example Energy Co"],
                        },
                    }
                ],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(2, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["campaign"])
        self.assertEqual(1, evidence["counts"]["target_organization"])
        organization = next(
            record
            for record in evidence["records"]
            if record["entity_type"] == "target_organization"
        )
        self.assertEqual("Example Energy Co", organization["value"])
        self.assertEqual("identity", organization["stix_object_type"])
        self.assertEqual("targets", organization["relationship_type"])
        self.assertEqual("Galaxy.meta.victim-organization", organization["source_field"])
        self.assertEqual(
            "Operation Example",
            organization["attributes"]["parent_cluster_value"],
        )

    def test_builds_misp_target_organization_from_expanded_victimology_fields(self):
        evidence = build_graph_evidence(
            {
                "misp_galaxies": [
                    {
                        "type": "intrusion-set",
                        "value": "Example Intrusion Set",
                        "uuid": "cluster-intrusion-set",
                        "galaxy_type": "mitre-intrusion-set",
                        "galaxy_name": "Intrusion Set",
                        "source_field": "Galaxy",
                        "meta": {
                            "targeted-company": ["Example Bank"],
                            "affected-organization": ["Example Hospital"],
                            "impacted_company": ["Example Energy Operator"],
                        },
                    }
                ],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(4, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["intrusion_set"])
        self.assertEqual(3, evidence["counts"]["target_organization"])
        organizations = {
            record["value"]: record
            for record in evidence["records"]
            if record["entity_type"] == "target_organization"
        }
        self.assertEqual(
            {
                "Example Bank",
                "Example Energy Operator",
                "Example Hospital",
            },
            set(organizations),
        )
        self.assertEqual(
            "Galaxy.meta.targeted-company",
            organizations["Example Bank"]["source_field"],
        )
        self.assertEqual(
            "Example Intrusion Set",
            organizations["Example Hospital"]["attributes"]["parent_cluster_value"],
        )

    def test_builds_misp_operational_meta_evidence_for_opencti_tabs(self):
        evidence = build_graph_evidence(
            {
                "misp_galaxies": [
                    {
                        "type": "campaign",
                        "value": "Operation Example",
                        "uuid": "cluster-campaign",
                        "galaxy_type": "campaign",
                        "galaxy_name": "Campaign",
                        "source_field": "Galaxy",
                        "meta": {
                            "c2-channel": ["Telegram"],
                            "objective": ["Credential theft"],
                            "incident-name": ["Observed phishing wave"],
                            "security-platform": ["Microsoft Defender for Endpoint"],
                            "targeted-system": ["Windows Workstations"],
                        },
                    }
                ],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(7, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["campaign"])
        self.assertEqual(2, evidence["counts"]["channel"])
        self.assertEqual(1, evidence["counts"]["event"])
        self.assertEqual(1, evidence["counts"]["narrative"])
        self.assertEqual(1, evidence["counts"]["security_platform"])
        self.assertEqual(1, evidence["counts"]["target_system"])
        records = {record["entity_type"]: record for record in evidence["records"]}
        self.assertEqual("Telegram", records["channel"]["value"])
        self.assertEqual("channel", records["channel"]["stix_object_type"])
        self.assertEqual(["c2"], records["channel"]["attributes"]["channel_types"])
        self.assertEqual("Credential theft", records["narrative"]["value"])
        self.assertEqual(
            ["objective"],
            records["narrative"]["attributes"]["narrative_types"],
        )
        self.assertEqual("Observed phishing wave", records["event"]["value"])
        self.assertEqual(["incident"], records["event"]["attributes"]["event_types"])
        self.assertEqual(
            "Microsoft Defender for Endpoint",
            records["security_platform"]["value"],
        )
        self.assertEqual(
            "security-platform",
            records["security_platform"]["stix_object_type"],
        )
        self.assertEqual(
            "Detection Platform",
            records["security_platform"]["attributes"]["security_platform_type"],
        )
        self.assertEqual("Windows Workstations", records["target_system"]["value"])
        self.assertEqual("identity", records["target_system"]["stix_object_type"])

    def test_misp_operational_meta_rejects_ioc_like_values(self):
        evidence = build_graph_evidence(
            {
                "misp_galaxies": [
                    {
                        "type": "campaign",
                        "value": "Operation Example",
                        "uuid": "cluster-campaign",
                        "galaxy_type": "campaign",
                        "galaxy_name": "Campaign",
                        "source_field": "Galaxy",
                        "meta": {
                            "targeted-system": ["CVE-2026-12345"],
                            "security-platform": ["https://example.test"],
                            "channel": ["c2.example.test"],
                            "objective": ["T1059"],
                        },
                    }
                ],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(1, evidence["record_count"])
        self.assertEqual({"campaign": 1}, evidence["counts"])

    def test_skips_misp_target_organization_provenance_and_observable_values(self):
        evidence = build_graph_evidence(
            {
                "misp_galaxies": [
                    {
                        "type": "campaign",
                        "value": "Operation Example",
                        "uuid": "cluster-campaign",
                        "galaxy_type": "campaign",
                        "galaxy_name": "Campaign",
                        "source_field": "Galaxy",
                        "meta": {
                            "victim": [
                                "OTX",
                                "MISP",
                                "example.org",
                                "analyst@example.org",
                                "https://example.org/report",
                                "Real Target Org",
                            ],
                            "source-organization": ["Should Not Promote"],
                        },
                    }
                ],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        organizations = [
            record
            for record in evidence["records"]
            if record["entity_type"] == "target_organization"
        ]
        self.assertEqual(1, len(organizations))
        self.assertEqual("Real Target Org", organizations[0]["value"])
        self.assertNotIn("source-organization", organizations[0]["source_field"])

    def test_builds_misp_target_individual_from_explicit_victimology_fields(self):
        evidence = build_graph_evidence(
            {
                "misp_galaxies": [
                    {
                        "type": "campaign",
                        "value": "Operation Example",
                        "uuid": "cluster-campaign",
                        "galaxy_type": "campaign",
                        "galaxy_name": "Campaign",
                        "source_field": "Galaxy",
                        "meta": {
                            "targeted-person": ["Incident Responder"],
                            "victim-individual": ["Executive Sponsor"],
                        },
                    }
                ],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(3, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["campaign"])
        self.assertEqual(2, evidence["counts"]["target_individual"])
        individuals = {
            record["value"]: record
            for record in evidence["records"]
            if record["entity_type"] == "target_individual"
        }
        self.assertEqual({"Executive Sponsor", "Incident Responder"}, set(individuals))
        self.assertEqual(
            "Galaxy.meta.targeted-person",
            individuals["Incident Responder"]["source_field"],
        )
        self.assertEqual("identity", individuals["Executive Sponsor"]["stix_object_type"])
        self.assertEqual("targets", individuals["Executive Sponsor"]["relationship_type"])
        self.assertEqual(
            "Operation Example",
            individuals["Executive Sponsor"]["attributes"]["parent_cluster_value"],
        )

    def test_skips_misp_target_individual_unsafe_and_ambiguous_values(self):
        evidence = build_graph_evidence(
            {
                "misp_galaxies": [
                    {
                        "type": "campaign",
                        "value": "Operation Example",
                        "uuid": "cluster-campaign",
                        "galaxy_type": "campaign",
                        "galaxy_name": "Campaign",
                        "source_field": "Galaxy",
                        "meta": {
                            "targeted-person": [
                                "OTX",
                                "analyst@example.org",
                                "https://example.org/report",
                                "12345",
                                "Named Target",
                            ],
                            "victim": ["Ambiguous Victim"],
                        },
                    }
                ],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        individuals = [
            record
            for record in evidence["records"]
            if record["entity_type"] == "target_individual"
        ]
        organizations = [
            record
            for record in evidence["records"]
            if record["entity_type"] == "target_organization"
        ]
        self.assertEqual(1, len(individuals))
        self.assertEqual("Named Target", individuals[0]["value"])
        self.assertEqual(1, len(organizations))
        self.assertEqual("Ambiguous Victim", organizations[0]["value"])

    def test_builds_misp_course_of_action_galaxy_graph_evidence(self):
        evidence = build_graph_evidence(
            {
                "misp_galaxies": [
                    {
                        "type": "mitre-course-of-action",
                        "value": "Disable or Remove Feature or Program",
                        "uuid": "cluster-coa",
                        "galaxy_type": "mitre-course-of-action",
                        "galaxy_name": "MITRE Course of Action",
                        "source_field": "Galaxy",
                        "meta": {
                            "external_id": ["M1042"],
                            "refs": ["https://attack.mitre.org/mitigations/M1042/"],
                        },
                    }
                ],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(1, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["course_of_action"])
        course = evidence["records"][0]
        self.assertEqual("course_of_action", course["entity_type"])
        self.assertEqual("Disable or Remove Feature or Program", course["value"])
        self.assertEqual("course-of-action", course["stix_object_type"])
        self.assertEqual("related-to", course["relationship_type"])
        self.assertEqual("cluster-coa", course["attributes"]["cluster_uuid"])

    def test_builds_misp_course_of_action_mitigation_relationship_evidence(self):
        evidence = build_graph_evidence(
            {
                "misp_galaxies": [
                    {
                        "type": "mitre-course-of-action",
                        "value": "Disable or Remove Feature or Program",
                        "uuid": "cluster-coa",
                        "galaxy_type": "mitre-course-of-action",
                        "galaxy_name": "MITRE Course of Action",
                        "source_field": "Galaxy",
                        "meta": {
                            "external_id": ["M1042"],
                            "mitigates": ["T1059"],
                            "refs": ["https://attack.mitre.org/mitigations/M1042/"],
                        },
                    }
                ],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(1, evidence["counts"]["course_of_action"])
        course = evidence["records"][0]
        self.assertEqual("course_of_action", course["entity_type"])
        self.assertEqual("mitigates", course["relationship_type"])
        self.assertEqual(
            "attack-pattern",
            course["attributes"]["relationship_source_stix_object_type"],
        )
        self.assertEqual("T1059", course["attributes"]["relationship_source_value"])
        self.assertEqual("meta.mitigates", course["attributes"]["relationship_source_field"])

    def test_builds_misp_vulnerability_graph_evidence(self):
        evidence = build_graph_evidence(
            {
                "misp_vulnerabilities": [
                    {
                        "value": "CVE-2024-12345",
                        "source_field": "Attribute[0]",
                        "source_type": "attribute",
                        "attribute_type": "vulnerability",
                        "attribute_category": "External analysis",
                        "attribute_uuid": "attr-cve",
                        "first_seen": "2026-06-20T10:00:00Z",
                        "last_seen": "2026-06-21T10:00:00Z",
                        "tags": ["exploit:known"],
                    }
                ],
                "misp_galaxies": [
                    {
                        "type": "branded-vulnerability",
                        "value": "CVE-2023-9999",
                        "uuid": "cluster-cve",
                        "galaxy_type": "branded-vulnerability",
                        "galaxy_name": "Branded Vulnerability",
                        "source_field": "Galaxy",
                        "meta": {"refs": ["https://nvd.nist.gov/vuln/detail/CVE-2023-9999"]},
                    }
                ],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(2, evidence["record_count"])
        self.assertEqual(2, evidence["counts"]["vulnerability"])
        self.assertIn(
            {
                "entity_type": "vulnerability",
                "value": "CVE-2024-12345",
                "stix_object_type": "vulnerability",
                "relationship_type": "related-to",
                "source_key": "misp:misp",
                "source_name": "misp",
                "source_field": "Attribute[0]",
                "confidence": 75,
                "attributes": {
                    "source_type": "attribute",
                    "attribute_type": "vulnerability",
                    "attribute_category": "External analysis",
                    "attribute_uuid": "attr-cve",
                    "first_seen": "2026-06-20T10:00:00Z",
                    "last_seen": "2026-06-21T10:00:00Z",
                    "tags": ["exploit:known"],
                },
            },
            evidence["records"],
        )
        galaxy_vulnerability = next(
            record
            for record in evidence["records"]
            if record["source_name"] == "misp-galaxy"
        )
        self.assertEqual("CVE-2023-9999", galaxy_vulnerability["value"])
        self.assertEqual("CVE-2023-9999", galaxy_vulnerability["attributes"]["external_id"])

    def test_builds_misp_event_report_note_evidence(self):
        evidence = build_graph_evidence(
            {
                "misp_event_reports": [
                    {
                        "title": "Initial analyst report",
                        "content": "The event describes exploitation activity.",
                        "uuid": "event-report-1",
                        "timestamp": "1782004900",
                        "source_field": "EventReport[0]",
                    }
                ]
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(1, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["event_report"])
        self.assertIn(
            {
                "entity_type": "event_report",
                "value": "Initial analyst report",
                "stix_object_type": "note",
                "relationship_type": "documents",
                "source_key": "misp:misp",
                "source_name": "misp",
                "source_field": "EventReport[0]",
                "confidence": 70,
                "attributes": {
                    "content": "The event describes exploitation activity.",
                    "event_report_uuid": "event-report-1",
                    "timestamp": "1782004900",
                },
            },
            evidence["records"],
        )

    def test_builds_misp_sighting_evidence(self):
        evidence = build_graph_evidence(
            {
                "misp_sightings": [
                    {
                        "value": "evil.example",
                        "sighting_id": "42",
                        "date_sighting": "1782004900",
                        "source": "SOC",
                        "confidence": "82",
                        "organization": "Example Org",
                        "attribute_type": "domain",
                        "attribute_uuid": "attribute-1",
                        "source_field": "Attribute[0].Sighting[0]",
                    }
                ]
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(1, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["sighting"])
        self.assertIn(
            {
                "entity_type": "sighting",
                "value": "evil.example",
                "stix_object_type": "sighting",
                "relationship_type": "sighting-of",
                "source_key": "misp:misp",
                "source_name": "misp",
                "source_field": "Attribute[0].Sighting[0]",
                "confidence": 82,
                "attributes": {
                    "sighting_id": "42",
                    "date_sighting": "1782004900",
                    "source": "SOC",
                    "confidence": "82",
                    "organization": "Example Org",
                    "attribute_type": "domain",
                    "attribute_uuid": "attribute-1",
                },
            },
            evidence["records"],
        )

    def test_builds_misp_object_reference_evidence(self):
        evidence = build_graph_evidence(
            {
                "misp_object_references": [
                    {
                        "value": "object-1 uses object-2",
                        "relationship_type": "uses",
                        "reference_uuid": "reference-1",
                        "source_uuid": "object-1",
                        "source_name": "malware",
                        "target_uuid": "object-2",
                        "target_type": "object",
                        "comment": "Malware uses this infrastructure.",
                        "source_field": "Object[0].ObjectReference[0]",
                    }
                ]
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(1, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["object_reference"])
        self.assertIn(
            {
                "entity_type": "object_reference",
                "value": "object-1 uses object-2",
                "stix_object_type": "relationship",
                "relationship_type": "uses",
                "source_key": "misp:misp",
                "source_name": "misp",
                "source_field": "Object[0].ObjectReference[0]",
                "confidence": 60,
                "attributes": {
                    "reference_uuid": "reference-1",
                    "source_uuid": "object-1",
                    "source_name": "malware",
                    "target_uuid": "object-2",
                    "target_type": "object",
                    "comment": "Malware uses this infrastructure.",
                },
            },
            evidence["records"],
        )

    def test_builds_misp_infrastructure_graph_evidence(self):
        evidence = build_graph_evidence(
            {
                "misp_infrastructure": [
                    {
                        "entity_type": "infrastructure",
                        "value": "MISP netblock 203.0.113.0/24",
                        "stix_object_type": "infrastructure",
                        "relationship_type": "uses",
                        "source_field": "Object[0]",
                        "confidence": 72,
                        "attributes": {
                            "object_name": "netblock",
                            "object_uuid": "object-netblock",
                        },
                    },
                    {
                        "entity_type": "observable",
                        "value": "203.0.113.0/24",
                        "stix_object_type": "observable",
                        "relationship_type": "consists-of",
                        "source_field": "Attribute[0]",
                        "confidence": 70,
                        "attributes": {
                            "observable_type": "ipv4-addr",
                            "relationship_source_stix_object_type": "infrastructure",
                            "relationship_source_value": "MISP netblock 203.0.113.0/24",
                        },
                    },
                    {
                        "entity_type": "autonomous_system",
                        "value": "AS64512 NarrowCTI Validation ASN",
                        "stix_object_type": "autonomous-system",
                        "relationship_type": "belongs-to",
                        "source_field": "Attribute[1]",
                        "confidence": 72,
                        "attributes": {
                            "asn": 64512,
                            "asn_name": "NarrowCTI Validation ASN",
                            "relationship_source_stix_object_type": "observable",
                            "relationship_source_value": "203.0.113.0/24",
                        },
                    },
                ]
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(3, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["infrastructure"])
        self.assertEqual(1, evidence["counts"]["observable"])
        self.assertEqual(1, evidence["counts"]["autonomous_system"])
        self.assertTrue(
            any(
                record["entity_type"] == "autonomous_system"
                and record["relationship_type"] == "belongs-to"
                and record["attributes"]["relationship_source_value"]
                == "203.0.113.0/24"
                for record in evidence["records"]
            )
        )

    def test_builds_misp_galaxy_tag_evidence(self):
        evidence = build_graph_evidence(
            {
                "tags": [
                    'misp-galaxy:mitre-intrusion-set="APT32"',
                    'misp-galaxy:mitre-attack-pattern="PowerShell - T1059.001"',
                    'misp-galaxy:malpedia="Lorenz"',
                ]
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertTrue(
            any(
                record["entity_type"] == "intrusion_set"
                and record["value"] == "APT32"
                and record["source_field"] == "tags[0]"
                for record in evidence["records"]
            )
        )
        self.assertTrue(
            any(
                record["entity_type"] == "attack_pattern"
                and record["value"] == "T1059.001"
                and record["display_name"] == "PowerShell - T1059.001"
                and record["source_field"] == "tags[1]"
                for record in evidence["records"]
            )
        )
        self.assertTrue(
            any(
                record["entity_type"] == "malware"
                and record["value"] == "Lorenz"
                and record["source_field"] == "tags[2]"
                for record in evidence["records"]
            )
        )

    def test_builds_misp_infrastructure_context_relationship_evidence(self):
        evidence = build_graph_evidence(
            {
                "tags": [
                    'misp-galaxy:mitre-intrusion-set="APT32"',
                    'misp-galaxy:mitre-attack-pattern="PowerShell - T1059.001"',
                    'misp-galaxy:malpedia="Lorenz"',
                ],
                "misp_infrastructure": [
                    {
                        "entity_type": "infrastructure",
                        "value": "MISP domain-ip c2.example",
                        "stix_object_type": "infrastructure",
                        "relationship_type": "uses",
                        "source_field": "Attribute[0]",
                        "confidence": 72,
                    },
                    {
                        "entity_type": "observable",
                        "value": "c2.example",
                        "stix_object_type": "observable",
                        "relationship_type": "consists-of",
                        "source_field": "Attribute[0]",
                        "confidence": 70,
                        "attributes": {
                            "observable_type": "domain-name",
                            "relationship_source_stix_object_type": "infrastructure",
                            "relationship_source_value": "MISP domain-ip c2.example",
                        },
                    },
                ],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertTrue(
            any(
                record["entity_type"] == "infrastructure"
                and record["source_name"] == "misp-context"
                and record["relationship_type"] == "uses"
                and record["attributes"]["relationship_source_stix_object_type"]
                == "intrusion-set"
                and record["attributes"]["relationship_source_value"] == "APT32"
                and record["attributes"]["relationship_inference"]
                == "misp-event-infrastructure-adversary-context"
                for record in evidence["records"]
            )
        )
        self.assertTrue(
            any(
                record["entity_type"] == "infrastructure"
                and record["source_name"] == "misp-context"
                and record["relationship_type"] == "uses"
                and record["attributes"]["relationship_source_stix_object_type"]
                == "malware"
                and record["attributes"]["relationship_source_value"] == "Lorenz"
                and record["attributes"]["relationship_inference"]
                == "misp-event-infrastructure-capability-context"
                for record in evidence["records"]
            )
        )
        self.assertTrue(
            any(
                record["entity_type"] == "attack_pattern"
                and record["source_name"] == "misp-context"
                and record["relationship_type"] == "related-to"
                and record["attributes"]["relationship_source_stix_object_type"]
                == "infrastructure"
                and record["attributes"]["relationship_source_value"]
                == "MISP domain-ip c2.example"
                and record["attributes"]["relationship_inference"]
                == "misp-event-infrastructure-ttp-context"
                for record in evidence["records"]
            )
        )

    def test_builds_misp_infrastructure_victimology_preview_evidence(self):
        evidence = build_graph_evidence(
            {
                "misp_galaxies": [
                    {
                        "type": "intrusion-set",
                        "value": "APT32",
                        "uuid": "cluster-actor",
                        "galaxy_type": "mitre-intrusion-set",
                        "galaxy_name": "Intrusion Set",
                        "source_field": "Galaxy",
                        "meta": {
                            "targeted-sector": ["Finance"],
                            "targeted-country": ["BR"],
                        },
                    }
                ],
                "misp_infrastructure": [
                    {
                        "entity_type": "infrastructure",
                        "value": "MISP domain-ip c2.example",
                        "stix_object_type": "infrastructure",
                        "relationship_type": "uses",
                        "source_field": "Attribute[0]",
                        "confidence": 72,
                    },
                ],
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        previews = [
            record
            for record in evidence["records"]
            if record["source_name"] == "misp-context"
            and record["relationship_type"] == "targets"
        ]
        self.assertEqual(2, len(previews))
        self.assertTrue(
            any(
                record["entity_type"] == "target_sector"
                and record["value"] == "Finance"
                and record["attributes"]["relationship_source_stix_object_type"]
                == "infrastructure"
                and record["attributes"]["relationship_source_value"]
                == "MISP domain-ip c2.example"
                and record["attributes"]["relationship_inference"]
                == "misp-event-infrastructure-victimology-context"
                and record["attributes"]["relationship_validation_state"]
                == "requires-opencti-validation"
                for record in previews
            )
        )
        self.assertTrue(
            any(
                record["entity_type"] == "target_country"
                and record["value"] == "Brazil"
                and record["attributes"]["source_value"] == "BR"
                and record["attributes"]["relationship_validation_state"]
                == "requires-opencti-validation"
                for record in previews
            )
        )

    def test_propagates_explicit_campaign_context_to_actor_infrastructure_and_victimology(self):
        evidence = build_graph_evidence(
            {
                "misp_campaigns": [
                    {
                        "value": "Dust Storm",
                        "source_field": "Attribute[2]",
                        "attribute_type": "campaign-name",
                    }
                ],
                "misp_galaxies": [
                    {
                        "type": "intrusion-set",
                        "value": "APT32",
                        "uuid": "cluster-actor",
                        "galaxy_type": "mitre-intrusion-set",
                        "galaxy_name": "Intrusion Set",
                        "source_field": "Galaxy",
                    }
                ],
                "misp_infrastructure": [
                    {
                        "entity_type": "infrastructure",
                        "value": "MISP C2 203.0.113.10",
                        "stix_object_type": "infrastructure",
                        "relationship_type": "uses",
                        "source_field": "Object[0]",
                        "confidence": 80,
                    }
                ],
                "misp_victimology": [
                    {
                        "entity_type": "target_sector",
                        "value": "Finance",
                        "source_field": "Attribute[3]",
                        "confidence": 75,
                    }
                ],
            },
            source_key="misp:misp",
            external_id="event-dust-storm-context",
            title="OSINT Dust Storm Campaign Targeting Japanese Critical Infrastructure",
        )

        contextual = [
            record
            for record in evidence["records"]
            if record["source_name"] == "misp-context"
        ]
        self.assertTrue(
            any(
                record["entity_type"] == "intrusion_set"
                and record["relationship_type"] == "attributed-to"
                and record["attributes"]["relationship_source_value"] == "Dust Storm"
                and record["attributes"]["relationship_inference"]
                == "misp-event-campaign-adversary-context"
                for record in contextual
            )
        )
        self.assertTrue(
            any(
                record["entity_type"] == "infrastructure"
                and record["relationship_type"] == "uses"
                and record["attributes"]["relationship_source_value"] == "Dust Storm"
                and record["attributes"]["relationship_inference"]
                == "misp-event-campaign-infrastructure-context"
                for record in contextual
            )
        )
        self.assertTrue(
            any(
                record["entity_type"] == "target_sector"
                and record["relationship_type"] == "targets"
                and record["attributes"]["relationship_source_value"] == "Dust Storm"
                and record["attributes"]["relationship_inference"]
                == "misp-event-campaign-victimology-context"
                for record in contextual
            )
        )
        self.assertTrue(
            any(
                record["entity_type"] == "infrastructure"
                and record["relationship_type"] == "uses"
                and record["attributes"]["relationship_source_value"] == "APT32"
                and record["attributes"]["relationship_inference"]
                == "misp-event-infrastructure-adversary-context"
                for record in contextual
            )
        )

    def test_does_not_infer_campaign_victimology_from_event_title(self):
        evidence = build_graph_evidence(
            {
                "misp_campaigns": [
                    {
                        "value": "Dust Storm",
                        "source_field": "Attribute[2]",
                        "attribute_type": "campaign-name",
                    }
                ]
            },
            source_key="misp:misp",
            external_id="event-dust-storm-title-only",
            title="OSINT Dust Storm Campaign Targeting Japanese Critical Infrastructure",
        )

        self.assertFalse(
            any(
                record["entity_type"].startswith("target_")
                for record in evidence["records"]
            )
        )

    def test_builds_misp_detection_rule_evidence(self):
        evidence = build_graph_evidence(
            {
                "misp_detection_rules": [
                    {
                        "value": "Suspicious PowerShell",
                        "rule_type": "sigma",
                        "pattern_type": "sigma",
                        "pattern": "title: Suspicious PowerShell",
                        "attribute_category": "Payload delivery",
                        "attribute_uuid": "attribute-rule-1",
                        "first_seen": "2026-06-20T10:00:00Z",
                        "last_seen": "2026-06-22T10:00:00Z",
                        "tags": ["tlp:green"],
                        "source_field": "Attribute[0]",
                    }
                ]
            },
            source_key="misp:misp",
            external_id="event-1",
            title="MISP event",
        )

        self.assertEqual(1, evidence["record_count"])
        self.assertEqual(1, evidence["counts"]["detection_rule"])
        self.assertIn(
            {
                "entity_type": "detection_rule",
                "value": "Suspicious PowerShell",
                "stix_object_type": "indicator",
                "relationship_type": "detects",
                "source_key": "misp:misp",
                "source_name": "misp",
                "source_field": "Attribute[0]",
                "confidence": 70,
                "attributes": {
                    "rule_type": "sigma",
                    "pattern_type": "sigma",
                    "pattern": "title: Suspicious PowerShell",
                    "attribute_category": "Payload delivery",
                    "attribute_uuid": "attribute-rule-1",
                    "first_seen": "2026-06-20T10:00:00Z",
                    "last_seen": "2026-06-22T10:00:00Z",
                    "tags": ["tlp:green"],
                },
            },
            evidence["records"],
        )

    def test_builds_explicit_sigma_attack_relationship_evidence(self):
        evidence = build_graph_evidence(
            {
                "misp_detection_rules": [
                    {
                        "value": "Suspicious PowerShell",
                        "rule_type": "sigma",
                        "pattern_type": "sigma",
                        "pattern": "title: Suspicious PowerShell",
                        "attribute_uuid": "attribute-rule-2",
                        "tags": ["attack.execution", "tlp:green"],
                        "attack_pattern_ids": ["T1059.001", "T1059.003"],
                        "attack_id_source": "sigma-tags-or-references",
                        "source_field": "Attribute[0]",
                    }
                ]
            },
            source_key="misp:misp",
            external_id="event-2",
            title="MISP Sigma event",
        )

        linked = [
            record
            for record in evidence["records"]
            if record["entity_type"] == "detection_rule"
            and record["attributes"].get("relationship_source_value")
        ]
        self.assertEqual(2, len(linked))
        self.assertEqual({"T1059.001", "T1059.003"}, {
            record["attributes"]["relationship_source_value"]
            for record in linked
        })
        self.assertTrue(all(record["relationship_type"] == "detects" for record in linked))
        self.assertTrue(all(record["confidence"] == 85 for record in linked))
        self.assertTrue(
            all(
                record["attributes"]["relationship_source_stix_object_type"]
                == "attack-pattern"
                for record in linked
            )
        )

    def test_does_not_link_incompatible_detection_rule(self):
        evidence = build_graph_evidence(
            {
                "misp_detection_rules": [
                    {
                        "value": "Unsupported Sigma",
                        "rule_type": "sigma",
                        "pattern_type": "sigma",
                        "pattern": "title: Unsupported Sigma",
                        "opencti_indicator_compatible": False,
                        "attack_pattern_ids": ["T1059.001"],
                        "attack_id_source": "misp-tags",
                        "source_field": "Attribute[1]",
                    }
                ]
            },
            source_key="misp:misp",
            external_id="event-3",
            title="MISP incompatible Sigma event",
        )

        self.assertEqual(1, evidence["record_count"])
        record = evidence["records"][0]
        self.assertEqual("detection_rule", record["entity_type"])
        self.assertEqual("detects", record["relationship_type"])
        self.assertNotIn("relationship_source_value", record.get("attributes", {}))


if __name__ == "__main__":
    unittest.main()
