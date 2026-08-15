import json
import unittest
from unittest.mock import patch

from exporters.opencti import (
    OpenCTIImportRejectedError,
    report_refs_from_bundle_json,
    send_bundle,
)
from exporters.stix_builder import deterministic_graph_object_id


class OpenCTIExporterTests(unittest.TestCase):
    def test_rejected_bundle_objects_fail_the_export(self):
        api_client = FakeOpenCTIClient()
        api_client.stix2.failed = [{"error_message": "observable rejected"}]

        with self.assertRaisesRegex(
            OpenCTIImportRejectedError,
            "OpenCTI rejected 1 bundle object",
        ):
            send_bundle(
                api_client,
                "Rejected validation",
                "Must fail closed.",
                70,
                [],
            )

    def test_pycti_worker_errors_fail_the_export(self):
        api_client = FakeOpenCTIClient()

        with patch(
            "exporters.opencti.capture_pycti_worker_errors",
            return_value=([("worker failure",)], lambda: None),
        ):
            with self.assertRaisesRegex(
                OpenCTIImportRejectedError,
                "worker recorded 1 permanent import error",
            ):
                send_bundle(
                    api_client,
                    "Worker rejection",
                    "Must fail closed.",
                    70,
                    [],
                )

    def test_audit_mode_keeps_legacy_report_indicator_bundle(self):
        api_client = FakeOpenCTIClient()

        indicator_count = send_bundle(
            api_client,
            "Curated report",
            "description",
            75,
            indicators=[{"type": "domain", "indicator": "one.example"}],
            graph_candidate_policy={"accepted": [target_sector_candidate()]},
            graph_export_mode="audit",
        )

        objects = imported_objects(api_client)
        self.assertEqual(1, indicator_count)
        self.assertEqual(["identity", "indicator", "report"], object_types(objects))
        self.assertFalse(has_sector_identity(objects, "Crypto"))

    def test_exporter_passes_source_publication_date_to_report(self):
        api_client = FakeOpenCTIClient()

        send_bundle(
            api_client,
            "Historical MISP event",
            "description",
            75,
            indicators=[{"type": "domain", "indicator": "one.example"}],
            published_at="2017-02-18",
        )

        report = first_object(
            api_client.stix2.imports[0]["bundle"]["objects"],
            "report",
        )
        self.assertTrue(report["published"].startswith("2017-02-18T00:00:00"))
        self.assertEqual("2017-02-18", report["x_narrowcti_source_date"])

    def test_export_mode_imports_curated_graph_entities(self):
        api_client = FakeOpenCTIClient()

        indicator_count = send_bundle(
            api_client,
            "Curated report",
            "description",
            75,
            indicators=[{"type": "domain", "indicator": "one.example"}],
            graph_candidate_policy={"accepted": [target_sector_candidate()]},
            graph_export_mode="export",
        )

        objects = imported_objects(api_client)
        self.assertEqual(1, indicator_count)
        self.assertTrue(has_sector_identity(objects, "Crypto"))
        self.assertIn("relationship", object_types(objects))

    def test_audit_mode_does_not_create_native_security_platform(self):
        api_client = FakeOpenCTIClient()

        send_bundle(
            api_client,
            "Curated report",
            "description",
            75,
            graph_candidate_policy={"accepted": [security_platform_candidate()]},
            graph_export_mode="audit",
        )

        self.assertEqual([], api_client.security_platform_adds)
        self.assertEqual([], api_client.report_object_refs)

    def test_audit_mode_does_not_create_native_threat_actor_individual(self):
        api_client = FakeOpenCTIClient()

        send_bundle(
            api_client,
            "Curated report",
            "description",
            75,
            graph_candidate_policy={"accepted": [threat_actor_individual_candidate()]},
            graph_export_mode="audit",
        )

        self.assertEqual([], api_client.threat_actor_individual_adds)
        self.assertEqual([], api_client.report_object_refs)

    def test_export_mode_creates_native_security_platform(self):
        api_client = FakeOpenCTIClient()

        send_bundle(
            api_client,
            "Curated report",
            "description",
            75,
            graph_candidate_policy={"accepted": [security_platform_candidate()]},
            graph_export_mode="export",
        )

        objects = imported_objects(api_client)
        self.assertNotIn("security-platform", object_types(objects))
        self.assertEqual(
            [
                {
                    "name": "NarrowCTI SIEM Validation",
                    "update": True,
                    "description": "Source-backed detection platform validation.",
                    "security_platform_type": "SIEM",
                    "confidence": 70,
                }
            ],
            api_client.security_platform_adds,
        )
        self.assertEqual(
            [
                {
                    "id": "report--internal",
                    "input": {
                        "toId": "security-platform--internal",
                        "relationship_type": "object",
                        "update": True,
                    },
                }
            ],
            api_client.report_object_refs,
        )

    def test_export_mode_creates_native_detection_rule_indicator(self):
        api_client = FakeOpenCTIClient()

        send_bundle(
            api_client,
            "Curated report",
            "description",
            75,
            graph_candidate_policy={"accepted": [sigma_detection_rule_candidate()]},
            graph_export_mode="export",
            identity_name="MISP via NarrowCTI",
        )

        self.assertEqual(
            [
                {
                    "name": "SIGMA: Suspicious PowerShell",
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
                    "update": True,
                    "indicator_types": ["malicious-activity"],
                    "x_opencti_detection": True,
                    "objectLabel": [
                        "label--narrowcti-detection-rule",
                        "label--rule-type-sigma",
                    ],
                    "description": (
                        "Source-backed SIGMA detection rule observed by misp at "
                        "Attribute[0]."
                    ),
                    "confidence": 70,
                    "x_opencti_score": 75,
                    "createdBy": "identity--misp-via-narrowcti",
                }
            ],
            api_client.indicator_adds,
        )
        self.assertEqual(
            [
                {"value": "narrowcti:detection-rule", "update": True},
                {"value": "rule-type:sigma", "update": True},
            ],
            api_client.label_adds,
        )
        self.assertIn(
            {
                "id": "report--internal",
                "input": {
                    "toId": "indicator--native",
                    "relationship_type": "object",
                    "update": True,
                },
            },
            api_client.report_object_refs,
        )

    def test_export_mode_preserves_snort_detection_rule_as_note_only(self):
        api_client = FakeOpenCTIClient()

        send_bundle(
            api_client,
            "Curated report",
            "description",
            75,
            graph_candidate_policy={"accepted": [snort_detection_rule_candidate()]},
            graph_export_mode="export",
            identity_name="MISP via NarrowCTI",
        )

        objects = imported_objects(api_client)
        self.assertNotIn("indicator", object_types(objects))
        note = first_object(objects, "note")
        self.assertEqual("SNORT: Adobe Flash Exploit", note["abstract"])
        self.assertIn("rule-type:snort", note["labels"])
        self.assertIn("alert tcp any any -> any any", note["content"])
        self.assertEqual([], api_client.indicator_adds)
        self.assertEqual([], api_client.label_adds)

    def test_export_mode_preserves_incompatible_sigma_as_note_only(self):
        api_client = FakeOpenCTIClient()

        send_bundle(
            api_client,
            "Curated report",
            "description",
            75,
            graph_candidate_policy={
                "accepted": [incompatible_sigma_detection_rule_candidate()]
            },
            graph_export_mode="export",
            identity_name="MISP via NarrowCTI",
        )

        objects = imported_objects(api_client)
        self.assertNotIn("indicator", object_types(objects))
        note = first_object(objects, "note")
        self.assertEqual("SIGMA: Broken Sigma", note["abstract"])
        self.assertIn("rule-type:sigma", note["labels"])
        self.assertIn("missing detection selection", note["content"])
        self.assertEqual([], api_client.indicator_adds)
        self.assertEqual([], api_client.label_adds)

    def test_export_mode_describes_native_security_platform_from_source_context(self):
        api_client = FakeOpenCTIClient()
        candidate = security_platform_candidate()
        candidate["attributes"] = {"security_platform_type": "SIEM"}

        send_bundle(
            api_client,
            "Curated report",
            "description",
            75,
            graph_candidate_policy={"accepted": [candidate]},
            graph_export_mode="export",
        )

        self.assertEqual(
            "Source-backed security platform observed by misp at security_platform: "
            "NarrowCTI SIEM Validation.",
            api_client.security_platform_adds[0]["description"],
        )

    def test_export_mode_creates_native_threat_actor_individual(self):
        api_client = FakeOpenCTIClient()

        send_bundle(
            api_client,
            "Curated report",
            "description",
            75,
            graph_candidate_policy={"accepted": [threat_actor_individual_candidate()]},
            graph_export_mode="export",
        )

        objects = imported_objects(api_client)
        self.assertNotIn("threat-actor", object_types(objects))
        self.assertEqual(
            [
                {
                    "name": "NarrowCTI Individual Actor Validation",
                    "update": True,
                    "description": "Source-backed individual actor validation.",
                    "confidence": 65,
                    "aliases": ["Individual Actor Alias"],
                    "threat_actor_types": ["crime-syndicate"],
                    "primary_motivation": "financial-gain",
                }
            ],
            api_client.threat_actor_individual_adds,
        )
        self.assertEqual(
            [
                {
                    "id": "report--internal",
                    "input": {
                        "toId": "threat-actor-individual--internal",
                        "relationship_type": "object",
                        "update": True,
                    },
                }
            ],
            api_client.report_object_refs,
        )

    def test_export_mode_describes_native_threat_actor_individual_from_source_context(self):
        api_client = FakeOpenCTIClient()
        candidate = threat_actor_individual_candidate()
        candidate["attributes"] = {"threat_actor_class": "individual"}

        send_bundle(
            api_client,
            "Curated report",
            "description",
            75,
            graph_candidate_policy={"accepted": [candidate]},
            graph_export_mode="export",
        )

        self.assertEqual(
            "Source-backed threat actor individual observed by misp-galaxy at "
            "Galaxy.threat-actor-individual: NarrowCTI Individual Actor Validation.",
            api_client.threat_actor_individual_adds[0]["description"],
        )

    def test_export_mode_reuses_existing_native_security_platform(self):
        api_client = FakeOpenCTIClient(existing_security_platform=True)

        send_bundle(
            api_client,
            "Curated report",
            "description",
            75,
            graph_candidate_policy={"accepted": [security_platform_candidate()]},
            graph_export_mode="export",
        )

        self.assertEqual([], api_client.security_platform_adds)
        self.assertEqual(
            [
                {
                    "id": "report--internal",
                    "input": {
                        "toId": "security-platform--internal",
                        "relationship_type": "object",
                        "update": True,
                    },
                }
            ],
            api_client.report_object_refs,
        )

    def test_export_mode_reuses_existing_native_threat_actor_individual(self):
        api_client = FakeOpenCTIClient(existing_threat_actor_individual=True)

        send_bundle(
            api_client,
            "Curated report",
            "description",
            75,
            graph_candidate_policy={"accepted": [threat_actor_individual_candidate()]},
            graph_export_mode="export",
        )

        self.assertEqual([], api_client.threat_actor_individual_adds)
        self.assertEqual(
            [
                {
                    "id": "report--internal",
                    "input": {
                        "toId": "threat-actor-individual--internal",
                        "relationship_type": "object",
                        "update": True,
                    },
                }
            ],
            api_client.report_object_refs,
        )

    def test_export_mode_references_existing_opencti_graph_objects(self):
        api_client = FakeOpenCTIClient()
        existing_attack_pattern_ref = (
            "attack-pattern--11111111-1111-4111-8111-111111111111"
        )

        send_bundle(
            api_client,
            "Curated report",
            "description",
            75,
            graph_candidate_policy={
                "accepted": [
                    threat_actor_candidate(),
                    existing_attack_pattern_candidate(existing_attack_pattern_ref),
                ]
            },
            graph_export_mode="export",
        )

        objects = imported_objects(api_client)
        report = first_object(objects, "report")
        relationship = first_relationship(objects, "uses")

        self.assertNotIn("attack-pattern", object_types(objects))
        self.assertIn(existing_attack_pattern_ref, report["object_refs"])
        self.assertEqual(existing_attack_pattern_ref, relationship["target_ref"])

    def test_export_mode_hydrates_empty_existing_graph_description(self):
        api_client = FakeOpenCTIClient(existing_description="")

        send_bundle(
            api_client,
            "Curated report",
            "description",
            75,
            graph_candidate_policy={
                "accepted": [
                    existing_target_sector_candidate(
                        deterministic_graph_object_id(
                            "identity",
                            "Crypto",
                            "Crypto",
                            {"identity_class": "class"},
                        ),
                        "opencti-sector-id",
                    )
                ]
            },
            graph_export_mode="export",
        )

        self.assertEqual(
            [
                {
                    "id": "opencti-sector-id",
                    "input": [
                            {
                                "key": "description",
                                "value": [
                                    "Source-backed target sector observed by otx at "
                                    "industries: Crypto."
                                ],
                            }
                        ],
                }
            ],
            api_client.patches,
        )

    def test_export_mode_keeps_non_empty_existing_graph_description(self):
        api_client = FakeOpenCTIClient(existing_description="Analyst maintained text.")

        send_bundle(
            api_client,
            "Curated report",
            "description",
            75,
            graph_candidate_policy={
                "accepted": [
                    existing_target_sector_candidate(
                        deterministic_graph_object_id(
                            "identity",
                            "Crypto",
                            "Crypto",
                            {"identity_class": "class"},
                        ),
                        "opencti-sector-id",
                    )
                ]
            },
            graph_export_mode="export",
        )

        self.assertEqual([], api_client.patches)

    def test_export_mode_hydrates_legacy_narrow_authored_graph_description(self):
        api_client = FakeOpenCTIClient(
            existing_description="",
            existing_author="MISP via NarrowCTI",
        )

        send_bundle(
            api_client,
            "Curated report",
            "description",
            75,
            graph_candidate_policy={
                "accepted": [
                    existing_target_sector_candidate(
                        "identity--11111111-1111-4111-8111-111111111111",
                        "opencti-sector-id",
                    )
                ]
            },
            graph_export_mode="export",
        )

        self.assertEqual(1, len(api_client.patches))

    def test_export_mode_does_not_hydrate_external_graph_description(self):
        api_client = FakeOpenCTIClient(
            existing_description="",
            existing_author="The MITRE Corporation",
        )

        send_bundle(
            api_client,
            "Curated report",
            "description",
            75,
            graph_candidate_policy={
                "accepted": [
                    existing_target_sector_candidate(
                        "identity--11111111-1111-4111-8111-111111111111",
                        "opencti-sector-id",
                    )
                ]
            },
            graph_export_mode="export",
        )

        self.assertEqual([], api_client.patches)

    def test_repeated_report_exports_use_stable_report_id(self):
        api_client = FakeOpenCTIClient()

        for _ in range(2):
            send_bundle(
                api_client,
                "LummaC2 Stealer: A Potent Threat to Crypto Users",
                "description",
                75,
                indicators=[{"type": "domain", "indicator": "one.example"}],
                graph_export_mode="audit",
            )

        first_report = first_object(
            api_client.stix2.imports[0]["bundle"]["objects"],
            "report",
        )
        second_report = first_object(
            api_client.stix2.imports[1]["bundle"]["objects"],
            "report",
        )

        self.assertEqual(first_report["id"], second_report["id"])
        self.assertTrue(first_report["id"].startswith("report--"))

    def test_report_lookup_refs_preserve_internal_whitespace(self):
        refs = report_refs_from_bundle_json(
            json.dumps(
                {
                    "objects": [
                        {
                            "type": "report",
                            "id": "report--example",
                            "name": "OSINT -  US CERT TA17-293A",
                        }
                    ]
                }
            )
        )

        self.assertEqual("OSINT -  US CERT TA17-293A", refs[0]["name"])


class FakeOpenCTIClient:
    def __init__(
        self,
        existing_description=None,
        existing_author="",
        existing_security_platform=False,
        existing_threat_actor_individual=False,
    ):
        self.stix2 = FakeStix2()
        self.existing_description = existing_description
        self.existing_author = existing_author
        self.existing_security_platform = existing_security_platform
        self.existing_threat_actor_individual = existing_threat_actor_individual
        self.patches = []
        self.security_platform_adds = []
        self.threat_actor_individual_adds = []
        self.indicator_adds = []
        self.label_adds = []
        self.labels_by_value = {}
        self.report_object_refs = []

    def query(self, query, variables=None):
        variables = variables or {}
        if "labels(" in query:
            value = variables["filters"]["filters"][0]["values"][0]
            node = self.labels_by_value.get(value)
            edges = [{"node": node}] if node else []
            return {"data": {"labels": {"edges": edges}}}
        if "labelAdd" in query:
            input_payload = dict(variables.get("input") or {})
            value = input_payload.get("value")
            self.label_adds.append(input_payload)
            node = {
                "id": "label--" + value.lower().replace(":", "-"),
                "standard_id": "label--standard-" + value.lower().replace(":", "-"),
                "entity_type": "Label",
                "value": value,
                "color": None,
            }
            self.labels_by_value[value] = node
            return {"data": {"labelAdd": node}}
        if "identities" in query:
            return {
                "data": {
                    "identities": {
                        "edges": [
                            {
                                "node": {
                                    "id": "identity--misp-via-narrowcti",
                                    "standard_id": (
                                        "identity--77777777-7777-4777-8777-"
                                        "777777777777"
                                    ),
                                    "entity_type": "Organization",
                                    "name": variables["filters"]["filters"][0][
                                        "values"
                                    ][0],
                                }
                            }
                        ]
                    }
                }
            }
        if "indicators" in query:
            return {"data": {"indicators": {"edges": []}}}
        if "indicatorAdd" in query:
            self.indicator_adds.append(dict(variables.get("input") or {}))
            return {
                "data": {
                    "indicatorAdd": {
                        "id": "indicator--native",
                        "standard_id": (
                            "indicator--66666666-6666-4666-8666-666666666666"
                        ),
                        "entity_type": "Indicator",
                        "name": variables.get("input", {}).get("name"),
                        "pattern_type": variables.get("input", {}).get(
                            "pattern_type"
                        ),
                    }
                }
            }
        if "threatActorsIndividuals" in query:
            edges = []
            if self.existing_threat_actor_individual:
                edges.append(
                    {
                        "node": {
                            "id": "threat-actor-individual--internal",
                            "standard_id": (
                                "threat-actor--55555555-5555-4555-8555-"
                                "555555555555"
                            ),
                            "entity_type": "Threat-Actor-Individual",
                            "name": variables["filters"]["filters"][0]["values"][0],
                            "aliases": ["Individual Actor Alias"],
                            "threat_actor_types": ["crime-syndicate"],
                        }
                    }
                )
            return {"data": {"threatActorsIndividuals": {"edges": edges}}}
        if "threatActorIndividualAdd" in query:
            self.threat_actor_individual_adds.append(
                dict(variables.get("input") or {})
            )
            return {
                "data": {
                    "threatActorIndividualAdd": {
                        "id": "threat-actor-individual--internal",
                        "standard_id": (
                            "threat-actor--55555555-5555-4555-8555-"
                            "555555555555"
                        ),
                        "entity_type": "Threat-Actor-Individual",
                        "name": variables.get("input", {}).get("name"),
                        "aliases": variables.get("input", {}).get("aliases"),
                        "threat_actor_types": variables.get("input", {}).get(
                            "threat_actor_types"
                        ),
                    }
                }
            }
        if "securityPlatforms" in query:
            edges = []
            if self.existing_security_platform:
                edges.append(
                    {
                        "node": {
                            "id": "security-platform--internal",
                            "standard_id": (
                                "identity--44444444-4444-4444-8444-444444444444"
                            ),
                            "entity_type": "SecurityPlatform",
                            "name": variables["filters"]["filters"][0]["values"][0],
                            "security_platform_type": "SIEM",
                        }
                    }
                )
            return {"data": {"securityPlatforms": {"edges": edges}}}
        if "securityPlatformAdd" in query:
            self.security_platform_adds.append(dict(variables.get("input") or {}))
            return {
                "data": {
                    "securityPlatformAdd": {
                        "id": "security-platform--internal",
                        "standard_id": (
                            "identity--44444444-4444-4444-8444-444444444444"
                        ),
                        "entity_type": "SecurityPlatform",
                        "name": variables.get("input", {}).get("name"),
                        "security_platform_type": variables.get("input", {}).get(
                            "security_platform_type"
                        ),
                    }
                }
            }
        if "reports" in query:
            filter_item = (variables.get("filters", {}).get("filters") or [{}])[0]
            key = filter_item.get("key")
            value = (filter_item.get("values") or ["Curated report"])[0]
            return {
                "data": {
                    "reports": {
                        "edges": [
                            {
                                "node": {
                                    "id": "report--internal",
                                    "standard_id": value
                                    if key == "standard_id"
                                    else "report--fake",
                                    "entity_type": "Report",
                                    "name": value if key == "name" else "Curated report",
                                }
                            }
                        ]
                    }
                }
            }
        if "reportEdit" in query and "relationAdd" in query:
            self.report_object_refs.append(
                {
                    "id": variables.get("id"),
                    "input": variables.get("input"),
                }
            )
            return {
                "data": {
                    "reportEdit": {
                        "relationAdd": {
                            "id": "object--internal",
                            "entity_type": "object",
                            "relationship_type": variables.get("input", {}).get(
                                "relationship_type"
                            ),
                        }
                    }
                }
            }
        if "stixDomainObjectEdit" in query:
            self.patches.append(
                {
                    "id": variables.get("id"),
                    "input": variables.get("input"),
                }
            )
            return {"data": {"stixDomainObjectEdit": {"fieldPatch": {}}}}
        return {
            "data": {
                "stixDomainObject": {
                    "id": variables.get("id"),
                    "createdBy": {"name": self.existing_author},
                    "description": self.existing_description,
                }
            }
        }


class FakeStix2:
    def __init__(self):
        self.imports = []
        self.failed = []

    def import_bundle_from_json(self, bundle_json, update=True):
        self.imports.append({"bundle": json.loads(bundle_json), "update": update})
        return [], self.failed


def imported_objects(api_client):
    return api_client.stix2.imports[-1]["bundle"]["objects"]


def object_types(objects):
    return sorted(item["type"] for item in objects)


def has_sector_identity(objects, name):
    return any(
        item["type"] == "identity"
        and item.get("identity_class") == "class"
        and item.get("name") == name
        for item in objects
    )


def first_object(objects, object_type):
    for item in objects:
        if item["type"] == object_type:
            return item
    raise AssertionError(f"missing object type: {object_type}")


def first_relationship(objects, relationship_type):
    for item in objects:
        if (
            item["type"] == "relationship"
            and item["relationship_type"] == relationship_type
        ):
            return item
    raise AssertionError(f"missing relationship type: {relationship_type}")


def target_sector_candidate():
    return {
        "fingerprint": "sector-crypto",
        "entity_type": "target_sector",
        "value": "Crypto",
        "name": "Crypto",
        "stix_object_type": "identity",
        "relationship_type": "targets",
        "source_key": "alienvault:otx",
        "source_name": "otx",
        "source_field": "industries",
        "confidence": 70,
        "relationship_confidence": 70,
    }


def security_platform_candidate():
    return {
        "fingerprint": "security-platform-siem",
        "entity_type": "security_platform",
        "value": "NarrowCTI SIEM Validation",
        "name": "NarrowCTI SIEM Validation",
        "stix_object_type": "security-platform",
        "relationship_type": "related-to",
        "source_key": "misp:misp",
        "source_name": "misp",
        "source_field": "security_platform",
        "confidence": 70,
        "relationship_confidence": 70,
        "attributes": {
            "description": "Source-backed detection platform validation.",
            "security_platform_type": "SIEM",
        },
    }


def sigma_detection_rule_candidate():
    return {
        "fingerprint": "detection-rule-sigma-powershell",
        "entity_type": "detection_rule",
        "value": "Suspicious PowerShell",
        "name": "Suspicious PowerShell",
        "stix_object_type": "indicator",
        "relationship_type": "detects",
        "source_key": "misp:misp",
        "source_name": "misp",
        "source_field": "Attribute[0]",
        "confidence": 70,
        "relationship_confidence": 70,
        "attributes": {
            "rule_type": "sigma",
            "pattern_type": "sigma",
            "pattern": (
                "title: Suspicious PowerShell\n"
                "logsource:\n"
                "  product: windows\n"
                "detection:\n"
                "  selection:\n"
                "    EventID: 1\n"
                "  condition: selection"
            ),
        },
    }


def incompatible_sigma_detection_rule_candidate():
    candidate = sigma_detection_rule_candidate()
    candidate["fingerprint"] = "detection-rule-sigma-broken"
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
        }
    )
    return candidate


def snort_detection_rule_candidate():
    return {
        "fingerprint": "detection-rule-snort-flash",
        "entity_type": "detection_rule",
        "value": "Adobe Flash Exploit",
        "name": "Adobe Flash Exploit",
        "stix_object_type": "indicator",
        "relationship_type": "detects",
        "source_key": "misp:misp",
        "source_name": "misp",
        "source_field": "Attribute[2]",
        "confidence": 70,
        "relationship_confidence": 70,
        "attributes": {
            "rule_type": "snort",
            "pattern_type": "snort",
            "pattern": 'alert tcp any any -> any any (msg:"Adobe Flash Exploit"; sid:1;)',
            "attribute_uuid": "attribute-snort-1",
        },
    }


def existing_target_sector_candidate(existing_ref, existing_id):
    candidate = target_sector_candidate()
    candidate["attributes"] = {
        "opencti_existing_ref": existing_ref,
        "opencti_existing_id": existing_id,
    }
    return candidate


def threat_actor_candidate():
    return {
        "fingerprint": "actor-example",
        "entity_type": "threat_actor",
        "value": "APT Example",
        "name": "APT Example",
        "stix_object_type": "threat-actor",
        "relationship_type": "related-to",
        "source_key": "alienvault:otx",
        "source_name": "otx",
        "source_field": "adversary",
        "confidence": 80,
        "relationship_confidence": 75,
    }


def threat_actor_individual_candidate():
    return {
        "fingerprint": "actor-individual-example",
        "entity_type": "threat_actor_individual",
        "value": "NarrowCTI Individual Actor Validation",
        "name": "NarrowCTI Individual Actor Validation",
        "stix_object_type": "threat-actor",
        "relationship_type": "attributed-to",
        "source_key": "misp:misp",
        "source_name": "misp-galaxy",
        "source_field": "Galaxy.threat-actor-individual",
        "confidence": 65,
        "relationship_confidence": 65,
        "attributes": {
            "description": "Source-backed individual actor validation.",
            "aliases": ["Individual Actor Alias"],
            "threat_actor_types": ["crime-syndicate"],
            "primary_motivation": "financial-gain",
            "threat_actor_class": "individual",
        },
    }


def existing_attack_pattern_candidate(existing_ref):
    return {
        "fingerprint": "attack-pattern-t1059",
        "entity_type": "attack_pattern",
        "value": "T1059",
        "name": "Command and Scripting Interpreter",
        "stix_object_type": "attack-pattern",
        "relationship_type": "uses",
        "source_key": "alienvault:otx",
        "source_name": "otx",
        "source_field": "attack_ids",
        "confidence": 80,
        "relationship_confidence": 75,
        "attributes": {
            "relationship_source_stix_object_type": "threat-actor",
            "relationship_source_value": "APT Example",
            "relationship_source_field": "adversary",
            "opencti_existing_ref": existing_ref,
        },
    }


if __name__ == "__main__":
    unittest.main()
