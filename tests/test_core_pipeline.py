import json
import os
import glob
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from connectors.otx.runtime import run_processor_loop
from connectors.otx.settings import load_settings
from core.decision_audit import DecisionAuditLog, DecisionRecord
from core.feed_contract import (
    FeedAdapter,
    FeedCandidate,
    FeedRunSummary,
    FeedSource,
)
from core.indicator_policy import (
    filter_indicators_by_type,
    normalize_allowed_indicator_types,
)
from core.policy import PolicyConfig, should_ingest
from core.retry import retry_delay
from core.scoring import calculate_score, calculate_score_details
from core.state_repository import (
    MISPEventStateRepository,
    ProcessedItemStateRepository,
    PulseStateRepository,
)
from core.tlp import extract_tlp_values, normalize_allowed_tlp, tlp_is_allowed
from exporters.stix_builder import build_report_bundle, indicator_pattern


class FeedContractTests(unittest.TestCase):
    def test_feed_source_builds_stable_key(self):
        source = FeedSource(
            name="OTX",
            source_type="external_import",
            provider="AlienVault",
        )

        self.assertEqual("alienvault:otx", source.key)

    def test_feed_candidate_normalizes_collections(self):
        source = FeedSource(name="MISP Feed", source_type="external_import")
        candidate = FeedCandidate(
            source=source,
            external_id="event-1",
            title="Suspicious infrastructure",
            indicators=[{"type": "domain", "indicator": "example.com"}],
            tags=["misp", "infrastructure"],
        )

        self.assertEqual("local:misp-feed", candidate.source.key)
        self.assertIsInstance(candidate.indicators, tuple)
        self.assertIsInstance(candidate.tags, tuple)
        self.assertEqual(1, len(candidate.indicators))

    def test_feed_run_summary_counts_handled_candidates(self):
        source = FeedSource(name="OTX", source_type="external_import")
        summary = FeedRunSummary(
            source=source,
            query="stealc",
            available=10,
            reviewed=5,
            ingested=2,
            dropped=2,
            quarantined=1,
        )

        self.assertEqual(5, summary.handled)

    def test_feed_adapter_protocol_accepts_matching_adapter(self):
        class DummyAdapter:
            source = FeedSource(name="Dummy", source_type="test")

            def search(self, query):
                return []

            def enrich(self, candidate):
                return candidate

        self.assertIsInstance(DummyAdapter(), FeedAdapter)


class PolicyTests(unittest.TestCase):
    def test_hard_filter_can_drop_old_pulses(self):
        pulse = {"created": "2020-01-01T00:00:00Z"}

        decision, reason = should_ingest(
            pulse,
            score=90,
            config=PolicyConfig(
                quarantine_score_threshold=50,
                enable_quarantine=True,
                min_score_to_ingest=60,
                max_days_old=1095,
                min_score_for_old_pulse=80,
                max_days_hard_filter=365,
            ),
        )

        self.assertFalse(decision)
        self.assertIn("older than hard filter", reason)

    def test_old_pulse_with_enough_score_can_pass_when_hard_filter_disabled(self):
        pulse = {"created": "2020-01-01T00:00:00Z"}

        decision, reason = should_ingest(
            pulse,
            score=85,
            config=PolicyConfig(
                quarantine_score_threshold=50,
                enable_quarantine=True,
                min_score_to_ingest=60,
                max_days_old=1095,
                min_score_for_old_pulse=80,
                max_days_hard_filter=0,
            ),
        )

        self.assertTrue(decision)
        self.assertEqual("ok", reason)


class TLPPolicyTests(unittest.TestCase):
    def test_extract_tlp_values_normalizes_tags(self):
        self.assertEqual(
            ("green", "amber"),
            extract_tlp_values(["TLP:GREEN", "tlp:amber", "ransomware"]),
        )

    def test_tlp_is_allowed_when_no_policy_or_no_tag(self):
        self.assertEqual((True, ""), tlp_is_allowed(["tlp:red"], []))
        self.assertEqual((True, ""), tlp_is_allowed(["ransomware"], ["green"]))

    def test_tlp_is_denied_when_candidate_tag_is_not_allowed(self):
        allowed, reason = tlp_is_allowed(["tlp:red"], ["white", "green"])

        self.assertFalse(allowed)
        self.assertEqual("tlp not allowed: red", reason)

    def test_normalize_allowed_tlp_accepts_prefixed_values(self):
        self.assertEqual(
            ("white", "green"),
            normalize_allowed_tlp(["tlp:white", "green"]),
        )

    def test_tlp_clear_and_legacy_white_are_policy_equivalents(self):
        self.assertEqual((True, ""), tlp_is_allowed(["tlp:clear"], ["white"]))
        self.assertEqual((True, ""), tlp_is_allowed(["tlp:white"], ["clear"]))
        self.assertEqual(("clear",), extract_tlp_values(["tlp:clear"]))


class IndicatorTypePolicyTests(unittest.TestCase):
    def test_normalize_allowed_indicator_types_accepts_aliases(self):
        self.assertEqual(
            ("ipv4", "domain", "filehash-sha256"),
            normalize_allowed_indicator_types(["ip", "domain-name", "sha256"]),
        )

    def test_filter_indicators_by_type_keeps_allowed_types(self):
        indicators = [
            {"type": "ip", "indicator": "8.8.8.8"},
            {"type": "email", "indicator": "user@example.com"},
            {"type": "sha256", "indicator": "abc"},
        ]

        filtered, dropped = filter_indicators_by_type(
            indicators,
            ["ipv4", "filehash-sha256"],
        )

        self.assertEqual(2, len(filtered))
        self.assertEqual(1, dropped)
        self.assertEqual(["ip", "sha256"], [item["type"] for item in filtered])

    def test_filter_indicators_by_type_is_noop_without_policy(self):
        indicators = [{"type": "unsupported", "indicator": "x"}]

        filtered, dropped = filter_indicators_by_type(indicators, [])

        self.assertEqual(indicators, filtered)
        self.assertEqual(0, dropped)


class ScoringTests(unittest.TestCase):
    def test_score_details_explain_adjustments(self):
        pulse = {
            "name": "LummaC2 fresh infrastructure",
            "tags": ["malware"],
            "created": "2099-01-01T00:00:00Z",
            "indicators": [
                {"type": "domain", "indicator": f"host-{index}.example"}
                for index in range(10)
            ],
        }

        details = calculate_score_details(pulse, "lummac2")

        self.assertEqual(40, details["base_score"])
        self.assertEqual(50, details["source_confidence"])
        self.assertEqual(95, details["final_score"])
        self.assertEqual(95, calculate_score(pulse, "lummac2"))
        self.assertIn(
            "query_name_exact",
            [adjustment["signal"] for adjustment in details["adjustments"]],
        )

    def test_source_confidence_can_weight_score(self):
        pulse = {"name": "unrelated", "tags": [], "indicators": []}

        low = calculate_score_details(pulse, "query", source_confidence=25)
        high = calculate_score_details(pulse, "query", source_confidence=75)

        self.assertEqual(35, low["final_score"])
        self.assertEqual(45, high["final_score"])


class StateRepositoryTests(unittest.TestCase):
    def test_retry_delay_adds_bounded_jitter(self):
        self.assertEqual(6, retry_delay(2, 3, 0))
        self.assertEqual(7, retry_delay(2, 3, 2, random_fn=lambda _low, _high: 1))

    def test_mark_pulse_is_idempotent_and_persistent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "state.json")
            repository = PulseStateRepository(state_file)

            repository.mark_pulse("pulse-1")
            repository.mark_pulse("pulse-1")

            with open(state_file, "r") as f:
                data = json.load(f)

            self.assertEqual(["pulse-1"], data["pulses"])
            self.assertTrue(PulseStateRepository(state_file).has_pulse("pulse-1"))

    def test_generic_state_repository_uses_independent_keys(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "state.json")
            pulse_repository = PulseStateRepository(state_file)
            misp_repository = MISPEventStateRepository(state_file)

            pulse_repository.mark_pulse("pulse-1")
            misp_repository.mark_event("event-1")
            misp_repository.mark_event("event-1")

            with open(state_file, "r") as f:
                data = json.load(f)

            self.assertEqual(["pulse-1"], data["pulses"])
            self.assertEqual(["event-1"], data["misp_events"])

            self.assertEqual(
                [],
                glob.glob(os.path.join(tmpdir, ".state.json.*.tmp")),
            )
            self.assertTrue(MISPEventStateRepository(state_file).has_event("event-1"))
            self.assertFalse(MISPEventStateRepository(state_file).has_event("pulse-1"))

    def test_processed_item_repository_preserves_existing_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "state.json")
            with open(state_file, "w") as f:
                json.dump({"pulses": ["pulse-1"]}, f)

            repository = ProcessedItemStateRepository(state_file, "misp_events")
            repository.mark_item("event-1")

            with open(state_file, "r") as f:
                data = json.load(f)

            self.assertEqual(["pulse-1"], data["pulses"])
            self.assertEqual(["event-1"], data["misp_events"])


class DecisionAuditTests(unittest.TestCase):
    def test_decision_record_serializes_core_fields(self):
        record = DecisionRecord(
            action="drop",
            reason="below minimum score",
            source_key="alienvault:otx",
            external_id="pulse-1",
            title="Suspicious infrastructure",
            query="stealc",
            score=55,
            age_days=12,
            indicator_count=4,
            recorded_at="2026-05-01T00:00:00Z",
            metadata={"policy": "default"},
        )

        data = record.to_dict()

        self.assertEqual("drop", data["action"])
        self.assertEqual("alienvault:otx", data["source_key"])
        self.assertEqual({"policy": "default"}, data["metadata"])

    def test_decision_audit_log_writes_jsonl_when_configured(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_file = os.path.join(tmpdir, "decisions.jsonl")
            record = DecisionRecord(
                action="ingest",
                reason="ok",
                source_key="alienvault:otx",
                external_id="pulse-1",
                title="Fresh pulse",
                recorded_at="2026-05-01T00:00:00Z",
            )

            DecisionAuditLog(audit_file).record(record)

            with open(audit_file, "r", encoding="utf-8") as f:
                data = json.loads(f.readline())

            self.assertEqual("ingest", data["action"])
            self.assertEqual("Fresh pulse", data["title"])

    def test_decision_audit_log_is_noop_without_file(self):
        record = DecisionRecord(
            action="skip",
            reason="already processed",
            source_key="alienvault:otx",
            external_id="pulse-1",
            title="Existing pulse",
        )

        self.assertIs(record, DecisionAuditLog().record(record))


class SettingsTests(unittest.TestCase):
    def test_load_settings_normalizes_search_limit(self):
        env = {
            "OPENCTI_URL": "http://opencti:8080",
            "OPENCTI_TOKEN": "token",
            "OTX_API_KEY": "key",
            "OTX_QUERIES": "lummac2, stealc",
            "MAX_PULSES_PER_QUERY": "5",
            "MAX_SEARCH_RESULTS_PER_QUERY": "2",
            "INGEST_PAUSE_SECONDS": "4",
            "DECISION_AUDIT_FILE": "/app/state/decisions.jsonl",
            "NARROWCTI_DRY_RUN": "true",
            "OTX_SOURCE_CONFIDENCE": "70",
            "NARROWCTI_ALLOWED_TLP": "white, green",
            "NARROWCTI_ALLOWED_INDICATOR_TYPES": "domain, ipv4",
            "NARROWCTI_MIN_ENTITY_CONFIDENCE": "55",
            "NARROWCTI_MIN_RELATIONSHIP_CONFIDENCE": "65",
            "NARROWCTI_REQUIRE_RELATIONSHIP_PROVENANCE": "true",
            "NARROWCTI_ALLOWED_GRAPH_ENTITY_TYPES": "attack_pattern, malware",
            "NARROWCTI_ALLOWED_GRAPH_STIX_OBJECT_TYPES": "attack-pattern, malware",
            "NARROWCTI_GRAPH_EXPORT_MODE": "dry_run",
            "NARROWCTI_GRAPH_DEDUP_STATE_FILE": "/app/state/graph_dedup.json",
            "NARROWCTI_OPENCTI_GRAPH_LOOKUP": "true",
            "NARROWCTI_CONTEXTUAL_SCORING_MODE": "enforce",
            "NARROWCTI_CONTEXTUAL_SCORING_MAX_IMPACT": "80",
            "NARROWCTI_CONTEXTUAL_SCORING_IMPACTS": "threat:25,ttp:10",
            "NARROWCTI_ENABLE_OTX_ENTITY_EXTRACTION": "false",
            "NARROWCTI_ENABLE_MITRE_ATTACK_RESOLUTION": "false",
            "NARROWCTI_MITRE_CACHE_FILE": "/app/state/mitre_attack_cache.json",
            "NARROWCTI_MITRE_STIX_URL": "https://example.com/enterprise.json",
        }

        with patch.dict(os.environ, env, clear=True):
            settings = load_settings()

        self.assertEqual(["lummac2", "stealc"], settings.otx_queries)
        self.assertEqual("NarrowCTI Gateway", settings.connector_name)
        self.assertEqual(5, settings.max_pulses_per_query)
        self.assertEqual(5, settings.max_search_results_per_query)
        self.assertEqual(3, settings.otx_retries)
        self.assertEqual(4, settings.ingest_pause_seconds)
        self.assertEqual("/app/state/decisions.jsonl", settings.decision_audit_file)
        self.assertTrue(settings.dry_run)
        self.assertEqual(70, settings.source_confidence)
        self.assertEqual(["white", "green"], settings.allowed_tlp)
        self.assertEqual(["domain", "ipv4"], settings.allowed_indicator_types)
        self.assertEqual(55, settings.graph_min_entity_confidence)
        self.assertEqual(65, settings.graph_min_relationship_confidence)
        self.assertTrue(settings.graph_require_relationship_provenance)
        self.assertEqual(
            ["attack_pattern", "malware"],
            settings.graph_allowed_entity_types,
        )
        self.assertEqual(
            ["attack-pattern", "malware"],
            settings.graph_allowed_stix_object_types,
        )
        self.assertEqual("dry-run", settings.graph_export_mode)
        self.assertEqual(
            "/app/state/graph_dedup.json",
            settings.graph_dedup_state_file,
        )
        self.assertTrue(settings.opencti_graph_lookup)
        self.assertEqual("enforce", settings.contextual_scoring_mode)
        self.assertEqual(80, settings.contextual_scoring_max_impact)
        self.assertEqual(
            {"threat": 25, "ttp": 10},
            settings.contextual_scoring_impacts,
        )
        self.assertFalse(settings.enable_otx_entity_extraction)
        self.assertFalse(settings.enable_mitre_attack_resolution)
        self.assertEqual(
            "/app/state/mitre_attack_cache.json",
            settings.mitre_cache_file,
        )
        self.assertEqual(
            "https://example.com/enterprise.json",
            settings.mitre_stix_url,
        )

    def test_load_settings_accepts_gateway_policy_fallbacks(self):
        env = {
            "OPENCTI_URL": "http://opencti:8080",
            "OPENCTI_TOKEN": "token",
            "OTX_API_KEY": "key",
            "OTX_QUERIES": "lummac2",
            "NARROWCTI_MIN_SCORE_TO_INGEST": "75",
            "NARROWCTI_MAX_DAYS_OLD": "365",
            "NARROWCTI_ENABLE_QUARANTINE": "false",
            "NARROWCTI_QUARANTINE_SCORE_THRESHOLD": "55",
        }

        with patch.dict(os.environ, env, clear=True):
            settings = load_settings()

        self.assertEqual(75, settings.min_score_to_ingest)
        self.assertEqual(365, settings.max_days_old)
        self.assertFalse(settings.enable_quarantine)
        self.assertEqual(55, settings.quarantine_score_threshold)

    def test_load_settings_legacy_policy_names_override_gateway_defaults(self):
        env = {
            "OPENCTI_URL": "http://opencti:8080",
            "OPENCTI_TOKEN": "token",
            "OTX_API_KEY": "key",
            "OTX_QUERIES": "lummac2",
            "NARROWCTI_MIN_SCORE_TO_INGEST": "75",
            "NARROWCTI_ENABLE_QUARANTINE": "false",
            "MIN_SCORE_TO_INGEST": "65",
            "ENABLE_QUARANTINE": "true",
        }

        with patch.dict(os.environ, env, clear=True):
            settings = load_settings()

        self.assertEqual(65, settings.min_score_to_ingest)
        self.assertTrue(settings.enable_quarantine)

    def test_load_settings_rejects_invalid_otx_retry_configuration(self):
        env = {
            "OPENCTI_URL": "http://opencti:8080",
            "OPENCTI_TOKEN": "token",
            "OTX_API_KEY": "key",
            "OTX_QUERIES": "lummac2",
            "OTX_RETRIES": "0",
        }

        with patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(ValueError, "otx_retries"):
                load_settings()


class RuntimeTests(unittest.TestCase):
    def test_run_processor_loop_runs_cycle_and_sleeps(self):
        calls = []
        processor = SimpleNamespace(run_once=lambda: calls.append("run_once"))
        settings = SimpleNamespace(connector_run_interval=15)

        def sleeper(seconds):
            calls.append(("sleep", seconds))
            raise StopIteration

        with self.assertRaises(StopIteration):
            run_processor_loop(processor, settings, calls.append, sleeper=sleeper)

        self.assertEqual(["run_once", "Sleeping 15s", ("sleep", 15)], calls)


class StixBuilderTests(unittest.TestCase):
    def test_indicator_pattern_maps_supported_ioc_types(self):
        self.assertEqual(
            "[domain-name:value = 'example.com']",
            indicator_pattern({"type": "domain", "indicator": "example.com"}),
        )
        self.assertEqual(
            "[file:hashes.SHA256 = 'abc']",
            indicator_pattern({"type": "FileHash-SHA256", "indicator": "abc"}),
        )
        self.assertIsNone(indicator_pattern({"type": "unknown", "indicator": "value"}))

    def test_build_report_bundle_deduplicates_indicators(self):
        bundle, indicator_count = build_report_bundle(
            "Example report",
            "description",
            80,
            [
                {"type": "domain", "indicator": "example.com"},
                {"type": "domain", "indicator": "example.com"},
                {"type": "IPv4", "indicator": "8.8.8.8"},
                {"type": "unsupported", "indicator": "ignored"},
            ],
        )

        data = json.loads(bundle.serialize())
        identities = [item for item in data["objects"] if item["type"] == "identity"]
        indicator_objects = [
            item for item in data["objects"] if item["type"] == "indicator"
        ]
        reports = [item for item in data["objects"] if item["type"] == "report"]

        self.assertEqual("NarrowCTI Gateway", identities[0]["name"])
        self.assertEqual(2, indicator_count)
        self.assertEqual(2, len(indicator_objects))
        self.assertEqual(2, len(reports[0]["object_refs"]))

    def test_build_report_bundle_preserves_source_publication_date(self):
        bundle, indicator_count = build_report_bundle(
            "Historical MISP event",
            "Imported source event",
            80,
            [{"type": "domain", "indicator": "example.com"}],
            published_at="2017-02-18",
        )

        data = json.loads(bundle.serialize())
        report = next(item for item in data["objects"] if item["type"] == "report")
        indicator = next(
            item for item in data["objects"] if item["type"] == "indicator"
        )

        self.assertEqual(1, indicator_count)
        self.assertTrue(report["published"].startswith("2017-02-18T00:00:00"))
        self.assertEqual("2017-02-18", report["x_narrowcti_source_date"])
        self.assertTrue(indicator["valid_from"].startswith("2017-02-18T00:00:00"))

    def test_build_report_bundle_uses_custom_identity_name(self):
        bundle, _ = build_report_bundle(
            "Example report",
            "description",
            80,
            identity_name="Custom Connector",
        )

        data = json.loads(bundle.serialize())
        identities = [item for item in data["objects"] if item["type"] == "identity"]

        self.assertEqual("Custom Connector", identities[0]["name"])

    def test_build_report_bundle_uses_stable_identity_id(self):
        first_bundle, _ = build_report_bundle(
            "Example report",
            "description",
            80,
            identity_name="OTX AlienVault",
        )
        second_bundle, _ = build_report_bundle(
            "Another report",
            "other description",
            80,
            identity_name="OTX AlienVault",
        )

        first_data = json.loads(first_bundle.serialize())
        second_data = json.loads(second_bundle.serialize())
        first_identity = [
            item for item in first_data["objects"] if item["type"] == "identity"
        ][0]
        second_identity = [
            item for item in second_data["objects"] if item["type"] == "identity"
        ][0]

        self.assertEqual(first_identity["id"], second_identity["id"])


if __name__ == "__main__":
    unittest.main()
