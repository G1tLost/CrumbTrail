"""Oracle comparisons fail closed without storing real EVTX or identifying rows."""
import copy
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("evtx_acceptance", Path(__file__).resolve().parents[1] / "scripts" / "validate_evtx.py")
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


class AcceptanceTests(unittest.TestCase):
    def rows(self):
        oracle = dict(channel="Security", event_code=4624, record_id=1, hostname="test.invalid",
                      provider="Microsoft-Windows-Security-Auditing", event_data={"TargetLogonId": "0x42"},
                      timestamp_source="2026-01-01T00:00:00.8943413Z")
        actual = {**oracle, "timestamp_utc": "2026-01-01T00:00:00.894341Z",
                  "source_logon_ids": [{"field": "TargetLogonId", "value": "66"}],
                  "references": [{"row": 1, "sha256": "0" * 64}]}
        return oracle, actual

    def test_precise_source_and_microsecond_value_are_measured(self):
        first, second = self.rows()
        result = acceptance.compare_records([first], [second])
        self.assertEqual(result["mismatch_count"], 0)
        self.assertEqual(result["maximum_absolute_timestamp_delta_ns"], 300)
        self.assertEqual(result["exact_at_microsecond_count"], 1)

    def test_whole_second_loss_fails_precision_gate(self):
        first, second = self.rows()
        second["timestamp_utc"] = "2026-01-01T00:00:00Z"
        result = acceptance.compare_records([first], [second])
        self.assertTrue(result["row_facts_passed"])
        self.assertFalse(result["timestamp_precision_passed"])
        self.assertEqual(result["maximum_absolute_timestamp_delta_ns"], 894341300)

    def test_upstream_quantization_above_one_microsecond_stays_failed(self):
        first, second = self.rows()
        first["timestamp_source"] = "2026-01-01T00:00:00.1120297Z"
        second["timestamp_utc"] = "2026-01-01T00:00:00.112031Z"
        result = acceptance.compare_records([first], [second])
        self.assertEqual(result["timestamp_mismatch_count"], 1)
        self.assertEqual(result["maximum_absolute_timestamp_delta_ns"], 1300)
        self.assertTrue(result["row_facts_passed"])

    def test_subject_and_target_identity_are_not_interchangeable(self):
        first, second = self.rows()
        second["source_logon_ids"][0]["field"] = "SubjectLogonId"
        result = acceptance.compare_records([first], [second])
        self.assertFalse(result["row_facts_passed"])
        self.assertEqual(result["mismatches"][0]["reason"], "source_logon_ids")

    def test_missing_and_unexpected_records_are_reported(self):
        first, second = self.rows()
        second["record_id"] = 2
        result = acceptance.compare_records([first], [second])
        self.assertEqual({item["reason"] for item in result["mismatches"]}, {"missing", "unexpected"})

    def test_duplicate_record_identity_is_not_collapsed(self):
        first, second = self.rows()
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            acceptance.compare_records([first, copy.deepcopy(first)], [second])

    def test_missing_provenance_and_conflicting_provider_fail(self):
        first, second = self.rows()
        second["references"] = []
        second["provider"] = "untrusted"
        result = acceptance.compare_records([first], [second])
        self.assertEqual({item["reason"] for item in result["mismatches"]}, {"provider", "missing_provenance"})

    def test_precise_offsets_are_equivalent_and_timezone_required(self):
        self.assertEqual(acceptance.utc_nanoseconds("2026-01-01T00:00:00.1234567Z"),
                         acceptance.utc_nanoseconds("2025-12-31T19:00:00.1234567-05:00"))
        with self.assertRaises(ValueError):
            acceptance.utc_nanoseconds("2026-01-01T00:00:00.1234567")

    @unittest.skipUnless(os.name == "nt", "Native helper guard is Windows-only")
    def test_native_helper_rejects_output_alias_and_existing_destination_before_read(self):
        helper = Path(__file__).resolve().parents[1] / "scripts" / "read_evtx_oracle.ps1"
        with tempfile.TemporaryDirectory() as folder:
            source, target = Path(folder) / "inert.evtx", Path(folder) / "existing.json"
            source.write_bytes(b"inert input, never parsed")
            target.write_bytes(b"original output")
            for destination in (source, target):
                result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(helper),
                    "-InputFile", str(source), "-OutputFile", str(destination)], capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Output must be a new file", result.stderr)
            self.assertEqual(source.read_bytes(), b"inert input, never parsed")
            self.assertEqual(target.read_bytes(), b"original output")


if __name__ == "__main__":
    unittest.main()
