import copy
import json
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from crumbtrail.events import analyze
from crumbtrail.native import data_path
from crumbtrail.native import run_local
from crumbtrail.precision import (FIELD_PATH, PARSER_VERSION, build_precision, exact_substitution,
    file_hash, native_identity, parse_source, require_parser, source_identity, validate_precision)
from crumbtrail.storage import Case, CaseError, digest, encode, iso_ticks, records, ticks

CLIENT = "C.0123456789abcdef"


class PrecisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.row = copy.deepcopy(records(data_path("windows.jsonl").read_bytes())[0])
        self.row["OSPath"] = "C:\\PrivateLab\\Security.evtx"
        self.exact = ticks("2026-10-30T20:27:00.1234567Z")
        self.row["System"]["TimeCreated"] = {"SystemTime": (float(self.exact) - 116444736000000000) / 10000000}
        self.raw = encode([self.row])
        self.document = {"schema": 1, "parser": {"name": "python-evtx", "version": PARSER_VERSION},
            "raw_sha256": digest(self.raw),
            "sources": [{"path": "C:/PrivateLab/Security.evtx", "sha256": "a" * 64, "bytes": 69632}],
            "rows": [{"row": 1, "row_sha256": digest(encode(self.row)), "identity": native_identity(self.row),
                "source_path": "c:/privatelab/security.evtx", "source_sha256": "a" * 64,
                "chunk_offset": 4096, "record_offset": 4608, "record_length": 1024, "record_sha256": "b" * 64,
                "field_path": FIELD_PATH, "field_offset": 4672,
                "filetime_ticks": str(self.exact), "filetime_bytes": struct.pack("<Q", self.exact).hex(),
                "timestamp_utc": iso_ticks(self.exact), "record_header_filetime": str(self.exact + 10000000),
                "record_header_id": "999"}]}

    def case(self, start="2026-10-30T20:00:00Z", end="2026-10-30T22:00:00Z"):
        case = Case.create(self.folder / "case", start, end)
        case.bind(CLIENT, "LAB-WIN01")
        return case

    def preserve(self, case):
        return case.preserve(self.raw, CLIENT, "test-exact-export", True, precision=self.document)

    def test_exact_ticks_roundtrip_and_equivalent_offset(self):
        self.assertEqual(iso_ticks(self.exact), "2026-10-30T20:27:00.1234567Z")
        self.assertEqual(ticks("2026-10-30T16:27:00.1234567-04:00"), self.exact)
        self.assertEqual(ticks("2026-10-30T20:27:00.1234568Z") - self.exact, 1)

    def test_legacy_whole_minute_case_creation_remains_supported(self):
        case = self.case("2026-10-30T12:00Z", "2026-10-30T08:00-04:00")
        self.assertEqual(case.meta["start"], "2026-10-30T12:00:00Z")
        self.assertEqual(case.meta["end"], case.meta["start"])

    def test_excess_precision_and_fractional_offsets_are_rejected(self):
        for value in ("2026-10-30T20:27:00.12345678Z", "2026-10-30T20:27:00+00:00:00.0000001", "2026-10-30T20:27.1234567Z"):
            with self.subTest(value=value), self.assertRaises(CaseError):
                ticks(value)

    def test_inclusive_single_tick_case_and_adjacent_exclusion(self):
        case = self.case(iso_ticks(self.exact), iso_ticks(self.exact))
        self.preserve(case)
        self.assertEqual(analyze(case)["summary"]["events"], 1)
        self.assertEqual(case.meta["start"], "2026-10-30T20:27:00.1234567Z")
        case.meta["start"] = iso_ticks(self.exact + 1)
        case.meta["end"] = iso_ticks(self.exact + 1)
        self.assertEqual(analyze(case)["summary"]["events"], 0)

    def test_windows_source_identity_portable_without_external_source_reads(self):
        case = self.case()
        entry = self.preserve(case)
        with patch("crumbtrail.precision.file_hash", side_effect=AssertionError("external read")), \
             patch("crumbtrail.precision.parse_source", side_effect=AssertionError("parser dependency")):
            self.assertEqual(case.verify(), 1)
            event = analyze(case)["events"][0]
        self.assertEqual((case.root / entry["path"]).read_bytes(), self.raw)
        self.assertEqual(event["timestamp_utc"], iso_ticks(self.exact))
        self.assertEqual(event["timestamp_original"], self.row["System"]["TimeCreated"]["SystemTime"])
        reference = event["references"][0]["exact_time"]
        self.assertEqual(reference["filetime_ticks"], str(self.exact))
        self.assertNotEqual(reference["record_header_filetime"], reference["filetime_ticks"])
        self.assertNotEqual(reference["record_header_id"], str(event["record_id"]))

    def test_source_path_lexical_case_and_separator_binding(self):
        self.assertEqual(source_identity("C:\\PrivateLab\\Security.evtx"), source_identity("c:/privatelab/security.evtx"))
        for value in ("Security.evtx", "C:/PrivateLab/../Security.evtx", None):
            with self.assertRaises(CaseError):
                source_identity(value)

    def test_missing_sidecar_stops_verification(self):
        case = self.case()
        entry = self.preserve(case)
        (case.root / entry["provenance"]["details"]["precision"]["path"]).unlink()
        with self.assertRaisesRegex(CaseError, "sidecar size"):
            case.verify()

    def test_changed_sidecar_stops_analysis(self):
        case = self.case()
        entry = self.preserve(case)
        path = case.root / entry["provenance"]["details"]["precision"]["path"]
        raw = path.read_bytes()
        path.write_bytes(raw.replace(b'"schema":1', b'"schema":2'))
        with self.assertRaisesRegex(CaseError, "SHA-256"):
            analyze(case)

    def test_orphan_precision_bytes_are_not_silently_ignored(self):
        case = self.case()
        (case.root / "precision").mkdir()
        (case.root / "precision" / "orphan.json").write_text("{}")
        with self.assertRaisesRegex(CaseError, "Unregistered exact-time"):
            case.verify()

    def test_missing_ambiguous_and_wrong_source_sidecars_rejected(self):
        variants = []
        for rows in ([], self.document["rows"] * 2):
            doc = copy.deepcopy(self.document); doc["rows"] = rows; variants.append(doc)
        for field, value in (("source_path", "C:/Other/Security.evtx"), ("row_sha256", "0" * 64),
                             ("field_path", "record-header/FileTime"), ("filetime_bytes", "00" * 8),
                             ("record_offset", True), ("record_sha256", "z" * 64), ("timestamp_utc", "2026-01-01T00:00:00Z")):
            doc = copy.deepcopy(self.document); doc["rows"][0][field] = value; variants.append(doc)
        for doc in variants:
            with self.subTest(document=variants.index(doc)), self.assertRaises(CaseError):
                validate_precision(doc, [self.row], digest(self.raw))

    def test_changed_native_float_does_not_join_by_time_tolerance(self):
        row = copy.deepcopy(self.row)
        row["System"]["TimeCreated"]["SystemTime"] += 0.00001
        doc = copy.deepcopy(self.document)
        doc["rows"][0]["row_sha256"] = digest(encode(row))
        with self.assertRaisesRegex(CaseError, "conversion"):
            validate_precision(doc, [row], digest(self.raw))

    def test_duplicate_native_identity_and_missing_parser_match_fail(self):
        with self.assertRaisesRegex(CaseError, "duplicate native"):
            build_precision(encode([self.row, self.row]), self.document["sources"])
        with patch("crumbtrail.precision.parse_source", return_value={}):
            with self.assertRaisesRegex(CaseError, "no exact matching"):
                build_precision(self.raw, self.document["sources"])

    def test_unsupported_installed_parser_has_actionable_error(self):
        with patch("crumbtrail.precision.version", return_value="0.0.0"):
            with self.assertRaisesRegex(CaseError, r"crumbtrail-ir\[evtx\]"):
                require_parser()

    def fake_tree(self, duplicates=False):
        class Element:
            def __init__(self, name, children): self.name, self.items = name, children
            def tag_name(self): return self.name
            def children(self): return self.items
        class Substitution:
            def index(self): return 0
            def type(self): return 0x11
        class Attribute:
            def attribute_name(self): return SimpleNamespace(string=lambda: "SystemTime")
            def attribute_value(self): return Substitution()
        class Filetime:
            def length(self): return 8
            def offset(self): return 4672
            def unpack_qword(node, offset): return self.exact
        timestamp_element = Element("TimeCreated", [Attribute()])
        system = Element("System", [timestamp_element] * (2 if duplicates else 1))
        root = SimpleNamespace(template=lambda: SimpleNamespace(children=lambda: [Element("Event", [system])]),
                               substitutions=lambda: [Filetime()])
        record = SimpleNamespace(root=lambda: root, offset=lambda: 4608, size=lambda: 1024,
                                 unpack_qword=lambda offset: self.exact + 1234567)
        nodes = SimpleNamespace(OpenStartElementNode=Element, AttributeNode=Attribute,
            NormalSubstitutionNode=Substitution, ConditionalSubstitutionNode=Substitution, FiletimeTypeNode=Filetime)
        return record, nodes

    def test_binxml_field_selection_never_uses_record_header_time(self):
        record, nodes = self.fake_tree()
        self.assertEqual(exact_substitution(record, nodes)[3:], (self.exact, 4672))
        self.assertNotEqual(record.unpack_qword(16), self.exact)

    def test_duplicate_systemtime_nodes_are_ambiguous(self):
        with self.assertRaisesRegex(CaseError, "one explicit"):
            exact_substitution(*self.fake_tree(duplicates=True))

    def malformed_source(self, suffix):
        header = bytearray(4096)
        header[:8] = b"ElfFile\x00"
        struct.pack_into("<IHHHH", header, 32, 128, 1, 3, 4096, 0)
        struct.pack_into("<I", header, 124, zlib.crc32(header[:120]) & 0xffffffff)
        path = self.folder / "inert.evtx"
        path.write_bytes(header + suffix)
        return {"path": str(path), "bytes": path.stat().st_size, "sha256": file_hash(path)}

    def test_nonzero_malformed_chunk_fails_without_source_write(self):
        require_parser()
        source = self.malformed_source(b"invalid!" + bytes(65528))
        with self.assertRaisesRegex(CaseError, "chunk checksum"):
            parse_source(source, set())
        self.assertEqual(file_hash(source["path"]), source["sha256"])

    def test_nonzero_incomplete_trailer_fails_without_source_write(self):
        require_parser()
        source = self.malformed_source(b"nonzero incomplete chunk")
        with self.assertRaisesRegex(CaseError, "trailing chunk"):
            parse_source(source, set())
        self.assertEqual(file_hash(source["path"]), source["sha256"])

    def test_source_growth_exceeds_hash_budget_before_native_invocation(self):
        case = self.case()
        log_dir = self.folder / "logs"; log_dir.mkdir()
        # Exercise an alias spelling on every platform, like Windows short TMP paths.
        source = log_dir / ".." / "logs" / "Security.evtx"; source.write_bytes(b"a" * 32)
        resolved_source = source.resolve()
        self.assertNotEqual(source, resolved_source)
        executable = self.folder / "inert.exe"; executable.write_bytes(b"inert")
        original_open = Path.open
        injected_readers = []
        class GrowingReader:
            def __init__(self, stream): self.stream, self.grown = stream, False
            def __enter__(self): return self
            def __exit__(self, *args): self.stream.close()
            def fileno(self): return self.stream.fileno()
            def read(self, size):
                if not self.grown:
                    self.grown = True
                    with original_open(source, "ab") as writer: writer.write(b"b" * 64)
                return self.stream.read(size)
        def opening(path, mode="r", *args, **kwargs):
            stream = original_open(path, mode, *args, **kwargs)
            if mode == "rb" and path.resolve() == resolved_source:
                reader = GrowingReader(stream)
                injected_readers.append(reader)
                return reader
            return stream
        with patch("crumbtrail.precision.MAX_BYTES", 64), patch("crumbtrail.precision.require_parser"), \
             patch.object(Path, "open", opening), patch("crumbtrail.native.subprocess.run") as native:
            with self.assertRaisesRegex(CaseError, "byte budget"):
                run_local(case, CLIENT, executable, log_directory=log_dir)
            native.assert_not_called()
        self.assertEqual(len(injected_readers), 1)
        self.assertTrue(injected_readers[0].grown)
        self.assertEqual(source.stat().st_size, 96)
        self.assertFalse((case.root / "collection").exists())

    def test_nonregular_evtx_input_rejected_before_native_invocation(self):
        case = self.case()
        log_dir = self.folder / "logs"; log_dir.mkdir()
        (log_dir / "Security.evtx").mkdir()
        executable = self.folder / "inert.exe"; executable.write_bytes(b"inert")
        with patch("crumbtrail.precision.require_parser"), patch("crumbtrail.native.subprocess.run") as native:
            with self.assertRaisesRegex(CaseError, "regular files"):
                run_local(case, CLIENT, executable, log_directory=log_dir)
            native.assert_not_called()


if __name__ == "__main__":
    unittest.main()
