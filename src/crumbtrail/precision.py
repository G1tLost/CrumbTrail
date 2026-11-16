"""Exact EVTX SystemTime recovery; optional parser is confined to a bounded worker.

Read the actual BinXML attribute substitution, never the record-header time.
The evidence sidecar is usable without the optional parser after collection.
"""
import hashlib
import json
import os
import re
import stat
import struct
import sys
from importlib.metadata import version
from pathlib import Path, PurePosixPath, PureWindowsPath
from xml.etree import ElementTree

from .storage import CaseError, MAX_BYTES, MAX_ROWS, digest, encode, iso_ticks, records, row_type, ticks

PARSER_VERSION = "0.8.1"
FIELD_PATH = "Event/System/TimeCreated/@SystemTime"
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def require_parser():
    try:
        if version("python-evtx") != PARSER_VERSION:
            raise ImportError("Unsupported parser version")
        from Evtx.Evtx import Evtx
        from Evtx import Nodes, Views
        return Evtx, Nodes, Views
    except (ImportError, ModuleNotFoundError) as exc:
        raise CaseError('Exact local EVTX parsing requires: python -m pip install "crumbtrail-ir[evtx]" (python-evtx==0.8.1).') from exc


def file_hash(path, expected_size=None):
    path = Path(path)
    before = path.lstat()
    if expected_size is not None and before.st_size != expected_size:
        raise CaseError("EVTX source size changed before hashing.")
    if not stat.S_ISREG(before.st_mode) or getattr(before, "st_file_attributes", 0) & 0x400:
        raise CaseError("EVTX inputs must be regular files without reparse aliases.")
    if not 0 < before.st_size <= MAX_BYTES:
        raise CaseError("EVTX source exceeds the 64 MiB byte budget or is empty.")
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
    total, fingerprint = 0, hashlib.sha256()
    with path.open("rb") as stream:
        if identity(os.fstat(stream.fileno())) != identity(before):
            raise CaseError("EVTX source identity changed while opening.")
        while True:
            block = stream.read(min(4 * 1024 * 1024, MAX_BYTES - total + 1))
            if not block:
                break
            total += len(block)
            if total > MAX_BYTES:
                raise CaseError("EVTX source exceeded the 64 MiB byte budget while hashing.")
            fingerprint.update(block)
        if total != before.st_size or identity(os.fstat(stream.fileno())) != identity(before):
            raise CaseError("EVTX source size or identity changed while hashing.")
    after = path.lstat()
    if identity(after) != identity(before) or not stat.S_ISREG(after.st_mode) or getattr(after, "st_file_attributes", 0) & 0x400:
        raise CaseError("EVTX source identity changed after hashing.")
    return fingerprint.hexdigest()


def native_identity(row):
    system = row.get("System") or {}
    provider = system.get("Provider") or row.get("Provider") or ""
    provider = provider.get("Name", "") if isinstance(provider, dict) else provider
    code = row.get("EventID", system.get("EventID"))
    code = code.get("Value") if isinstance(code, dict) else code
    return dict(hostname=str(system.get("Computer") or row.get("Computer") or "").casefold(),
                channel=str(row.get("Channel") or system.get("Channel") or ""), provider=str(provider),
                event_code=int(code), record_id=int(row.get("EventRecordID", system.get("EventRecordID"))))


def identity_key(identity):
    return tuple(identity[name] for name in ("hostname", "channel", "provider", "event_code", "record_id"))


def source_identity(value):
    """Lexical binding only: portable verification never resolves external paths."""
    if not isinstance(value, str) or "\x00" in value:
        raise CaseError("Exact native rows require an unambiguous absolute source OSPath.")
    windows = PureWindowsPath(value)
    path = windows if windows.is_absolute() else PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts:
        raise CaseError("Exact native rows require an unambiguous absolute source OSPath.")
    return str(path).casefold() if isinstance(path, PureWindowsPath) else str(path)


def source_path(row):
    return source_identity(row.get("OSPath"))


def is_hash(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def _validate_precision(document, rows, raw_sha256):
    """Validate a persisted sidecar without reading external files or importing Evtx."""
    if not isinstance(document, dict) or type(document.get("schema")) is not int or document.get("schema") != 1 or document.get("raw_sha256") != raw_sha256 or document.get("parser") != {"name": "python-evtx", "version": PARSER_VERSION}:
        raise CaseError("Invalid exact-time sidecar identity.")
    if not isinstance(document.get("sources"), list) or len(document["sources"]) > 5 or not isinstance(document.get("rows"), list) or len(document["rows"]) > MAX_ROWS:
        raise CaseError("Invalid exact-time sidecar collections.")
    sources, result = {}, {}
    for source in document.get("sources", []):
        path = source_identity(source["path"])
        if path in sources or not is_hash(source["sha256"]) or type(source["bytes"]) is not int or not 0 < source["bytes"] <= MAX_BYTES:
            raise CaseError("Invalid or duplicate exact-time source.")
        sources[path] = source
    if sum(source["bytes"] for source in sources.values()) > 256 * 1024 * 1024:
        raise CaseError("Exact-time source byte budget exceeded.")
    expected = {index for index, row in enumerate(rows, 1) if row_type(row) == "event"}
    for item in document.get("rows", []):
        index = item["row"]
        if type(index) is not int or index not in expected or index in result:
            raise CaseError("Ambiguous or unexpected exact-time row binding.")
        row = rows[index - 1]
        source = sources.get(source_identity(item["source_path"]))
        if not source or source_identity(item["source_path"]) != source_path(row) or item["source_sha256"] != source["sha256"]:
            raise CaseError("Exact timestamp source binding differs from native row.")
        if item["row_sha256"] != digest(encode(row)) or encode(item["identity"]) != encode(native_identity(row)):
            raise CaseError("Exact timestamp identity differs from native row.")
        if not isinstance(item["filetime_ticks"], str) or not re.fullmatch(r"[1-9][0-9]{0,19}", item["filetime_ticks"]):
            raise CaseError("Exact FILETIME must be an unsigned decimal integer string.")
        value = int(item["filetime_ticks"])
        if not 0 < value < 2**64 or item["field_path"] != FIELD_PATH or bytes.fromhex(item["filetime_bytes"]) != struct.pack("<Q", value):
            raise CaseError("Invalid exact FILETIME bytes or field identity.")
        for name in ("record_header_filetime", "record_header_id"):
            if not isinstance(item[name], str) or not re.fullmatch(r"[0-9]{1,20}", item[name]) or not 0 <= int(item[name]) < 2**64:
                raise CaseError("Invalid separately labeled record-header provenance.")
        offset, size, field = item["record_offset"], item["record_length"], item["field_offset"]
        chunk = item["chunk_offset"]
        if any(type(number) is not int for number in (offset, size, field, chunk)) or not is_hash(item["record_sha256"]):
            raise CaseError("Invalid exact timestamp offset types or record hash.")
        if not 4096 <= chunk or (chunk - 4096) % 65536 or not chunk + 512 <= offset or not 24 < size <= 65536 or not offset + 24 <= field <= offset + size - 12 or offset + size > min(source["bytes"], chunk + 65536):
            raise CaseError("Exact timestamp byte offsets are invalid.")
        if item["timestamp_utc"] != iso_ticks(value):
            raise CaseError("Exact timestamp differs from its preserved FILETIME bytes.")
        original = row["System"]["TimeCreated"]["SystemTime"]
        # Bind the source ticks to the actual upstream conversion, not a tolerance
        # or nearest timestamp. Other encodings are refused on this native path.
        if type(original) not in (int, float) or original != (float(value) - 116444736000000000) / 10000000:
            raise CaseError("Native SystemTime does not match the exact source FILETIME conversion.")
        result[index] = item
    if set(result) != expected:
        raise CaseError("Exact timestamp evidence is missing for a native result row.")
    return result


def validate_precision(document, rows, raw_sha256):
    try:
        return _validate_precision(document, rows, raw_sha256)
    except (ValueError, KeyError, TypeError, AttributeError, struct.error) as exc:
        raise CaseError("Malformed exact-time sidecar.") from exc


def load_precision(case, entry):
    descriptor = entry["provenance"].get("details", {}).get("precision")
    if not descriptor:
        return {}
    path = case.root / descriptor["path"]
    sha = descriptor["sha256"]
    if not is_hash(sha) or descriptor["path"] != "precision/" + sha + ".json" or not path.resolve().is_relative_to(case.root) or path.is_symlink():
        raise CaseError("Invalid exact-time sidecar path.")
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_BYTES or path.stat().st_size != descriptor["bytes"]:
        raise CaseError("Exact-time sidecar size verification failed.")
    raw = path.read_bytes()
    if digest(raw) != sha:
        raise CaseError("Exact-time sidecar SHA-256 verification failed.")
    try:
        return validate_precision(json.loads(raw), records((case.root / entry["path"]).read_bytes()), entry["sha256"])
    except (ValueError, KeyError, TypeError) as exc:
        raise CaseError("Malformed exact-time sidecar.") from exc


def exact_substitution(record, Nodes):
    root, matches, visited = record.root(), [], 0

    def walk(node, path=()):
        nonlocal visited
        visited += 1
        if visited > 4096 or len(path) > 16:
            raise CaseError("BinXML SystemTime traversal budget exceeded.")
        if not isinstance(node, Nodes.OpenStartElementNode):
            return
        path = (*path, node.tag_name())
        if path == ("Event", "System", "TimeCreated"):
            matches.extend(child.attribute_value() for child in node.children()
                           if isinstance(child, Nodes.AttributeNode) and child.attribute_name().string() == "SystemTime")
        for child in node.children():
            if isinstance(child, Nodes.OpenStartElementNode):
                walk(child, path)

    for child in root.template().children():
        walk(child)
    if len(matches) != 1 or not isinstance(matches[0], (Nodes.NormalSubstitutionNode, Nodes.ConditionalSubstitutionNode)):
        raise CaseError("SystemTime must have one explicit BinXML substitution.")
    subs = root.substitutions()
    index = matches[0].index()
    if not 0 <= index < len(subs) or matches[0].type() != 0x11 or not isinstance(subs[index], Nodes.FiletimeTypeNode):
        raise CaseError("SystemTime must be a scalar FILETIME substitution.")
    node = subs[index]
    if node.length() != 8 or not record.offset() + 24 <= node.offset() <= record.offset() + record.size() - 12:
        raise CaseError("SystemTime bytes escape their record.")
    return root, subs, index, node.unpack_qword(0), node.offset()


class ExactText:
    def __init__(self, value):
        self.value = value

    def string(self):
        return self.value


def parse_source(source, wanted, max_records=MAX_ROWS):
    Evtx, Nodes, Views = require_parser()
    path = Path(source["path"])
    if path.stat().st_size != source["bytes"] or file_hash(path) != source["sha256"]:
        raise CaseError("EVTX source changed before exact parsing.")
    found, count, valid_chunks = {}, 0, 0
    with Evtx(str(path)) as log:
        header = log.get_file_header()
        if len(header._buf) != source["bytes"]:
            raise CaseError("EVTX source size changed before mapping.")
        if not header.verify():
            raise CaseError("EVTX file header checksum/version validation failed.")
        # Dirty exports can under-report chunk_count. Inspect physical chunks,
        # skipping only all-zero preallocation, never damaged nonzero chunks.
        for chunk in header.chunks(include_inactive=True):
            block = chunk.unpack_binary(0, 65536)
            if not any(block):
                continue
            if not chunk.verify() or not 512 <= chunk.next_record_offset() <= 65536:
                raise CaseError("EVTX chunk checksum/extent validation failed.")
            valid_chunks += 1
            offset = chunk.offset() + 512
            for record in chunk.records():
                count += 1
                if count > max_records:
                    raise CaseError("Exact EVTX parser exceeds its remaining physical-record budget.")
                if record.offset() != offset or record.magic() != 0x2A2A or not record.verify() or record.size() < 28 or offset + record.size() > chunk.offset() + chunk.next_record_offset():
                    raise CaseError("Malformed EVTX record boundary.")
                offset += record.size()
                if not wanted:
                    continue
                root, subs, index, value, field_offset = exact_substitution(record, Nodes)
                exact = iso_ticks(value)
                # The renderer receives a replacement text value for this exact
                # substitution only; no global monkeypatch and no header fallback.
                rendered = list(subs)
                rendered[index] = ExactText(exact)
                xml = ElementTree.fromstring(Views.render_root_node_with_subs(root, rendered))
                system = xml.find(NS + "System")
                if system is None or len(system.findall(NS + "TimeCreated")) != 1 or system.find(NS + "TimeCreated").get("SystemTime") != exact:
                    raise CaseError("BinXML SystemTime path cannot be validated in the rendered event.")
                identity = dict(hostname=system.findtext(NS + "Computer", "").casefold(),
                    channel=system.findtext(NS + "Channel", ""), provider=system.find(NS + "Provider").get("Name", ""),
                    event_code=int(system.findtext(NS + "EventID")), record_id=int(system.findtext(NS + "EventRecordID")))
                # Exports may rewrite record headers independently of the XML.
                # Both identity and time come from Event/System, not the header.
                if identity["record_id"] not in wanted:
                    continue
                key = identity_key(identity)
                if key in found:
                    raise CaseError("Ambiguous duplicate EVTX source identity.")
                found[key] = dict(source_path=str(path), source_sha256=source["sha256"], identity=identity,
                    chunk_offset=chunk.offset(), record_offset=record.offset(), record_length=record.size(),
                    record_sha256=digest(record.data()), field_path=FIELD_PATH, field_offset=field_offset,
                    filetime_bytes=struct.pack("<Q", value).hex(), filetime_ticks=str(value), timestamp_utc=exact,
                    record_header_filetime=str(record.unpack_qword(16)), record_header_id=str(record.record_num()))
            if offset != chunk.offset() + chunk.next_record_offset():
                raise CaseError("EVTX record traversal stopped before the validated chunk end.")
        tail_offset = 4096 + ((source["bytes"] - 4096) // 65536) * 65536
        with path.open("rb") as stream:
            stream.seek(tail_offset)
            tail_size = source["bytes"] - tail_offset
            tail = stream.read(tail_size + 1)
            if len(tail) != tail_size:
                raise CaseError("EVTX source size changed while checking its trailer.")
            if any(tail):
                raise CaseError("Nonzero incomplete EVTX trailing chunk.")
        source.update(physical_records=count, valid_chunks=valid_chunks, header_chunk_count=header.chunk_count(), dirty=header.is_dirty())
    if file_hash(path) != source["sha256"]:
        raise CaseError("EVTX source changed during exact parsing.")
    return found


def build_precision(raw, sources):
    rows = records(raw)
    lookup, wanted = {}, {}
    for index, row in enumerate(rows, 1):
        if row_type(row) == "event":
            path = source_path(row)
            identity = native_identity(row)
            join = (path, identity_key(identity))
            if join in lookup:
                raise CaseError("Ambiguous duplicate native result identity.")
            lookup[join] = index
            wanted.setdefault(path, set()).add(identity["record_id"])
    if set(wanted) - {source_identity(source["path"]) for source in sources}:
        raise CaseError("Native result refers to an unregistered EVTX source.")
    exact_rows = []
    for source in sources:
        path_identity = source_identity(source["path"])
        remaining = MAX_ROWS - sum(item.get("physical_records", 0) for item in sources)
        parsed = parse_source(source, wanted.get(path_identity, set()), max_records=remaining)
        if sum(item.get("physical_records", 0) for item in sources) > MAX_ROWS:
            raise CaseError("Exact EVTX parser exceeds 100,000 physical records in aggregate.")
        for (path, key), index in lookup.items():
            if path != path_identity:
                continue
            if key not in parsed:
                raise CaseError("Native event has no exact matching EVTX identity.")
            exact_rows.append(dict(parsed[key], row=index, row_sha256=digest(encode(rows[index - 1]))))
    document = dict(schema=1, parser={"name": "python-evtx", "version": PARSER_VERSION},
                    raw_sha256=digest(raw), sources=sources, rows=sorted(exact_rows, key=lambda item: item["row"]))
    validate_precision(document, rows, digest(raw))
    return document


def worker(request_path, output_path):
    request = json.loads(Path(request_path).read_text(encoding="utf-8"))
    raw_path = Path(request["raw"])
    if not 0 < raw_path.stat().st_size <= MAX_BYTES:
        raise CaseError("Native output exceeds the exact-time worker budget.")
    sources = request["sources"]
    if len(sources) > 5 or any(not 0 < source["bytes"] <= MAX_BYTES for source in sources) or sum(source["bytes"] for source in sources) > 256 * 1024 * 1024:
        raise CaseError("Exact EVTX source byte budget exceeded.")
    result = encode(build_precision(raw_path.read_bytes(), sources))
    if len(result) > MAX_BYTES:
        raise CaseError("Exact-time sidecar exceeds 64 MiB.")
    with Path(output_path).open("xb") as stream:
        stream.write(result)


if __name__ == "__main__":
    try:
        worker(*sys.argv[1:])
    except Exception as exc:
        print("Exact EVTX parser failed: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
