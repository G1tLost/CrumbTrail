"""Original-byte preservation and a bounded, local case manifest."""
import hashlib
import json
import os
import re
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

LOGS = (
    "Security", "System", "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
)
MAX_BYTES = 64 * 1024 * 1024
MAX_CASE_BYTES = 256 * 1024 * 1024
MAX_ROWS = 100000


class CaseError(Exception):
    """A recoverable input, identity, or integrity error."""


@contextmanager
def case_lock(root):
    """Hold a nonblocking kernel lock; a crashed process releases it automatically."""
    root = Path(root).resolve()
    if not root.is_dir():
        raise CaseError("Case directory does not exist.")
    with (root / ".crumbtrail.lock").open("a+b") as stream:
        if stream.seek(0, os.SEEK_END) == 0:
            stream.write(b"\0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise CaseError("Case is already in use; wait for its current operation to finish.") from exc
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def timestamp(value):
    if not isinstance(value, str):
        raise CaseError("Timestamp must be an ISO 8601 string with a timezone.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CaseError("Invalid timestamp: " + value) from exc
    if parsed.tzinfo is None:
        raise CaseError("Timestamp must include a timezone.")
    return parsed.astimezone(timezone.utc)


def iso(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def now():
    return iso(datetime.now(timezone.utc))


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(encode(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CaseError("Cannot read case JSON: " + str(path)) from exc


def records(raw):
    if not raw or len(raw) > MAX_BYTES:
        raise CaseError("Input is empty or exceeds the 64 MiB result-file limit.")
    try:
        text = raw.decode("utf-8-sig")
        if text.lstrip().startswith("["):
            rows = json.loads(text)
        else:
            rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    except (ValueError, UnicodeError) as exc:
        raise CaseError("Expected UTF-8 native event JSON or JSONL, not EVTX or ZIP bytes.") from exc
    if not isinstance(rows, list) or len(rows) > MAX_ROWS or any(not isinstance(row, dict) for row in rows):
        raise CaseError("Results must be at most 100,000 JSON objects.")
    if not rows:
        raise CaseError("Results contain no events or coverage rows.")
    return rows


def row_type(row):
    # Legacy exports remain readable; new artifacts use CrumbTrailRowType.
    return row.get("CrumbTrailRowType", row.get("BECRowType", "event"))


class Case:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.meta = read(self.root / "case.json")
        if self.meta.get("schema") != 1 or self.meta.get("tool") != "CrumbTrail":
            raise CaseError("Unsupported case schema.")
        if timestamp(self.meta["start"]) > timestamp(self.meta["end"]):
            raise CaseError("Invalid case time window.")

    @classmethod
    def create(cls, root, start, end, case_id=None):
        first, last = timestamp(start), timestamp(end)
        if first > last:
            raise CaseError("Case start must not follow its end.")
        root = Path(root).resolve()
        root.mkdir(parents=True, exist_ok=True)
        with case_lock(root):
            if any(path.name != ".crumbtrail.lock" for path in root.iterdir()):
                raise CaseError("Create a case in a new or empty directory.")
            save(root / "case.json", dict(schema=1, tool="CrumbTrail", case_id=case_id or "CT-" + uuid.uuid4().hex[:12],
                 start=iso(first), end=iso(last), created_at=now(), endpoints={}))
            save(root / "manifest.json", dict(schema=1, artifacts=[]))
            return cls(root)

    def bind(self, client_id, hostname, org="root"):
        hostname = hostname.strip().rstrip(".").casefold()
        if not re.fullmatch(r"C\.[a-fA-F0-9]{16}", client_id):
            raise CaseError("Expected a Velociraptor client ID: C. plus 16 hex digits.")
        if not re.fullmatch(r"[a-z0-9_.-]+", hostname) or not re.fullmatch(r"[A-Za-z0-9_.-]+", org):
            raise CaseError("Invalid hostname or organization.")
        value = dict(client_id=client_id, hostname=hostname, org_id=org)
        existing = self.meta["endpoints"].get(client_id)
        if existing and existing != value:
            raise CaseError("Endpoint binding is immutable; create a new case for changed identity.")
        if any(k != client_id and v["hostname"] == hostname for k, v in self.meta["endpoints"].items()):
            raise CaseError("Hostname already belongs to a different client in this case.")
        self.meta["endpoints"][client_id] = value
        save(self.root / "case.json", self.meta)
        return value

    def binding(self, client_id):
        if client_id not in self.meta["endpoints"]:
            raise CaseError("Bind the endpoint before importing results.")
        return self.meta["endpoints"][client_id]

    def manifest(self):
        value = read(self.root / "manifest.json")
        if value.get("schema") != 1 or not isinstance(value.get("artifacts"), list):
            raise CaseError("Unsupported evidence manifest.")
        return value

    def preserve(self, raw, client_id, source, simulation=False, details=None):
        from .events import normalize

        self.verify()
        bound = self.binding(client_id)
        rows = records(raw)
        coverage_channels = set()
        for row in rows:
            if row_type(row) == "coverage":
                if row.get("LogChannel") not in LOGS or any(type(row.get(k)) is not int or row[k] < 0 for k in ("Files", "Events")) or type(row.get("AtLimit")) is not bool:
                    raise CaseError("Invalid coverage channel or counts.")
                if row["LogChannel"] in coverage_channels:
                    raise CaseError("Duplicate coverage row for one channel; import one complete source per file.")
                coverage_channels.add(row["LogChannel"])
            elif row_type(row) == "event":
                normalize(self, row, bound, bool(simulation))
            else:
                raise CaseError("Unrecognized result row type.")
        provenance = dict(**bound, simulation=bool(simulation), source=source, details=details or {})
        sha = digest(raw)
        manifest = self.manifest()
        existing = next((entry for entry in manifest["artifacts"] if entry["sha256"] == sha), None)
        if existing:
            if existing["provenance"] != provenance:
                raise CaseError("These bytes already have different source provenance.")
            return existing
        if len(rows) + sum(entry["rows"] for entry in manifest["artifacts"]) > MAX_ROWS:
            raise CaseError("Case row budget would exceed 100,000; use a narrower case window.")
        if len(raw) + sum(entry["bytes"] for entry in manifest["artifacts"]) > MAX_CASE_BYTES:
            raise CaseError("Case original-result budget would exceed 256 MiB.")
        relative = "raw/" + sha + ".json"
        path = self.root / relative
        if not path.resolve().is_relative_to(self.root) or path.is_symlink():
            raise CaseError("Raw evidence destination escapes the case.")
        path.parent.mkdir(exist_ok=True)
        # Orphan bytes from a failed manifest commit are never silently replaced.
        with path.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        entry = dict(path=relative, sha256=sha, bytes=len(raw), rows=len(rows), provenance=provenance,
                     provenance_sha256=digest(encode(provenance)), imported_at=now())
        manifest["artifacts"].append(entry)
        save(self.root / "manifest.json", manifest)
        return entry

    def verify(self):
        manifest, registered = self.manifest(), set()
        for entry in manifest["artifacts"]:
            sha = entry.get("sha256", "")
            if not re.fullmatch(r"[a-f0-9]{64}", sha) or entry.get("path") != "raw/" + sha + ".json":
                raise CaseError("Invalid raw artifact identity or path.")
            path = self.root / entry["path"]
            if not path.resolve().is_relative_to(self.root) or path.is_symlink():
                raise CaseError("Raw evidence path escapes the case.")
            if entry["path"] in registered:
                raise CaseError("Duplicate raw evidence entry.")
            registered.add(entry["path"])
            if not path.is_file() or not 0 < path.stat().st_size <= MAX_BYTES or path.stat().st_size != entry["bytes"] or digest(path.read_bytes()) != sha:
                raise CaseError("Raw evidence SHA-256 or size verification failed.")
            provenance = entry["provenance"]
            if digest(encode(provenance)) != entry["provenance_sha256"]:
                raise CaseError("Evidence provenance checksum failed.")
            bound = self.binding(provenance["client_id"])
            if any(provenance[k] != bound[k] for k in ("client_id", "org_id", "hostname")):
                raise CaseError("Evidence provenance differs from the endpoint binding.")
            if len(records(path.read_bytes())) != entry["rows"]:
                raise CaseError("Raw evidence row count differs from the manifest.")
        actual = {p.relative_to(self.root).as_posix() for p in (self.root / "raw").glob("**/*") if p.is_file()}
        if actual != registered:
            raise CaseError("Unregistered raw evidence exists; inspect the interrupted write before proceeding.")
        return len(registered)
