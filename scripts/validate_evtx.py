"""Bounded Windows EVTX acceptance; all identifying results stay in private output.

This runner invokes the installed package in isolated mode and independently
reads only a copied EVTX file through Windows Get-WinEvent. It does not collect
the current host or download anything. See docs/evtx-lab.md.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

SELECTED_IDS = (1, 3, 11, 15, 104, 1102, 1116, 1117, 4104, 4624, 4625, 4688, 4697, 4698, 7045)
LOG_FILES = {
    "Security": "Security.evtx", "System": "System.evtx",
    "Microsoft-Windows-Sysmon/Operational": "Microsoft-Windows-Sysmon%4Operational.evtx",
    "Microsoft-Windows-PowerShell/Operational": "Microsoft-Windows-PowerShell%4Operational.evtx",
    "Microsoft-Windows-Windows Defender/Operational": "Microsoft-Windows-Windows Defender%4Operational.evtx",
}
MAX_INPUT_BYTES = 16 * 1024 * 1024
CLIENT = "C.0000000000000001"
NS_PER_SECOND = 1_000_000_000


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def utc(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("A timezone is required.")
    return parsed.astimezone(timezone.utc)


def iso(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def utc_nanoseconds(value):
    """Keep the Windows oracle's 100 ns fractional digits for explicit error metrics."""
    match = re.fullmatch(r"(.+T\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)", value)
    if not match:
        raise ValueError("Unsupported precise timestamp representation.")
    whole = utc(match[1] + match[3])
    delta = whole - datetime(1970, 1, 1, tzinfo=timezone.utc)
    seconds = delta.days * 86400 + delta.seconds
    return seconds * NS_PER_SECOND + int((match[2] or "").ljust(9, "0"))


def logon(value):
    try:
        text = str(value)
        number = int(text, 16 if text.lower().startswith("0x") else 10)
        return str(number) if number > 0 else ""
    except ValueError:
        return ""


def fields_oracle(row):
    data = row["event_data"]
    return {field: logon(data[field]) for field in ("LogonId", "TargetLogonId", "SubjectLogonId") if field in data}


def key(row):
    return row["channel"], int(row["event_code"]), str(row["record_id"]), row["hostname"].casefold()


def compare_records(expected, actual):
    """Compare exact identity/provider/logon facts, with an explicit 1 us time bound."""
    wanted, observed = {}, {}
    for rows, mapping in ((expected, wanted), (actual, observed)):
        for row in rows:
            identity = key(row)
            if identity in mapping:
                raise ValueError("Duplicate source identities require a separate investigation; comparison is not collapsed.")
            mapping[identity] = row
    mismatches, deltas = [], []
    exact_microseconds = 0
    for identity in sorted(wanted.keys() | observed.keys()):
        first, second = wanted.get(identity), observed.get(identity)
        if first is None or second is None:
            mismatches.append({"identity": identity, "reason": "unexpected" if first is None else "missing"})
            continue
        if first["provider"] != second["provider"]:
            mismatches.append({"identity": identity, "reason": "provider"})
        if fields_oracle(first) != {field["field"]: field["value"] for field in second["source_logon_ids"]}:
            mismatches.append({"identity": identity, "reason": "source_logon_ids"})
        expected_ns, actual_ns = utc_nanoseconds(first["timestamp_source"]), utc_nanoseconds(second["timestamp_utc"])
        delta = actual_ns - expected_ns
        deltas.append(delta)
        exact_microseconds += expected_ns // 1000 == actual_ns // 1000
        if abs(delta) > 1000:
            mismatches.append({"identity": identity, "reason": "timestamp", "delta_nanoseconds": delta})
        if not second.get("references"):
            mismatches.append({"identity": identity, "reason": "missing_provenance"})
    precision_failures = sum(item["reason"] == "timestamp" for item in mismatches)
    return dict(expected_rows=len(expected), actual_events=len(actual), mismatch_count=len(mismatches),
                row_facts_passed=len(mismatches) == precision_failures,
                timestamp_precision_passed=not precision_failures, timestamp_mismatch_count=precision_failures,
                mismatches=mismatches, exact_at_microsecond_count=exact_microseconds,
                maximum_absolute_timestamp_delta_ns=max(map(abs, deltas), default=0),
                timestamp_bound_ns=1000,
                source_logon_id_rows=sum(bool(fields_oracle(row)) for row in expected))


def run_command(command, directory, label, timeout):
    stdout, stderr = directory / (label + ".private.stdout"), directory / (label + ".private.stderr")
    started = time.perf_counter()
    with stdout.open("wb") as out, stderr.open("wb") as err:
        result = subprocess.run(command, stdout=out, stderr=err, timeout=timeout)
    elapsed = time.perf_counter() - started
    write_json(directory / (label + ".private.command.json"), dict(command=command, exit_code=result.returncode, elapsed_seconds=elapsed))
    return result.returncode, elapsed


def cli_command(*args):
    return [sys.executable, "-I", "-m", "crumbtrail", *map(str, args)]


def validate(args):
    if os.name != "nt":
        raise ValueError("This acceptance runner requires the native Windows event reader.")
    repository = Path(__file__).resolve().parents[1]
    source, output = args.evtx.resolve(), args.output.resolve()
    if output.is_relative_to(repository):
        raise ValueError("Evidence output must be outside the source checkout.")
    live = Path(os.environ["SystemRoot"]) / "System32" / "winevt" / "Logs"
    if source.is_relative_to(live.resolve()):
        raise ValueError("Current-host log directories are not allowed.")
    if not source.is_file() or source.suffix.casefold() != ".evtx" or not 0 < source.stat().st_size <= MAX_INPUT_BYTES:
        raise ValueError("Supply a nonempty EVTX export of at most 16 MiB.")
    with source.open("rb") as stream:
        if stream.read(8) != b"ElfFile\x00":
            raise ValueError("Input has no EVTX file signature.")
    source_hash = sha256(source)
    if args.expected_sha256 and source_hash != args.expected_sha256.lower():
        raise ValueError("Input SHA-256 differs from the pinned expectation.")
    if output.exists() and any(output.iterdir()):
        raise ValueError("Use a new or empty private output directory.")
    output.mkdir(parents=True, exist_ok=True)
    input_dir = output / "input"
    input_dir.mkdir()
    copied = input_dir / LOG_FILES[args.channel]
    shutil.copyfile(source, copied)
    if sha256(copied) != source_hash:
        raise ValueError("The private input copy failed verification.")
    # Get-WinEvent may repair a dirty exported file in place. Never let its
    # working copy become the collector input or the preserved source.
    oracle_input = output / "oracle-working-copy.evtx"
    shutil.copyfile(source, oracle_input)
    if sha256(oracle_input) != source_hash:
        raise ValueError("The oracle input copy failed verification.")
    oracle_file = output / "oracle.private.json"
    code, oracle_elapsed = run_command(["powershell.exe", "-NoProfile", "-NonInteractive", "-File",
        str(repository / "scripts" / "read_evtx_oracle.ps1"), "-InputFile", str(oracle_input),
        "-OutputFile", str(oracle_file), "-MaxRecords", str(args.max_records)], output, "oracle", 120)
    if code:
        raise ValueError("Native oracle failed; inspect the private oracle diagnostics.")
    oracle = json.loads(oracle_file.read_text(encoding="utf-8-sig"))
    oracle_hash_after = sha256(oracle_input)
    records = oracle["records"]
    hosts = {row["hostname"] for row in records}
    if len(hosts) != 1 or {row["channel"] for row in records} != {args.channel}:
        raise ValueError("Use a single-host, single-channel exported file for this bounded runner.")
    start = utc(args.start) if args.start else min(utc(row["timestamp_source"]) for row in records) - timedelta(seconds=1)
    end = utc(args.end) if args.end else max(utc(row["timestamp_source"]) for row in records) + timedelta(seconds=1)
    if start > end:
        raise ValueError("The selected window is reversed.")
    start_ns, end_ns = utc_nanoseconds(iso(start)), utc_nanoseconds(iso(end))
    expected = [row for row in records if row["event_code"] in SELECTED_IDS
                and start_ns <= utc_nanoseconds(row["timestamp_source"]) <= end_ns]
    case = output / "case"
    for label, command in (
        ("create", cli_command("create", "--root", case, "--case-id", "CT-EVTX-LAB", "--start", iso(start), "--end", iso(end))),
        ("bind", cli_command("bind", "--root", case, "--client-id", CLIENT, "--hostname", next(iter(hosts)))),
    ):
        if run_command(command, output, label, 30)[0]:
            raise ValueError("Case setup failed; inspect private diagnostics.")
    native_code, native_elapsed = run_command(cli_command("local", "--root", case, "--client-id", CLIENT,
        "--velociraptor", args.velociraptor.resolve(), "--log-directory", input_dir), output, "local", 700)
    if native_code not in (0, 2) or not (case / "timeline.json").is_file():
        raise ValueError("The actual local EVTX command failed; inspect private local diagnostics.")
    timeline = json.loads((case / "timeline.json").read_text(encoding="utf-8"))
    comparison = compare_records(expected, timeline["events"])
    expected_gaps = sorted(channel + " coverage unavailable." for channel in LOG_FILES if channel != args.channel)
    actual_gaps = sorted(gap["reason"] for gap in timeline["gaps"])
    comparison["coverage_matches"] = actual_gaps == expected_gaps
    comparison["original_input_unchanged"] = sha256(source) == source_hash and sha256(copied) == source_hash
    verify_code, verify_elapsed = run_command(cli_command("verify", "--root", case), output, "verify", 120)
    comparison["evidence_verified"] = verify_code == 0
    write_json(output / "comparison.private.json", comparison)
    write_json(output / "provenance.private.json", dict(source_path=str(source), copied_path=str(copied),
        source_sha256=source_hash, source_reference=args.source_reference, acquisition_history="operator-supplied; not inferred",
        channel=args.channel, start=iso(start), end=iso(end), selected_ids=SELECTED_IDS,
        oracle_copy_sha256_before=source_hash, oracle_copy_sha256_after=oracle_hash_after,
        oracle_copy_bytes_after=oracle_input.stat().st_size, collector_input_sha256_after=sha256(copied),
        executable_sha256=sha256(args.velociraptor.resolve()), python_version=sys.version,
        os_version=oracle["os_version"], oracle_reader=oracle["reader"]))
    manifest = json.loads((case / "manifest.json").read_text(encoding="utf-8"))
    passed = not comparison["mismatch_count"] and all(comparison[field] for field in
        ("coverage_matches", "original_input_unchanged", "evidence_verified"))
    summary = dict(schema=1, passed=passed, channel=args.channel, source_sha256=source_hash,
        input_bytes=source.stat().st_size, oracle_records=len(records), selected_rows=len(expected),
        selected_event_id_counts=dict(sorted(Counter(str(row["event_code"]) for row in expected).items())),
        actual_events=len(timeline["events"]), mismatch_count=comparison["mismatch_count"],
        row_facts_passed=comparison["row_facts_passed"],
        timestamp_precision_passed=comparison["timestamp_precision_passed"],
        timestamp_mismatch_count=comparison["timestamp_mismatch_count"],
        exact_at_microsecond_count=comparison["exact_at_microsecond_count"],
        maximum_absolute_timestamp_delta_ns=comparison["maximum_absolute_timestamp_delta_ns"],
        timestamp_bound_ns=1000, source_logon_id_rows=comparison["source_logon_id_rows"],
        coverage_gap_count=len(actual_gaps), coverage_matches=comparison["coverage_matches"],
        evidence_verified=comparison["evidence_verified"], original_input_unchanged=comparison["original_input_unchanged"],
        oracle_working_copy_changed=oracle_hash_after != source_hash,
        oracle_working_copy_bytes_after=oracle_input.stat().st_size,
        local_exit_code=native_code, session_counts=timeline["session_view"]["summary"],
        oracle_wall_seconds=round(oracle_elapsed, 3), local_wall_seconds=round(native_elapsed, 3),
        verify_wall_seconds=round(verify_elapsed, 3),
        oracle_peak_working_set_bytes=oracle["reader_peak_working_set_bytes"],
        collector_peak_working_set_bytes=None,
        raw_result_bytes=sum(entry["bytes"] for entry in manifest["artifacts"]),
        derived_output_bytes=sum((case / name).stat().st_size for name in ("timeline.json", "sessions.json", "timeline.csv", "report.html")))
    write_json(output / "summary.aggregate.json", summary)
    print(json.dumps(summary, indent=2))
    return 0 if passed else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evtx", required=True, type=Path)
    parser.add_argument("--channel", required=True, choices=LOG_FILES)
    parser.add_argument("--velociraptor", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="New private directory outside the checkout")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--source-reference", default="Origin not established")
    parser.add_argument("--max-records", type=int, choices=range(1, 10001), default=10000, metavar="1..10000")
    parser.add_argument("--start")
    parser.add_argument("--end")
    args = parser.parse_args(argv)
    try:
        return validate(args)
    except (ValueError, OSError, KeyError, subprocess.TimeoutExpired) as exc:
        print("EVTX acceptance failed; identifying details remain in private output. " + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
