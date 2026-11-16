# CrumbTrail

Independent Windows event triage with original-byte preservation, a UTC timeline, and an offline report. CrumbTrail 0.1.0 reads native Velociraptor event exports or parses an explicitly supplied EVTX directory through the local Velociraptor engine. It needs no email account, cloud connector, sibling repository, or shared evidence engine.

The Python package is `crumbtrail`, the distribution is `crumbtrail-ir`, and the CLI is `crumbtrail`. Runtime Python dependencies: standard library only, Python 3.11 or newer. Velociraptor is optional for `demo`, `import`, `analyze`, and `verify`; it is required for `lab` and `local`.

## Install and try

From this repository:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe -m crumbtrail demo --root .\cases\demo
```

Open `cases/demo/report.html`. The CLI equivalent in an activated environment is `crumbtrail demo --root ./cases/demo`. Use a new directory for every demo/lab run; existing cases are never overwritten.

Expected deterministic fixture result: **21 distinct Windows events, four findings from three rule types, one duplicate row, five covered channels, zero gaps**. The fixture contains 22 event rows and five coverage rows. Findings consist of two logon/process associations, one recovery-suppression observation, and one rapid file-creation/recovery-note association. Benign backup activity does not trigger the file-burst rule. The fixture is telemetry text; no malicious command in it is executed. All its derived events are labeled synthetic.

## Native inert lab

Use an independently obtained Windows x64 Velociraptor executable:

```powershell
python -m crumbtrail lab --root .\cases\native-lab `
  --velociraptor C:\IRTools\velociraptor.exe
```

This executes the real VQL engine against the bundled JSONL fixture through `Custom.CrumbTrail.LabReplay`, then preserves its original stdout bytes. It does not load a driver, read live RAM/disks, or collect current-host logs. The result should match the demo's 21 events/four findings/zero gaps. `collection/run-*/` retains the collector request, stdout, stderr, executable SHA-256, and result. The supplied executable runs with the caller's current token; no automatic elevation is requested.

## Bring real event evidence

Create a case and bind the exact endpoint hostname represented by the records. The client ID and organization are provenance supplied by the operator; an offline import cannot independently confirm them against a server.

```powershell
crumbtrail create --root D:\Cases\example --case-id CT-EXAMPLE `
  --start 2026-11-01T00:00:00Z --end 2026-11-02T00:00:00Z
crumbtrail bind --root D:\Cases\example --client-id C.0123456789abcdef `
  --hostname workstation.example.test --org root
crumbtrail import --root D:\Cases\example --client-id C.0123456789abcdef `
  --file D:\Exports\windows.jsonl
```

Import accepts UTF-8 JSON arrays or JSONL from the bundled `Custom.CrumbTrail.WindowsTriage` artifact, including its coverage rows. The original legacy `BECRowType` marker is accepted for compatible older exports; new artifacts use `CrumbTrailRowType`. Add `--simulation` only for synthetic exports. `import` does not directly accept binary EVTX, ZIP collectors, arbitrary vendor JSON, disk images, or RAM dumps.

For exported EVTX files, use local native parsing:

```powershell
crumbtrail local --root D:\Cases\example --client-id C.0123456789abcdef `
  --velociraptor C:\IRTools\velociraptor.exe --log-directory D:\Exports\Logs
```

Expected filenames are `Security.evtx`, `System.evtx`, `Microsoft-Windows-Sysmon%4Operational.evtx`, `Microsoft-Windows-PowerShell%4Operational.evtx`, and `Microsoft-Windows-Windows Defender%4Operational.evtx`. Missing files remain coverage gaps. A log directory is mandatory; the CLI never silently falls back to current-host logs. The parser reads only selected IDs in the case window, not every event. The selected IDs are `1`, `3`, `11`, `15`, `104`, `1102`, `1116`, `1117`, `4104`, `4624`, `4625`, `4688`, `4697`, `4698`, and `7045`; interpretation also checks the channel.

The two artifact YAML files are packaged under `src/crumbtrail/data`. They may be installed in an existing Velociraptor deployment using its normal artifact management, then the full unnamed source can be exported for `import`. **Version 0.1 has no remote API client, artifact installer, server provisioning, remote scheduling, pagination, or collection resume command.** Do not treat a local lab pass as validation of a server deployment. [Velociraptor server API documentation](https://docs.velociraptor.app/docs/server_automation/server_api/)

## Evidence and interpretation

Each case contains:

| File | Purpose |
| --- | --- |
| `case.json` | Case ID, explicit incident window, immutable endpoint bindings |
| `raw/<sha256>.json` | Exact original imported bytes, including duplicates and out-of-window rows |
| `manifest.json` | Original hash, byte/row count, source, endpoint/organization, simulation flag, and provenance checksum |
| `timeline.json` | Normalized events, per-row raw references, findings, coverage gaps, and counts |
| `timeline.csv` | Portable event table with spreadsheet-formula neutralization |
| `report.html` | Self-contained offline report with escaped evidence text and local raw links |
| `collection/run-*/` | Native execution request/stdout/stderr diagnostics, when applicable |

Every retained raw event reference includes the original artifact hash and its one-based row number in the parsed result sequence. Duplicate events share one timeline event while retaining all references. Event IDs include the case and endpoint identities. Timestamp offsets normalize to UTC; timestamps without a timezone are rejected. Events outside the inclusive case window remain in raw evidence and are counted as excluded from the timeline.

Run full verification before handoff or rebuilding derived views:

```powershell
crumbtrail verify --root D:\Cases\example
crumbtrail analyze --root D:\Cases\example
```

`verify` checks registered raw hashes, sizes, rows, provenance checksums, and endpoint binding. It detects unregistered raw files rather than discarding them. The manifest and checksums are local and unsigned; someone who rewrites the entire case can rewrite them. Keep a separately controlled evidence copy/hash anchor under your procedure. Native diagnostic files are operational logs; only the imported raw result bytes are registered evidence. Derived JSON/CSV/HTML can be regenerated after verification.

Rules correlate only within an endpoint, organization, and simulation status. A shared logon ID within 30 minutes gives context; a recovery-related command records an attempt; six distinct paths within two minutes plus a recovery-note-like filename creates a suspicious observation. None establishes that encryption occurred or that an account was compromised. Missing coverage, row-limit hits, and count mismatches are visible gaps. Absence of a finding is not a clean-host verdict.

Exit codes: `0` completed without reported gaps, `1` runtime/input/integrity error, `2` report generated with coverage gaps (also standard argparse usage errors), `130` interruption. `create`, `bind`, and `verify` report their own operation result, not a complete-coverage verdict.

## Python API

```python
from crumbtrail.storage import Case, case_lock
from crumbtrail.events import analyze
from crumbtrail.report import write_report

with case_lock("D:/Cases/example"):
    case = Case("D:/Cases/example")
    case.verify()
    result = analyze(case)
    write_report(case, result)
```

`Case.create(root, start, end, case_id=None)`, `case.bind(client_id, hostname, org="root")`, and `case.preserve(raw_bytes, client_id, source, simulation=False, details=None)` expose the same offline workflow. Supply complete native result objects, including coverage. The CLI rejects concurrent case operations using a nonblocking OS file lock. Direct API users must acquire `case_lock(root)` and then reopen `Case` before reading or changing an existing case, as above; methods do not nest their own locks. `Case.create` locks creation internally. There is no multiuser authorization layer.

## Limits and development

Imports are bounded to 64 MiB per result file, 256 MiB of original result bytes per case, and 100,000 rows per case. Native queries use a 655-second VQL timeout and a 660-second subprocess timeout, with 20,000 selected rows per channel. Native stdout streams to the case disk; the 64 MiB import check runs after the process exits and is not a hard disk quota. Allocate collection storage explicitly. There is no resumable large-result import in this version.

CrumbTrail provides event triage, not full filesystem or memory forensics. It does not acquire disks/RAM, extract credentials, alter protection settings, run ransomware, or contain email/cloud correlation. Original source attribution and MIT terms are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The fixture and event rules were selectively adapted; no legacy runtime package is required.

```powershell
python -m pip install -e .
python -m unittest discover -s tests -v
```

See [validation and lab acceptance](docs/validation.md) for exactly what was exercised, and [the Windows triage agent role](agents/windows-triage.md) for scoped maintenance work.
