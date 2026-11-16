# Bounded exported-EVTX acceptance

This Windows-only runner tests the installed CrumbTrail package's actual `local` EVTX path against the independent native Windows file reader. It reads an existing export, not current-host logs. It downloads nothing, creates no endpoint activity, and requires no server, driver or security-control changes. In **0.3.0 both System and Security pass**, including exact 100 ns timestamps and the unchanged 1,000 ns gate. The [exact-time implementation and current results](exact-time.md) close the eight 0.2.1 precision failures. W2 remains partial because the wider telemetry/OS/responder matrix is open.

## Inputs and private output

Use a new private directory **outside this checkout**, a trusted existing Windows Velociraptor executable, and a single-host, single-channel exported EVTX file. Install this checkout and its pinned exact-parser extra into a dedicated Python 3.11+ environment using `python -m pip install ".[evtx]"`. The runner invokes that interpreter's installed package with `-I`; it does not inject source paths. Keep original files separately controlled.

Optional upstream fixture locations, full immutable revision, Git blob IDs, sizes, SHA-256 hashes and the root license URL are in [evtx-corpus.json](evtx-corpus.json). Download only those data files into private storage if using them; verify the listed SHA-256. The fixture bytes are not part of this project. Repository licensing does not establish source collection history, truth of event contents, or permission to publish account/host details. The supplied existing System export matched the pinned System fixture exactly, but its local acquisition history is unknown. The Security sample was downloaded from that pinned primary-maintainer URL and both hash forms were checked.

```powershell
python scripts/validate_evtx.py `
  --evtx D:\PrivateLab\Inputs\System.evtx --channel System `
  --velociraptor C:\IRTools\velociraptor.exe `
  --expected-sha256 5579cdca073ee4864ea82d656aa2d25400b5c1e85b8e688db5d85f6dc558c2af `
  --source-reference 'Velocidex/velociraptor@7d287b0b988b35657e1b401f7b2ffebaf60dbcae System fixture' `
  --output D:\PrivateLab\Runs\system-001

python scripts/validate_evtx.py `
  --evtx D:\PrivateLab\Inputs\RDPAuth_Security.evtx --channel Security `
  --velociraptor C:\IRTools\velociraptor.exe `
  --expected-sha256 e8aedecca631f5d69691d9c67b25f68947805ad37df13863567ca28778f6ddde `
  --source-reference 'Velocidex/velociraptor@7d287b0b988b35657e1b401f7b2ffebaf60dbcae Security fixture' `
  --output D:\PrivateLab\Runs\security-001
```

The runner's exit is `0` only when every gate passes; `1` means a failed gate/input/runtime error. The underlying `crumbtrail local` returns `2` for the four expected missing channels in these one-channel tests. A local exit of `2` alone is not a parser failure. Both pinned corpus commands are expected to return runner exit `0` with CrumbTrail 0.3.0, the `evtx` extra and Velociraptor 0.77.3. Do not suppress failures or widen the precision gate.

Default selection spans the file's earliest to latest native timestamp, padded by one second. Optional `--start` and `--end` preserve supplied timezone-aware ISO fractions through 100 ns. Set both to a known event's seven-digit timestamp for an inclusive single-tick check, then use each adjacent 100 ns instant as an exclusion check. Exact identifying windows stay in `provenance.private.json`. Selection uses IDs `1,3,11,15,104,1102,1116,1117,4104,4624,4625,4688,4697,4698,7045`, with channel-specific interpretation unchanged. Security 4634/4608 boundary records are not selected by this native artifact.

Lab limits: 16 MiB input, 10,000 oracle records (`--max-records` can lower this), 120 seconds for Windows reading, and 850 seconds around the CLI's 660-second native process and separate 120-second exact parser. The native query retains its 20,000-candidate-row/channel limit; exact input/source bounds are documented in [exact-time.md](exact-time.md). One collector runs at a time. These are bounded checks, not hard process-memory or output-disk quotas. The pinned upstream artifact's omitted StartDate/EndDate parameters have no defaults and conditional filters allow all times; CrumbTrail supplies candidate filtering outside that call, then applies the exact requested window after source recovery. More candidate rows can pass through. Large-file throughput is not asserted unchanged.

## Comparison and artifacts

The runner hashes the original and makes two independent copies: `input/<channel filename>` for CrumbTrail and `oracle-working-copy.evtx` for Windows. The internal `read_evtx_oracle.ps1` helper accepts only an explicit file and rejects current-host log paths and existing/output-alias destinations. Invoke it only through the runner on a disposable oracle copy: **Get-WinEvent can rewrite that copy**. Its destination is created exclusively, never overwritten. [Microsoft Get-WinEvent reference](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-5.1)

Windows supplies record ID, channel, provider, hostname, exact XML SystemTime, and named EventData or UserData/LogFileCleared fields. The runner compares every selected identity, provider and explicit logon-ID field/value against normalized CrumbTrail results, including exact-source provenance and integer timeline ordering. Subject and target IDs are distinct. Missing/unexpected rows, duplicate identities or absent references fail. Full raw/sidecar `verify`, unchanged source/collector-input hashes and exactly four missing-channel coverage reasons are required. Windows is acceptance-only; product timestamp recovery independently reads BinXML with the optional Python parser. Reader agreement does not authenticate event contents.

| Private artifact | Purpose |
| --- | --- |
| `oracle.private.json` | Independent native records, XML timestamp values, reader version/OS and reader resource measurement |
| `comparison.private.json` | Exact identity/field mismatches, timestamp deltas and integrity results |
| `provenance.private.json` | Original path/hash, selected window/IDs, declared source, collector hash and all copy hashes |
| `*.private.command.json`, stdout/stderr | Exact invocation, return status, elapsed time and retained diagnostics |
| `case/` | Full normal case, exact raw native JSON, manifest, sessions/timeline CSV/JSON and offline HTML |
| `summary.aggregate.json` | Counts, hashes, gates and resource metrics without event records, hostnames or source paths |

Keep the complete run private. Review only the aggregate summary for publication; even hashes/counts may be sensitive for operational cases. The runner prints aggregates only. No EVTX, records, hostnames, account names or identifying local paths belong in Git. Do not commit diagnostics even when upstream fixture data is public.

## Precision defect history (0.2.1)

The following measurements explain the original defects. Version 0.3.0 now recovers the exact field independently and achieves 0 ns differences on both corpora; see [current design/results](exact-time.md). The historical gate was never widened.

The original EVTX XML time has 100-nanosecond digits. CrumbTrail's normalized `datetime` has microsecond resolution; numeric native Unix seconds round through Python's floating-point conversion, while ISO sub-microsecond digits truncate. Each event and reference retain the original supplied native value and field name, and original JSON bytes remain hashed. [Python datetime documentation](https://docs.python.org/3/library/datetime.html)

The comparison keeps the oracle's fractional digits as integer nanoseconds. It separately records exact agreement after truncation to microseconds, maximum absolute error, and any error **greater than 1,000 ns**. That explicit gate accommodates only sub-microsecond representation loss; it is not a claim that every timestamp is exact. The threshold is unchanged when a corpus fails. Whole/fractional-second loss cannot pass it.

Two application defects were found and fixed in 0.2.1:

1. Normalization preferred the upstream formatted whole-second `TimeCreated`. The real System event was early by 894,341,300 ns. Preferring native `System.TimeCreated.SystemTime` reduces this difference to 300 ns and agrees at microsecond precision.
2. A window 150 ms wide around that event returned zero native rows, because the upstream artifact filters its integer-second `TimeCreated`. CrumbTrail now applies its own inclusive window to fractional native SystemTime before the row cap. The same actual EVTX test then returned the expected one row. An unrelated empty window returned zero rows with correct coverage.

The pinned [Windows.EventLogs.Evtx artifact](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/artifacts/definitions/Windows/EventLogs/Evtx.yaml) shows the integer conversion. The [0.77.3 go.mod](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/go.mod) pins its EVTX parser to `v0.2.1-0.20260916104054-0ef2ce4e83a8`. In [that parser's evtx.go](https://github.com/Velocidex/evtx/blob/0ef2ce4e83a8/evtx.go), `filetimeToUnixtime` converts FILETIME to float64 before subtracting the epoch and dividing. [The VQL worker](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/vql/parsers/event_logs/pool.go) emits the parsed event map, not its record-header FILETIME; no exact XML/tick output is exposed on this path. Formatting the resulting float cannot recover lost ticks. No upstream parser was patched or replaced.

This explains the remaining observed Security precision failure: all 181 row identities/providers/source-logon fields agree, 76 timestamps agree after truncation to microseconds, and eight differ by more than 1 microsecond (maximum 1.3 microseconds). This bound is an observation of these files/runtime, not a guarantee for every event date/parser. Extremely narrow windows and apparent ties remain subject to that upstream uncertainty. Session ordering/actor attribution is not independently proven by matching input IDs.

## Recorded 0.2.1 outcome (historical)

Executed on 2026-11-16 with Python 3.14.7, PowerShell 5.1.19041.6456, native reported OS version 10.0.19045.0, and Velociraptor 0.77.3 Windows amd64. Collector SHA-256: `3d20a5a2d272e3eb2bccae4a80ebe469fc1a6f63eb4a8f8a586dbae356437d32`. OS is the reader API's reported version, not a complete verified OS support matrix.

| Measure | System | Security |
| --- | ---: | ---: |
| Input bytes / Windows records | 69,632 / 1 | 1,187,840 / 789 |
| Selected / normalized events | 1 / 1 | 181 / 181 |
| Selected IDs and counts | 104: 1 | 1102: 1; 4624: 67; 4688: 107; 4697: 6 |
| Field/provenance mismatches | 0 | 0 |
| Timestamps beyond 1,000 ns gate | 0 | 8 |
| Maximum timestamp difference | 300 ns | 1,300 ns |
| Expected coverage gaps / local exit | 4 / 2 | 4 / 2 |
| Source and collector input unchanged | Yes | Yes |
| Oracle working copy changed | No | Yes: header bytes and file length; 1,183,744 bytes after reading |
| Oracle / local / verify wall seconds | 0.316 / 0.555 / 0.130 | 3.309 / 0.679 / 0.134 |
| Oracle process peak working set, bytes | 81,952,768 | 175,603,712 |
| Native original result bytes | 1,816 | 589,996 |
| Combined derived JSON/CSV/HTML bytes | 13,133 | 1,435,918 |
| Overall runner result | Pass | Fail: precision gate |

Resource values are single runs, not throughput guarantees. Native collector peak memory was not measured (explicit null in summary); oracle peak includes PowerShell. Output sizes vary with private path lengths. Security session views retained 67 starts, 74 linked events, 106 ambiguous events, one unlinked event and one unbounded ID group; these are deterministic interpretation outputs, not independently adjudicated sessions.

At 0.2.1 the System check passed and the eight Security precision failures stopped strict timestamp acceptance. In 0.3.0 both checks pass without changing the gate. **Stop** on any unexpected identity/count/host/source-field/hash/coverage change, missing/malformed exact source binding, source or collector-input mutation, or runtime failure. A disclosed Windows oracle-working-copy mutation never authorizes altering the original; both readers must begin from separate byte-identical copies.

W2 is not closed. Missing real Sysmon, Defender and PowerShell channel checks; additional Windows/export/parser versions; real supported logoff/startup boundary coverage; full resource/stress measurements; and independent responder review remain open. No fleet, remote server, production-detection, source-completeness or live-collection acceptance is claimed.
