# Exact source timestamps in 0.3

CrumbTrail 0.3.0 closes the eight Security timestamp failures observed in 0.2.1. The actual installed `local` workflow now agrees with the independent Windows reader on **all 181 Security and one System timestamps, with a maximum difference of 0 ns**. The acceptance gate remains 1,000 ns. The solution reads the original EVTX field; it does not relax a tolerance, manufacture decimal digits, or insert oracle times into product output.

## Source field and parser dependency

Install `python -m pip install ".[evtx]"` from this checkout for `local`. The extra pins `python-evtx==0.8.1`; its actual installed version is checked before reading EVTX and recorded in each precision sidecar. Missing/different versions fail with an installation instruction. The base package and `demo`, JSON `import`, reports, `verify`, `sessions`, and inert JSONL `lab` remain usable without that extra. A completed exact case can be verified and analyzed without the original EVTX, optional parser, Windows or a collector.

The adapter follows the actual BinXML template path `Event/System/TimeCreated/@SystemTime`, requires exactly one scalar FILETIME substitution, and reads that substitution's eight bytes as an unsigned little-endian integer. No floating-point conversion is used to derive its UTC representation. A FILETIME unit is 100 ns since 1601-01-01 UTC. [Microsoft FILETIME definition](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime)

The primary parser source inspected was [python-evtx at 4d8ba92d934d8c08975ecb325124d480249312a6](https://github.com/williballenthin/python-evtx/tree/4d8ba92d934d8c08975ecb325124d480249312a6), whose metadata declares 0.8.1. Relevant APIs are [RootNode substitutions and FiletimeTypeNode](https://github.com/williballenthin/python-evtx/blob/4d8ba92d934d8c08975ecb325124d480249312a6/Evtx/Nodes.py), [record/chunk validation](https://github.com/williballenthin/python-evtx/blob/4d8ba92d934d8c08975ecb325124d480249312a6/Evtx/Evtx.py), and [render_root_node_with_subs](https://github.com/williballenthin/python-evtx/blob/4d8ba92d934d8c08975ecb325124d480249312a6/Evtx/Views.py). CrumbTrail does not call the parser's datetime conversion for the selected FILETIME. It supplies exact integer-formatted text to that substitution when rendering the event for XML identity validation; no global parser monkeypatch or vendored implementation is used.

**Record headers are not substitutes for XML.** The supplied System corpus has both a different record-header time and a different record-header ID. The exact adapter selects XML SystemTime and XML EventRecordID and retains the header values under separate diagnostic names. That real discrepancy and synthetic semantic-path tests guard against using the wrong source field.

## Binding and preservation

Each native event must match one exact source record by canonical source path, XML hostname, channel, provider, event ID and XML record ID. Duplicate native/source identities and missing matches fail. The source ticks must also reproduce the original native numeric SystemTime through the known upstream conversion exactly; this is an equality check, not nearest-time matching. This numeric binding was verified with Velociraptor 0.77.3. A changed upstream encoding can require a reviewed adapter update; no silent fallback claims exactness.

The original native stdout bytes remain registered as `raw/<sha256>.json`. A separate `precision/<sha256>.json` is registered in the manifest's checksummed provenance and contains:

- Parser name/version and the original native result hash.
- Source path, SHA-256, size, dirty/header-chunk metadata and physical-record counts.
- Per-row native identity and canonical row hash.
- Source chunk/record/field byte offsets, record size/hash, exact eight FILETIME bytes and decimal tick integer.
- The validated BinXML field path and exact UTC string, plus separately labeled header time/ID.

Every timeline reference to an exact row includes `exact_time`. `timestamp_original` still contains the supplied native numeric value; `timestamp_source` still names that original field. `timestamp_precision="evtx-systemtime-100ns"` identifies the additional verified source value used by `timestamp_utc`. Original records are never rewritten to hide the upstream value.

Verification checks sidecar hash/size, original-result hash, all row/source/identity bindings, exact bytes/ticks/UTC agreement and offsets. Missing, changed, duplicate or unregistered sidecars stop verification/analysis. Source identities use Windows/POSIX lexical normalization; recipient-platform filesystem resolution is not used. Verification never opens the external source paths. This preserves portable offline handoff while allowing the lab owner to check the separately retained EVTX against its recorded hash. Sidecars do not contain the complete source EVTX. Local hashes/provenance are unsigned and do not establish authenticity against an adversary controlling the entire case.

## Window and ordering semantics

The collector receives a candidate window starting one whole second before the start's second and ending two whole seconds after the end's second. This bounded overread prevents native floating-point rounding from dropping a boundary event before it can be checked. The original requested window is retained separately. All native candidate rows retain coverage and provenance; the final timeline uses the exact integer source tick against the inclusive requested bounds. Out-of-window candidates remain original evidence and count as excluded.

Case creation, timeline ordering, correlation time differences and session cutoffs use integer 100 ns units. A case whose start and end equal an event's seven-digit timestamp includes it; cases at either adjacent tick exclude it. Synthetic start/logoff/activity records separated by 100 ns remain ordered correctly and do not collapse into a false shared-timestamp ambiguity.

JSON-only imports remain supported. Supplied ISO strings retain up to seven fractional digits; ordinary whole-minute timestamps remain accepted with zero seconds. Nonzero finer-than-100 ns fractions, fractional timezone offsets and ambiguous fractional time layouts are rejected. Existing numeric imports still use their previous Python microsecond conversion and are explicitly labeled `native-float-microsecond`. ISO imports are labeled `iso-supplied`, not independently source-verified. Shorter input precision is not filled in as newly measured digits. Ordering resolution does not prove clock accuracy, full telemetry retention or actor attribution.

Derived IDs/windows can change when previously truncated ISO digits are retained or exact native evidence is added. Regenerate derived exports together with version 0.3 or newer. Reanalyzing an old float-only case cannot recreate lost EVTX bits: retain/reparse the original EVTX in a new native run.

## Bounds and failure behavior

The exact worker is a separate process with a 120-second timeout. Inputs are at most five regular files, 64 MiB per file and 256 MiB combined; at most 100,000 physical records are traversed in aggregate. Source hashing enforces its byte limit during reads and checks regular-file status, file identity, size and modification metadata before/open/after reads. File symlinks/reparse aliases and changed/growing inputs fail before native invocation or evidence intake as applicable.

File-header and physical nonzero chunk checksums, chunk extents, record framing/trailers and field bounds are checked. Dirty exported files can have stale header chunk counts: the bounded adapter checks physical chunks and skips only all-zero preallocation/trailing padding. Nonzero malformed chunks or incomplete trailers fail. The Security corpus had ten checksum-valid chunks and 789 physical records although its dirty header declared one chunk. No recovery write is performed.

The existing native 655-second query, 660-second process and 20,000 candidate rows/channel limits remain. The lab wrapper allows 850 seconds around the CLI, including the exact worker. Sidecars are limited to 64 MiB and count against the 256 MiB registered-case byte budget. There is no hard output-disk or memory quota, nor a large-file throughput guarantee. Extra candidate rows may trigger a visible row-limit gap. Unsupported BinXML layouts/provider schemas or parse/identity errors stop exact local intake and leave private diagnostics; they never become silent float fallbacks. This is a bounded parser path, not a damaged-log recovery tool.

## Actual validation

The pinned System/Security inputs, approved collector hash, Windows/PowerShell versions and origin limits are in [the lab runbook](evtx-lab.md) and [corpus manifest](evtx-corpus.json). The independent oracle remains Windows `Get-WinEvent -Path` / `EventRecord.ToXml`, executed only by the lab runner on a separate disposable copy. Product code does not use that reader or its results. Source and collector copies remained unchanged; Windows rewrote only its own Security copy as previously documented.

| Check | Observed result |
| --- | --- |
| System selected record | 1/1, all projected facts and seven timestamp digits agree; 0 ns difference |
| Security selected records | 181/181 from 789 native-reader rows; all identities/providers/logon fields and timestamps agree; 0 ns difference; all eight former failures closed |
| Real single-tick boundaries | Exact instant 1/1; immediately previous and next 100 ns instants 0/0; raw candidate/sidecar preserved in every case |
| Timeline/source integrity | Exact ordering and per-row provenance pass; source, collector inputs, native bytes and registered sidecars verify |
| Coverage | Four expected missing channels in each one-channel test; local CLI exit 2, overall acceptance exit 0 |
| System local/verify wall seconds | 0.896 / 0.160 |
| Security local/verify wall seconds | 4.575 / 0.178 |
| Original native bytes / exact sidecar bytes | System 1,822 / 1,368; Security 591,082 / 166,775 |

These are single observed runs; native/exact-worker peak memory is not measured. Synthetic tests additionally cover unsupported versions, ambiguity, sidecar tamper/loss, portability without external reads, source growth/bounds, nonregular inputs, malformed nonzero chunks/trailers, precise UTC offsets and session cutoffs. Wider real Sysmon/Defender/PowerShell, logoff/startup EVTX, Windows/export/parser versions, responder review and full resource/stress acceptance remain open. No current-host or remote collection was performed.
