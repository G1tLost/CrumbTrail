# Validation and lab acceptance

CrumbTrail 0.2.1 has a standalone test suite, source-ID-backed logon-session views, and bounded real-EVTX comparison against the native Windows file reader. W2 is partial: System checks pass; Security identity/field checks pass while eight timestamps fail a strict one-microsecond gate. The old BEC suite is not a test result for this package. No ransomware, current-host log collection, server deployment, kernel driver, RAM acquisition, or physical-disk imaging is part of this acceptance procedure.

## Automated and inert checks

Run from an installed checkout using a new directory for each case:

```powershell
python -m unittest discover -s tests -v
python -m crumbtrail demo --root C:\IRLab\crumbtrail-demo
python -m crumbtrail verify --root C:\IRLab\crumbtrail-demo
python -m crumbtrail sessions --root C:\IRLab\crumbtrail-demo
python -m crumbtrail lab --root C:\IRLab\crumbtrail-native `
  --velociraptor C:\IRTools\velociraptor.exe
python -m crumbtrail verify --root C:\IRLab\crumbtrail-native
```

Expected demo and native-fixture results: 21 events, four findings from three rule types, one deduplicated row, one raw artifact, and zero gaps. Open each `report.html`; confirm synthetic labels, 22 original event references across 21 events, all four finding links, escaped text, and raw SHA-256 links. `timeline.json`, `timeline.csv`, `manifest.json`, and the original raw result file must exist. Native execution additionally retains its stdout/stderr/request/result under `collection/run-*/` and records the supplied executable's hash.

Version 0.2 also writes `sessions.json`: one observed start, three ID-linked events, 18 unlinked events, no ambiguous events, no explicit logoff/startup boundaries, and unknown end time. Check that all 21 session-view event entries retain raw references, including both references on the duplicated event. The unlinked fixture file events must not acquire session membership from their process GUID. The existing timeline/event/finding counts remain unchanged.

## Session-view acceptance

The automated synthetic cases cover two sessions on each of two hosts reusing IDs; same-host repeated starts; organization/simulation separation; missing IDs and boundaries; distinct subject/target IDs; events before a start; provider conflicts; validated logoff/startup followed by same-ID activity without a new start; a new start after a cutoff; timestamp ties; shuffled input; and equivalent UTC offsets. Unlinked and ambiguous events retain their provenance. HTML escaping, scoped CLI output, original-byte verification, and the CLI case lock remain enforced.

For lab review, use a private existing export with an independently known successful logon and any already-recorded supported boundaries. Check source `TargetLogonId`, source provider, hostname, UTC time, original event reference, and every included/unlinked event. A 4634 logoff may supply an observed end; 4608 supplies only a startup cutoff. No new endpoint activity is required. Unknown boundaries stay unknown. The native selection does not add these boundary events in 0.2.

**Go:** no cross-host/context ID merge, no event disappears, repeated/conflicting IDs remain explicit, supplied supported cutoffs block linking to an earlier start, and filtered CLI output leaves full saved reports intact. **Stop:** assignment based only on proximity, loss of source roles/references, fabricated end time, or an unvalidated provider establishing a cutoff.

**Go:** tests pass; both fixture workflows have the expected counts; full verification succeeds. **Stop:** any hash/provenance mismatch, lost reference, changed expected count, unexpected host/device access, or native parser error. Keep failed-case diagnostics and investigate the specific check before rerunning into a new directory.

## Exported EVTX acceptance on a designated Windows lab

1. Record Windows build, installed Velociraptor version/hash, case window, actual source hostname/client/organization, and which of the five channels are expected to be present. Retain the original logs and their independently recorded hashes outside the repository.
2. Use an existing benign log export containing an independently observed event in the chosen window. Prefer a normal process/logon record; do not clear logs or execute a destructive command to create a test. Native VQL also requires the Windows runtime when using the supplied artifact.
3. Create and bind a new case using the README commands, then run `local` with that explicit exported-log directory. No live source path is implicit. Missing configured telemetry is a recorded limitation, not a reason to disable protection or fabricate rows.
4. Verify the manifest, raw result hash, source identity, normalized event time, record ID, channel, and original source-log path. Independently compare the known event with the EVTX export using the lab owner's existing viewer. Check that absent channels and row-limit/count discrepancies are visible.
5. Review `report.html` offline and retain the complete case directory. Run `verify` after copying it to its handoff destination. Record all command exit codes, gaps, output hashes, and the operator's observations in the private lab record.

**Go for exported-log parsing:** the known event maps to its correct host/channel/record ID and UTC time, full verification passes, and expected/missing channel coverage is represented accurately. **Stop:** wrong host, unknown time zone, malformed results, partial native execution, changed raw bytes, or a coverage claim inconsistent with the supplied logs. Zero findings does not prove the host is clean.

Native fixture acceptance validates the engine invocation and JSON result pipeline. It does not validate real EVTX parsing on every Windows/Sysmon version, server scheduling, sensor readiness, completeness of source retention, detection accuracy, or fleet-scale throughput. Follow the [bounded real-EVTX runbook](evtx-lab.md) for the independent reader comparison and its explicit remaining gates.

## Version 0.2.1 real-EVTX execution record

Executed 2026-11-16 using the installed editable standalone package, Python 3.14.7 and the approved Velociraptor 0.77.3 Windows runtime. The [EVTX runbook](evtx-lab.md) records exact versions/hashes, pinned primary-maintainer sources/license, aggregate resource measurements, selection rules and copy handling. No EVTX records or identifying host/source paths are published.

| W2 substage | Observed result |
| --- | --- |
| System real EVTX | 1/1 selected event agrees with Get-WinEvent on identity/provider; timestamp differs by 300 ns, exact at microsecond precision; all original/result integrity checks pass; four absent channels visible |
| Fractional case-window regression | Before fix, a 150 ms window lost its known event. Actual EVTX rerun after native-window fix returns 1/1; an empty window returns 0/0 without claiming missing coverage for the supplied System file |
| Security real EVTX row facts | 789 native-reader rows, 181 selected/normalized events: 67 logons, 107 processes, six services and one log-clear; identity/provider and explicit source-ID field/value comparisons all pass |
| Security precision gate | **Failed** for eight of 181 events: maximum 1,300 ns versus the unchanged 1,000 ns bound; 76/181 exact after truncation to microseconds. Loss originates in pinned upstream FILETIME-to-float conversion; no exact ticks are exposed by that VQL path |
| Source preservation and independent reader | Source and collector copies remain byte-identical. Windows rewrites only its separate disposable Security working copy; before/after hashes and changed size retained privately |
| Coverage and session limitations | Four expected missing channels in each one-channel case. Security view: 67 starts, 74 linked, 106 ambiguous, one unlinked event and one unbounded ID group. These are interpretation counts, not responder-adjudicated session truth |
| Automated regressions | 56 tests passed, including authoritative fractional timestamp/reference preservation, fractional case windows, strict comparison failures, identity/provenance checks and native-helper overwrite guards |
| Installed smoke and inert native VQL | Installed smoke passed outside checkout including new fractional import/window. Actual native JSONL replay retained 21 events, four findings, one duplicate, zero gaps; its original artifact verifies |
| Open W2 gates | Strict Security timestamp acceptance; real Sysmon/Defender/PowerShell and supported boundary EVTX; additional Windows/export/parser versions; full resource/stress testing; independent responder review |

Patch 0.2.1 fixes application-level whole-second normalization and native case-window filtering. It retains the remaining upstream precision failure rather than widening the comparison threshold. Rebuild derived exports together; older native runs may require reparsing their original EVTX to recover omitted events. Final isolated-wheel and hosted-CI release evidence is recorded by the release coordinator separately from this development validation.

The coordinator built and installed the final 0.2.1 wheel in a new CrumbTrail-only Windows/Python 3.14.7 environment. All **56 tests passed with Python isolated mode**, and the extended installed smoke passed. Package imports resolved from that environment's `site-packages`, with neither sibling available. The packaged native artifact also passed a fresh file-only System EVTX check in the same 150 ms window: one expected/observed event, zero mismatches, 300 ns maximum timestamp difference, four expected gaps and verified unchanged inputs. This validates the packaged fix within that scope; it does not remove the separate Security precision failure or broader W2 gaps.

## Version 0.2 implementation validation (historical)

The implementation was exercised using the designated development virtual environment with `crumbtrail-ir` 0.2.0 installed in editable mode. The release coordinator then built a wheel and installed it into a separate fresh Windows/Python 3.14.7 environment.

| Check | Observed result |
| --- | --- |
| Automated regression suite | 44 tests passed: the original 22 tests plus 22 session-view regressions |
| Independent wheel acceptance | All 44 tests passed against the fresh installed wheel using Python isolated mode; the extended installed smoke passed outside the checkout. The package resolved from the new environment's `site-packages`; neither sibling tool was available. |
| Installed feature smoke | `scripts/installed_smoke.py` launched the installed module with `-I` outside the checkout, exercised `demo`, filtered `sessions`, and `verify`; 21 events, four findings, zero gaps, one session, three ID-linked events, 18 unlinked events, and preserved references |
| Actual inert native VQL | Velociraptor 0.77.3 replayed the same packaged fixture; 21 events, four findings, one duplicate, zero gaps, and the expected one/three/18 session counts |
| Native raw verification | One original artifact verified after the native run |
| Version | Installed CLI reports `CrumbTrail 0.2.0` |
| Collection scope | Native artifact selection and remote-collection support are unchanged; no host capture was performed |

Session boundary regressions use synthetic event records based on the cited Microsoft schemas; they are not claims of real-host boundary collection or production attribution accuracy. Hosted CI records the platform checks for each published revision. Provider-aware derived IDs and the instruction to regenerate derived exports are documented in the README. All validation cases remain outside the tracked source deliverable.

## Version 0.1 execution record (historical)

Executed on 2026-11-16 using Windows, Python 3.14.7, and the existing official Velociraptor 0.77.3 Windows amd64 executable (commit `7d287b0b9`). No new collector deployment was created.

| Check | Observed result |
| --- | --- |
| Editable package installation | `crumbtrail-ir` 0.1.0 installed from this repository with no runtime dependency requirement |
| Standalone automated suite | 22 tests passed; includes original-byte/hash preservation, provenance rejection, UTC/dedup, case-window exclusions, identity binding, coverage/count/limit handling, host/simulation correlation isolation, safe HTML/CSV, aggregate byte budget, and a second-process writer contention test |
| Offline demo | 21 events, four findings, one duplicate row, one raw artifact, zero gaps; deterministic events/findings tested across two new cases |
| Actual local native VQL fixture | Same expected counts using `Custom.CrumbTrail.LabReplay`; completed successfully again after CLI case-lock integration |
| Full raw verification | Demo and native cases each reported one verified original artifact |
| Independence check | No runtime imports of legacy `bec`, shared `casecrumb`, sibling `hashbrown`, or path-injection code found in this package |

The release coordinator also built the wheel and installed it into a fresh CrumbTrail-only virtual environment. All 22 tests passed there. `scripts/installed_smoke.py` ran the installed module in Python isolated mode outside the checkout: 21 events, four findings, one duplicate, no gaps, and verified evidence. The installed wheel's native VQL fixture run passed the same expected counts using Velociraptor 0.77.3. No sibling project was installed in that environment.

At version 0.1, real exported EVTX parsing, production telemetry coverage, and live-server acceptance had not been executed for this new package. See the 0.2.1 execution record for the later bounded exported-file checks. Local generated validation cases are ignored by Git and are not source deliverables. No live endpoint evidence or credentials were added to this repository.
