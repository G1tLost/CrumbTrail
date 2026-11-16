# Validation and lab acceptance

CrumbTrail 0.1.0 has a new standalone test suite. The old BEC suite is not a test result for this package. No ransomware, current-host log collection, server deployment, kernel driver, RAM acquisition, or physical-disk imaging is part of this acceptance procedure.

## Automated and inert checks

Run from an installed checkout using a new directory for each case:

```powershell
python -m unittest discover -s tests -v
python -m crumbtrail demo --root C:\IRLab\crumbtrail-demo
python -m crumbtrail verify --root C:\IRLab\crumbtrail-demo
python -m crumbtrail lab --root C:\IRLab\crumbtrail-native `
  --velociraptor C:\IRTools\velociraptor.exe
python -m crumbtrail verify --root C:\IRLab\crumbtrail-native
```

Expected demo and native-fixture results: 21 events, four findings from three rule types, one deduplicated row, one raw artifact, and zero gaps. Open each `report.html`; confirm synthetic labels, 22 original event references across 21 events, all four finding links, escaped text, and raw SHA-256 links. `timeline.json`, `timeline.csv`, `manifest.json`, and the original raw result file must exist. Native execution additionally retains its stdout/stderr/request/result under `collection/run-*/` and records the supplied executable's hash.

**Go:** tests pass; both fixture workflows have the expected counts; full verification succeeds. **Stop:** any hash/provenance mismatch, lost reference, changed expected count, unexpected host/device access, or native parser error. Keep failed-case diagnostics and investigate the specific check before rerunning into a new directory.

## Exported EVTX acceptance on a designated Windows lab

1. Record Windows build, installed Velociraptor version/hash, case window, actual source hostname/client/organization, and which of the five channels are expected to be present. Retain the original logs and their independently recorded hashes outside the repository.
2. Use an existing benign log export containing an independently observed event in the chosen window. Prefer a normal process/logon record; do not clear logs or execute a destructive command to create a test. Native VQL also requires the Windows runtime when using the supplied artifact.
3. Create and bind a new case using the README commands, then run `local` with that explicit exported-log directory. No live source path is implicit. Missing configured telemetry is a recorded limitation, not a reason to disable protection or fabricate rows.
4. Verify the manifest, raw result hash, source identity, normalized event time, record ID, channel, and original source-log path. Independently compare the known event with the EVTX export using the lab owner's existing viewer. Check that absent channels and row-limit/count discrepancies are visible.
5. Review `report.html` offline and retain the complete case directory. Run `verify` after copying it to its handoff destination. Record all command exit codes, gaps, output hashes, and the operator's observations in the private lab record.

**Go for exported-log parsing:** the known event maps to its correct host/channel/record ID and UTC time, full verification passes, and expected/missing channel coverage is represented accurately. **Stop:** wrong host, unknown time zone, malformed results, partial native execution, changed raw bytes, or a coverage claim inconsistent with the supplied logs. Zero findings does not prove the host is clean.

Native fixture acceptance validates the engine invocation and JSON result pipeline. It does not validate real EVTX parsing on every Windows/Sysmon version, server scheduling, sensor readiness, completeness of source retention, detection accuracy, or fleet-scale throughput. Real exported EVTX acceptance remains a separate lab-owner gate.

## Local execution record

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

Real exported EVTX parsing, production telemetry coverage, and live-server acceptance were not executed for this new package. Local generated validation cases are ignored by Git and are not source deliverables. No live endpoint evidence or credentials were added to this repository.
