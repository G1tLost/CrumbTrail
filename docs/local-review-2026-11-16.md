# Local-only review patch, 2026-11-16

Base: `e1317275714c472b516db2a4576e20d59ea4f65c` (0.3.0).
This patch is not a release or a production acceptance claim.

## Changes

- Logon/process findings reuse the full case's conservative session membership. Validated logoff/startup boundaries, repeated-start ambiguity, conflicting source IDs, start target-ID roles and provider validation now agree between findings and session views. The existing positive, at-most-30-minute window and process-GUID requirement remain.
- The exported WindowsTriage artifact defaults `LogDirectory` to empty and requires a nonblank path in its Windows precondition. This removes its implicit current-host log path. It is not a sandbox or proof that an explicitly supplied directory contains offline evidence.
- Added five correlation regressions and a static packaged-artifact guard test.
- Added the approved local banner and documented the changed behavior.

## Executed locally

No live Velociraptor, host logs, real EVTX corpus, remote target, deployment, or repository publication was used.

- Python 3.14.10: `PYTHONPATH=src:tests python -m unittest test_sessions test_crumbtrail -v`: **54 passed**.
- Python 3.14.10 and Python 3.11.15: full discovery each ran **82 tests: 79 passed, 2 errors, 1 skipped**. Both errors are the existing malformed-EVTX tests requiring unavailable `python-evtx==0.8.1`; the Windows-only native-helper guard test was skipped. The erroring tests are `test_nonzero_incomplete_trailer_fails_without_source_write` and `test_nonzero_malformed_chunk_fails_without_source_write` in `test_precision.PrecisionTests`. The skipped test is `test_native_helper_rejects_output_alias_and_existing_destination_before_read` in `test_evtx_acceptance.AcceptanceTests`. No dependency was installed and these errors were not hidden or converted to passes.
- An initial run with macOS system Python 3.9.6 was unsupported (project requires >=3.11): 82 tests, 22 errors, 1 skipped. Do not use it as compatibility evidence.
- Synthetic CLI demo: 21 events, 4 findings, 0 gaps, 1 duplicate, 1 raw artifact. Subsequent verify: 1 verified artifact. Fresh temporary case retained outside the repository.
- `git diff --check`: passed.

The VQL precondition was checked statically, not executed. Independent VQL parsing and omitted/blank/explicit-directory acceptance remain required before publishing the artifact change. A static guard test does not establish runtime failure signaling.

## Unchanged limits and open acceptance gates

64 MiB per imported result/sidecar or EVTX source, 256 MiB combined registered bytes/source inputs, five native EVTX inputs, 100,000 case rows/physical records, and 20,000 candidate rows per channel remain in effect. Native query/process timeouts are 655/660 seconds; the separate exact parser timeout is 120 seconds. Native stdout/stderr are streamed before post-run size validation, not protected by a hard disk quota.

The native artifact still does not select 4634/4608; boundary support applies to records supplied in imported exports. This patch does not expand collection.

Remaining W2 gates: real Sysmon/Defender/PowerShell exports; real supported logoff/startup records; additional Windows/export/parser versions; resource and stress tests; independent responder review. Earlier repository-documented exact-time System/Security results were not rerun here. Full testing with the pinned optional parser and packaged-wheel isolation also remain open for this patch.
