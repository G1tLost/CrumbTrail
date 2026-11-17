# Prerequisites

Run setup commands below from this repository's root, using an existing, approved Python installation. These are operator instructions, not actions performed by this document. Installation may download build/dependency packages; do it only in an approved environment.

## Choose the workflow

| Workflow | Requirements |
| --- | --- |
| `demo`, JSON/JSONL `import`, `analyze`, `sessions`, `verify` | Python **3.11 or newer** and the base package; no third-party runtime dependency, cloud account, sibling repository or Velociraptor executable |
| `lab` | Base package plus independently approved Velociraptor executable; runs only the bundled synthetic fixture |
| `local` exported-EVTX parsing | Base package, optional **`python-evtx==0.8.1`**, approved Windows Velociraptor executable, and explicitly supplied exported-EVTX directory |

The distribution is `crumbtrail-ir`; module and CLI are `crumbtrail`. Python >=3.11 is declared in `pyproject.toml`. Local review used Python 3.11.15 and 3.14.10; macOS system Python 3.9.6 is unsupported. Python's `venv` and `pip` must be available. Source installation uses `setuptools>=77` as its build requirement. No `dev` or `test` extra is defined.

## Isolated base installation

Windows PowerShell, with the Python launcher and an approved Python 3.11 installed:

```powershell
py -3.11 --version
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe -m crumbtrail --version
```

macOS or Linux, with an approved `python3.11` on PATH:

```sh
python3.11 --version
python3.11 -m venv .venv
./.venv/bin/python -m pip install .
./.venv/bin/python -m crumbtrail --version
```

An approved newer Python >=3.11 can replace the interpreter used to create the environment. Check its version first. Use the environment's explicit executable thereafter; activation and PowerShell execution-policy changes are unnecessary. Do not overwrite an existing environment with a different interpreter. On Linux distributions where `venv` is packaged separately, have the administrator provide it through the approved package-management process.

## Optional EVTX parsing and tests

Only if exported-EVTX parsing or its parser-dependent tests are required, install the defined extra into that same environment:

```powershell
# Windows
.\.venv\Scripts\python.exe -m pip install ".[evtx]"
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

```sh
# macOS/Linux
./.venv/bin/python -m pip install ".[evtx]"
./.venv/bin/python -m unittest discover -s tests -v
```

Tests use the standard-library `unittest` runner, not pytest. The full suite includes optional-parser-dependent cases, so a base-only installation is insufficient for a completely passing run. The exact adapter checks parser version 0.8.1 and fails closed on another version. Completed cases remain verifiable/analyzable without this optional parser or access to original source paths.

The base offline workflow is portable across Windows, macOS and Linux; this does **not** make the bundled native EVTX workflow cross-platform. `Custom.CrumbTrail.WindowsTriage` has a Windows precondition, and the independent `Get-WinEvent` oracle and native-helper guard require Windows. macOS/Linux test success cannot substitute for Windows native acceptance. The local review lacked the optional parser: 79 of 82 tests passed, two parser-dependent tests errored, and one Windows-only test skipped. See [local review record](local-review-2026-11-16.md), not a claim that all tests passed.

## Evidence and executable prerequisites

- JSON/JSONL imports must use the supported native event/coverage schema, not arbitrary vendor JSON, binary EVTX or ZIP files.
- Bind the authorized endpoint identity and explicit UTC incident window before importing evidence. Retain original EVTX and its independently recorded hashes separately; case sidecars do not contain full source EVTX copies.
- `local` requires an explicit exported-log directory. The CLI never falls back to current-host logs. The local artifact patch also removes its current-host default; its new precondition still awaits native runtime validation.
- Use only an independently approved Velociraptor executable matching the execution platform. CrumbTrail records its hash but does not authenticate its publisher or download/install it. No automatic elevation is requested.
- Existing documented native validation used Windows Velociraptor 0.77.3. This is bounded validation, not a promise that every version or Windows/export combination works. Consult [validation](validation.md) and [exact-time compatibility](exact-time.md) before native use.
- Keep all collection separately authorized. Installation, synthetic tests and offline case analysis do not authorize live endpoint collection, remote deployment or changing security settings.
