"""Local Velociraptor execution over explicit files; no server or driver API."""
import hashlib
import os
import re
import subprocess
import uuid
from importlib.resources import files
from pathlib import Path

from .storage import CaseError, MAX_BYTES, save


def data_path(name):
    return Path(str(files("crumbtrail").joinpath("data", name)))


def run_local(case, client_id, executable, *, fixture=False, log_directory=None):
    executable = Path(executable).resolve()
    if not executable.is_file():
        raise CaseError("Velociraptor executable is missing.")
    if not fixture and (log_directory is None or not Path(log_directory).is_dir()):
        raise CaseError("Supply an existing exported EVTX log directory explicitly.")
    case.binding(client_id)
    artifact = "Custom.CrumbTrail.LabReplay" if fixture else "Custom.CrumbTrail.WindowsTriage"
    variables = {"FixtureFile": str(data_path("windows.jsonl"))} if fixture else {
        "StartDate": case.meta["start"], "EndDate": case.meta["end"], "LogDirectory": str(Path(log_directory).resolve())}
    parameters = ",".join(key + "=" + key for key in variables)
    query = "SELECT * FROM Artifact." + artifact + "(" + parameters + ")"
    cmd = [str(executable), "--definitions", str(data_path("Custom.CrumbTrail.LabReplay.yaml").parent),
           "query", "--format", "jsonl", "--timeout", "655"]
    for key, value in variables.items():
        cmd.extend(["--env", key + "=" + value])
    cmd.append(query)
    fingerprint = hashlib.sha256()
    with executable.open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            fingerprint.update(block)
    detail = dict(executable_sha256=fingerprint.hexdigest(), artifact=artifact, parameters=variables)
    # Logs belong to the case, not the public source tree. Unique runs retain failures.
    run_dir = case.root / "collection" / ("run-" + uuid.uuid4().hex[:12])
    run_dir.mkdir(parents=True)
    save(run_dir / "request.json", detail)
    env = os.environ.copy()
    if os.name == "nt":
        env["__COMPAT_LAYER"] = "RunAsInvoker"
    output, errors = run_dir / "stdout.jsonl", run_dir / "stderr.log"
    try:
        with output.open("xb") as stdout, errors.open("xb") as stderr:
            result = subprocess.run(cmd, stdout=stdout, stderr=stderr, timeout=660, env=env,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired as exc:
        raise CaseError("Native parsing timed out; inspect " + str(run_dir)) from exc
    stderr = errors.read_bytes()
    if result.returncode or re.search(rb"(?im)^.*\[(error|fatal)\]|^.*: error:", stderr):
        raise CaseError("Native parsing failed; inspect " + str(errors))
    if output.stat().st_size > MAX_BYTES:
        raise CaseError("Native result exceeds the 64 MiB import budget; output retained at " + str(output))
    entry = case.preserve(output.read_bytes(), client_id, "native-fixture" if fixture else "native-evtx",
                          simulation=fixture, details=detail)
    save(run_dir / "result.json", dict(exit_code=result.returncode, artifact_sha256=entry["sha256"]))
    return entry
