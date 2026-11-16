"""Check the installed distribution from outside the source checkout."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def run(directory, *args):
    result = subprocess.run([sys.executable, '-I', '-m', 'crumbtrail', *args], cwd=directory,
                            capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return json.loads(result.stdout)


with tempfile.TemporaryDirectory(prefix='crumbtrail-installed-') as folder:
    root = Path(folder) / 'case'
    summary = run(folder, 'demo', '--root', str(root))
    assert summary['events'] == 21 and summary['findings'] == 4 and summary['gaps'] == 0
    assert summary['duplicate_rows'] == 1
    assert (root / 'report.html').is_file()
    result = run(folder, 'verify', '--root', str(root))
    assert result['verified_artifacts'] == 1
    print('Installed CrumbTrail: 21 Windows events, four findings, no gaps, evidence verified outside checkout.')
