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
    sessions = run(folder, 'sessions', '--root', str(root), '--client-id', 'C.0123456789abcdef')
    assert sessions['summary'] == {'sessions': 1, 'linked_events': 3, 'unlinked_events': 18,
                                   'ambiguous_events': 0, 'unbounded_id_groups': 0, 'events': 21}
    assert all(event['references'] for event in sessions['events'])
    assert len(sessions['sessions'][0]['event_ids']) == 3
    assert sessions['sessions'][0]['end_utc'] is None
    assert (root / 'sessions.json').is_file()
    saved = json.loads((root / 'timeline.json').read_text(encoding='utf-8'))
    assert saved['session_view'] == sessions
    assert 'Logon-session views' in (root / 'report.html').read_text(encoding='utf-8')
    result = run(folder, 'verify', '--root', str(root))
    assert result['verified_artifacts'] == 1
    print('Installed CrumbTrail: 21 Windows events, four findings, no gaps; one session, three ID-linked '
          'and 18 explicitly unlinked events; source references and raw evidence verified outside checkout.')
