# CrumbTrail agent instructions

CrumbTrail is an independent Windows event triage project. Read [agents/windows-triage.md](agents/windows-triage.md) before changing its implementation.

- Keep runtime code inside `src/crumbtrail`; do not import sibling repositories, legacy `bec`, CaseCrumb, HashBrown, or cloud-provider clients.
- Preserve original evidence bytes, source identity, synthetic labels, UTC timestamps, references, and visible coverage gaps. Never report a parser or fixture pass as live collection acceptance.
- No driver loading, live-host collection, security-control changes, malware execution, server provisioning, or public evidence uploads are authorized by routine development.
- Read targeted files; do not scan neighboring projects. Tests use temporary directories and inert fixtures. Never overwrite or remove a case to make a test pass.
- Use RTK for supported verbose commands on Windows, preserving the project's runner, arguments, working directory, environment, and status. PowerShell cmdlets and unsupported commands run normally. Read saved failure logs before rerunning.
- Run `python -m unittest discover -s tests -v` after behavior changes. Exercise `demo` and, when an approved local Velociraptor path is available, the inert `lab`. Record exact results and limitations.
- Do not spawn agents, edit another standalone repository, or write to GitHub unless explicitly assigned. The coordinator owns publishing and final isolated-install checks.
