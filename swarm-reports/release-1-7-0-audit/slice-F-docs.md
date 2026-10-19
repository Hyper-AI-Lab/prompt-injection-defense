# Slice F — README / ARCHITECTURE / docs consistency

**Verdict:** PASS

- README, SKILL.md, AGENT_INSTALL, ARCHITECTURE (`doctor`, `resources` rows, release flow), DECISIONS (Bar F+G), shared box skill: all pin `@v1.7.0`, all `pip install` hints name the git source or a local wheel; no bare PyPI install.
- RELEASE.md check order 1–9 matches the script; publish section matches the workflow; G0 steps match workflow names (`publish.yml`, env `pypi`, var `PYPI_PUBLISH`).
- CHANGELOG 1.7.0 entries each map to a shipped change (doctor, playbook, release ritual, resources, wheel smoke, backfilled tags, three fixes).
- `release_gate.sh` marker scan clean.
- Note: PROGRESS_LOG's "337 passed, 2 skipped" for 1.7.0 is confirmed by this audit's fresh run (same count).
