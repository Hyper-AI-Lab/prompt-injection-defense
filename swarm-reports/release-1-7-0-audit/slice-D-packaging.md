# Slice D — resources + packaging (wheel / sdist)

**Verdict:** ISSUES (G5 LOW)

- Local `python -m build` at `8d18e31` content is **bit-identical** to the release assets: wheel `197e671c…7c50`, sdist `7f01cecd…513b` (sha256 equal to GitHub asset digests). `twine check --strict` PASSED both.
- Wheel: 148 files, 94 under `containment/_data/` (= 94 tracked files in `policies/` + `fixtures/`); same file list as the release wheel.
- `resources.data_path` prefers `_data`, falls back to checkout; tests cover both. Wheel venv: doctor, eval card (gate=PASS), reference host 3/3, `containment-claude-hook` loads the shipped policy.
- Extras from a local wheel path (`'./containment-1.7.0-py3-none-any.whl[crypto]'`) install and doctor reports `extra.crypto` pass — playbook line is correct.
- **G5 (LOW)** sdist `include` has `/tests` but not `/scripts`: unpacked 1.7.0 sdist `pytest` → **327 passed, 2 skipped, 10 errors** (`tests/test_cut_release.py` cannot find `scripts/cut_release.sh`). Fix: add `/scripts` to the sdist include + test.
