# Slice C — doctor CLI integrity / unfinished markers

**Method:** local executor. Read `doctor.py` + `cli.py` diff; ran `tests/test_doctor.py`
(15 passed); live CLI in checkout and from a clean-venv wheel; unfinished-marker `rg` on
`src/containment/doctor.py src/containment/resources.py src/containment/cli.py`: clean.

## Integrity checks

| Check | Result |
| --- | --- |
| Reuses `HostChecklist` (codes verbatim), real providers, `build_enterprise_host` | PASS |
| Hermetic: no network; compose uses temp audit log; ship destination untouched | PASS (test asserts dir not created) |
| Secret values never printed (text + JSON) | PASS (test) |
| Exit codes 0 / 1 / 2 | PASS (CLI tests) |
| Policy errors (missing file, YAML error, wrong root) caught as `install.policy` fail | PASS (`OSError, ValueError, TypeError, KeyError, yaml.YAMLError`) |
| `--install-only` works from wheel outside checkout | PASS (`OK — 2/2`) |

## Findings

| ID | Severity | Finding | Evidence | Fix |
| --- | --- | --- | --- | --- |
| C-1 | LOW | JSON report carries host `residuals` even for `scope=install`, while human output shows them only for host scope (two renderings disagree) | `DoctorReport.residuals` default always `HOST_RESIDUALS`; `format_report` gates on scope | `run_doctor` sets `residuals=()` for install scope; test asserts |
| C-2 | → D-1 | extra install hints are bare `pip install 'containment[x]'` | `_EXTRAS` hints | Folded into D-1 |

Verdict: 1 ISSUE (C-1).
