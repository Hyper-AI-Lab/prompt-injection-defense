# Slice D — docs claim scrub

**Method:** local executor. `rg -n -i "pypi|pip install 'containment|pip install \"containment"`
across README, SKILL.md, docs/, CHANGELOG, src/, box skill; checked SOTA / certification wording
and that every "released"/"attached" claim is true after step 8.

## Findings

| ID | Severity | Finding | Evidence | Fix |
| --- | --- | --- | --- | --- |
| D-1 | HIGH | Install hints `pip install "containment[crypto]"` / `[redis]` / `[ml]` resolve the name `containment` from **PyPI**, where this project is not published and the name is unclaimed. Anyone registering it would receive these installs (name-squat supply-chain path). | `src/containment/intent.py` L189/L209/L265; `capability_store_redis.py` L54; `doctor.py` `_EXTRAS`; `docs/AGENT_INSTALL.md` L122; `docs/BOT_PLAYBOOK.md` L81; `docs/HOST_HARDENING.md` L97 | Every hint names the GitHub source: `containment[x] @ git+https://github.com/Hyper-AI-Lab/prompt-injection-defense.git` (doctor pins `@v<version>`); docs pin `@v1.7.0` |
| D-OK | — | No PyPI presence claim; README/SKILL/AGENT_INSTALL/playbook/box skill say "not on PyPI" | rg output | — |
| D-OK | — | No SOTA / certification claims added; eval numbers scoped to fixture suite | CHANGELOG header, playbook §9 | — |

Verdict: 1 ISSUE (D-1).
