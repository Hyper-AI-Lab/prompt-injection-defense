# Slice B — BOT_PLAYBOOK + skills vs vision G

**Method:** local executor. Walked the playbook top to bottom against the code: imports, function
signatures, policy rule ids, CLI flags; ran the §5 example (also locked as
`tests/test_bot_playbook.py`, 3 passed); parsed both skills' content; checked box skill frontmatter.

## Vision G matrix

| Item | Status | Evidence |
| --- | --- | --- |
| install → policy → ingest → broker → adapters → reference host → eval card → host residuals | PRESENT | §1–§9 (+ §4 plan, §7 doctor, §10 upgrade) |
| Concrete, runnable (not prose) | PRESENT | §5 example executed: deny `no-tainted-egress`, allow fetch, `require_human approved-email`, approve → sent |
| Repo `SKILL.md` refreshed A–E + doctor | PRESENT | `@v1.7.0` pin, Host check section, references lead with playbook |
| Box skill refreshed, frontmatter valid | PRESENT | `yaml.safe_load` OK; name unchanged; v1.7.0 pin; broker/registry/intent/hook/ref host/doctor/card |
| Doctor flags in docs == CLI | PRESENT | §7 flags `--secrets-dir --isolation-declared --egress-pinned --audit-ship` exist in `cli.py` |
| `IngestResult.extract.data`, `read_posts(sort=...)` | PRESENT | `ingest.py` L32; `moltbook.read_posts(sort: str)` |

## Findings

| ID | Severity | Finding | Evidence | Fix |
| --- | --- | --- | --- | --- |
| B-1 | → D-1 | §3 tells readers `pip install 'containment[ml]'` (resolves from PyPI) | BOT_PLAYBOOK L81 | Folded into D-1 |
| B-2 | → A-1 | §1 verify command not bound to the tag | BOT_PLAYBOOK §1 | Folded into A-1 (add `--source-ref`) |

Verdict: no slice-local ISSUE; two cross-slice items folded into A-1 / D-1.
