# Slice C — containment doctor correctness + JSON

**Verdict:** ISSUES (G1 MED, G2 MED, G3 LOW)

Ran from a throwaway venv with the release wheel (outside the checkout):
- `doctor --install-only` → 2/2, exit 0; JSON `ok=true scope=install residuals=[]`.
- `doctor` (nothing declared) → 2/8, exit 1, four `HostChecklist` codes verbatim.
- full host (file secrets, isolation, pinned, audit ship) → 8/8, exit 0, compose PASS.
- bad policies (non-list rules, missing effect, broken YAML, missing file) → `install.policy` FAIL, exit 1, valid JSON.
- argparse conflicts (`--egress-pinned --egress-proxy`) → exit 2.

Defects:
- **G1 (MED)** secret file mode 000 → `FileSecretProvider.get_bytes` raises `PermissionError`; doctor only catches `SecretError` → traceback, `--json` prints nothing. Monitoring that parses JSON gets no report.
- **G2 (MED)** `--egress-proxy http://u:pw@h:1` (or `CONTAINMENT_EGRESS_PROXY`) → `host.egress: proxy http://u:pw@h:1` in human and JSON output. Module docstring and docs say secret values are never printed.
- **G3 (LOW)** `http://[::1` → `ValueError: Invalid IPv6 URL` traceback; `"  "` → `ValueError: proxy url must be a non-empty string` traceback; `http://h:99999` → PASS (port never parsed).

Fix: validate the proxy URL (scheme, host, port) before building `ProxyEgressProvider`, redact userinfo in details, catch `OSError` with `SecretError` on secret loads. Tests for each.
