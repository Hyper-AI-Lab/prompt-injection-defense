# Mutation eval split (frozen)

Rule (`containment.mutation_eval.case_split`): a case id is **holdout** iff
`int(sha256(case_id), 16) % 3 == 0`, else **train**. The same rule applies to benign fixture
stems. Detector thresholds and fusion weights may be tuned on `train` only.

Held-out attack cases (18 of 64): direct_hitl_urgency_approve, direct_json_tool_call,
direct_multi_lang, direct_new_system, direct_override_safety, direct_policy_delete,
encoded_hex_payload, encoded_morse_transfer, encoded_url_escape,
indirect_constraint_steering_fallback, indirect_csv_cell, indirect_email_thread,
indirect_goal_decomposition_diagnostics, indirect_mcp_tool_description_log_to_leak,
indirect_session_state_spoof_compaction, indirect_web_fetch_body, invisible_rlo_filename,
invisible_zwnj_payload.

Families per case: `original`; hand-written `reword`, `indirect`, `ru`, `ja`
(`paraphrases.yaml`); generated `synonym`, `split`, `b64`, `hex`, `url_escape`, `rot13`,
`md_wrapper`, `html_comment`, `css_class`.
