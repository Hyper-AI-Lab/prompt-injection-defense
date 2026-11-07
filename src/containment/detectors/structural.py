"""Wording-independent intent signals for untrusted text (zero dependencies).

Instead of matching attack phrases, each window of text (a sentence plus its neighbour) is
tagged with *categories* — who the text addresses, what it asks for, and what it targets —
and a finding is raised only when categories combine the way an injection does: an AI
reader + a privileged action, secrets + an outbound verb + a destination, a claim of
authority + a privileged action, an instruction to discard prior instructions, concealment
from the user, a role switch + a sensitive target, "decode this and obey", "merge the parts
and act". Each category is a multilingual lexicon (EN, RU, JA, DE, FR, ES, ZH, PT, IT), so a
rewording, a synonym or a translation still lands in the same category.

This is still a heuristic: it is the zero-dependency fallback and a fusion input for the
ML classifier (``onnx_classifier``), not a guarantee. Policy remains the authority.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass


def _rx(*parts: str) -> re.Pattern[str]:
    return re.compile("|".join(f"(?:{p})" for p in parts if p), re.IGNORECASE)


_NEG_EN = (
    r"(?:\b(?:never|not|don't|do\s+not|doesn't|mustn't|must\s+not|shouldn't|should\s+not|"
    r"no\s+need\s+to|cannot|can't|won't|ask\s+you\s+to)\s+(?:\w+\s+){0,3})"
)

# --- category lexicons -----------------------------------------------------------------

# Discarding prior instructions: verb near an "instructions" noun (either order), or the
# noun declared void.
_DISCARD_VERB = _rx(
    r"\b(?:ignore|ignoring|disregard|forget|discard|drop|override|overrule|bypass|skip|suspend|"
    r"retire|void|cancel|revoke|supersede|throw\s+out|set\s+aside|pay\s+no\s+(?:attention|heed)|"
    r"never\s+mind|stop\s+(?:following|honou?ring|obeying)|no\s+longer\s+(?:follow|obey|honou?r))\w*",
    r"игнорир\w*|забуд\w*|забыть|не\s+обращай|не\s+обращать|отмен\w*|пропуст\w*|обой\w*|"
    r"перестань|не\s+соблюда\w*|не\s+следуй",
    r"無視|忘れ|破棄|従わ|従うのをやめ|スキップ|上書き|取り消|気にせず|気にしない",
    r"\b(?:ignorier\w*|vergiss|vergessen|missacht\w*|olvida\w*|ignora\w*|oublie\w*|"
    r"esqueça|esquece\w*|dimentica\w*|desconsider\w*)",
    r"忽略|无视|忘记|忘掉|不要遵守|取消",
)
# Scope qualifiers that mark an instruction-noun as the agent's *governing* instructions
# ("all previous instructions", "your earlier rules"), separating injections from prose that
# merely mentions a policy or a check.
_INSTR_QUALIFIER = _rx(
    r"\b(?:previous|prior|earlier|above|preceding|former|initial|original|existing|current|"
    r"all\s+(?:the\s+|your\s+)?|any\s+(?:earlier|previous|prior)\s+|your|these|those|"
    r"the\s+(?:system|safety|security|operating))\b",
    r"\b(?:предыдущ\w*|прежн\w*|ранее|ран\w*|все\s+\w*|свои\w*|эти\w*|систем\w*)",
    r"以前|前の|すべて|全ての|これまで|元の|従来|先ほど",
)
_INSTR_NOUN = _rx(
    r"\b(?:instructions?|directions?|directives?|rules?|guidelines?|guidance|polic(?:y|ies)|"
    r"prompts?|restrictions?|limits?|limitations?|safeguards?|guardrails?|constraints?|"
    r"allowlists?|safety|security\s+(?:rules?|checks?)|checks?|verification|least[\s-]privilege|"
    r"(?:operating|earlier|previous|prior|original)\s+(?:rules?|setup|configuration|instructions?)|"
    r"(?:what|whatever|everything|anything)\s+you\s+(?:were|have\s+been|got)\s+"
    r"(?:told|instructed|given))\b",
    r"инструкци\w*|указани\w*|правил\w*|политик\w*|ограничени\w*|промпт\w*|установк\w*|"
    r"проверк\w*|подтвержден\w*|безопасност\w*|привилеги\w*",
    r"指示|ルール|ポリシー|制限|プロンプト|規則|指令|安全|確認|承認|許可リスト",
    r"\b(?:anweisungen|regeln|richtlinien|vorgaben|instrucciones|reglas|normas|consignes|"
    r"règles|instruções|regras|istruzioni|regole)\b",
    r"指令|指示|规则|提示词|限制",
)
_VOID_STATE = _rx(
    r"\b(?:instructions?|directions?|directives?|rules?|guidelines?|guidance|polic(?:y|ies)|"
    r"restrictions?|limits?|safeguards?|prompt|configuration|setup)\b[^.\n]{0,40}?\b(?:are|is|were|was"
    r"|have\s+been|has\s+been)\s+(?:now\s+)?(?:void|retired|cancel+ed|withdrawn|lifted|suspended|"
    r"superseded|replaced|revoked|obsolete|no\s+longer\s+(?:valid|in\s+effect|appl(?:y|ies)))",
    r"\b(?:instructions?|directions?|directives?|rules?|guidelines?|guidance|polic(?:y|ies)|"
    r"restrictions?|safeguards?|allowlists?)\b[^.\n]{0,40}?\b(?:no\s+longer|do(?:es)?n't|do(?:es)?\s+not)\s+"
    r"appl(?:y|ies)",
    r"\b(?:previous|prior|earlier|original)\s+(?:instructions?|directions?|rules?|guidance|"
    r"guidelines?|polic(?:y|ies)|directives?)\b[^.\n]{0,30}?\b(?:void|notwithstanding|"
    r"no\s+longer)",
    r"(?:инструкци|правил|ограничени)\w*\s+(?:больше\s+)?не\s+(?:действу|применя)\w*",
    r"(?:Anweisungen|Regeln)\s+gelten\s+nicht\s+mehr",
)

# The text addresses an AI reader.
_AI = _rx(
    r"(?-i:\bAI\b)|\b(?:a\.i\.|llms?|language\s+models?|chat\s?bots?|ai\s+(?:agents?|assistants?|models?|"
    r"summari[sz]ers?|tools?)|assistants?|(?:automated|autonomous|browsing|shopping)\s+"
    r"(?:agents?|assistants?|clients?|tools?)|the\s+(?:model|agent|bot)|calling\s+agent|"
    r"reading\s+(?:model|assistant|agent)|whoever\s+(?:reads|processes|summari[sz]es|handles)|"
    r"the\s+reader|readers\s+that\s+are|any\s+ai)\b",
    r"\b(?:ии|ии-ассистент\w*|ассистент\w*|нейросет\w*|агент\w*|модел[ьи])\b",
    r"アシスタント|エージェント|モデル|ボット|(?-i:(?<![A-Za-z])AI(?![A-Za-z]))",
    r"\b(?:assistent\w*|asistente|assistant[e]?|agente|ki-assistent)\b",
    r"助手|智能体|模型",
)
# Obligation / request markers (directive mood).
_DIRECTIVE = _rx(
    r"\b(?:must|should|shall|need\s+to|needs\s+to|have\s+to|has\s+to|is\s+to|are\s+to|"
    r"(?:is|are)\s+(?:expected|required|asked|meant|cleared|permitted|allowed)\s+to|"
    r"please|kindly|immediately|now|right\s+away|at\s+once)\b",
    r"\b(?:должен|должна|должны|обязан\w*|необходимо|нужно|надо|пожалуйста|немедленно|срочно)\b",
    r"してください|ください|しなさい|せよ|必ず|今すぐ|直ちに|なければなりません",
    r"\b(?:bitte|muss|müssen|debe|deben|por\s+favor|doit|doivent|veuillez|deve|devono|per\s+favore)\b",
    r"请|必须|立即",
)
_SECRET = _rx(
    r"\.env\b|secrets?\.(?:json|ya?ml|toml)|~/\.(?:aws|ssh)\b|\bid_(?:rsa|ed25519|ecdsa)\b|"
    r"/etc/(?:passwd|shadow)\b|\bdocument\.cookie\b|security-credentials",
    r"\b(?:secrets?|credentials?|passwords?|passphrases?|api[\s_-]?keys?|access\s+keys?|keys|"
    r"tokens?|seed\s+phrases?|private\s+keys?|mnemonic|vault|password\s+vault|login\s+details|"
    r"environment\s+(?:variables?|secrets?)|env\s+vars?|card\s+(?:details|number)|"
    r"saved\s+(?:card|payment)|(?:system|hidden|setup|configuration|developer)\s+prompt|"
    r"private\s+(?:data|notes|records)|personal\s+notes|confidential\s+values)\b",
    r"секрет\w*|парол\w*|ключ\w*|токен\w*|учётн\w*|учетн\w*|реквизит\w*|хранилищ\w*|"
    r"переменн\w*\s+окружени\w*|системн\w*\s+промпт\w*|личн\w*\s+(?:данн|заметк)\w*|данные\s+карт\w*",
    r"秘密|パスワード|キー|認証情報|トークン|保管庫|環境変数|システムプロンプト|カード情報|個人メモ|"
    r"個人データ",
    r"\b(?:geheimnisse|passwort|secretos|contraseñas?|claves|segredos|segreti|chiavi)\b",
    r"秘密|密钥|密码|凭证",
)
_EXFIL = _rx(
    r"\b(?:send|sends|sending|forward|forwards|upload|uploads|post|posts|mail|mails|e-?mail|"
    r"emails|transmit|leak|leaks|exfiltrat\w*|publish|paste|export|dump|print|reveal|display|"
    r"output|recite|repeat|show|list|ship|push|submit|enter|type|share|smuggle|spill|collect|"
    r"bundle|gather|copy|wire)\b",
    r"\b(?:отправ\w*|пересл\w*|перешл\w*|загруз\w*|сле(?:й|йте)|выгруз\w*|опубликуй\w*|покаж\w*|"
    r"выведи\w*|вставь\w*|перечисл\w*|введи\w*|собер\w*|соберите|переда\w*|верни\w*)",
    r"送信|送って|送る|送付|アップロード|流出|公開|表示|出力|貼り付け|入力|転送|POST",
    r"\b(?:sende|senden|envía|envia|envoie|envoyer|invia|enviar|weiterleiten|publica)\w*",
    r"发送|上传|泄露|公开|显示",
)
_DEST = _rx(
    r"https?://\S+",
    r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b",
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    r"\b(?:publicly|public\s+mirror|external\s+(?:server|address))\b",
    r"(?<![.\w])[a-z0-9-]+\.(?:example|test|io|net|com|org|dev)\b(?!\.[a-z])",
)
_MONEY = _rx(
    r"\b(?:transfer|wire|move|send|pay|settle|push\s+through)\w*\b[^.\n]{0,40}?"
    r"(?:\b\d[\d,.]*\s*(?:usd|usdc|eur|btc|eth|dollars?)\b|\bfunds\b|\bmoney\b|\bbalance\b|"
    r"\bwallet\b|\baccount\s+\d+)",
    r"\bwallet\.transfer\b|\bsettlement\s+of\s+\d|\bwallet\s+(?:transfer|balance)\b",
    r"\b(?:bank\s+account|payout|payment\s+details|iban)\b[^.\n]{0,60}?\b(?:change|update|switch)",
    r"\b(?:change|update|switch)\w*\b[^.\n]{0,60}?\b(?:bank\s+account|payout|payment\s+details|"
    r"bank\s+details|iban)\b",
    r"перев\w*[^.\n]{0,40}?(?:usd|usdc|eur|\d+\s*(?:руб|долл)|деньг|средств|кошел)|"
    r"(?:обнови|измени)\w*[^.\n]{0,40}?реквизит",
    r"送金|振込口座[^。\n]{0,20}変更|口座[^。\n]{0,20}変更",
)
# Strong privileged action: a tool/shell call or executing a command (not a mere mention of
# "access"). Used by tight rules that must not fire on descriptive prose.
_PRIV_EXEC = _rx(
    r"\b(?:shell\.exec|email\.send|http\.post|wallet\.transfer|web\.fetch|fs\.write|file\.write)\b",
    r"\b(?:call|calls|invoke|invokes|run|runs|execute|executes|trigger|use|uses)\s+(?:the\s+)?"
    r"`?[a-z_][\w-]*\.[a-z_][\w-]*`?",
    r"\b(?:curl|wget)\b[^\n]{0,80}\|\s*(?:ba)?sh\b|\bcat\s+/etc/|\brm\s+-rf\b",
    r"\b(?:execute|run|launch)\w*\b[^.\n]{0,30}?\b(?:command|code|script|snippet|shell)\b",
    r"\b(?:shell|command[\s-]line)\s+(?:access|session|privilege)",
    r"(?:вызови|вызвать|запусти|используй)\w*\s+`?[a-z_][\w-]*\.[a-z_][\w-]*|"
    r"(?:запусти|выполни)\w*[^.\n]{0,30}?(?:shell|команд|код)\w*",
)
# Privilege escalation addressed as a request: grant yourself access, enable a tool, unlock
# admin. Requires an imperative/second-person frame to avoid "the viewer role grants access".
_PRIV_GRANT = _rx(
    r"\b(?:grant|unlock|enable|allow|permit|issue|mint|give)\s+(?:yourself|me|us|the\s+agent|"
    r"the\s+assistant)?\s*(?:\w+\s+){0,3}?\b(?:tools?|access|privileges?|capabilit\w*|"
    r"permissions?|shell|developer\s+mode|admin|root|sudo)\b",
    r"\b(?:click|open)\w*\b[^.\n]{0,40}?\b(?:banner|link|button)\b[^.\n]{0,80}?\b(?:card|password|"
    r"credentials?)\b",
    r"(?:выдай|разреши|включи|выпусти)\w*[^.\n]{0,40}?(?:инструмент|доступ|разрешени|токен|shell|"
    r"режим)\w*",
    r"許可して|有効に|付与|発行|実行して",
)
_PRIV = _rx(_PRIV_EXEC.pattern, _PRIV_GRANT.pattern)
# Named protections a document might ask the agent to switch off.
_PROTECTION = _rx(
    r"\bdefault[_\s-]?deny\b|\bguard[\s-]?rails?\b|\ballow[\s-]?lists?\b|\bwhite[\s-]?lists?\b|"
    r"\bdeny\s+rules?\b|\bsafety\s+(?:checks?|filters?|rules?|guardrails?)\b|"
    r"\bsecurity\s+(?:checks?|filters?|policy|policies|rules?|controls?)\b|\bsand\s?box(?:ing)?\b|"
    r"\bcontent\s+filters?\b|\bmoderation\b|\brate[\s-]?limit\w*\b|\bapproval\s+"
    r"(?:requirement|step|gate|check)s?\b|\bhuman\s+(?:approval|review|in[\s-]the[\s-]loop)\b|"
    r"\bthe\s+policy\b|\bthese\s+(?:checks?|rules?|guardrails?|protections?)\b|\bthe\s+filters?\b|"
    r"\bsafety\s+(?:instructions?|directions?)\b|\bpolicy\s+broker\b|\bprotections?\b|"
    r"\b(?:all\s+)?safety\s+rules?\b|\bsecurity\s+rules?\b|"
    r"\b(?:all\s+)?(?:safety|security)\s+(?:guidelines?|guards?|measures?|controls?|policies|policy)\b|"
    r"\b(?:every\s+)?safety\s+guideline\b",
    r"\b(?:default[_\s-]?deny|политик\w*\s+безопасн\w*|guardrail\w*|белый\s+список|"
    r"список\s+разрешени\w*|защитн\w*\s+(?:правил|фильтр)\w*|песочниц\w*|фильтр\w*\s+безопасн\w*|"
    r"проверк\w*\s+безопасн\w*|подтвержден\w*|правил\w*\s+безопасн\w*|политик\w*\s+безопасн\w*|"
    r"policy\s+broker|брокер\w*\s+политик)",
    r"デフォルト拒否|ガードレール|許可リスト|ホワイトリスト|安全(?:フィルター|チェック|対策)|"
    r"セキュリティ(?:フィルター|チェック|ポリシー)|サンドボックス|承認(?:要件|ステップ)|モデレーション|"
    r"安全(?:指示|ルール|規則)|ポリシーブローカー|保護(?:機能)?",
)
# Verbs that neutralise a protection.
_TAMPER_VERB = _rx(
    r"\b(?:disable|turn\s+off|switch\s+off|shut\s+(?:off|down)|erase|wipe|delete|remove|drop|strip|"
    r"clear|purge|deactivate|relax|loosen|weaken|lift|unset|circumvent|bypass|suspend|override|"
    r"kill|skip|get\s+around|work\s+around)\b",
    r"\b(?:отключ\w*|выключ\w*|удал\w*|сотр\w*|убер\w*|сним\w*|сброс\w*|обход\w*|обойд\w*|"
    r"ослаб\w*|отмен\w*)",
    r"無効|オフに|切って|削除|解除|回避|迂回|バイパス|緩和|止めて|外して|停止",
)
# Tool/function metadata asking the caller to copy conversation or user data elsewhere.
_SINK_VERB = _rx(
    r"\b(?:log|logs|logging|record|records|mirror|mirrors|forward|forwards|cc|bcc|copy|copies|"
    r"send|sends|sync|syncs|report|reports|relay|relays|capture|captures|transmit|transmits|"
    r"upload|uploads|post|posts|exfiltrat\w*|echo)\b",
    r"\b(?:логир\w*|записыва\w*|пересыла\w*|пересыл\w*|отправля\w*|отправ\w*|копир\w*|"
    r"зеркал\w*|синхрон\w*|переда\w*)",
    r"ログ|記録|ミラー|転送|送信|コピー|同期|報告",
)
_DATA_OBJ = _rx(
    r"\b(?:conversation|dialogue|chat\s+(?:history|log|transcript|messages)|transcript|"
    r"user(?:['\u2019]s)?\s+(?:quer(?:y|ies)|question|message|input|prompt|request|data)|"
    r"your\s+(?:full\s+)?(?:reply|response|answer)|server\s+(?:output|response)|agent\s+response|"
    r"full\s+(?:reply|response|dialog\w*|conversation)|the\s+complete\s+(?:conversation|dialog\w*)|"
    r"everything\s+(?:the\s+user|you)\s+\w+|each\s+(?:user\s+)?(?:message|request|answer)|"
    r"user_query|agent_response|server_response)\b",
    r"\b(?:диалог\w*|разговор\w*|перепис\w*|сообщени\w*\s+пользовател\w*|"
    r"запрос\w*\s+пользовател\w*|ввод\w*\s+пользовател\w*|полн\w*\s+диалог\w*|"
    r"ответ\w*\s+(?:пользовател|агент|сервер)\w*|user_query|agent_response|server_response)",
    r"会話|対話|ユーザー(?:の)?(?:入力|質問|メッセージ|リクエスト)|あなたの(?:返信|応答|回答)|"
    r"サーバー(?:出力|応答)|エージェント(?:の)?(?:応答|返信)|user_query|agent_response|server_response",
)
_SINK_DEST = _rx(
    r"https?://\S+|\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b",
    # A telemetry/logging-style tool whose method name is a recording/forwarding verb.
    r"\b[a-z_][\w.]*\.(?:record|capture|log|log_event|mirror|mirror_event|forward|sync|ingest|"
    r"collect|track|report|send)\b",
    r"\b(?:analytics|telemetry|audit|logging|logger|monitoring|tracking|metrics|intake|collector)"
    r"[\w.]*\b",
    r"\b(?:external|third[\s-]party|remote)\s+(?:endpoint|service|server|webhook|sink|collector)\b",
    r"\bаналитик\w*|телеметри\w*|audit_logger|\bсервис\s+\w+",
    r"telemetry[\w.]*|audit_logger|analytics[\w.]*",
)

_BYPASS = _rx(
    r"\b(?:skip|skipping|bypass|without|drop|dropped|no|don't\s+wait|not\s+wait|"
    r"don't\s+bother\s+waiting)\b[^.\n]{0,30}?\b(?:approval|sign[\s-]?off|mfa|verification|"
    r"human|asking\s+anyone|confirm\w*|re-?asking)\b",
    r"\b(?:approval|sign[\s-]?off|mfa|verification)\s+(?:step\s+)?(?:is\s+)?(?:dropped|skipped|"
    r"waived|not\s+needed|omitted)",
    r"без\s+(?:подтвержден|одобрен|проверк)\w*|не\s+жди\w*\s+подтвержден\w*|пропусти\w*\s+mfa",
    r"承認なし|承認は?省略|確認なし|MFAは?省略|人間による承認は省略",
)
_TOOL_CALL = _rx(
    r"\b(?:call|calls|invoke|invokes|use|uses|run|runs|trigger)\s+(?:the\s+)?"
    r"(?:`?[a-z_][\w-]*\.[a-z_][\w-]*`?|\w+\s+tool)\b",
    r"(?:вызови|вызвать|запусти|используй)\w*\s+`?[a-z_][\w-]*\.[a-z_][\w-]*",
    r"[a-z_]+\.[a-z_]+\s*(?:を|で)\s*(?:呼び出|実行|使)",
)
_SELF = _rx(r"\byourself\b|\bits\s+own\b|\bсебе\b|自分|自身")
_DISCUSSION = _rx(
    r"\battackers\b|\ban\s+attacker\b|\bprompt[\s-]?injection|\binjection\s+(?:attack|example|payload)|"
    r"\bjailbreak\w*|\bred[\s-]team\w*|\battacker-controlled\b|"
    r"\bfor\s+example\b|\be\.g\.|\bsuch\s+as\b|\bred\s+flags?\b|\bsocial\s+engineering\b|"
    r"\bphishing\b",
    r"промпт-инъекц\w*|злоумышленник\w*|например|фишинг\w*",
    r"プロンプトインジェクション|例えば|手口|フィッシング",
)
_CODE_EXFIL = re.compile(
    r"(?:https?://[^\s\"'`]{1,200}[^\n]{0,150}?\b(?:to_json|to_csv|to_dict|json\.dumps|os\.environ|"
    r"getenv|document\.cookie|localStorage|read_text|b64encode|process\.env)\b)|"
    r"(?:\b(?:to_json|to_csv|document\.cookie|os\.environ|process\.env)\b[^\n]{0,150}?https?://)",
    re.IGNORECASE,
)

_AUTH = _rx(
    r"\bSYSTEM\s*(?::|message|update|notice|prompt\s+override)|\bOPERATOR\b|\bADMIN\b|"
    r"\b(?:root|sudo)\s*:",
    r"\b(?:developer|debug|god|unrestricted)\s+mode\b|\b(?:ceo|chief\s+executive|cfo)\b",
    r"\bpre-?(?:approved|cleared|authori[sz]ed)\b|\balready\s+(?:approved|authori[sz]ed|cleared|"
    r"confirmed|verified|recorded)\b|\b(?:consent|approval|authori[sz]ation)\s+(?:is\s+)?"
    r"(?:on\s+record|recorded|granted)\b|\bsigned\s+off\b|\b(?:has|have)\s+(?:prior\s+)?clearance\b",
    r"\b(?:verified|trusted)\s+(?:sender|vendor|administrator|admin)\b|\bsupersedes?\b|"
    r"\bnew\s+(?:system\s+)?(?:prompt|configuration|directive)\b|\bconfiguration\s+has\s+been\s+"
    r"replaced\b|\brestrictions?\s+(?:are|is)\s+lifted\b|\bunrestricted\b|\bwithout\s+(?:any\s+)?"
    r"(?:restrictions|limits|rules)\b|\bno\s+(?:limits|rules|restrictions)\b|\boverride\b",
    r"\[?(?:internal\s+reasoning|assistant's\s+notes)\]?",
    r"СИСТЕМА|систем\w*\s+промпт|одобрен\w*|разрешен\w*\s+без|генеральн\w*\s+директор|"
    r"без\s+ограничений|ограничения\s+сняты|режим\w*\s+(?:разработчика|отладки)",
    r"システム|承認済|管理者|開発者モード|デバッグモード|制限は解除|制限なし|CEO",
)
_CONCEAL = _rx(
    r"\b(?:do\s+not|don't|never|without)\s+(?:mention\w*|tell\w*|inform\w*|notify\w*|disclos\w*|"
    r"call(?:ing)?\s+out|flag\w*|report\w*|asking|alert\w*)\b",
    r"\bleave\s+(?:this|it|the\s+\w+)\s+(?:note\s+)?out\b|\bquietly\b|\bsilently\b|"
    r"\bnot\s+(?:be\s+)?mention(?:ed)?\b|\bwithout\s+telling\b|\bnever\s+mention\b",
    r"не\s+упомина\w*|не\s+сообща\w*|тихо|молча|без\s+уведомлени\w*|не\s+спрашива\w*",
    r"触れない|書かない|黙って|伝えない|言わない|再確認しない",
)
_ROLE = _rx(
    r"\byou\s*(?:are|'re)\s+now\b|\bfrom\s+(?:here|now)\s+on\s+you\b|\bpretend\b|\bact\s+as\b|"
    r"\bplays?\s+(?:the\s+role|a|an|the\s+character)\b|\brole[\s-]?play\b|\blet's\s+play\b|"
    r"\bimagine\s+you\b|\bswitch\s+into\b|\bin\s+this\s+exercise\b",
    r"\bты\s+теперь\b|\bтеперь\s+ты\b|представь|сыгра\w*|роль\w*",
    r"あなたは今から|として振る舞|ロールプレイ|なりきって",
)
_LEAK_OBJ = _rx(
    r"\b(?:system|hidden|setup|configuration|initial|developer|concealed|confidential|"
    r"original)\s+(?:prompt|instructions?|message|config\w*)\b|\bprompt\s+you\s+were\s+"
    r"(?:configured|started|given)\b|\bconfiguration\s+prompt\b",
    r"системн\w*\s+(?:промпт|инструкци)\w*|скрыт\w*\s+(?:промпт|инструкци)\w*|промпт\w*\s+разработчик\w*",
    r"システムプロンプト|システム指示|開発者プロンプト|隠された.{0,6}指示",
)
_LEAK_VERB = _rx(
    r"\b(?:print|show|reveal|repeat|recite|output|display|dump|leak|reproduce|verbatim|word\s+for\s+word)",
    r"покаж\w*|выведи|повтори\w*|дословно|раскро\w*",
    r"表示|出力|繰り返|そのまま",
)
_SUPPRESS = _rx(
    r"\b(?:words?|phrases?)\b[^.\n]{0,80}?\b(?:forbidden|banned|not\s+allowed|prohibited)\b",
    r"\b(?:never|no)\s+(?:include|use|add)?\s*(?:apolog\w*|caveats?|disclaimers?|refusals?|warnings?)",
    r"\b(?:replies|answers?|responses?)\b[^.\n]{0,60}?\b(?:rejected|invalid|discarded)\b",
    r"нельзя\s+использовать\s+слова|недействительн\w*",
    r"使用禁止|無効です",
)
_DECODE = _rx(
    r"\b(?:decode|decoding|decoder|unpack|unwrap|un-?hex|translate\s+(?:this\s+)?from\s+morse|"
    r"rot-?13\s+this|base64-?decode|inflate)\w*",
    r"раскодир\w*|декодир\w*|расшифр\w*",
    r"デコード|解読",
)
_OBEY = _rx(
    r"\b(?:follow|obey|comply|do\s+(?:exactly\s+)?what\s+it\s+says|carry\s+(?:it\s+)?out|"
    r"execute|act\s+on|apply|run\s+it|honou?r|do\s+exactly|be\s+followed|act\s+on\s+it)\w*",
    r"выполн\w*|следуй\w*|подчиня\w*",
    r"従って|従え|その通り",
)
_MERGE = _rx(
    r"\b(?:join|merge|combine|concatenate)\w*\b[^\n]{0,120}?\b(?:act|follow|obey|carr(?:y|ied)\s+out|"
    r"execute|before\s+(?:acting|following))",
    r"\b(?:continuation|completes?)\s+(?:of\s+)?this\s+instruction",
    r"объедин\w*[^\n]{0,80}?выполн\w*|продолжени\w*\s+этого\s+набора",
    r"結合して|続きとして",
)

# Multi-step exfiltration: a "collect sensitive data" step and a "transmit to outside" step,
# which on their own look harmless but together are a staged injection.
_COLLECT_VERB = _rx(
    r"\b(?:read|gather|collect|bundle|compile|copy|enumerate|locate|grab|dump|archive|assemble|"
    r"pull|list|harvest|scan|aggregate)\w*",
    r"\b(?:собер\w*|собрать|прочита\w*|считай\w*|найди\w*|скопир\w*|перечисл\w*|собира\w*)",
    r"集め|読み|読んで|取得|収集|まとめ|コピー|列挙",
)
_TRANSMIT_VERB = _rx(
    r"\b(?:send|sends|upload|uploads|post|posts|forward|forwards|transmit|transmits|sync|syncs|"
    r"submit|submits|wire|exfiltrat\w*|leak|leaks|ship|ships|push|pushes|deliver|delivers|mail|"
    r"mails|e-?mail|emails|hand\s+over|pass\s+along)\b",
    r"\b(?:отправ\w*|пересл\w*|перешл\w*|загруз\w*|выгруз\w*|переда\w*|опубликуй\w*)",
    r"送信|送って|送る|送付|アップロード|転送|提出|流出|POST|post|ポスト",
)
_EMBED_OBEY = _rx(
    r"\bapply\s+(?:it|this|that|the\s+(?:quoted|following|above|below))\b|"
    r"\bcarry\s+(?:it\s+)?out\b|\bact\s+on\s+(?:it|this|the\s+(?:quoted|following|above))\b|"
    r"\bexecute\s+(?:it|this|that|the\s+(?:quoted|following|payload|string))\b|"
    r"\bdo\s+(?:exactly\s+)?what\s+(?:it|the\s+(?:quoted|following|payload|string))\s+says\b|"
    r"\breproduce\s+(?:its|the)\s+(?:effect|payload|behaviou?r)\b|"
    r"\bfollow\s+the\s+(?:quoted|following|above|below)\b|"
    r"\btreat\s+(?:the\s+)?(?:quoted|following|below|above|this)[^.\n]{0,30}?(?:as|your)"
    r"[^.\n]{0,25}?(?:directive|instruction|rule|command|order)\b|"
    r"\bwhatever\s+the\s+(?:quoted|following)\s+(?:payload|string|line|text)\s+says\b",
    r"выполни\s+(?:это|следующ\w*|указанн\w*|приведённ\w*)|примени\s+(?:это|следующ\w*)|"
    r"действуй\s+согласно|сдела\w*\s+то,\s+что",
    r"実行して|その通りにして|従ってください|書かれていることを実行",
)

_QUOTED = re.compile(r'"[^"\n]{3,300}"|“[^”\n]{3,300}”|«[^»\n]{3,300}»|「[^」\n]{3,300}」')
_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+|[。！？\n]+")
_NEG_BEFORE = re.compile(_NEG_EN + r"$", re.IGNORECASE)
_NEG_RU_BEFORE = re.compile(r"(?:\bне|\bникогда\s+не)\s+$", re.IGNORECASE)
_NEG_JA_AFTER = re.compile(r"^.{0,4}(?:ないで|しない|禁止|ません|ないこと)")


@dataclass(frozen=True, slots=True)
class IntentHit:
    """One window's categories and the combination rule that fired (if any)."""

    rule: str
    categories: frozenset[str]
    preview: str


def _positive(pattern: re.Pattern[str], text: str) -> bool:
    """True when ``pattern`` occurs in ``text`` at least once without a nearby negation."""
    for match in pattern.finditer(text):
        before = text[max(0, match.start() - 40) : match.start()]
        after = text[match.end() : match.end() + 8]
        if _NEG_BEFORE.search(before) or _NEG_RU_BEFORE.search(before):
            continue
        if _NEG_JA_AFTER.search(after):
            continue
        return True
    return False


_AUTH_CLAIM = _rx(
    r"\bSYSTEM\s*(?::|message|update|notice|prompt\s+override)|\bOPERATOR\b",
    r"\bpre-?(?:approved|cleared|authori[sz]ed)\b|\balready\s+(?:approved|authori[sz]ed|cleared|"
    r"confirmed|verified|recorded)\b|\b(?:consent|approval|authori[sz]ation)\s+(?:is\s+)?"
    r"(?:on\s+record|recorded|granted)\b|\bsigned\s+off\b|\b(?:has|have)\s+(?:prior\s+)?clearance\b",
    r"\bsupersedes?\b|\bnew\s+(?:system\s+)?(?:prompt|configuration|directive)\b|"
    r"\bconfiguration\s+has\s+been\s+replaced\b|\brestrictions?\s+(?:are|is)\s+lifted\b|"
    r"\b(?:verified|trusted)\s+(?:sender|vendor|administrator|admin)\b",
    r"\[?(?:internal\s+reasoning|assistant's\s+notes)\]?",
    r"систем\w*\s+промпт|одобрен\w*|разрешен\w*\s+без|предварительно\s+одобрен\w*|"
    r"ограничения\s+сняты",
    r"システム(?:：|:|メッセージ|通知)|承認済|事前承認|制限は解除",
)

# A spoofed privilege banner at the start of a line: "root:", "sudo:", "SYSTEM:".
# Distinct from role *nouns* (e.g. "cluster-admin") so it does not fire on ordinary prose.
_AUTH_PREFIX = re.compile(
    r"""(?:^|[\s=\[\](){}>"'?&])(?:root|sudo|system|administrator|operator)\s*:""",
    re.IGNORECASE,
)


def _categories(window: str) -> set[str]:
    cats: set[str] = set()
    if _VOID_STATE.search(window) or (
        _near(_DISCARD_VERB, _INSTR_NOUN, window, 60)
        and (_INSTR_QUALIFIER.search(window) or _DIRECTIVE.search(window))
    ):
        cats.add("override")
    for name, pattern in (
        ("ai", _AI),
        ("directive", _DIRECTIVE),
        ("secret", _SECRET),
        ("dest", _DEST),
        ("auth", _AUTH),
        ("conceal", _CONCEAL),
        ("role", _ROLE),
        ("suppress", _SUPPRESS),
        ("merge", _MERGE),
        ("bypass", _BYPASS),
        ("self", _SELF),
        ("tool_call", _TOOL_CALL),
        ("obey", _OBEY),
    ):
        if pattern.search(window):
            cats.add(name)
    if _positive(_EXFIL, window):
        cats.add("exfil")
    if _positive(_MONEY, window):
        cats.add("money")
    if _positive(_PRIV, window):
        cats.add("priv")
    if _positive(_PRIV_EXEC, window):
        cats.add("priv_exec")
    if _AUTH_CLAIM.search(window):
        cats.add("auth_claim")
    if _AUTH_PREFIX.search(window):
        cats.add("auth_prefix")
    if _policy_tamper(window):
        cats.add("policy_tamper")
    if _tool_meta_exfil(window):
        cats.add("tool_meta_exfil")
    if _near(_LEAK_VERB, _LEAK_OBJ, window, 80):
        cats.add("leak")
    if _near(_DECODE, _OBEY, window, 80):
        cats.add("decode_obey")
    if _CODE_EXFIL.search(window):
        cats.add("code_exfil")
    if _secret_send(window):
        cats.add("secret_send")
    return cats


_SEND_THEN_SECRET = re.compile(
    r"(?:" + _EXFIL.pattern + r")[^.\n]{0,80}?(?:" + _SECRET.pattern + r")", re.IGNORECASE
)
# Object-before-verb order (Japanese, Russian word order): secret then outbound verb.
_SECRET_THEN_SEND_CJK = re.compile(
    r"(?:" + _SECRET.pattern + r")[^。\n]{0,40}?"
    r"(?:送信|送って|送る|送付|アップロード|流出|公開|転送)",
    re.IGNORECASE,
)


def _secret_send(window: str) -> bool:
    """An outbound verb whose object (within 80 chars after it) is a secret."""
    for match in _SEND_THEN_SECRET.finditer(window):
        before = window[max(0, match.start() - 40) : match.start()]
        if _NEG_BEFORE.search(before) or _NEG_RU_BEFORE.search(before):
            continue
        span = window[match.start() : match.end() + 12]
        if re.search(r"public\s+key|\.pub\b", span, re.IGNORECASE):
            continue  # the public half of a key pair is not a secret
        return True
    match = _SECRET_THEN_SEND_CJK.search(window)
    return bool(match and not _NEG_JA_AFTER.search(window[match.end() : match.end() + 8]))


# Inflected (past/passive/gerund) English tamper verbs: only actionable when the window is
# explicitly addressing the agent, so factual narrative ("the engineer disabled the limiter")
# is not mistaken for an instruction.
_TAMPER_INFLECTED = re.compile(
    r"\b(?:disabled|disabling|turned?\s+off|switched?\s+off|shut\s+off|erased|erasing|wiped|"
    r"wiping|deleted|deleting|removed|removing|dropped|dropping|stripped|cleared|clearing|purged|"
    r"deactivated|relaxed|loosened|weakened|lifted|unset|circumvented|bypassed|bypassing|"
    r"suspended|overrode|overridden|killed|skipped)\b",
    re.IGNORECASE,
)
_PROT_PAT = _PROTECTION.pattern
_TAMPER_PAT = _TAMPER_VERB.pattern
_TAMPER_ANY_PAT = _TAMPER_VERB.pattern + "|" + _TAMPER_INFLECTED.pattern
_DET = r"(?:the|all|any|our|your|these|those|every|each|a|an|its|this|том|той|тот|那|这|其)?"
# verb -> (det) (<=2 words) -> protection  (left-to-right imperative order)
_BIND_VO_BASE = re.compile(
    rf"(?:{_TAMPER_PAT})\W+{_DET}\s*(?:[\w-]+\s+){{0,2}}(?:{_PROT_PAT})", re.IGNORECASE
)
_BIND_VO_ANY = re.compile(
    rf"(?:{_TAMPER_ANY_PAT})\W+{_DET}\s*(?:[\w-]+\s+){{0,2}}(?:{_PROT_PAT})", re.IGNORECASE
)
# object-first with a particle (Japanese を/は, ·): "安全フィルターを無効にして" -> imperative.
_BIND_OV_JA = re.compile(
    rf"(?:{_PROT_PAT})[^。\n]{{0,6}}?(?:を|は|が)[^。\n]{{0,8}}?(?:{_TAMPER_PAT})", re.IGNORECASE
)
# English passive with an auxiliary: "the default_deny policy gets deleted" -> agent-gated.
_BIND_OV_PASSIVE = re.compile(
    rf"(?:{_PROT_PAT})(?:\s+[\w-]+){{0,2}}\s+(?:is|are|be|been|gets?|get|should\s+be|"
    rf"must\s+be|will\s+be|to\s+be)\s+(?:{_TAMPER_INFLECTED.pattern})", re.IGNORECASE
)


def _agent_frame(window: str) -> bool:
    return bool(_AI.search(window) or _DIRECTIVE.search(window) or _AUTH_PREFIX.search(window))


def _neg_at(window: str, start: int) -> bool:
    before = window[max(0, start - 40) : start]
    return bool(_NEG_BEFORE.search(before) or _NEG_RU_BEFORE.search(before))


def _policy_tamper(window: str) -> bool:
    """A tamper verb directly governs a named protection.

    Imperative base forms ('disable the guardrails', 'erase default_deny') fire on their own;
    inflected/passive forms ('the default_deny policy gets deleted') fire only when the window
    is addressed to the agent, so incident narrative is not read as an instruction.
    """
    for rx in (_BIND_VO_BASE, _BIND_OV_JA):
        for m in rx.finditer(window):
            if not _neg_at(window, m.start()) and not _NEG_JA_AFTER.search(
                window[m.end() : m.end() + 8]
            ):
                return True
    if _agent_frame(window):
        for rx in (_BIND_VO_ANY, _BIND_OV_PASSIVE):
            for m in rx.finditer(window):
                if not _neg_at(window, m.start()) and not _NEG_JA_AFTER.search(
                    window[m.end() : m.end() + 8]
                ):
                    return True
    return False


def _tool_meta_exfil(window: str) -> bool:
    """A sink verb whose object is conversation/user data and whose target is a tool/endpoint."""
    for m in _SINK_VERB.finditer(window):
        before = window[max(0, m.start() - 40) : m.start()]
        if _NEG_BEFORE.search(before) or _NEG_RU_BEFORE.search(before):
            continue
        after = window[m.end() : m.end() + 8]
        if _NEG_JA_AFTER.search(after):
            continue
        # Verb-final languages (JA) put the data object and destination before the verb,
        # so look both ways within a bounded window.
        near = window[max(0, m.start() - 200) : m.end() + 200]
        if _DATA_OBJ.search(near) and _SINK_DEST.search(near):
            return True
    return False


_NEAR_SPAN = 160


def _near(a: re.Pattern[str], b: re.Pattern[str], text: str, span: int) -> bool:
    b_pos = [m.start() for m in b.finditer(text)]
    if not b_pos:
        return False
    for m in a.finditer(text):
        before = text[max(0, m.start() - 40) : m.start()]
        if _NEG_BEFORE.search(before) and "override" not in m.group(0).lower():
            continue
        if any(-span <= p - m.start() <= span for p in b_pos):
            return True
    return False


_ACTIONS = frozenset({"priv", "money", "conceal", "override", "leak", "auth", "bypass"})
# Categories that make a borderline classifier score actionable in fusion.
ACTION_CATEGORIES = _ACTIONS | frozenset(
    {"secret_send", "decode_obey", "merge", "role", "suppress", "priv_exec",
     "policy_tamper", "tool_meta_exfil", "staged"}
)


def _rule(c: set[str]) -> str | None:
    """The first injection-shaped combination present in category set ``c``."""
    if "override" in c:
        return "override_prior_instructions"
    if "decode_obey" in c:
        return "decode_and_obey"
    if "merge" in c:
        return "merge_and_act"
    if "suppress" in c:
        return "refusal_suppression"
    if "code_exfil" in c:
        return "data_to_url_code"
    if "leak" in c and ("directive" in c or "role" in c or "ai" in c or "exfil" in c):
        return "prompt_leak_request"
    if "policy_tamper" in c:
        return "policy_tamper"
    if "tool_meta_exfil" in c:
        return "tool_meta_exfil"
    if "ai" in c and (c & _ACTIONS or "secret_send" in c or {"exfil", "dest"} <= c):
        return "ai_addressed_action"
    if "secret_send" in c and ("dest" in c or "priv_exec" in c):
        return "secret_to_destination"
    if "auth_prefix" in c and (
        c & {"priv", "priv_exec", "override", "money", "leak", "bypass", "secret_send", "exfil"}
    ):
        return "authority_spoof_action"
    if "auth_claim" in c and (c & {"priv", "priv_exec", "money", "leak", "bypass", "secret_send"}):
        return "authority_claim_action"
    if "bypass" in c and c & {"priv", "money", "secret_send"}:
        return "approval_bypass_action"
    if "conceal" in c and c & {"priv", "money", "secret_send", "auth"}:
        return "concealed_action"
    if "role" in c and (c & {"priv", "secret", "money", "leak"} or "auth" in c):
        return "role_switch_action"
    if "self" in c and "priv" in c:
        return "self_privilege"
    if "obey" in c and "priv" in c:
        return "obey_privileged"
    if "priv_exec" in c and "secret" in c and ("exfil" in c or "secret_send" in c):
        return "privileged_secret_access"
    if "tool_call" in c and ("secret" in c or {"exfil", "dest"} <= c):
        return "tool_call_with_sensitive_data"
    if "money" in c and "directive" in c and ("auth" in c or "dest" in c):
        return "directed_payment"
    if "priv" in c and "directive" in c and ("dest" in c or "secret_send" in c):
        return "directed_privileged_action"
    return None


def _windows(text: str) -> Iterable[str]:
    sentences = [s.strip() for s in _SENT_SPLIT.split(text) if s and s.strip()]
    if not sentences:
        return
    if len(text) <= 300:
        yield text
    for i, sentence in enumerate(sentences):
        yield sentence
        if i + 1 < len(sentences):
            yield sentence + " " + sentences[i + 1]


def strip_quoted_mentions(text: str) -> str:
    """Blank quoted examples in text that discusses attacks; leave other text unchanged.

    Explainers, training slides and red-team notes quote injections as *mentions*.
    Unquoted text is still scanned, so an attacker gains nothing by adding a marker word
    unless the payload itself is inside quotes next to it (a remaining blind spot).
    """
    if _DISCUSSION.search(text):
        return _QUOTED.sub(" ", text)
    return text


def _collect_steps(text: str) -> bool:
    for m in _COLLECT_VERB.finditer(text):
        before = text[max(0, m.start() - 40) : m.start()]
        if _NEG_BEFORE.search(before) or _NEG_RU_BEFORE.search(before):
            continue
        if _SECRET.search(text[max(0, m.start() - 120) : m.end() + 120]):
            return True
    return False


def _transmit_steps(text: str) -> bool:
    for m in _TRANSMIT_VERB.finditer(text):
        before = text[max(0, m.start() - 40) : m.start()]
        if _NEG_BEFORE.search(before) or _NEG_RU_BEFORE.search(before):
            continue
        if _DEST.search(text[max(0, m.start() - 160) : m.end() + 160]):
            return True
    return False


def staged_intent(text: str) -> str | None:
    """Document-level: a 'collect sensitive data' step plus a 'transmit outside' step.

    Catches goal-decomposition injections where no single step is an attack but the
    sequence reads then exfiltrates. Scanned over the whole (joined) document.
    """
    if _collect_steps(text) and _transmit_steps(text):
        return text[:96]
    return None


def quoted_injection_spans(text: str) -> list[str]:
    """Quoted spans, in attack-discussion context, that are themselves injection-shaped.

    Reported (low severity) so policy treats the content as carrying live instructions,
    without the quoted example alone making a benign security article high risk.
    """
    if not _DISCUSSION.search(text):
        return []
    spans: list[str] = []
    for m in _QUOTED.finditer(text):
        inner = m.group(0)[1:-1]
        if _rule(_categories(inner)) is not None:
            spans.append(inner[:96])
    return spans


def has_embedded_obey(text: str) -> bool:
    """Non-quoted text that tells the reader to carry out quoted/following content."""
    stripped = _QUOTED.sub(" ", text)
    return bool(_EMBED_OBEY.search(stripped))


def intent_hits(text: str, *, max_chars: int = 200_000) -> list[IntentHit]:
    """Injection-shaped category combinations found in ``text`` (deduplicated by rule)."""
    hits: dict[str, IntentHit] = {}
    text = strip_quoted_mentions(text[:max_chars])
    for window in _windows(text):
        if len(window) > 4000:
            window = window[:4000]
        cats = _categories(window)
        rule = _rule(cats)
        if rule is not None and rule not in hits:
            hits[rule] = IntentHit(rule, frozenset(cats), window[:96])
    if "staged_intent" not in hits:
        staged = staged_intent(text)
        if staged is not None:
            hits["staged_intent"] = IntentHit("staged_intent", frozenset({"staged"}), staged)
    return list(hits.values())


def weak_signal(text: str, *, max_chars: int = 200_000) -> frozenset[str]:
    """Union of categories over the text (for fusion with an ML score)."""
    out: set[str] = set()
    for window in _windows(text[:max_chars]):
        out |= _categories(window[:4000])
    return frozenset(out)


__all__ = [
    "ACTION_CATEGORIES",
    "IntentHit",
    "has_embedded_obey",
    "intent_hits",
    "quoted_injection_spans",
    "staged_intent",
    "strip_quoted_mentions",
    "weak_signal",
]
