"""Stage-0 fusion of the zero-dependency learned scorer with rules and discourse cues.

Two jobs, both thresholds chosen on the fresh *train pool* out-of-fold (never the holdout):

1. **Learned windows → finding.** Every window of the whole document is scored
   (:mod:`ngram_scorer`). A window raises ``learned_injection`` when its probability is high
   and it is not dense in "about attacks" reporting language; when it is mid-confidence *and*
   corroborated by a discourse signal (addressee shift toward the agent, imperative-density
   spike vs. the document baseline, or an agent-addressed imperative); or when the window
   turns to address the agent with an imperative while the rest of the document does not
   (addressee shift) even with weak lexical support.
2. **Expository rule hits → low severity.** A sentence-window intent hit that is neither
   imperative nor addressed to the agent, whose own learned score is low and whose document has
   no confident learned window, is *description* ("attackers can override instructions …"), not
   instruction. It is reported as ``described_intent`` (low severity, still instruction text)
   instead of a high-risk ``injection_intent``. Code / encoding / leak / staged rules are never
   demoted.
"""

from __future__ import annotations

from dataclasses import dataclass

from containment.detectors.discourse import sentence_cues, window_discourse, window_has_cues
from containment.detectors.ngram_scorer import NgramScorer, default_scorer
from containment.detectors.structural import IntentHit

T_HIGH = 0.85
T_HIGH_SHORT = 0.90  # very short texts carry few grams and are over-confident
SHORT_BYTES = 150
MIN_BYTES_UNCORROBORATED = 48  # below this a lone score is not evidence (rules still apply)
T_MID = 0.70
T_SHIFT = 0.30  # addressee shift + imperative toward the agent, weak lexical support
ABOUT_MAX_HIGH = 0.2
ABOUT_MAX_MID = 0.5
DEMOTE_BELOW = 0.5
DOC_CONFIDENT = 0.7
NON_DEMOTABLE = frozenset({
    "staged_intent", "data_to_url_code", "decode_and_obey", "merge_and_act",
    "refusal_suppression", "prompt_leak_request", "tool_meta_exfil", "privileged_secret_access",
    # Authority spoofs and approval claims are declarative by nature ("SYSTEM: …", "the user
    # has signed off on …"); the absence of an imperative says nothing about them.
    "authority_spoof_action", "authority_claim_action", "approval_bypass_action",
})
# A lone sentence or two has no surrounding discourse that could establish it as description.
MIN_DEMOTE_BYTES = 250


@dataclass(frozen=True, slots=True)
class LearnedHit:
    probability: float
    corroborated: bool
    signals: tuple[str, ...]
    preview: str


@dataclass(frozen=True, slots=True)
class LearnedResult:
    doc_probability: float
    hits: tuple[LearnedHit, ...]
    n_bytes: int = 0


def learned_scan(text: str, scorer: NgramScorer | None = None) -> LearnedResult | None:
    """Score every window of ``text``; ``None`` when no model is shipped."""
    scorer = scorer or default_scorer()
    if scorer is None or not text.strip():
        return None
    norm, wins = scorer.score_text(text)
    if not wins:
        return None
    doc_p = max(p for _, _, p in wins)
    n_bytes = len(norm.encode("utf-8"))
    if doc_p < T_SHIFT:
        return LearnedResult(doc_p, (), n_bytes)
    t_high = T_HIGH_SHORT if n_bytes < SHORT_BYTES else T_HIGH
    wd = window_discourse(sentence_cues(norm), [(a, b) for a, b, _ in wins])
    hits: list[LearnedHit] = []
    for (a, b, p), d in zip(wins, wd, strict=True):
        signals = tuple(name for name, on in (
            ("addressee_shift", d.addressee_shift and d.imperative_density > 0),
            ("imperative_spike", d.imperative_spike),
            ("agent_imperative", d.agent_addressed and d.imperative_density > 0),
        ) if on)
        if (p >= t_high and d.about_density <= ABOUT_MAX_HIGH
                and (signals or n_bytes >= MIN_BYTES_UNCORROBORATED)):
            hits.append(LearnedHit(p, bool(signals), signals, norm[a:b][:96]))
        elif p >= T_MID and signals and d.about_density < ABOUT_MAX_MID:
            hits.append(LearnedHit(p, True, signals, norm[a:b][:96]))
        elif (p >= T_SHIFT and d.addressee_shift and d.imperative_density > 0
              and d.about_density < ABOUT_MAX_MID):
            hits.append(LearnedHit(p, True, signals, norm[a:b][:96]))
    hits.sort(key=lambda h: -h.probability)
    return LearnedResult(doc_p, tuple(hits), n_bytes)


def is_descriptive(hit: IntentHit, learned: LearnedResult | None,
                   scorer: NgramScorer | None = None) -> bool:
    """True when an intent hit reads as description rather than instruction (see module doc)."""
    if hit.rule in NON_DEMOTABLE or not hit.window:
        return False
    if learned is None or learned.n_bytes < MIN_DEMOTE_BYTES:
        return False
    imperative, agent = window_has_cues(hit.window)
    if imperative or agent:
        return False
    scorer = scorer or default_scorer()
    if scorer is None or learned is None:
        return False  # without the model, keep 1.9.0 behaviour
    if learned.doc_probability >= DOC_CONFIDENT:
        return False
    return max((w.probability for w in scorer.score(hit.window)), default=0.0) < DEMOTE_BELOW


__all__ = ["LearnedHit", "LearnedResult", "is_descriptive", "learned_scan"]
