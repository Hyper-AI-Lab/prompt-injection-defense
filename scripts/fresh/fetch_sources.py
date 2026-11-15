#!/usr/bin/env python3
# ruff: noqa: E501  (data-heavy offline script; long literal lines are clearer)
"""Download the raw public sources for the 1.10.0 fresh holdout (stdlib only).

Usage: python scripts/fresh/fetch_sources.py RAW_DIR

Licenses (checked 2026-11-15) are recorded in fixtures/fresh/SOURCES.md. Raw downloads are a
cache and are not committed; `build_fresh.py` turns them into the frozen fixtures.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

UA = "containment-eval/1.10 (https://github.com/Hyper-AI-Lab/prompt-injection-defense)"
GH = "https://raw.githubusercontent.com"


def get(url: str, *, retries: int = 8, timeout: int = 60) -> bytes:
    import urllib.error

    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
                return r.read()
        except urllib.error.HTTPError as exc:
            if attempt == retries - 1:
                raise
            wait = 2 * (attempt + 1)
            if exc.code == 429:  # honour Retry-After when rate limited
                wait = max(int(exc.headers.get("Retry-After") or 0), 15 * (attempt + 1))
            time.sleep(wait)
        except Exception:  # noqa: BLE001 - retry any transient failure
            if attempt == retries - 1:
                raise
            time.sleep(2 * (attempt + 1))
    raise RuntimeError("unreachable")


def hf_rows(dataset: str, split: str) -> list[dict]:
    rows: list[dict] = []
    offset = 0
    while True:
        q = urllib.parse.urlencode(
            {"dataset": dataset, "config": "default", "split": split, "offset": offset, "length": 100}
        )
        data = json.loads(get(f"https://datasets-server.huggingface.co/rows?{q}"))
        batch = [r["row"] for r in data["rows"]]
        rows.extend(batch)
        offset += len(batch)
        if not batch or offset >= data["num_rows_total"]:
            return rows


# Wikipedia security articles (English titles; other languages via langlinks).
WIKI_TITLES = [
    "Prompt injection", "Phishing", "Social engineering (security)", "SQL injection",
    "Cross-site scripting", "Malware", "Ransomware", "Computer virus", "Computer worm",
    "Trojan horse (computing)", "Denial-of-service attack", "Man-in-the-middle attack",
    "Buffer overflow", "Zero-day vulnerability", "Common Vulnerabilities and Exposures",
    "Penetration test", "Red team", "Firewall (computing)", "Intrusion detection system",
    "Antivirus software", "Multi-factor authentication", "Password strength",
    "Password manager", "Public-key cryptography", "Transport Layer Security", "Heartbleed",
    "Log4Shell", "Spectre (security vulnerability)", "Meltdown (security vulnerability)",
    "Stuxnet", "WannaCry ransomware attack", "Data breach", "Identity theft",
    "Keystroke logging", "Rootkit", "Botnet", "Backdoor (computing)",
    "Exploit (computer security)", "Vulnerability (computer security)",
    "Security information and event management", "Zero trust architecture",
    "Principle of least privilege", "Access control", "Role-based access control", "OAuth",
    "Single sign-on", "Email spoofing", "DMARC", "Sender Policy Framework",
    "Business email compromise", "Voice phishing", "SMS phishing", "Typosquatting",
    "Supply chain attack", "Clickjacking", "Cross-site request forgery",
    "Directory traversal attack", "Code injection", "Shellcode", "Return-oriented programming",
    "Fuzzing", "Bug bounty program", "Coordinated vulnerability disclosure",
    "Computer emergency response team", "Security awareness", "Large language model",
    "AI safety", "Adversarial machine learning", "Deepfake", "Cyberwarfare",
    "Advanced persistent threat", "Honeypot (computing)", "Sandbox (computer security)",
    "Secure by design", "OWASP", "Kerberos (protocol)", "Pass the hash",
    "Credential stuffing", "Brute-force attack", "Dictionary attack", "Rainbow table",
    "Salt (cryptography)", "Computer security", "Information security", "Spamming",
    "Scareware", "Spyware", "Adware", "Cryptojacking", "Watering hole attack",
    "Drive-by download", "Session hijacking", "DNS spoofing", "ARP spoofing",
    "Privilege escalation", "Remote code execution", "Arbitrary code execution",
    "Security hacker", "Script kiddie", "Hacktivism", "Cybercrime", "Computer forensics",
    "Incident response", "Threat model", "Attack surface", "Defense in depth (computing)",
]
WIKI_LANGS = ["ru", "ja", "de", "fr", "es"]


def wiki_extract(lang: str, title: str) -> tuple[str, list[dict]]:
    q = urllib.parse.urlencode({
        "action": "query", "prop": "extracts|langlinks", "explaintext": 1, "titles": title,
        "lllimit": 100, "format": "json", "formatversion": 2, "redirects": 1,
    })
    page = json.loads(get(f"https://{lang}.wikipedia.org/w/api.php?{q}"))["query"]["pages"][0]
    return page.get("extract", ""), page.get("langlinks", [])


def fetch_wikipedia(raw: Path) -> None:
    # Resumable: one JSON line per finished topic in a partial cache.
    part = raw / "wikipedia.partial.jsonl"
    done = {}
    if part.exists():
        for line in part.read_text().splitlines():
            rec = json.loads(line)
            done[rec["topic"]] = rec["pages"]
    for title in WIKI_TITLES:
        if title in done:
            continue
        pages = []
        text, links = wiki_extract("en", title)
        if text:
            pages.append({"lang": "en", "title": title, "text": text})
        for link in links:
            if link["lang"] in WIKI_LANGS:
                time.sleep(1.0)
                t, _ = wiki_extract(link["lang"], link["title"])
                if t:
                    pages.append({"lang": link["lang"], "title": link["title"], "en_title": title,
                                  "text": t})
        with part.open("a") as fh:
            fh.write(json.dumps({"topic": title, "pages": pages}, ensure_ascii=False) + "\n")
        done[title] = pages
        time.sleep(1.0)
    out = [p for t in WIKI_TITLES for p in done.get(t, [])]
    (raw / "wikipedia.json").write_text(json.dumps(out, ensure_ascii=False))
    print("wikipedia", len(out), flush=True)


def fetch_owasp(raw: Path) -> None:
    listing = json.loads(get("https://api.github.com/repos/OWASP/CheatSheetSeries/contents/cheatsheets"))
    sheets = []
    for item in listing:
        if item["name"].endswith(".md"):
            sheets.append({"name": item["name"], "text": get(item["download_url"]).decode("utf-8")})
    (raw / "owasp_cheatsheets.json").write_text(json.dumps(sheets, ensure_ascii=False))
    base = f"{GH}/OWASP/www-project-top-10-for-large-language-model-applications/main/2_0_vulns"
    llm = []
    for n in ["LLM00_Preface", "LLM01_PromptInjection", "LLM02_SensitiveInformationDisclosure",
              "LLM03_SupplyChain", "LLM04_DataModelPoisoning", "LLM05_ImproperOutputHandling",
              "LLM06_ExcessiveAgency", "LLM07_SystemPromptLeakage",
              "LLM08_VectorAndEmbeddingWeaknesses", "LLM09_Misinformation",
              "LLM10_UnboundedConsumption"]:
        llm.append({"name": n, "text": get(f"{base}/{n}.md").decode("utf-8")})
    (raw / "owasp_llm_top10.json").write_text(json.dumps(llm, ensure_ascii=False))
    print("owasp", len(sheets), len(llm))


def fetch_nvd(raw: Path) -> None:
    # Two 30-day publication windows; public domain (US Gov). No API key: be slow.
    out = []
    for start, end in [("2025-03-01", "2025-03-31"), ("2025-09-01", "2025-09-30")]:
        q = urllib.parse.urlencode({
            "pubStartDate": f"{start}T00:00:00.000", "pubEndDate": f"{end}T23:59:59.999",
            "resultsPerPage": 1000, "startIndex": 0,
        })
        data = json.loads(get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?{q}", timeout=120))
        for v in data.get("vulnerabilities", []):
            cve = v["cve"]
            desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
            if desc and not desc.startswith("** REJECT"):
                out.append({"id": cve["id"], "text": desc})
        time.sleep(7)
    (raw / "nvd.json").write_text(json.dumps(out))
    print("nvd", len(out))


def fetch_mitre(raw: Path) -> None:
    bundle = json.loads(get(f"{GH}/mitre/cti/master/enterprise-attack/enterprise-attack.json",
                            timeout=300))
    out = []
    for o in bundle["objects"]:
        if o.get("type") == "attack-pattern" and not o.get("revoked") and o.get("description"):
            ext = next((r["external_id"] for r in o.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), o["id"])
            out.append({"id": ext, "name": o.get("name", ""), "text": o["description"]})
    (raw / "mitre_attack.json").write_text(json.dumps(out))
    print("mitre", len(out))


def fetch_arxiv(raw: Path) -> None:
    import xml.etree.ElementTree as ET

    ns = {"a": "http://www.w3.org/2005/Atom"}
    out = []
    for query in ['all:"prompt injection"', 'all:"jailbreak" AND all:"language model"',
                  'all:"phishing detection"', 'all:"red teaming" AND all:"language model"']:
        q = urllib.parse.urlencode({"search_query": query, "max_results": 120})
        root = ET.fromstring(get(f"https://export.arxiv.org/api/query?{q}", timeout=120))
        for e in root.findall("a:entry", ns):
            out.append({
                "id": e.findtext("a:id", "", ns).rsplit("/", 1)[-1],
                "title": " ".join(e.findtext("a:title", "", ns).split()),
                "text": " ".join(e.findtext("a:summary", "", ns).split()),
            })
        time.sleep(3.5)
    dedup = {r["id"]: r for r in out}
    (raw / "arxiv.json").write_text(json.dumps(list(dedup.values())))
    print("arxiv", len(dedup))


GOV_PAGES = [  # US Government works (public domain): phishing / security-awareness guidance
    "https://www.cisa.gov/secure-our-world/recognize-and-report-phishing",
    "https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-attacks",
    "https://www.cisa.gov/secure-our-world/use-strong-passwords",
    "https://www.cisa.gov/secure-our-world/turn-mfa",
    "https://www.cisa.gov/secure-our-world/update-software",
    "https://www.cisa.gov/news-events/news/understanding-patches-and-software-updates",
    "https://www.cisa.gov/news-events/news/protecting-against-malicious-code",
    "https://www.cisa.gov/news-events/news/understanding-denial-service-attacks",
    "https://www.cisa.gov/news-events/news/using-caution-email-attachments",
    "https://www.cisa.gov/news-events/news/securing-wireless-networks",
    "https://www.nist.gov/itl/smallbusinesscyber/guidance-topic/phishing",
    "https://www.nist.gov/itl/smallbusinesscyber/guidance-topic/ransomware",
    "https://www.nist.gov/itl/smallbusinesscyber/guidance-topic/multi-factor-authentication",
    "https://www.nist.gov/itl/smallbusinesscyber/guidance-topic/malware",
    "https://www.ic3.gov/PSA",
]


def html_main_text(html: str) -> str:
    from html.parser import HTMLParser

    class P(HTMLParser):
        SKIP = {"script", "style", "nav", "header", "footer", "noscript", "svg", "form"}
        BLOCK = {"p", "li", "h1", "h2", "h3", "h4", "div", "br", "tr", "section", "article"}

        def __init__(self) -> None:
            super().__init__()
            self.skip = 0
            self.in_main = 0
            self.parts: list[str] = []
            self.main_parts: list[str] = []

        def handle_starttag(self, tag, attrs):  # noqa: ANN001
            if tag in self.SKIP:
                self.skip += 1
            if tag == "main":
                self.in_main += 1
            if tag in self.BLOCK:
                (self.main_parts if self.in_main else self.parts).append("\n")

        def handle_endtag(self, tag):  # noqa: ANN001
            if tag in self.SKIP and self.skip:
                self.skip -= 1
            if tag == "main" and self.in_main:
                self.in_main -= 1

        def handle_data(self, data):  # noqa: ANN001
            if not self.skip:
                (self.main_parts if self.in_main else self.parts).append(data)

    p = P()
    p.feed(html)
    text = "".join(p.main_parts or p.parts)
    lines = [" ".join(line.split()) for line in text.splitlines()]
    out, blank = [], False
    for line in lines:
        if line:
            out.append(line)
            blank = False
        elif not blank:
            out.append("")
            blank = True
    return "\n".join(out).strip()


def fetch_gov(raw: Path) -> None:
    out = []
    for url in GOV_PAGES:
        try:
            text = html_main_text(get(url).decode("utf-8", "replace"))
        except Exception as exc:  # noqa: BLE001 - optional source; record and continue
            print("gov skip", url, exc, flush=True)
            continue
        if len(text) > 400:
            out.append({"url": url, "text": text})
        time.sleep(1.0)
    (raw / "gov_guidance.json").write_text(json.dumps(out, ensure_ascii=False))
    print("gov", len(out), flush=True)


def fetch_attacks(raw: Path) -> None:
    for name, ds in [("deepset", "deepset/prompt-injections")]:
        for split in ("train", "test"):
            (raw / f"{name}_{split}.json").write_text(json.dumps(hf_rows(ds, split)))
    (raw / "gandalf_train.json").write_text(
        json.dumps(hf_rows("Lakera/gandalf_ignore_instructions", "train")))
    for f in ("text_attack_test", "text_attack_train", "code_attack_test", "code_attack_train"):
        (raw / f"bipia_{f}.json").write_bytes(get(f"{GH}/microsoft/BIPIA/main/benchmark/{f}.json"))
    for f in ("attacker_cases_dh.jsonl", "attacker_cases_ds.jsonl"):
        (raw / f"injecagent_{f}").write_bytes(get(f"{GH}/uiuc-kang-lab/InjecAgent/main/data/{f}"))
    base = f"{GH}/ethz-spylab/agentdojo/main/src/agentdojo"
    for s in ("workspace", "travel", "banking", "slack"):
        (raw / f"agentdojo_{s}_inj.py").write_bytes(
            get(f"{base}/default_suites/v1/{s}/injection_tasks.py"))
    print("attacks ok")


def main() -> None:
    raw = Path(sys.argv[1])
    raw.mkdir(parents=True, exist_ok=True)
    which = set(sys.argv[2:]) or {"attacks", "wikipedia", "owasp", "nvd", "mitre", "arxiv", "gov"}
    for name, fn in [("attacks", fetch_attacks), ("owasp", fetch_owasp), ("nvd", fetch_nvd),
                     ("mitre", fetch_mitre), ("arxiv", fetch_arxiv), ("gov", fetch_gov),
                     ("wikipedia", fetch_wikipedia)]:
        if name in which:
            fn(raw)


if __name__ == "__main__":
    main()
