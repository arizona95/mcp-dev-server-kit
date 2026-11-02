"""skill_threat_scan — ClawVet + SkillSpector static threat-pattern scanner, ported VERBATIM.

Runs 400+ SKILL.md threat regexes over a plugin's SKILL.md + source — the CATEGORY-② (agentic /
malicious-skill) layer that "catches what VirusTotal misses":
  - ClawVet (MohibShaikh/clawvet, skill_scan.clawvet_patterns): 57 patterns — prompt injection,
    credential theft, RCE, obfuscation, data exfiltration, social engineering, persistence, privilege
    escalation, container escape.
  - SkillSpector (Cisco, skill_scan.skillspector_patterns): 347 patterns — memory poisoning,
    system-prompt leakage, rogue agent, excessive agency, output handling, supply chain, tool misuse,
    privilege escalation, data exfiltration, prompt injection.
No VirusTotal, no network. Static regex only → a finding is a pattern hit, nothing more; how much it
is worth is the caller's call.
Emits {location, category, severity, title, fix, cwe, pattern, kind='malicious_skill', source}
(`severity` is the upstream pattern DB's own field, kept verbatim).
"""
import os
import re


from rules.clawvet_patterns import CLAWVET_PATTERNS
from rules.skillspector_patterns import SKILLSPECTOR_PATTERNS

# category -> representative MITRE CWE (plumbing; the advice/severity stay the source tool's).
_CWE = {
    "remote_code_execution": "CWE-94", "code_execution": "CWE-94",
    "credential_theft": "CWE-522", "data_exfiltration": "CWE-200", "environment": "CWE-200",
    "prompt_injection": "CWE-77", "social_engineering": "CWE-77", "system_prompt_leakage": "CWE-200",
    "obfuscation": "CWE-506", "persistence": "CWE-506", "memory_poisoning": "CWE-77",
    "privilege_escalation": "CWE-250", "container_escape": "CWE-693", "rogue_agent": "CWE-77",
    "file_system": "CWE-22", "network": "CWE-918", "excessive_agency": "CWE-250",
    "output_handling": "CWE-116", "supply_chain": "CWE-1357", "tool_misuse": "CWE-77",
    "tool_poisoning": "CWE-77", "least_privilege": "CWE-250", "harmful_content": "CWE-1426",
}


# skillspector_patterns 에 평탄화돼 들어온 것 중 upstream 에서 위협 패턴이 아닌 것 (배선 수정, 판단 변경 아님):
#  DOCKERFILE_CONTEXT / SAFE_INSTALL_PATTERN = 안전 관용구를 빼 주는 필터 (static_patterns_tool_misuse.py:172, supply_chain.py:532)
#  FALLBACK_VULNERABLE_PYPI/NPM = osv.dev 에 못 닿을 때만 쓰는 예비 목록 (supply_chain.py:101) — 키트는 osv.dev 실조회
#  TAGS / FRAMEWORK_TAGS = 분류 태그 상수
_NOT_THREAT = {"DOCKERFILE_CONTEXT", "SAFE_INSTALL_PATTERN", "FALLBACK_VULNERABLE_PYPI", "FALLBACK_VULNERABLE_NPM",
               "TAGS", "FRAMEWORK_TAGS"}


def _all_patterns():
    """clawvet dicts + skillspector tuples -> one normalized pattern list."""
    out = list(CLAWVET_PATTERNS)                             # already dicts (source=clawvet)
    for p in out:
        p.setdefault("source", "clawvet")
    for rule, cat, sev, title, rgx in SKILLSPECTOR_PATTERNS:  # prose NL patterns -> case-insensitive
        if rule in _NOT_THREAT:
            continue
        out.append({"name": rule, "regex": rgx, "flags": "i", "severity": sev, "category": cat,
                    "title": title, "fix": "", "code_only": False, "source": "skillspector"})
    return out
# plugSpector languages.extensions() 값 그대로 (그 모듈 대신 상수로 둠)
_CODE_EXT = (".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts") + (".sh", ".bash")   # engine languages + shell skills
_SCAN_EXT = _CODE_EXT + (".md", ".json", ".txt", ".yaml", ".yml", ".toml")
_FENCE = re.compile(r"```[\w+.-]*\n(.*?)```", re.DOTALL)   # SKILL.md code blocks = "code" for code_only patterns


_PATTERN_ERRORS = []          # patterns of the vendored DB this `re` could not compile (surfaced in _scan)


def _compiled():
    out = []
    for p in _all_patterns():
        try:
            out.append((p, re.compile(p["regex"], re.I if "i" in p.get("flags", "") else 0)))
        except re.error as e:     # surfaced: a pattern that never runs is reported, not dropped silently
            _PATTERN_ERRORS.append({"pattern": p.get("name", ""), "source": p.get("source", ""), "error": str(e)})
    return out


_COMPILED = _compiled()
if _PATTERN_ERRORS:
    import sys as _sys
    print(f"[skill_threat_scan] {len(_PATTERN_ERRORS)} pattern(s) failed to compile and will not run: "
          + "; ".join(f"{x['source']}:{x['pattern']}: {x['error']}" for x in _PATTERN_ERRORS), file=_sys.stderr)


def _scan_text(text, rel, is_code):
    code = text if is_code else "\n".join(_FENCE.findall(text))   # doc: code_only patterns hit fences only
    out = []
    for p, rx in _COMPILED:
        target = code if p.get("code_only") else text
        m = rx.search(target)
        if not m:
            continue
        idx = text.find(m.group(0))                              # locate in the original for a line hint
        line = text.count(chr(10), 0, idx) + 1 if idx >= 0 else 1
        out.append({
            "location": f"{rel}:{line}",
            "category": p["category"], "severity": p["severity"], "title": p["title"],
            "fix": p["fix"], "cwe": _CWE.get(p["category"], "CWE-707"), "pattern": p["name"],
            "kind": "malicious_skill", "source": p.get("source", "clawvet"),
            "match": m.group(0)[:100]})
    return out


def _scan(path="", **_):
    d = path if os.path.isdir(path) else os.path.dirname(path)
    findings, errors = [], []
    for root, dirs, files in os.walk(d):
        dirs[:] = [x for x in dirs if x not in ("node_modules", ".git", "__pycache__") and not x.startswith(".")]
        for fn in sorted(files):
            low = fn.lower()
            if not low.endswith(_SCAN_EXT):
                continue
            rel = os.path.relpath(os.path.join(root, fn), d)
            try:
                text = open(os.path.join(root, fn), encoding="utf-8", errors="replace").read()
            except Exception as e:    # surfaced: unreadable file is recorded, not skipped silently
                errors.append({"file": rel, "error": f"{type(e).__name__}: {e}"})
                continue
            findings += _scan_text(text, rel, low.endswith(_CODE_EXT))
    return {"findings": findings, "count": len(findings),
            "categories": sorted({f["category"] for f in findings}),
            "patterns_loaded": len(_COMPILED), "source": "clawvet+skillspector",
            "errors": errors, "pattern_errors": list(_PATTERN_ERRORS)}


