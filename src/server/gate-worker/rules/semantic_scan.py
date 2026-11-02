"""skill_semantic_scan — SkillSpector semantic security-discovery LLM analyzer, prompt VERBATIM.

The LLM layer that catches what regex/static misses: SSD-1 semantic prompt injection, SSD-2 novel /
paraphrased attack phrasing, SSD-3 natural-language exfiltration, SSD-4 narrative / gradual deception.
The analyzer + base prompts are VERBATIM from skillspector (see skill_scan.semantic_prompts); only the
structured-output contract is our JSON (plumbing). Needs an LLM — pass llm=...; returns empty otherwise
(no autonomous LLM). Category-② (malicious_skill). What it returns is what the model saw, not a
verdict — nothing here decides how serious it is. Complements skill_threat_scan
(the static-regex layer) with semantic understanding.
"""
import json
import os
import re


from rules.semantic_prompts import BASE_PROMPT, SSD_PROMPT

_SSD_CWE = {"SSD-1": "CWE-77", "SSD-2": "CWE-77", "SSD-3": "CWE-200", "SSD-4": "CWE-77"}
_JSON = re.compile(r"\{.*\}", re.DOTALL)
_OUTPUT = ('\n\nReturn ONLY a JSON object: {"findings": [{"rule_id": "SSD-1..4", "line": <int>, '
           '"severity": "low|medium|high", "description": "<why this is a semantic risk>"}]}. '
           'Empty findings list if the file is clean.')


def _number(text):
    return "\n".join(f"L{i + 1}: {ln}" for i, ln in enumerate(text.split("\n")))


def _analyze(llm, rel, text):
    prompt = BASE_PROMPT.format(analyzer_prompt=SSD_PROMPT, file_label=rel,
                                numbered_content=_number(text[:12000])) + _OUTPUT
    try:
        out = llm.complete(prompt) or ""
    except Exception as e:            # surfaced: LLM call failure is an error, not "file is clean"
        return {"error": f"llm: {type(e).__name__}: {e}", "file": rel}
    m = _JSON.search(out)
    if not m:                         # surfaced: a reply without JSON is unparsable, not "clean"
        return {"error": "llm reply has no JSON object", "file": rel, "llm_reply_head": out[:200]}
    try:
        data = json.loads(m.group(0))
    except Exception as e:            # surfaced: unparsable JSON is an error, not "clean"
        return {"error": f"llm reply JSON: {type(e).__name__}: {e}", "file": rel, "llm_reply_head": out[:200]}
    findings = []
    for f in (data.get("findings") or []):
        rid = str(f.get("rule_id", "SSD-1")).upper()
        rid = rid if rid in _SSD_CWE else "SSD-1"
        findings.append({
            "location": f"{rel}:{f.get('line', 0)}", "category": "semantic_security",
            "severity": str(f.get("severity", "medium")), "title": rid,
            "description": str(f.get("description", ""))[:300], "cwe": _SSD_CWE[rid],
            "pattern": rid, "kind": "malicious_skill", "source": "skillspector"})
    return findings


def _semantic(path="", llm=None, **_):
    if llm is None:
        return {"findings": [], "count": 0, "note": "no llm (semantic scan needs an LLM)", "source": "skillspector"}
    d = path if os.path.isdir(path) else os.path.dirname(path)
    findings, errors = [], []
    for root, dirs, files in os.walk(d):
        dirs[:] = [x for x in dirs if x not in ("node_modules", ".git", "__pycache__") and not x.startswith(".")]
        for fn in sorted(files):
            if not fn.lower().endswith((".md", ".txt")):        # semantic layer targets prose (SKILL.md/docs)
                continue
            rel = os.path.relpath(os.path.join(root, fn), d)
            try:
                text = open(os.path.join(root, fn), encoding="utf-8", errors="replace").read()
            except Exception as e:    # surfaced: unreadable file is recorded, not skipped silently
                errors.append({"file": rel, "error": f"{type(e).__name__}: {e}"})
                continue
            r = _analyze(llm, rel, text)
            if isinstance(r, dict):   # LLM/parse failure for this file (see _analyze)
                errors.append(r)
            else:
                findings += r
    return {"findings": findings, "count": len(findings), "source": "skillspector", "errors": errors}


