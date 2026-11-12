#!/usr/bin/env python3
"""Run Bandit (and optionally Semgrep) on a split and score against gold labels.

Mapping from tool rule ids to our classes is explicit below and deliberately
generous; rules with no counterpart (e.g. Bandit has nothing for static IVs or
timing-unsafe compares) simply never fire, which is part of the comparison.
Usage: eval_baselines.py <split.jsonl> <out.json> [--semgrep]
"""
import json, subprocess, sys, tempfile, shutil
from pathlib import Path
from common import load, score, fmt_row, CLASSES

BANDIT_MAP = {
    "B303": "weak_hash", "B324": "weak_hash", "B304": "weak_cipher", "B305": "ecb_mode",
    "B311": "insecure_random", "B501": "tls_verify_disabled", "B323": "tls_verify_disabled",
    "B105": "hardcoded_key", "B106": "hardcoded_key", "B107": "hardcoded_key", "B505": "small_rsa_key",
}
BANDIT_COVERED = sorted(set(BANDIT_MAP.values()))

SEMGREP_KEYS = [  # substring of rule id (lowercase) -> class
    ("ecb", "ecb_mode"), ("md5", "weak_hash"), ("sha1", "weak_hash"), ("insecure-hash", "weak_hash"),
    ("des", "weak_cipher"), ("arc4", "weak_cipher"), ("blowfish", "weak_cipher"), ("insecure-cipher", "weak_cipher"),
    ("insecure-random", "insecure_random"), ("random", "insecure_random"), ("verify-false", "tls_verify_disabled"),
    ("disabled-cert", "tls_verify_disabled"), ("unverified", "tls_verify_disabled"), ("cert-validation", "tls_verify_disabled"),
    ("hardcoded", "hardcoded_key"), ("hard-coded", "hardcoded_key"), ("rsa", "small_rsa_key"), ("key-size", "small_rsa_key"),
    ("timing", "nonconstant_compare"), ("compare", "nonconstant_compare"),
]

def write_files(rows, d):
    for r in rows:
        (d / ("%s.py" % r["id"])).write_text(r["code"])

def run_bandit(rows, bandit):
    d = Path(tempfile.mkdtemp(prefix="bandit_"))
    write_files(rows, d)
    p = subprocess.run([bandit, "-r", str(d), "-f", "json", "-q"], capture_output=True, text=True)
    res = json.loads(p.stdout or "{}").get("results", [])
    preds = {r["id"]: [] for r in rows}
    seen_ids = {}
    for it in res:
        c = BANDIT_MAP.get(it["test_id"])
        seen_ids[it["test_id"]] = seen_ids.get(it["test_id"], 0) + 1
        if c:
            rid = Path(it["filename"]).stem
            preds[rid].append({"id": c, "line": it["line_number"]})
    shutil.rmtree(d, ignore_errors=True)
    return preds, seen_ids

def run_semgrep(rows, semgrep):
    d = Path(tempfile.mkdtemp(prefix="semgrep_"))
    write_files(rows, d)
    p = subprocess.run([semgrep, "scan", "--config", "p/python", "--config", "p/security-audit", "--json", "--quiet",
                        "--metrics=off", "--disable-version-check", str(d)], capture_output=True, text=True)
    res = json.loads(p.stdout or "{}").get("results", [])
    preds = {r["id"]: [] for r in rows}
    seen = {}
    for it in res:
        cid = it["check_id"].lower()
        seen[cid.split(".")[-1]] = seen.get(cid.split(".")[-1], 0) + 1
        for key, c in SEMGREP_KEYS:
            if key in cid:
                preds[Path(it["path"]).stem].append({"id": c, "line": it["start"]["line"]})
                break
    shutil.rmtree(d, ignore_errors=True)
    return preds, seen

if __name__ == "__main__":
    split, out = sys.argv[1], sys.argv[2]
    rows = load(split)
    base = Path(sys.executable).parent
    result = {}
    preds, seen = run_bandit(rows, str(base / "bandit"))
    result["bandit"] = score(rows, preds, covered=BANDIT_COVERED)
    result["bandit_all_classes"] = score(rows, preds)
    result["bandit_rule_hits"] = seen
    result["bandit_preds"] = preds
    print(fmt_row("bandit (covered classes)", result["bandit"]))
    print(fmt_row("bandit (all 10 classes)", result["bandit_all_classes"]))
    print("bandit rules fired:", seen)
    if "--semgrep" in sys.argv:
        preds, seen = run_semgrep(rows, str(base / "semgrep"))
        result["semgrep_all_classes"] = score(rows, preds)
        result["semgrep_rule_hits"] = seen
        result["semgrep_preds"] = preds
        print(fmt_row("semgrep (all 10 classes)", result["semgrep_all_classes"]))
        print("semgrep rules fired:", seen)
    Path(out).write_text(json.dumps(result, indent=1))
