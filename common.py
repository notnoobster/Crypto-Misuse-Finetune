"""Shared prompt building, answer parsing, and scoring."""
import json, re
from gen_data import CLASSES

INSTR = (
    "Review the Python code below for cryptographic misuse. Report every instance of these classes:\n"
    + "\n".join("- %s: %s" % (k, v) for k, v in CLASSES.items())
    + '\nReply with JSON only: {"issues":[{"id":"<class>","line":<line number>}]}. '
    'Use {"issues":[]} if the code has none.\n\nCode (with line numbers):\n'
)

def numbered(code):
    return "\n".join("%d: %s" % (i, l) for i, l in enumerate(code.splitlines(), 1))

def build_prompt(code):
    return INSTR + numbered(code)

def target_text(gold):
    issues = [{"id": g["id"], "line": g["lines"][0]} for g in gold]
    issues.sort(key=lambda d: d["line"])
    return json.dumps({"issues": issues}, separators=(",", ":"))

def load(path):
    with open(path) as fh:
        return [json.loads(l) for l in fh if l.strip()]

def parse_answer(text):
    """Return list of {id,line} or None when unparseable."""
    t = text.strip()
    t = re.sub(r"^<think>.*?</think>", "", t, flags=re.S).strip()
    m = re.search(r"\{.*\}", t, flags=re.S)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
        out = []
        for it in obj.get("issues", []):
            if isinstance(it, dict) and it.get("id") in CLASSES:
                line = it.get("line")
                out.append({"id": it["id"], "line": line if isinstance(line, int) else None})
        return out
    except Exception:
        return None

def score(rows, preds, covered=None):
    """rows: gold rows; preds: dict id -> list of {id,line} or None (parse fail)."""
    classes = list(CLASSES)
    tp = {c: 0 for c in classes}; fp = {c: 0 for c in classes}; fn = {c: 0 for c in classes}
    line_hit = line_tot = parse_fail = exact = 0
    bin_tp = bin_fp = bin_fn = bin_tn = 0
    for r in rows:
        gold = {g["id"]: g["lines"] for g in r["gold"]}
        p = preds.get(r["id"])
        if p is None:
            parse_fail += 1
            p = []
        pset = {d["id"] for d in p}
        for c in classes:
            if c in gold and c in pset: tp[c] += 1
            elif c in pset: fp[c] += 1
            elif c in gold: fn[c] += 1
        for d in p:
            if d["id"] in gold:
                line_tot += 1
                if d["line"] in gold[d["id"]]:
                    line_hit += 1
        exact += int(set(gold) == pset)
        g_any, p_any = bool(gold), bool(pset)
        bin_tp += g_any and p_any; bin_fp += (not g_any) and p_any
        bin_fn += g_any and (not p_any); bin_tn += (not g_any) and (not p_any)
    def prf(t, f_p, f_n):
        pr = t / (t + f_p) if t + f_p else 0.0
        rc = t / (t + f_n) if t + f_n else 0.0
        f1 = 2 * pr * rc / (pr + rc) if pr + rc else 0.0
        return pr, rc, f1
    per = {c: dict(zip(("precision", "recall", "f1"), prf(tp[c], fp[c], fn[c])), tp=tp[c], fp=fp[c], fn=fn[c]) for c in classes}
    cov = covered or classes
    micro = prf(sum(tp[c] for c in cov), sum(fp[c] for c in cov), sum(fn[c] for c in cov))
    macro = sum(per[c]["f1"] for c in cov) / len(cov)
    return {
        "n": len(rows), "per_class": per,
        "micro_precision": micro[0], "micro_recall": micro[1], "micro_f1": micro[2], "macro_f1": macro,
        "exact_match": exact / len(rows), "line_accuracy": (line_hit / line_tot) if line_tot else None,
        "parse_fail": parse_fail,
        "any_issue": dict(zip(("precision", "recall", "f1"), prf(bin_tp, bin_fp, bin_fn))),
        "covered_classes": cov,
    }

def fmt_row(name, s):
    return "%-28s micro-P %.3f  micro-R %.3f  micro-F1 %.3f  macro-F1 %.3f  exact %.3f  line %s  parse-fail %d" % (
        name, s["micro_precision"], s["micro_recall"], s["micro_f1"], s["macro_f1"], s["exact_match"],
        ("%.3f" % s["line_accuracy"]) if s["line_accuracy"] is not None else "n/a", s["parse_fail"])
