#!/usr/bin/env python3
"""Adjudicate the natural set, rescore every system, write RESULTS.md and ADJUDICATION.md.

Adjudication was done by reading every case where any system (tuned, base, Bandit, Semgrep)
disagreed with the generator's label, then applying the written class definitions:
  ADD    = real flaw present in the code that the label missed
  REMOVE = label claims a flaw that is not in the code
Ambiguous cases (e.g. env-var defaults like os.environ.get('X', 'default_secret')) are left as they were.
"Lenient" variant additionally counts MD5/SHA-1 applied to passwords as weak_hash (Bandit and Semgrep flag it
that way), which favors the baselines.
"""
import glob, json, random, re
from common import load, parse_answer, score
from eval_baselines import BANDIT_COVERED

ADD = [("0002", "hardcoded_key"), ("0004", "hardcoded_key"), ("0010", "nonconstant_compare"), ("0019", "hardcoded_key"),
       ("0020", "static_iv_nonce"), ("0038", "hardcoded_key"), ("0065", "hardcoded_key"), ("0072", "nonconstant_compare"),
       ("0082", "nonconstant_compare"), ("0096", "hardcoded_key"), ("0125", "hardcoded_key"), ("0143", "hardcoded_key"),
       ("0172", "hardcoded_key"), ("0172", "nonconstant_compare"), ("0184", "hardcoded_key"), ("0197", "hardcoded_key"),
       ("0226", "nonconstant_compare"), ("0233", "hardcoded_key")]
REMOVE = [("0025", "insecure_random"), ("0068", "nonconstant_compare"), ("0193", "hardcoded_key"),
          ("0233", "nonconstant_compare"), ("0235", "weak_password_storage")]
SYSTEMS = ["tuned", "base", "bandit", "semgrep"]

def llm_preds(mode, split):
    p = {}
    for f in glob.glob("results/preds_run1b_%s_%s_rank*.jsonl" % (mode, split)):
        for l in open(f):
            d = json.loads(l); p[d["id"]] = parse_answer(d["text"])
    return p

def adjudicate(rows, preds_for_lines):
    out = []
    for r in rows:
        gold = {g["id"]: list(g["lines"]) for g in r["gold"]}
        sid = r["id"].split("-")[1]
        for s, c in REMOVE:
            if s == sid: gold.pop(c, None)
        for s, c in ADD:
            if s == sid and c not in gold:
                line = None
                for p in preds_for_lines:
                    for d in p.get(r["id"]) or []:
                        if d["id"] == c and d["line"]: line = d["line"]
                gold[c] = [line or 1]
        out.append(dict(r, gold=[{"id": c, "lines": ls} for c, ls in gold.items()]))
    return out

def lenient(rows):
    out = []
    for r in rows:
        gold = {g["id"]: list(g["lines"]) for g in r["gold"]}
        if "weak_hash" not in gold:
            for n, l in enumerate(r["code"].splitlines(), 1):
                if re.search(r"md5|sha1", l, re.I) and re.search(r"password|pwd|pin|passphrase", l, re.I):
                    gold["weak_hash"] = [n]; break
        out.append(dict(r, gold=[{"id": c, "lines": ls} for c, ls in gold.items()]))
    return out

def sc(rows, p): return score(rows, p)

def main():
    raw = load("data/test_natural.jsonl")
    base_json = json.load(open("results/baseline_natural.json"))
    P = {"tuned": llm_preds("tuned", "test_natural"), "base": llm_preds("base", "test_natural"),
         "bandit": base_json["bandit_preds"], "semgrep": base_json["semgrep_preds"]}
    adj = adjudicate(raw, [P["tuned"], P["base"], P["bandit"], P["semgrep"]])
    len_ = lenient(adj)
    with open("data/test_natural_v1_unadjudicated.jsonl", "w") as fh:
        for r in raw: fh.write(json.dumps(r) + "\n")
    with open("data/test_natural_adjudicated.jsonl", "w") as fh:
        for r in adj: fh.write(json.dumps(r) + "\n")
    res = {}
    for name, rows in (("unadjudicated", raw), ("adjudicated (strict)", adj), ("adjudicated (lenient)", len_)):
        res[name] = {s: sc(rows, P[s]) for s in SYSTEMS}
    # template sets
    tmpl = {}
    for split in ("test_iid", "test_ood"):
        tmpl[split] = {}
        for mode in ("tuned", "base"):
            tmpl[split][mode] = json.load(open("results/score_run1b_%s_%s.json" % (mode, split)))
        b = json.load(open("results/baseline_%s.json" % split.replace("test_", "")))
        s = json.load(open("results/baseline_semgrep_%s.json" % split.replace("test_", "")))
        tmpl[split]["bandit"] = b["bandit_all_classes"]; tmpl[split]["semgrep"] = s["semgrep_all_classes"]
    # bootstrap (adjudicated strict)
    rng = random.Random(0); idx = list(range(len(adj)))
    def boot(a, b):
        ds = []
        for _ in range(2000):
            samp = [rng.choice(idx) for _ in idx]
            rows = [adj[i] for i in samp]
            ds.append(score(rows, P[a])["micro_f1"] - score(rows, P[b])["micro_f1"])
        ds.sort(); return sum(ds) / len(ds), ds[50], ds[1949]
    ci = {b: boot("tuned", b) for b in ("base", "bandit", "semgrep")}
    cls = list(res["adjudicated (strict)"]["tuned"]["per_class"])
    n_pos = {c: sum(1 for r in adj if any(g["id"] == c for g in r["gold"])) for c in cls}

    L = ["# Results: fine-tuned Qwen3.8-27B vs baselines on cryptographic misuse in Python", ""]
    L += ["Micro-F1 over the 10 classes (snippet-level class detection). Bandit and Semgrep are scored on all 10 classes; classes",
          "they have no rule for count as misses.", ""]
    L += ["| System | test_iid (templates) | test_ood (unseen libs, templates) | natural (adjudicated, strict) | natural (lenient) | natural (unadjudicated) |", "|---|---|---|---|---|---|"]
    for s in SYSTEMS:
        L.append("| %s | %.3f | %.3f | %.3f | %.3f | %.3f |" % (s, tmpl["test_iid"][s]["micro_f1"], tmpl["test_ood"][s]["micro_f1"],
                 res["adjudicated (strict)"][s]["micro_f1"], res["adjudicated (lenient)"][s]["micro_f1"], res["unadjudicated"][s]["micro_f1"]))
    L += ["", "Natural set, adjudicated strict: precision / recall", "", "| System | precision | recall | exact-match snippets |", "|---|---|---|---|"]
    for s in SYSTEMS:
        r_ = res["adjudicated (strict)"][s]
        L.append("| %s | %.3f | %.3f | %.3f |" % (s, r_["micro_precision"], r_["micro_recall"], r_["exact_match"]))
    L += ["", "Restricted to the classes Bandit has rules for (%s), natural set micro-F1, strict / lenient:" % ", ".join(BANDIT_COVERED), ""]
    for s in SYSTEMS:
        L.append("- %s: %.3f / %.3f" % (s, score(adj, P[s], covered=BANDIT_COVERED)["micro_f1"], score(len_, P[s], covered=BANDIT_COVERED)["micro_f1"]))
    L += ["", "Paired bootstrap (2000 resamples of the %d natural snippets), micro-F1 difference, tuned minus X:" % len(adj), ""]
    for b, (m, lo, hi) in ci.items(): L.append("- vs %s: %+.3f (95%% CI %+.3f to %+.3f)" % (b, m, lo, hi))
    L += ["", "Per class on the natural set (adjudicated strict), tuned F1 / base F1 / Bandit F1 / Semgrep F1, positives:", "",
          "| class | n positive | tuned | base | bandit | semgrep |", "|---|---|---|---|---|---|"]
    for c in cls:
        v = [res["adjudicated (strict)"][s]["per_class"][c]["f1"] for s in SYSTEMS]
        L.append("| %s | %d | %.2f | %.2f | %.2f | %.2f |" % ((c, n_pos[c]) + tuple(v)))
    L += ["", "## Caveats", "",
          "- test_iid and test_ood are generated from the same template generator as the training data. test_ood uses libraries absent from",
          "  training, but the underlying patterns are the same; the tuned model's 1.000 there shows it learned the task definition, not that",
          "  it would score 1.000 on arbitrary real code. The natural set is the realistic measure.",
          "- The natural set is %d snippets written by a separate Qwen model (Qwen3.6-35B-A3B). Labels came from the generation request and" % len(adj),
          "  were cross-checked, then adjudicated (see ADJUDICATION.md): 18 missed labels added, 5 wrong labels removed, by one reviewer",
          "  (Claude) who saw the model outputs. Per-class counts for weak_cipher (3) and ecb_mode (8) are too small to read.",
          "- The first evaluation run applied the adapter on only 1 of 4 GPUs (a harness bug, fixed and rerun); only the rerun is reported.",
          "- Line-number accuracy is not reported for the natural set: the generator often tagged the wrong line of multi-line calls."]
    open("RESULTS.md", "w").write("\n".join(L) + "\n")
    A = ["# Natural-set adjudication", "", "Added labels (real flaw present, label missed):", ""]
    A += ["- natural-%s: %s" % (s, c) for s, c in ADD]
    A += ["", "Removed labels (flaw not actually present):", ""] + ["- natural-%s: %s" % (s, c) for s, c in REMOVE]
    A += ["", "Left unchanged on purpose: env-var defaults such as os.environ.get('X', 'default_secret'); plaintext password storage",
          "(outside the 'fast/unsalted/low-iteration hash' definition); PBKDF2 at 100000 iterations; license-key literals."]
    open("ADJUDICATION.md", "w").write("\n".join(A) + "\n")
    print("\n".join(L))

if __name__ == "__main__":
    main()
