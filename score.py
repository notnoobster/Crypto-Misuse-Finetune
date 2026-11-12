#!/usr/bin/env python3
"""Score shard files from eval_hf.py:  score.py <split.jsonl> <name> <preds_prefix> [<out.json>]"""
import glob, json, sys
from common import load, parse_answer, score, fmt_row

split, name, prefix = sys.argv[1], sys.argv[2], sys.argv[3]
rows = load(split)
preds, raw = {}, {}
for f in glob.glob(prefix + "_rank*.jsonl"):
    for l in open(f):
        d = json.loads(l)
        raw[d["id"]] = d["text"]
        preds[d["id"]] = parse_answer(d["text"])
missing = [r["id"] for r in rows if r["id"] not in preds]
for m in missing:
    preds[m] = None
s = score(rows, preds)
s["missing_rows"] = len(missing)
print(fmt_row(name, s), "missing", len(missing))
for c, v in s["per_class"].items():
    print("   %-24s P %.3f R %.3f F1 %.3f  (tp %d fp %d fn %d)" % (c, v["precision"], v["recall"], v["f1"], v["tp"], v["fp"], v["fn"]))
if len(sys.argv) > 4:
    json.dump(s, open(sys.argv[4], "w"), indent=1)
