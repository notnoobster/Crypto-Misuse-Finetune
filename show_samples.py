#!/usr/bin/env python3
"""Print random snippets with gold labels for hand-checking: show_samples.py <split.jsonl> <n> [seed]"""
import json, random, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 0).shuffle(rows)
for r in rows[:int(sys.argv[2])]:
    print("=" * 70, r["id"], "GOLD:", [(g["id"], g["lines"]) for g in r["gold"]] or "none")
    for i, l in enumerate(r["code"].splitlines(), 1):
        print("%3d: %s" % (i, l))
