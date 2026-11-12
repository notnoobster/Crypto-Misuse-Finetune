#!/usr/bin/env python3
"""Natural held-out test set: snippets written by a served Qwen model, not by templates.

Each request names the flaws that must be present (or asks for a clean snippet).
The model tags each flawed line with ' #@@<class>'; tags are stripped and turned into
gold line numbers. A snippet is kept only if its tags, its own CLASSES line, and the
request all agree. Labels are therefore "by construction"; a random sample is hand-checked.
Usage: gen_natural.py --n 260 --out data   (expects an OpenAI-compatible server on :8000)
"""
import argparse, ast, concurrent.futures as cf, json, random, re
import requests
from gen_data import CLASSES

DOMAINS = ["a password reset service", "a file vault command line tool", "a webhook receiver", "an S3 backup uploader",
           "a config file encryptor", "a license key validator", "session cookie middleware", "a chat message encryptor",
           "an IoT telemetry signer", "a payment callback handler", "OAuth state handling", "a database field encryptor",
           "an API client for a partner service", "a mobile app backend login", "a password manager export tool",
           "a log shipping agent", "an invite-link generator", "a secure notes app", "an email verification flow",
           "a document signing service", "a firmware update checker", "a key rotation script", "a file sharing service",
           "a CSRF protection helper", "a two-factor code generator", "a cache layer for user profiles",
           "a metrics exporter that calls an HTTPS API", "a data migration tool", "a certificate pinning helper",
           "a token-based API gateway"]
STYLES = ["a standalone script", "a small class with methods", "a Flask view function", "a helper module",
          "a command line tool using argparse", "a background worker", "a Django utility module"]
LIBS = ["pycryptodome (Crypto.*)", "the cryptography package", "hashlib and hmac from the standard library", "bcrypt",
        "PyJWT", "requests", "the standard library ssl module", "urllib3", "httpx", "numpy", "the standard library only"]

DEFS = "\n".join("- %s: %s" % (k, v) for k, v in CLASSES.items())

CLASS_LIST = list(CLASSES)
CLEAN_FRAC = 0.12

def make_request(r, i=0):
    p = r.random()
    if p < CLEAN_FRAC:
        want = []
    else:
        first = CLASS_LIST[i % len(CLASS_LIST)]          # class-balanced primary flaw
        want = [first]
        if r.random() < 0.2:
            want.append(r.choice([c for c in CLASS_LIST if c != first]))
    domain, style, lib = r.choice(DOMAINS), r.choice(STYLES), r.choice(LIBS)
    if want:
        req = ("The code must contain exactly these flaws, and no other flaw from the list below:\n"
               + "\n".join("- %s: %s" % (c, CLASSES[c]) for c in want))
    else:
        req = "The code must contain none of the flaws in the list below; use sound practices throughout."
    prompt = ("Write a realistic Python code snippet (20 to 50 lines) for %s, written as %s. Prefer %s.\n%s\n\n"
              "Full list of flaw classes, for reference:\n%s\n\n"
              "Rules: do not add comments or names that hint at a flaw or a fix; use natural identifiers; "
              "the code must be valid Python syntax. Append ' #@@<class>' to the end of every line that contains "
              "a flaw (one tag per flawed line, class name from the list). Output only the code in one ```python "
              "block, then a final line 'CLASSES: a,b' (or 'CLASSES: none')." % (domain, style, lib, req, DEFS))
    return {"want": sorted(want), "domain": domain, "style": style, "lib": lib, "prompt": prompt}

def call(url, model, prompt, temp):
    body = {"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": temp, "top_p": 0.95,
            "max_tokens": 1400, "chat_template_kwargs": {"enable_thinking": False}}
    resp = requests.post(url, json=body, timeout=600)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"] or ""

TAG = re.compile(r"\s*#@@\s*([a-z_]+)\s*$")

def parse(text, want):
    m = re.search(r"```python\n(.*?)```", text, flags=re.S)
    if not m:
        return None
    raw_lines = m.group(1).rstrip("\n").split("\n")
    lines, gold = [], {}
    for i, l in enumerate(raw_lines, 1):
        t = TAG.search(l)
        if t:
            cls = t.group(1)
            if cls not in CLASSES:
                return None
            gold.setdefault(cls, []).append(i)
            l = TAG.sub("", l)
        if "#@@" in l:
            return None
        lines.append(l)
    code = "\n".join(lines) + "\n"
    try:
        ast.parse(code)
    except SyntaxError:
        return None
    cm = re.search(r"CLASSES:\s*(.*)", text[m.end():])
    said = set() if (not cm or cm.group(1).strip().lower().startswith("none")) else {c.strip() for c in cm.group(1).split(",") if c.strip()}
    if set(gold) != set(want) or said != set(want):
        return None
    return code, gold

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=260)
    ap.add_argument("--out", default="data")
    ap.add_argument("--url", default="http://localhost:8000/v1/chat/completions")
    ap.add_argument("--model", default="gen")
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    r = random.Random(a.seed)
    reqs = [make_request(r, i) for i in range(a.n)]
    def work(q):
        try:
            return q, call(a.url, a.model, q["prompt"], 0.9)
        except Exception as e:
            return q, ""
    kept, seen = [], set()
    with cf.ThreadPoolExecutor(max_workers=32) as ex:
        for q, text in ex.map(work, reqs):
            res = parse(text, q["want"])
            if not res or res[0] in seen:
                continue
            seen.add(res[0])
            code, gold = res
            kept.append({"id": "natural-%04d" % len(kept), "split": "test_natural", "code": code,
                         "gold": [{"id": c, "lines": ls} for c, ls in sorted(gold.items(), key=lambda kv: kv[1][0])],
                         "meta": {k: q[k] for k in ("domain", "style", "lib")}})
    with open("%s/test_natural.jsonl" % a.out, "w") as fh:
        for row in kept:
            fh.write(json.dumps(row) + "\n")
    cnt = {}
    for row in kept:
        for g in row["gold"]:
            cnt[g["id"]] = cnt.get(g["id"], 0) + 1
    print("requested", a.n, "kept", len(kept), "clean", sum(1 for r_ in kept if not r_["gold"]), dict(sorted(cnt.items())))

if __name__ == "__main__":
    main()
