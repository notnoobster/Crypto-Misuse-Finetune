#!/usr/bin/env python3
"""Cross-check the natural set against simple code markers and drop disputed snippets.

Rules (conservative: drop on any disagreement):
  * deterministic classes (ecb_mode, weak_cipher, small_rsa_key, tls_verify_disabled, weak_hash):
    marker present  <=>  class in gold
  * fuzzy classes (hardcoded_key, static_iv_nonce, insecure_random, nonconstant_compare,
    weak_password_storage): marker present and class not in gold  -> drop
  * comments that hint at flaws are dropped
Usage: filter_natural.py data/test_natural_raw.jsonl data/test_natural.jsonl
"""
import json, re, sys
from common import load

def evidence(code):
    ev = set()
    if re.search(r"MODE_ECB|modes\.ECB", code): ev.add("ecb_mode")
    if re.search(r"DES3?\.new|ARC4|Blowfish|TripleDES|algorithms\.(CAST5|IDEA|SEED)|\bDES\b", code): ev.add("weak_cipher")
    for m in re.finditer(r"RSA\.generate\(\s*(\d+)|key_size\s*=\s*(\d+)", code):
        bits = int(m.group(1) or m.group(2))
        if bits < 2048: ev.add("small_rsa_key")
    if re.search(r"verify\s*=\s*False|CERT_NONE|_create_unverified_context|check_hostname\s*=\s*False", code): ev.add("tls_verify_disabled")
    for line in code.splitlines():
        if re.search(r"md5|sha1|MD5\(|SHA1\(", line, flags=re.I) and "usedforsecurity=False" not in line and "password" not in line.lower():
            ev.add("weak_hash")
    if re.search(r"(?i)\b\w*(key|secret|token|passphrase)\w*\s*=\s*b?f?['\"][^'\"\n]{6,}['\"]", code): ev.add("hardcoded_key")
    if re.search(r"hmac\.new\(\s*b?['\"]|Fernet\(\s*b?['\"]|AES\.new\(\s*b?['\"]|jwt\.(encode|decode)\([^,\n]+,\s*['\"]|AESGCM\(\s*b?['\"]", code): ev.add("hardcoded_key")
    if re.search(r"(?i)\b(iv|nonce)\w*\s*=\s*(b['\"]|bytes\(\d+\)|bytearray)|nonce\s*=\s*b['\"]", code): ev.add("static_iv_nonce")
    if re.search(r"random\.(random|randint|choice|randrange|getrandbits|seed|randbytes|choices)|np\.random|numpy\.random|int\(time\.time", code): ev.add("insecure_random")
    if re.search(r"(?i)\b\w*(sig|signature|mac|token|digest|hash)\w*(\.hex\(\)|\(\))?\s*[!=]=\s*\w", code): ev.add("nonconstant_compare")
    if re.search(r"(?i)(sha256|sha512|sha1|md5|blake2)\w*\(.*password|password.*(sha256|sha512|md5)", code): ev.add("weak_password_storage")
    return ev

DET = {"ecb_mode", "weak_cipher", "small_rsa_key", "tls_verify_disabled", "weak_hash"}
HINT = re.compile(r"#.*(weak|insecure|flaw|vulnerab|unsafe|hardcod|hard-cod|never use|should use|correction|bad practice|not secure|fix)", re.I)

def main():
    rows = load(sys.argv[1])
    kept, why = [], {}
    for r in rows:
        gold = {g["id"] for g in r["gold"]}
        ev = evidence(r["code"])
        reason = None
        if HINT.search(r["code"]):
            reason = "hint_comment"
        elif any((c in ev) != (c in gold) for c in DET):
            reason = "det_mismatch"
        elif any(c in ev and c not in gold for c in ev - DET):
            reason = "fuzzy_unlabeled"
        if reason:
            why[reason] = why.get(reason, 0) + 1
        else:
            kept.append(r)
    with open(sys.argv[2], "w") as fh:
        for i, r in enumerate(kept):
            r["id"] = "natural-%04d" % i
            fh.write(json.dumps(r) + "\n")
    cnt = {}
    for r in kept:
        for g in r["gold"]:
            cnt[g["id"]] = cnt.get(g["id"], 0) + 1
    print("raw", len(rows), "kept", len(kept), "dropped", why, "clean", sum(1 for r in kept if not r["gold"]))
    print(dict(sorted(cnt.items())))

if __name__ == "__main__":
    main()
