#!/usr/bin/env python3
"""Synthetic labeled dataset of Python snippets with cryptographic misuse.

Labels are known by construction: every template line that is a misuse carries a
class tag. Splits:
  train / val / test_iid : PyCryptodome, hashlib, random, requests, stdlib hmac
  test_ood               : APIs never seen in training (cryptography, ssl,
                           urllib3, httpx, numpy, jwt, argon2, SystemRandom)
Usage: python gen_data.py --out data --n-train 3000
"""
import argparse, ast, base64, hashlib, json, random, re, string
from pathlib import Path

CLASSES = {
    "ecb_mode": "block cipher used in ECB mode",
    "static_iv_nonce": "constant, hardcoded, or reused IV or nonce",
    "hardcoded_key": "secret key, password, or signing secret hardcoded in source",
    "weak_hash": "MD5 or SHA-1 used for signatures, MACs, or integrity checks",
    "weak_cipher": "DES, 3DES, RC4, or Blowfish cipher",
    "weak_password_storage": "password stored with a fast, unsalted, or low-iteration hash",
    "insecure_random": "non-cryptographic randomness (random, numpy, time) used for keys, tokens, or nonces",
    "small_rsa_key": "RSA key shorter than 2048 bits",
    "nonconstant_compare": "secret, MAC, or token compared with == or != instead of a constant-time check",
    "tls_verify_disabled": "TLS certificate or hostname verification disabled",
}

NOUNS = ["payload", "record", "message", "document", "profile", "order", "note", "report", "blob", "data"]
KEYN = ["key", "enc_key", "secret_key", "master_key", "aes_key", "session_key", "wrap_key"]
KEYCONST = ["KEY", "SECRET_KEY", "MASTER_KEY", "AES_KEY", "APP_KEY", "ENC_KEY"]
PWN = ["password", "pwd", "user_password", "raw_password", "passphrase"]
SIGN = ["signature", "provided_sig", "sig", "mac", "tag"]
URLN = ["url", "endpoint", "api_url", "target"]
STATIC_IVS = [r'b"\x00" * 16', "bytes(16)", 'b"0123456789abcdef"', 'b"1234567812345678"', 'b"\x00" * 16', 'b"abcdefghijklmnop"']
STATIC_N8 = ['b"12345678"', 'b"\\x00" * 8', 'b"nonce000"', 'b"abcdefgh"']
STATIC_N12 = ['b"fixednonce12"', 'b"\\x00" * 12', 'b"000000000000"', 'b"unique_nonce"']
PASSPHRASES = ["supersecretkey!", "changeme123", "my_app_secret", "hunter2-hunter2", "s3cr3t-k3y-2024",
               "company-internal-key", "letmein-please", "P@ssw0rd-prod", "default-signing-secret", "topsecret"]
SALTS = ["salt", "static-salt", "mysalt", "pepper123", "appsalt"]

# ---------------------------------------------------------------- specs
# Line suffix " !!label" marks the misuse line. Fields {k},{x},{pw},... are filled.
# Spec: (cls, kind, split_family, imports, module_lines, fn_prefix, params, body)
SPECS = []

def S(cls, kind, fam, imports, fn, params, body, module=()):
    SPECS.append(dict(cls=cls, kind=kind, fam=fam, imports=list(imports), fn=fn,
                      params=params, body=list(body), module=list(module)))

AES_IMP = ["from Crypto.Cipher import AES", "from Crypto.Util.Padding import pad"]
GRB = "from Crypto.Random import get_random_bytes"
CIPHER = "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes"
AEAD = "from cryptography.hazmat.primitives.ciphers.aead import AESGCM"
CHACHA = "from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305"
HASHES = "from cryptography.hazmat.primitives import hashes"

# ---- ecb_mode
S("ecb_mode", "vuln", "train", AES_IMP, "encrypt_{x}", "{k}, {x}",
  ["cipher = AES.new({k}, AES.MODE_ECB) !!ecb_mode", "return cipher.encrypt(pad({x}, AES.block_size))"])
S("ecb_mode", "vuln", "train", AES_IMP + ["from Crypto.Util.Padding import unpad"], "decrypt_{x}", "{k}, {x}",
  ["cipher = AES.new({k}, AES.MODE_ECB) !!ecb_mode", "return unpad(cipher.decrypt({x}), AES.block_size)"])
S("ecb_mode", "vuln", "train", AES_IMP, "seal_{x}", "{k}, {x}",
  ["return cipher.encrypt(pad({x}, 16))"], module=["MODE = AES.MODE_ECB !!ecb_mode"])
SPECS[-1]["body"] = ["cipher = AES.new({k}, MODE)", "return cipher.encrypt(pad({x}, 16))"]
S("ecb_mode", "safe", "train", ["from Crypto.Cipher import AES"], "encrypt_{x}", "{k}, {x}",
  ["cipher = AES.new({k}, AES.MODE_GCM)", "ct, tag = cipher.encrypt_and_digest({x})", "return cipher.nonce + tag + ct"])
S("ecb_mode", "safe", "train", AES_IMP + [GRB], "protect_{x}", "{k}, {x}",
  ["iv = get_random_bytes(16)", "cipher = AES.new({k}, AES.MODE_CBC, iv)", "return iv + cipher.encrypt(pad({x}, AES.block_size))"])
S("ecb_mode", "safe", "train", ["from Crypto.Cipher import AES"], "seal_{x}", "{k}, {x}",
  ["cipher = AES.new({k}, AES.MODE_EAX)", "ct, tag = cipher.encrypt_and_digest({x})", "return cipher.nonce, tag, ct"])
S("ecb_mode", "vuln", "ood", [CIPHER, "from cryptography.hazmat.primitives import padding"], "encrypt_{x}", "{k}, {x}",
  ["padder = padding.PKCS7(128).padder()", "padded = padder.update({x}) + padder.finalize()",
   "encryptor = Cipher(algorithms.AES({k}), modes.ECB()).encryptor() !!ecb_mode",
   "return encryptor.update(padded) + encryptor.finalize()"])
S("ecb_mode", "vuln", "ood", [CIPHER], "decrypt_{x}", "{k}, {x}",
  ["decryptor = Cipher(algorithms.AES({k}), modes.ECB()).decryptor() !!ecb_mode", "return decryptor.update({x}) + decryptor.finalize()"])
S("ecb_mode", "safe", "ood", [AEAD, "import os"], "encrypt_{x}", "{k}, {x}",
  ["nonce = os.urandom(12)", "ct = AESGCM({k}).encrypt(nonce, {x}, None)", "return nonce + ct"])
S("ecb_mode", "safe", "ood", ["from cryptography.fernet import Fernet"], "protect_{x}", "{k}, {x}",
  ["return Fernet({k}).encrypt({x})"])

# ---- static_iv_nonce
S("static_iv_nonce", "vuln", "train", AES_IMP, "encrypt_{x}", "{k}, {x}",
  ["iv = {ivl} !!static_iv_nonce", "cipher = AES.new({k}, AES.MODE_CBC, iv)", "return cipher.encrypt(pad({x}, AES.block_size))"])
S("static_iv_nonce", "vuln", "train", ["from Crypto.Cipher import AES"], "seal_{x}", "{k}, {x}",
  ["cipher = AES.new({k}, AES.MODE_CTR, nonce={n8}) !!static_iv_nonce", "return cipher.encrypt({x})"])
S("static_iv_nonce", "vuln", "train", ["from Crypto.Cipher import AES"], "protect_{x}", "{k}, {x}",
  ["cipher = AES.new({k}, AES.MODE_GCM, nonce={n12}) !!static_iv_nonce", "ct, tag = cipher.encrypt_and_digest({x})", "return ct + tag"])
S("static_iv_nonce", "vuln", "train", AES_IMP, "encrypt_{x}", "{k}, {x}",
  ["cipher = AES.new({k}, AES.MODE_CBC, IV)", "return cipher.encrypt(pad({x}, 16))"], module=["IV = {ivl} !!static_iv_nonce"])
S("static_iv_nonce", "safe", "train", AES_IMP + [GRB], "encrypt_{x}", "{k}, {x}",
  ["iv = get_random_bytes(16)", "cipher = AES.new({k}, AES.MODE_CBC, iv)", "return iv + cipher.encrypt(pad({x}, AES.block_size))"])
S("static_iv_nonce", "safe", "train", ["from Crypto.Cipher import AES"], "seal_{x}", "{k}, {x}",
  ["cipher = AES.new({k}, AES.MODE_CTR)", "return cipher.nonce + cipher.encrypt({x})"])
S("static_iv_nonce", "safe", "train", ["from Crypto.Cipher import AES", GRB], "protect_{x}", "{k}, {x}",
  ["nonce = get_random_bytes(12)", "cipher = AES.new({k}, AES.MODE_GCM, nonce=nonce)",
   "ct, tag = cipher.encrypt_and_digest({x})", "return nonce + tag + ct"])
S("static_iv_nonce", "vuln", "ood", [CIPHER], "encrypt_{x}", "{k}, {x}",
  ["iv = {ivl} !!static_iv_nonce", "enc = Cipher(algorithms.AES({k}), modes.CBC(iv)).encryptor()", "return enc.update({x}) + enc.finalize()"])
S("static_iv_nonce", "vuln", "ood", [AEAD], "seal_{x}", "{k}, {x}",
  ["nonce = {n12} !!static_iv_nonce", "return AESGCM({k}).encrypt(nonce, {x}, None)"])
S("static_iv_nonce", "vuln", "ood", [CHACHA], "protect_{x}", "{k}, {x}",
  ["nonce = {n12} !!static_iv_nonce", "return ChaCha20Poly1305({k}).encrypt(nonce, {x}, None)"])
S("static_iv_nonce", "safe", "ood", [AEAD, "import os"], "seal_{x}", "{k}, {x}",
  ["nonce = os.urandom(12)", "return nonce + AESGCM({k}).encrypt(nonce, {x}, None)"])
S("static_iv_nonce", "safe", "ood", [CHACHA, "import os"], "protect_{x}", "{k}, {x}",
  ["nonce = os.urandom(12)", "return nonce + ChaCha20Poly1305({k}).encrypt(nonce, {x}, None)"])

# ---- hardcoded_key
S("hardcoded_key", "vuln", "train", ["from Crypto.Cipher import AES"], "encrypt_{x}", "{x}",
  ["cipher = AES.new({KN}, AES.MODE_GCM)", "ct, tag = cipher.encrypt_and_digest({x})", "return cipher.nonce + tag + ct"],
  module=['{KN} = b"{secret}" !!hardcoded_key'])
S("hardcoded_key", "vuln", "train", ["from Crypto.Cipher import AES"], "seal_{x}", "{x}",
  ['{k} = b"{secret}" !!hardcoded_key', "cipher = AES.new({k}, AES.MODE_GCM)", "ct, tag = cipher.encrypt_and_digest({x})", "return cipher.nonce + tag + ct"])
S("hardcoded_key", "vuln", "train", ["import hmac", "import hashlib"], "sign_{x}", "{x}",
  ["return hmac.new({KN}.encode(), {x}, hashlib.sha256).hexdigest()"], module=['{KN} = "{secret}" !!hardcoded_key'])
S("hardcoded_key", "vuln", "train", ["from Crypto.Cipher import AES", "from Crypto.Protocol.KDF import PBKDF2"], "protect_{x}", "{x}, salt",
  ["key = PBKDF2(PASSPHRASE, salt, dkLen=32, count=600000)", "cipher = AES.new(key, AES.MODE_GCM)",
   "ct, tag = cipher.encrypt_and_digest({x})", "return cipher.nonce + tag + ct"], module=['PASSPHRASE = "{secret}" !!hardcoded_key'])
S("hardcoded_key", "safe", "train", ["from Crypto.Cipher import AES", "import os"], "encrypt_{x}", "{x}",
  ["cipher = AES.new({KN}, AES.MODE_GCM)", "ct, tag = cipher.encrypt_and_digest({x})", "return cipher.nonce + tag + ct"],
  module=['{KN} = os.environ["{KN}"].encode()'])
S("hardcoded_key", "safe", "train", ["from Crypto.Cipher import AES", GRB], "seal_{x}", "{x}",
  ["{k} = get_random_bytes(32)", "cipher = AES.new({k}, AES.MODE_GCM)", "ct, tag = cipher.encrypt_and_digest({x})",
   "return {k}, cipher.nonce + tag + ct"])
S("hardcoded_key", "safe", "train", ["from Crypto.Cipher import AES"], "protect_{x}", "{x}, key_path",
  ["{k} = load_key(key_path)", "cipher = AES.new({k}, AES.MODE_GCM)", "ct, tag = cipher.encrypt_and_digest({x})", "return cipher.nonce + tag + ct"])
S("hardcoded_key", "safe", "train", ["import hmac", "import hashlib", "import os"], "sign_{x}", "{x}",
  ["return hmac.new({KN}.encode(), {x}, hashlib.sha256).hexdigest()"], module=['{KN} = os.environ["SIGNING_SECRET"]'])
S("hardcoded_key", "vuln", "ood", ["from cryptography.fernet import Fernet"], "protect_{x}", "{x}",
  ["return Fernet({KN}).encrypt({x})"], module=['{KN} = b"{b64key}" !!hardcoded_key'])
S("hardcoded_key", "vuln", "ood", ["import jwt"], "issue_token", "user_id, exp",
  ["payload = dict(sub=user_id, exp=exp)", 'return jwt.encode(payload, JWT_SECRET, algorithm="HS256")'],
  module=['JWT_SECRET = "{secret}" !!hardcoded_key'])
S("hardcoded_key", "vuln", "ood", [AEAD, "import os"], "seal_{x}", "{x}",
  ['{k} = b"{secret32}" !!hardcoded_key', "nonce = os.urandom(12)", "return nonce + AESGCM({k}).encrypt(nonce, {x}, None)"])
S("hardcoded_key", "safe", "ood", ["from cryptography.fernet import Fernet", "import os"], "protect_{x}", "{x}",
  ["return Fernet({KN}).encrypt({x})"], module=['{KN} = os.environ["FERNET_KEY"].encode()'])
S("hardcoded_key", "safe", "ood", ["import jwt", "import os"], "issue_token", "user_id, exp",
  ["payload = dict(sub=user_id, exp=exp)", 'return jwt.encode(payload, JWT_SECRET, algorithm="HS256")'],
  module=['JWT_SECRET = os.environ["JWT_SECRET"]'])
S("hardcoded_key", "safe", "ood", [AEAD, "import os"], "seal_{x}", "{x}",
  ["{k} = AESGCM.generate_key(bit_length=256)", "nonce = os.urandom(12)", "return {k}, nonce + AESGCM({k}).encrypt(nonce, {x}, None)"])

# ---- weak_hash
S("weak_hash", "vuln", "train", ["import hmac", "import hashlib"], "sign_{x}", "{k}, {x}",
  ["return hmac.new({k}, {x}, hashlib.sha1).hexdigest() !!weak_hash"])
S("weak_hash", "vuln", "train", ["import hashlib"], "tag_{x}", "{k}, {x}",
  ["digest = hashlib.md5({x} + {k}).hexdigest() !!weak_hash", "return digest"])
S("weak_hash", "vuln", "train", ["from Crypto.Hash import MD5"], "authenticate_{x}", "{x}",
  ["h = MD5.new() !!weak_hash", "h.update({x})", "return h.hexdigest()"])
S("weak_hash", "vuln", "train", ["import hashlib"], "sign_{x}", "{k}, {x}",
  ["return hashlib.sha1({k} + {x}).hexdigest() !!weak_hash"])
S("weak_hash", "safe", "train", ["import hmac", "import hashlib"], "sign_{x}", "{k}, {x}",
  ["return hmac.new({k}, {x}, hashlib.sha256).hexdigest()"])
S("weak_hash", "safe", "train", ["import hashlib"], "cache_key_for_{x}", "{x}",
  ["return hashlib.md5({x}, usedforsecurity=False).hexdigest()"])
S("weak_hash", "safe", "train", ["import hashlib"], "checksum_{x}", "{x}",
  ["return hashlib.sha256({x}).hexdigest()"])
S("weak_hash", "safe", "train", ["import hashlib"], "tag_{x}", "{x}",
  ["return hashlib.blake2b({x}, digest_size=32).hexdigest()"])
S("weak_hash", "vuln", "ood", [HASHES], "tag_{x}", "{x}",
  ["digest = hashes.Hash(hashes.MD5()) !!weak_hash", "digest.update({x})", "return digest.finalize()"])
S("weak_hash", "vuln", "ood", ["from cryptography.hazmat.primitives import hashes, hmac"], "sign_{x}", "{k}, {x}",
  ["h = hmac.HMAC({k}, hashes.SHA1()) !!weak_hash", "h.update({x})", "return h.finalize()"])
S("weak_hash", "vuln", "ood", [HASHES, "from cryptography.hazmat.primitives.asymmetric import padding"], "sign_{x}", "private_key, {x}",
  ["return private_key.sign({x}, padding.PKCS1v15(), hashes.SHA1()) !!weak_hash"])
S("weak_hash", "safe", "ood", [HASHES], "tag_{x}", "{x}",
  ["digest = hashes.Hash(hashes.SHA256())", "digest.update({x})", "return digest.finalize()"])
S("weak_hash", "safe", "ood", ["from cryptography.hazmat.primitives import hashes, hmac"], "sign_{x}", "{k}, {x}",
  ["h = hmac.HMAC({k}, hashes.SHA256())", "h.update({x})", "return h.finalize()"])
S("weak_hash", "safe", "ood", [HASHES, "from cryptography.hazmat.primitives.asymmetric import padding"], "sign_{x}", "private_key, {x}",
  ["pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)",
   "return private_key.sign({x}, pss, hashes.SHA256())"])

# ---- weak_cipher
S("weak_cipher", "vuln", "train", ["from Crypto.Cipher import DES3", "from Crypto.Util.Padding import pad", GRB], "encrypt_{x}", "{k}, {x}",
  ["iv = get_random_bytes(8)", "cipher = DES3.new({k}, DES3.MODE_CBC, iv) !!weak_cipher", "return iv + cipher.encrypt(pad({x}, DES3.block_size))"])
S("weak_cipher", "vuln", "train", ["from Crypto.Cipher import ARC4"], "seal_{x}", "{k}, {x}",
  ["cipher = ARC4.new({k}) !!weak_cipher", "return cipher.encrypt({x})"])
S("weak_cipher", "vuln", "train", ["from Crypto.Cipher import Blowfish", "from Crypto.Util.Padding import pad", GRB], "protect_{x}", "{k}, {x}",
  ["iv = get_random_bytes(8)", "cipher = Blowfish.new({k}, Blowfish.MODE_CBC, iv) !!weak_cipher", "return iv + cipher.encrypt(pad({x}, Blowfish.block_size))"])
S("weak_cipher", "vuln", "train", ["from Crypto.Cipher import DES", "from Crypto.Util.Padding import pad", GRB], "encrypt_{x}", "{k}, {x}",
  ["iv = get_random_bytes(8)", "cipher = DES.new({k}, DES.MODE_CBC, iv) !!weak_cipher", "return iv + cipher.encrypt(pad({x}, DES.block_size))"])
S("weak_cipher", "safe", "train", ["from Crypto.Cipher import AES"], "encrypt_{x}", "{k}, {x}",
  ["cipher = AES.new({k}, AES.MODE_GCM)", "ct, tag = cipher.encrypt_and_digest({x})", "return cipher.nonce + tag + ct"])
S("weak_cipher", "safe", "train", ["from Crypto.Cipher import ChaCha20"], "seal_{x}", "{k}, {x}",
  ["cipher = ChaCha20.new(key={k})", "return cipher.nonce + cipher.encrypt({x})"])
S("weak_cipher", "vuln", "ood", [CIPHER, "import os"], "encrypt_{x}", "{k}, {x}",
  ["iv = os.urandom(8)", "enc = Cipher(algorithms.TripleDES({k}), modes.CBC(iv)).encryptor() !!weak_cipher", "return iv + enc.update({x}) + enc.finalize()"])
S("weak_cipher", "vuln", "ood", [CIPHER], "seal_{x}", "{k}, {x}",
  ["enc = Cipher(algorithms.ARC4({k}), mode=None).encryptor() !!weak_cipher", "return enc.update({x})"])
S("weak_cipher", "vuln", "ood", [CIPHER, "import os"], "protect_{x}", "{k}, {x}",
  ["iv = os.urandom(8)", "enc = Cipher(algorithms.Blowfish({k}), modes.CBC(iv)).encryptor() !!weak_cipher", "return iv + enc.update({x}) + enc.finalize()"])
S("weak_cipher", "safe", "ood", [AEAD, "import os"], "encrypt_{x}", "{k}, {x}",
  ["nonce = os.urandom(12)", "return nonce + AESGCM({k}).encrypt(nonce, {x}, None)"])
S("weak_cipher", "safe", "ood", [CHACHA, "import os"], "seal_{x}", "{k}, {x}",
  ["nonce = os.urandom(12)", "return nonce + ChaCha20Poly1305({k}).encrypt(nonce, {x}, None)"])

# ---- weak_password_storage
S("weak_password_storage", "vuln", "train", ["import hashlib"], "hash_password", "{pw}",
  ["return hashlib.sha256({pw}.encode()).hexdigest() !!weak_password_storage"])
S("weak_password_storage", "vuln", "train", ["import hashlib"], "register_user", "db, username, {pw}",
  ["digest = hashlib.sha512({pw}.encode()).hexdigest() !!weak_password_storage", "db.save(username, digest)"])
S("weak_password_storage", "vuln", "train", ["import hashlib"], "hash_password", "{pw}",
  ['return hashlib.pbkdf2_hmac("sha256", {pw}.encode(), b"{salt}", {low}) !!weak_password_storage'])
S("weak_password_storage", "vuln", "train", ["import hashlib"], "store_password", "db, username, {pw}, salt",
  ["digest = hashlib.sha1((salt + {pw}).encode()).hexdigest() !!weak_password_storage", "db.save(username, digest)"])
S("weak_password_storage", "safe", "train", ["import bcrypt"], "hash_password", "{pw}",
  ["return bcrypt.hashpw({pw}.encode(), bcrypt.gensalt())"])
S("weak_password_storage", "safe", "train", ["import hashlib", "import os"], "hash_password", "{pw}",
  ["salt = os.urandom(16)", "digest = hashlib.scrypt({pw}.encode(), salt=salt, n=2**14, r=8, p=1)", "return salt + digest"])
S("weak_password_storage", "safe", "train", ["import hashlib", "import os"], "store_password", "db, username, {pw}",
  ["salt = os.urandom(16)", 'digest = hashlib.pbkdf2_hmac("sha256", {pw}.encode(), salt, 600000)', "db.save(username, salt + digest)"])
S("weak_password_storage", "safe", "train", ["import bcrypt"], "verify_password", "{pw}, stored",
  ["return bcrypt.checkpw({pw}.encode(), stored)"])
PBK = ["from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC", HASHES]
S("weak_password_storage", "vuln", "ood", PBK, "hash_password", "{pw}",
  ['kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"{salt}", iterations={low}) !!weak_password_storage',
   "return kdf.derive({pw}.encode())"])
S("weak_password_storage", "vuln", "ood", [HASHES], "hash_password", "{pw}",
  ["digest = hashes.Hash(hashes.SHA256()) !!weak_password_storage", "digest.update({pw}.encode())", "return digest.finalize()"])
S("weak_password_storage", "safe", "ood", PBK + ["import os"], "hash_password", "{pw}",
  ["salt = os.urandom(16)", "kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)",
   "return salt + kdf.derive({pw}.encode())"])
S("weak_password_storage", "safe", "ood", ["from argon2 import PasswordHasher"], "hash_password", "{pw}",
  ["return PasswordHasher().hash({pw})"])
S("weak_password_storage", "safe", "ood", ["from cryptography.hazmat.primitives.kdf.scrypt import Scrypt", "import os"], "hash_password", "{pw}",
  ["salt = os.urandom(16)", "kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)", "return salt + kdf.derive({pw}.encode())"])

# ---- insecure_random
S("insecure_random", "vuln", "train", ["import random", "import string"], "generate_{tok}", "",
  ["alphabet = string.ascii_letters + string.digits", '{tok} = "".join(random.choice(alphabet) for _ in range({n})) !!insecure_random', "return {tok}"])
S("insecure_random", "vuln", "train", ["import random"], "new_session_id", "",
  ["session_id = str(random.randint(10**15, 10**16)) !!insecure_random", "return session_id"])
S("insecure_random", "vuln", "train", ["import random", "import time"], "make_key", "",
  ["random.seed(int(time.time()))", "key = bytes(random.getrandbits(8) for _ in range(32)) !!insecure_random", "return key"])
S("insecure_random", "vuln", "train", ["import random"], "make_nonce", "",
  ["nonce = random.randbytes(12) !!insecure_random", "return nonce"])
S("insecure_random", "safe", "train", ["import secrets"], "generate_{tok}", "",
  ["return secrets.token_urlsafe({n})"])
S("insecure_random", "safe", "train", ["import os"], "make_key", "",
  ["return os.urandom(32)"])
S("insecure_random", "safe", "train", ["import secrets", "import string"], "generate_{tok}", "",
  ["alphabet = string.ascii_letters + string.digits", 'return "".join(secrets.choice(alphabet) for _ in range({n}))'])
S("insecure_random", "safe", "train", [GRB], "make_nonce", "",
  ["return get_random_bytes(12)"])
S("insecure_random", "vuln", "ood", ["import numpy as np"], "generate_{tok}", "",
  ['{tok} = "".join(str(d) for d in np.random.randint(0, 10, size={n})) !!insecure_random', "return {tok}"])
S("insecure_random", "vuln", "ood", ["import time"], "new_reset_code", "",
  ["reset_code = str(int(time.time()))[-6:] !!insecure_random", "return reset_code"])
S("insecure_random", "vuln", "ood", ["import numpy as np"], "make_key", "",
  ["key = np.random.bytes(32) !!insecure_random", "return key"])
S("insecure_random", "safe", "ood", ["import random"], "new_otp", "",
  ["rng = random.SystemRandom()", "return rng.randint(100000, 999999)"])
S("insecure_random", "safe", "ood", ["import secrets"], "new_reset_code", "",
  ["return secrets.token_hex(8)"])

# ---- small_rsa_key
S("small_rsa_key", "vuln", "train", ["from Crypto.PublicKey import RSA"], "create_keypair", "",
  ["key = RSA.generate({bits_small}) !!small_rsa_key", "return key.export_key(), key.publickey().export_key()"])
S("small_rsa_key", "safe", "train", ["from Crypto.PublicKey import RSA"], "create_keypair", "",
  ["key = RSA.generate({bits_ok})", "return key.export_key(), key.publickey().export_key()"])
S("small_rsa_key", "vuln", "ood", ["from cryptography.hazmat.primitives.asymmetric import rsa"], "create_keypair", "",
  ["private_key = rsa.generate_private_key(public_exponent=65537, key_size={bits_small}) !!small_rsa_key", "return private_key, private_key.public_key()"])
S("small_rsa_key", "safe", "ood", ["from cryptography.hazmat.primitives.asymmetric import rsa"], "create_keypair", "",
  ["private_key = rsa.generate_private_key(public_exponent=65537, key_size={bits_ok})", "return private_key, private_key.public_key()"])
S("small_rsa_key", "safe", "ood", ["from cryptography.hazmat.primitives.asymmetric import ec"], "create_keypair", "",
  ["private_key = ec.generate_private_key(ec.SECP256R1())", "return private_key, private_key.public_key()"])

# ---- nonconstant_compare
S("nonconstant_compare", "vuln", "train", ["import hmac", "import hashlib"], "verify_{x}_signature", "{k}, {x}, {sig}",
  ["expected = hmac.new({k}, {x}, hashlib.sha256).hexdigest()", "return expected == {sig} !!nonconstant_compare"])
S("nonconstant_compare", "vuln", "train", [], "check_token", "supplied, stored",
  ["if supplied == stored: !!nonconstant_compare", "    return True", "return False"])
S("nonconstant_compare", "vuln", "train", ["import hmac", "import hashlib"], "verify_{x}", "{k}, {x}, {sig}",
  ["computed = hmac.new({k}, {x}, hashlib.sha256).digest()", "if computed != {sig}: !!nonconstant_compare", '    raise ValueError("bad mac")', "return True"])
S("nonconstant_compare", "vuln", "train", [], "check_api_key", "supplied_key, stored_key",
  ["return supplied_key == stored_key !!nonconstant_compare"])
S("nonconstant_compare", "safe", "train", ["import hmac", "import hashlib"], "verify_{x}_signature", "{k}, {x}, {sig}",
  ["expected = hmac.new({k}, {x}, hashlib.sha256).hexdigest()", "return hmac.compare_digest(expected, {sig})"])
S("nonconstant_compare", "safe", "train", ["import hmac"], "check_token", "supplied, stored",
  ["return hmac.compare_digest(supplied, stored)"])
S("nonconstant_compare", "safe", "train", ["import secrets"], "check_api_key", "supplied_key, stored_key",
  ["return secrets.compare_digest(supplied_key, stored_key)"])
S("nonconstant_compare", "vuln", "ood", ["import hmac", "import hashlib"], "verify_request", "request, secret",
  ["expected = hmac.new(secret, request.body, hashlib.sha256).hexdigest()", 'provided = request.headers.get("X-Signature", "")',
   "return provided == expected !!nonconstant_compare"])
S("nonconstant_compare", "vuln", "ood", [], "verify_digest", "digest, signature",
  ["if digest.hex() == signature: !!nonconstant_compare", "    return True", "return False"])
S("nonconstant_compare", "vuln", "ood", [], "validate_csrf", "token_from_cookie, session",
  ["return token_from_cookie == session.csrf_token !!nonconstant_compare"])
S("nonconstant_compare", "safe", "ood", ["import hmac", "import hashlib"], "verify_request", "request, secret",
  ["expected = hmac.new(secret, request.body, hashlib.sha256).hexdigest()", 'provided = request.headers.get("X-Signature", "")',
   "return hmac.compare_digest(provided, expected)"])
S("nonconstant_compare", "safe", "ood", ["import hmac"], "validate_csrf", "token_from_cookie, session",
  ["return hmac.compare_digest(token_from_cookie, session.csrf_token)"])

# ---- tls_verify_disabled
S("tls_verify_disabled", "vuln", "train", ["import requests"], "fetch_{x}", "{url}",
  ["response = requests.get({url}, verify=False, timeout=10) !!tls_verify_disabled", "return response.json()"])
S("tls_verify_disabled", "vuln", "train", ["import requests"], "download_{x}", "{url}",
  ["session = requests.Session()", "session.verify = False !!tls_verify_disabled", "return session.get({url}, timeout=10).text"])
S("tls_verify_disabled", "vuln", "train", ["import requests"], "upload_{x}", "{url}, {x}",
  ["return requests.post({url}, json={x}, verify=False, timeout=10) !!tls_verify_disabled"])
S("tls_verify_disabled", "safe", "train", ["import requests"], "fetch_{x}", "{url}",
  ["response = requests.get({url}, timeout=10)", "response.raise_for_status()", "return response.json()"])
S("tls_verify_disabled", "safe", "train", ["import requests"], "download_{x}", "{url}",
  ['response = requests.get({url}, verify="/etc/ssl/certs/ca-certificates.crt", timeout=10)', "return response.text"])
S("tls_verify_disabled", "vuln", "ood", ["import ssl", "import urllib.request"], "fetch_{x}", "{url}",
  ["context = ssl._create_unverified_context() !!tls_verify_disabled", "return urllib.request.urlopen({url}, context=context).read()"])
S("tls_verify_disabled", "vuln", "ood", ["import ssl", "import urllib.request"], "download_{x}", "{url}",
  ["context = ssl.create_default_context()", "context.check_hostname = False !!tls_verify_disabled",
   "context.verify_mode = ssl.CERT_NONE !!tls_verify_disabled", "return urllib.request.urlopen({url}, context=context).read()"])
S("tls_verify_disabled", "vuln", "ood", ["import urllib3"], "fetch_{x}", "{url}",
  ['http = urllib3.PoolManager(cert_reqs="CERT_NONE") !!tls_verify_disabled', 'return http.request("GET", {url}).data'])
S("tls_verify_disabled", "vuln", "ood", ["import httpx"], "download_{x}", "{url}",
  ["with httpx.Client(verify=False) as client: !!tls_verify_disabled", "    return client.get({url}).text"])
S("tls_verify_disabled", "safe", "ood", ["import ssl", "import urllib.request"], "fetch_{x}", "{url}",
  ["context = ssl.create_default_context()", "return urllib.request.urlopen({url}, context=context).read()"])
S("tls_verify_disabled", "safe", "ood", ["import httpx"], "download_{x}", "{url}",
  ["with httpx.Client(timeout=10) as client:", "    return client.get({url}).text"])
S("tls_verify_disabled", "safe", "ood", ["import urllib3", "import certifi"], "fetch_{x}", "{url}",
  ['http = urllib3.PoolManager(cert_reqs="CERT_REQUIRED", ca_certs=certifi.where())', 'return http.request("GET", {url}).data'])

# ---- benign noise (shared by all splits)
NOISE = []
def N(imports, fn, params, body, module=()):
    NOISE.append(dict(cls=None, kind="noise", fam="all", imports=list(imports), fn=fn, params=params,
                      body=list(body), module=list(module)))
N(["import json"], "load_config", "path", ["with open(path) as fh:", "    return json.load(fh)"])
N(["import random"], "retry_delay", "base, attempt", ["return base * (2 ** attempt) * (1 + random.random())"])
N(["import random"], "shuffle_items", "items", ["items = list(items)", "random.shuffle(items)", "return items"])
N(["import random"], "pick_greeting", "", ["return random.choice(GREETINGS)"], module=['GREETINGS = ["hello", "welcome", "hi there"]'])
N(["import random"], "sample_questions", "pool, count", ["return random.sample(pool, count)"])
N(["import hashlib"], "cache_key", "{x}", ["return hashlib.md5({x}, usedforsecurity=False).hexdigest()"])
N(["import hashlib"], "file_checksum", "path", ["h = hashlib.sha256()", 'with open(path, "rb") as fh:', "    for chunk in iter(lambda: fh.read(8192), b\"\"):", "        h.update(chunk)", "return h.hexdigest()"])
N([], "describe_mode", "mode", ['if mode == "encrypt":', '    return "enc"', 'if mode == "decrypt":', '    return "dec"', 'return "none"'])
N([], "", "", [], module=["KEY_SIZE = 32", "BLOCK_SIZE = 16", 'CIPHER_NAME = "aes-256-gcm"', 'KEY_FILE = "/etc/app/key.bin"'])
N([], "format_user", "name, email", ['return f"{name} <{email}>"'])
N(["import logging"], "log_event", "item", ['logger = logging.getLogger(__name__)', 'logger.info("processed %s", item)'])
N([], "is_empty", "data", ["if len(data) == 0:", "    return True", "return False"])
N(["import hashlib"], "name_to_id", "filename", ["return hashlib.sha256(filename.encode()).hexdigest()[:12]"])
N(["import argparse"], "parse_args", "", ["parser = argparse.ArgumentParser()", 'parser.add_argument("--input")', "return parser.parse_args()"])
N(["import numpy as np"], "add_noise", "values, scale", ["return values + np.random.randn(len(values)) * scale"])

# ---------------------------------------------------------------- assembly
FIELD_RE = re.compile(r"\{([a-z_0-9A-Z]+)\}")

def fill(t, f):
    return FIELD_RE.sub(lambda m: str(f[m.group(1)]) if m.group(1) in f else m.group(0), t)

def secret(r):
    mode = r.random()
    if mode < 0.4:
        return r.choice(PASSPHRASES)
    n = r.choice([16, 24, 32])
    return "".join(r.choice(string.ascii_letters + string.digits) for _ in range(n))

def make_fields(r):
    x = r.choice(NOUNS)
    return {
        "x": x, "k": r.choice(KEYN), "KN": r.choice(KEYCONST), "pw": r.choice(PWN), "sig": r.choice(SIGN),
        "url": r.choice(URLN), "tok": r.choice(["token", "session_token", "api_token", "reset_token", "csrf_token"]),
        "n": r.choice([16, 24, 32, 40]), "ivl": r.choice(STATIC_IVS), "n8": r.choice(STATIC_N8), "n12": r.choice(STATIC_N12),
        "secret": secret(r), "secret32": "".join(r.choice(string.ascii_letters + string.digits) for _ in range(32)),
        "b64key": base64.urlsafe_b64encode(bytes(r.randrange(256) for _ in range(32))).decode(),
        "salt": r.choice(SALTS), "low": r.choice([1000, 2000, 5000, 10000]),
        "bits_small": r.choice([512, 768, 1024]), "bits_ok": r.choice([2048, 3072, 4096]),
    }

def parse_line(t):
    if " !!" in t:
        a, b = t.rsplit(" !!", 1)
        return a, b.strip()
    return t, None

def build_block(spec, r, wrap, used_names):
    f = make_fields(r)
    mod = [parse_line(fill(m, f)) for m in spec["module"]]
    fn_lines = []
    if spec["fn"]:
        name = fill(spec["fn"], f)
        base, i = name, 2
        while name in used_names:
            name = "%s_%d" % (base, i); i += 1
        used_names.add(name)
        params = fill(spec["params"], f)
        if wrap:
            params = "self, " + params if params else "self"
        fn_lines.append(("def %s(%s):" % (name, params), None))
        body = [parse_line(fill(b, f)) for b in spec["body"]]
        if r.random() < 0.3:
            body.insert(0, (r.choice(["# TODO: revisit", "# helper used by the API layer", "# see design doc"]), None))
        if r.random() < 0.25:
            body.insert(0, ('"""%s"""' % r.choice(["Helper.", "Process the input.", "Internal utility."]), None))
        for t, lab in body:
            fn_lines.append(("    " + t, lab))
        if wrap:
            fn_lines = [("    " + t, lab) for t, lab in fn_lines]
    return mod, fn_lines, spec["imports"]

def assemble(blocks, r, wrap):
    imports, parts = set(), []
    for mod, fn_lines, imps in blocks:
        imports.update(imps)
        parts.append((mod, fn_lines))
    lines = [(i, None) for i in sorted(imports)]
    if lines:
        lines.append(("", None)); lines.append(("", None))
    for mod, _ in parts:
        for t, lab in mod:
            lines.append((t, lab))
    if any(mod for mod, _ in parts):
        lines.append(("", None)); lines.append(("", None))
    if wrap:
        lines.append(("class %s:" % r.choice(["CryptoHelper", "SecurityUtils", "TokenService", "Vault", "Manager"]), None))
    for idx, (_, fn_lines) in enumerate(parts):
        for t, lab in fn_lines:
            lines.append((t, lab))
        if fn_lines:
            lines.append(("", None))
            if not wrap:
                lines.append(("", None))
    while lines and lines[-1][0] == "":
        lines.pop()
    code = "\n".join(t for t, _ in lines) + "\n"
    gold = {}
    for n, (t, lab) in enumerate(lines, 1):
        if lab:
            gold.setdefault(lab, []).append(n)
    return code, gold

def gen_one(r, fam):
    by_cls_v = {c: [s for s in SPECS if s["cls"] == c and s["kind"] == "vuln" and s["fam"] == fam] for c in CLASSES}
    by_cls_s = {c: [s for s in SPECS if s["cls"] == c and s["kind"] == "safe" and s["fam"] == fam] for c in CLASSES}
    p = r.random()
    n_vuln = 0 if p < 0.30 else (1 if p < 0.80 else 2)
    vuln_cls = r.sample(list(CLASSES), n_vuln)
    # classes that conflict when present together (same function style) are fine; keep them distinct
    safe_pool = [c for c in CLASSES if c not in vuln_cls]
    n_safe = r.choice([0, 1, 1, 2]) if n_vuln else r.choice([1, 1, 2, 3])
    safe_cls = r.sample(safe_pool, min(n_safe, len(safe_pool)))
    n_noise = r.choice([0, 1, 1, 2])
    chosen = [r.choice(by_cls_v[c]) for c in vuln_cls] + [r.choice(by_cls_s[c]) for c in safe_cls] + \
             [r.choice(NOISE) for _ in range(n_noise)]
    if not chosen:
        chosen = [r.choice(NOISE)]
    r.shuffle(chosen)
    wrap = r.random() < 0.2
    used = set()
    blocks = [build_block(s, r, wrap, used) for s in chosen]
    code, gold = assemble(blocks, r, wrap)
    ast.parse(code)
    # verify the labels we expect are exactly the ones present
    assert set(gold) == set(vuln_cls), (gold, vuln_cls)
    return code, gold

def gen_split(name, fam, n, seed, seen):
    r = random.Random(seed)
    out, tries = [], 0
    while len(out) < n and tries < n * 50:
        tries += 1
        try:
            code, gold = gen_one(r, fam)
        except (SyntaxError, AssertionError):
            continue
        h = hashlib.sha1(code.encode()).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        out.append({"id": "%s-%05d" % (name, len(out)), "split": name, "code": code,
                    "gold": [{"id": c, "lines": ls} for c, ls in sorted(gold.items(), key=lambda kv: kv[1][0])]})
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data")
    ap.add_argument("--n-train", type=int, default=3000)
    ap.add_argument("--n-val", type=int, default=300)
    ap.add_argument("--n-test", type=int, default=500)
    a = ap.parse_args()
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    seen = set()
    # test sets first so train cannot contain any test snippet
    splits = [("test_ood", "ood", a.n_test, 3), ("test_iid", "train", a.n_test, 2),
              ("val", "train", a.n_val, 1), ("train", "train", a.n_train, 0)]
    for name, fam, n, seed in splits:
        rows = gen_split(name, fam, n, 1000 + seed, seen)
        with open(out / ("%s.jsonl" % name), "w") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")
        cnt = {}
        for row in rows:
            for g in row["gold"]:
                cnt[g["id"]] = cnt.get(g["id"], 0) + 1
        clean = sum(1 for row in rows if not row["gold"])
        print(name, len(rows), "clean:", clean, "classes:", dict(sorted(cnt.items())))

if __name__ == "__main__":
    main()
