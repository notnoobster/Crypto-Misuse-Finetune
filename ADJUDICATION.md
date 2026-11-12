# Natural-set adjudication

Added labels (real flaw present, label missed):

- natural-0002: hardcoded_key
- natural-0004: hardcoded_key
- natural-0010: nonconstant_compare
- natural-0019: hardcoded_key
- natural-0020: static_iv_nonce
- natural-0038: hardcoded_key
- natural-0065: hardcoded_key
- natural-0072: nonconstant_compare
- natural-0082: nonconstant_compare
- natural-0096: hardcoded_key
- natural-0125: hardcoded_key
- natural-0143: hardcoded_key
- natural-0172: hardcoded_key
- natural-0172: nonconstant_compare
- natural-0184: hardcoded_key
- natural-0197: hardcoded_key
- natural-0226: nonconstant_compare
- natural-0233: hardcoded_key

Removed labels (flaw not actually present):

- natural-0025: insecure_random
- natural-0068: nonconstant_compare
- natural-0193: hardcoded_key
- natural-0233: nonconstant_compare
- natural-0235: weak_password_storage

Left unchanged on purpose: env-var defaults such as os.environ.get('X', 'default_secret'); plaintext password storage
(outside the 'fast/unsalted/low-iteration hash' definition); PBKDF2 at 100000 iterations; license-key literals.
