# Results: fine-tuned Qwen3.8-27B vs baselines on cryptographic misuse in Python

Micro-F1 over the 10 classes (snippet-level class detection). Bandit and Semgrep are scored on all 10 classes; classes
they have no rule for count as misses.

| System | test_iid (templates) | test_ood (unseen libs, templates) | natural (adjudicated, strict) | natural (lenient) | natural (unadjudicated) |
|---|---|---|---|---|---|
| tuned | 1.000 | 1.000 | 0.963 | 0.930 | 0.898 |
| base | 0.890 | 0.946 | 0.913 | 0.932 | 0.849 |
| bandit | 0.542 | 0.588 | 0.662 | 0.718 | 0.664 |
| semgrep | 0.492 | 0.514 | 0.398 | 0.479 | 0.423 |

Natural set, adjudicated strict: precision / recall

| System | precision | recall | exact-match snippets |
|---|---|---|---|
| tuned | 0.933 | 0.994 | 0.949 |
| base | 0.862 | 0.970 | 0.886 |
| bandit | 0.865 | 0.536 | 0.700 |
| semgrep | 0.776 | 0.268 | 0.565 |

Restricted to the classes Bandit has rules for (ecb_mode, hardcoded_key, insecure_random, small_rsa_key, tls_verify_disabled, weak_cipher, weak_hash), natural set micro-F1, strict / lenient:

- tuned: 0.960 / 0.915
- base: 0.912 / 0.938
- bandit: 0.804 / 0.864
- semgrep: 0.506 / 0.600

Paired bootstrap (2000 resamples of the 237 natural snippets), micro-F1 difference, tuned minus X:

- vs base: +0.050 (95% CI +0.026 to +0.076)
- vs bandit: +0.300 (95% CI +0.230 to +0.373)
- vs semgrep: +0.564 (95% CI +0.473 to +0.654)

Per class on the natural set (adjudicated strict), tuned F1 / base F1 / Bandit F1 / Semgrep F1, positives:

| class | n positive | tuned | base | bandit | semgrep |
|---|---|---|---|---|---|
| ecb_mode | 8 | 1.00 | 1.00 | 0.67 | 0.00 |
| static_iv_nonce | 12 | 1.00 | 1.00 | 0.00 | 0.00 |
| hardcoded_key | 33 | 0.88 | 0.84 | 0.73 | 0.11 |
| weak_hash | 9 | 1.00 | 0.67 | 0.60 | 0.60 |
| weak_cipher | 3 | 1.00 | 1.00 | 0.50 | 0.00 |
| weak_password_storage | 12 | 0.92 | 0.78 | 0.00 | 0.00 |
| insecure_random | 21 | 0.98 | 0.95 | 1.00 | 0.00 |
| small_rsa_key | 19 | 1.00 | 1.00 | 1.00 | 0.97 |
| nonconstant_compare | 24 | 0.98 | 0.94 | 0.00 | 0.00 |
| tls_verify_disabled | 27 | 1.00 | 1.00 | 0.74 | 0.71 |

## Caveats

- test_iid and test_ood are generated from the same template generator as the training data. test_ood uses libraries absent from
  training, but the underlying patterns are the same; the tuned model's 1.000 there shows it learned the task definition, not that
  it would score 1.000 on arbitrary real code. The natural set is the realistic measure.
- The natural set is 237 snippets written by a separate Qwen model (Qwen3.6-35B-A3B). Labels came from the generation request and
  were cross-checked, then adjudicated (see ADJUDICATION.md): 18 missed labels added, 5 wrong labels removed, by one reviewer
  (Claude) who saw the model outputs. Per-class counts for weak_cipher (3) and ecb_mode (8) are too small to read.
- The first evaluation run applied the adapter on only 1 of 4 GPUs (a harness bug, fixed and rerun); only the rerun is reported.
- Line-number accuracy is not reported for the natural set: the generator often tagged the wrong line of multi-line calls.
