# Cryptographic misuse detection: QLoRA-tuned Qwen3.8-27B vs Bandit and Semgrep

Fine-tunes Qwen3.8-27B (4-bit QLoRA, 4x RTX 6000 Ada, Slurm) to flag 10 classes of cryptographic misuse in Python
and report line numbers. See `RESULTS.md` for numbers and caveats, `ADJUDICATION.md` for label corrections.

- `gen_data.py`: template generator with labels known by construction (train / val / test_iid / test_ood; test_ood
  uses libraries never seen in training).
- `gen_natural.py`, `filter_natural.py`, `natural.sbatch`: held-out "natural" set written by Qwen3.6-35B-A3B,
  cross-checked against code markers.
- `train_lora.py`, `train.sbatch`: DDP QLoRA training (188 steps, about 36 minutes, 3,000 examples, 2 epochs).
- `eval_hf.py`, `eval.sbatch`, `score.py`, `eval_baselines.py`, `report.py`: evaluation, Bandit and Semgrep baselines, report.

Known limits: template test sets are easy by construction; natural set is 237 snippets with labels adjudicated by one
reviewer; line numbers are not scored on the natural set. A first evaluation run applied the adapter on 1 of 4 GPUs
(harness bug); it was fixed and rerun, and only the rerun is reported.
