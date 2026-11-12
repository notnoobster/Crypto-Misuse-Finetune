#!/usr/bin/env python3
"""Greedy-decode splits with the 4-bit base model, with or without the LoRA adapter.

Run one process per GPU, each restricted with CUDA_VISIBLE_DEVICES so the model sits on cuda:0:
  CUDA_VISIBLE_DEVICES=$i eval_hf.py --model <dir> [--adapter <dir>] --shard $i --nshards 4 \
      --splits data/test_iid.jsonl,data/test_ood.jsonl --out-prefix results/preds_run1b_tuned
Writes {out_prefix}_{split}_rank{shard}.jsonl for each split.
"""
import argparse, json, os, time
from pathlib import Path
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from common import build_prompt, load

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--adapter")
    ap.add_argument("--splits", required=True)
    ap.add_argument("--out-prefix", required=True)
    ap.add_argument("--shard", type=int, default=0)
    ap.add_argument("--nshards", type=int, default=1)
    ap.add_argument("--bsz", type=int, default=8)
    ap.add_argument("--max-new", type=int, default=220)
    ap.add_argument("--no-quant", action="store_true")
    a = ap.parse_args()
    torch.cuda.set_device(0)
    tok = AutoTokenizer.from_pretrained(a.model)
    tok.padding_side = "left"
    kw = dict(dtype=torch.bfloat16, device_map={"": 0})
    if not a.no_quant:
        kw["quantization_config"] = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                                                      bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
    try:
        model = AutoModelForCausalLM.from_pretrained(a.model, **kw)
    except Exception:
        from transformers import AutoModelForImageTextToText
        model = AutoModelForImageTextToText.from_pretrained(a.model, **kw)
    if a.adapter:
        from peft import PeftModel
        model = PeftModel.from_pretrained(model, a.adapter)
        nb = sum(float(p.detach().abs().sum()) for n, p in model.named_parameters() if "lora_B" in n)
        nmod = sum(1 for n, _ in model.named_parameters() if "lora_B" in n)
        print("shard %d ADAPTER lora_B tensors %d, sum|B| %.3f (must be > 0)" % (a.shard, nmod, nb), flush=True)
        assert nb > 0, "LoRA weights are all zero: adapter not loaded"
    model.eval()
    for split in a.splits.split(","):
        name = Path(split).stem
        rows = load(split)[a.shard::a.nshards]
        prompts = []
        for r in rows:
            msgs = [{"role": "user", "content": build_prompt(r["code"])}]
            prompts.append(tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True, enable_thinking=False))
        order = sorted(range(len(rows)), key=lambda i: len(prompts[i]))
        out = open("%s_%s_rank%d.jsonl" % (a.out_prefix, name, a.shard), "w")
        t0 = time.time()
        for s in range(0, len(order), a.bsz):
            idx = order[s:s + a.bsz]
            enc = tok([prompts[i] for i in idx], return_tensors="pt", padding=True, add_special_tokens=False).to(0)
            with torch.no_grad():
                gen = model.generate(**enc, max_new_tokens=a.max_new, do_sample=False, pad_token_id=tok.pad_token_id or tok.eos_token_id)
            texts = tok.batch_decode(gen[:, enc["input_ids"].shape[1]:], skip_special_tokens=True)
            for i, t in zip(idx, texts):
                out.write(json.dumps({"id": rows[i]["id"], "text": t}) + "\n")
            out.flush()
        print("shard %d %s: %d rows in %.0fs" % (a.shard, name, len(rows), time.time() - t0), flush=True)

if __name__ == "__main__":
    main()
