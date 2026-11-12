#!/usr/bin/env python3
"""QLoRA fine-tune of a Qwen model to flag cryptographic misuse in Python code.

Launch with torchrun (one process per GPU, each holds a 4-bit copy of the base model):
  torchrun --nproc_per_node=4 train_lora.py --model <dir> --train data/train.jsonl --out adapters/run1
"""
import argparse, json, os, random, time
import torch
from transformers import (AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, Trainer, TrainingArguments)
from peft import LoraConfig, get_peft_model
from common import build_prompt, target_text, load

TARGETS = r"^(?!.*(visual|vision)).*\.(q_proj|k_proj|v_proj|o_proj|gate_proj|up_proj|down_proj)$"

def encode(tok, row, maxlen):
    msgs = [{"role": "user", "content": build_prompt(row["code"])}]
    prompt = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True, enable_thinking=False)
    p_ids = tok(prompt, add_special_tokens=False)["input_ids"]
    t_ids = tok(target_text(row["gold"]) + "<|im_end|>", add_special_tokens=False)["input_ids"]
    ids = (p_ids + t_ids)[:maxlen]
    labels = ([-100] * len(p_ids) + t_ids)[:maxlen]
    return {"input_ids": ids, "labels": labels}

class DS(torch.utils.data.Dataset):
    def __init__(self, items): self.items = items
    def __len__(self): return len(self.items)
    def __getitem__(self, i): return self.items[i]

def collate_factory(pad_id):
    def collate(batch):
        m = max(len(b["input_ids"]) for b in batch)
        ids = torch.full((len(batch), m), pad_id, dtype=torch.long)
        lab = torch.full((len(batch), m), -100, dtype=torch.long)
        att = torch.zeros((len(batch), m), dtype=torch.long)
        for i, b in enumerate(batch):
            n = len(b["input_ids"])
            ids[i, :n] = torch.tensor(b["input_ids"]); lab[i, :n] = torch.tensor(b["labels"]); att[i, :n] = 1
        return {"input_ids": ids, "labels": lab, "attention_mask": att}
    return collate

def load_model(path, quant, rank):
    kw = dict(dtype=torch.bfloat16, device_map={"": rank})
    if quant:
        kw["quantization_config"] = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                                                      bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
    try:
        return AutoModelForCausalLM.from_pretrained(path, **kw)
    except Exception as e:
        print("AutoModelForCausalLM failed (%s); falling back to ImageTextToText" % repr(e)[:200], flush=True)
        from transformers import AutoModelForImageTextToText
        return AutoModelForImageTextToText.from_pretrained(path, **kw)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--train", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--epochs", type=float, default=2)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--bsz", type=int, default=4)
    ap.add_argument("--accum", type=int, default=2)
    ap.add_argument("--maxlen", type=int, default=1536)
    ap.add_argument("--rank", type=int, default=16)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--max-steps", type=int, default=-1)
    ap.add_argument("--no-quant", action="store_true")
    ap.add_argument("--targets", default=TARGETS)
    a = ap.parse_args()

    local_rank = int(os.environ.get("LOCAL_RANK", 0)); world = int(os.environ.get("WORLD_SIZE", 1))
    torch.cuda.set_device(local_rank)
    tok = AutoTokenizer.from_pretrained(a.model)
    pad_id = tok.pad_token_id if tok.pad_token_id is not None else tok.eos_token_id
    rows = load(a.train)
    random.Random(0).shuffle(rows)
    if a.limit:
        rows = rows[:a.limit]
    items = [encode(tok, r, a.maxlen) for r in rows]
    if local_rank == 0:
        lens = sorted(len(i["input_ids"]) for i in items)
        print("examples", len(items), "tokens/example mean %.0f p95 %d max %d" % (sum(lens) / len(lens), lens[int(.95 * len(lens))], lens[-1]), flush=True)
        print("sample prompt tail:", repr(tok.decode(items[0]["input_ids"][-60:])), flush=True)

    model = load_model(a.model, not a.no_quant, local_rank)
    model.config.use_cache = False
    model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
    model.enable_input_require_grads()
    cfg = LoraConfig(r=a.rank, lora_alpha=2 * a.rank, lora_dropout=0.05, target_modules=a.targets,
                     bias="none", task_type="CAUSAL_LM")
    model = get_peft_model(model, cfg)
    if local_rank == 0:
        model.print_trainable_parameters()

    steps_per_epoch = max(1, len(items) // (a.bsz * a.accum * world))
    total = a.max_steps if a.max_steps > 0 else int(steps_per_epoch * a.epochs)
    args = TrainingArguments(
        output_dir=a.out, per_device_train_batch_size=a.bsz, gradient_accumulation_steps=a.accum,
        num_train_epochs=a.epochs, max_steps=a.max_steps, learning_rate=a.lr, lr_scheduler_type="cosine",
        warmup_steps=max(1, int(0.05 * total)), logging_steps=5, save_strategy="epoch" if a.max_steps < 0 else "no",
        bf16=True, gradient_checkpointing=True, gradient_checkpointing_kwargs={"use_reentrant": False},
        ddp_find_unused_parameters=False, remove_unused_columns=False, report_to="none",
        dataloader_num_workers=2, save_total_limit=2, optim="adamw_torch", weight_decay=0.0)
    trainer = Trainer(model=model, args=args, train_dataset=DS(items), data_collator=collate_factory(pad_id))
    t0 = time.time()
    trainer.train()
    el = time.time() - t0
    if local_rank == 0:
        ntok = sum(len(i["input_ids"]) for i in items) * (a.epochs if a.max_steps < 0 else 1)
        print("TRAIN_DONE seconds %.0f approx tokens/s (all GPUs) %.0f peak mem GB %.1f" % (
            el, ntok / el, torch.cuda.max_memory_allocated() / 1e9), flush=True)
        model.save_pretrained(a.out)
        tok.save_pretrained(a.out)
        json.dump({"args": vars(a), "seconds": el, "examples": len(items), "world": world},
                  open(os.path.join(a.out, "train_meta.json"), "w"), indent=1)

if __name__ == "__main__":
    main()
