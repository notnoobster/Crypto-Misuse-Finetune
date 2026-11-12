#!/bin/bash
#SBATCH --job-name=cmft-train
#SBATCH --nodes=1
#SBATCH --nodelist=gpu0
#SBATCH --partition=gpu
#SBATCH --time=06:00:00
#SBATCH --output=/home/%u/projects/crypto-misuse-ft/logs/train-%j.log
# Env overrides: RUN (adapter dir name), MAXSTEPS, LIMIT, EPOCHS, MODEL
P="$HOME/projects/crypto-misuse-ft"; LLM="$HOME/projects/llm"
RUN="${RUN:-run1}"; MODEL="${MODEL:-$LLM/models/Qwen3.8-27B}"
module load gcc/15.2 2>/dev/null || true
export CC="$(command -v gcc)" CXX="$(command -v g++)"
PY_HDR="$LLM/python/include/python3.12"
export C_INCLUDE_PATH="$PY_HDR:$C_INCLUDE_PATH" CPLUS_INCLUDE_PATH="$PY_HDR:$CPLUS_INCLUDE_PATH"
export HF_HUB_OFFLINE=1 TOKENIZERS_PARALLELISM=false PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
cd "$P"
nvidia-smi --query-gpu=name,memory.total --format=csv
"$P/ft-env/bin/torchrun" --nproc_per_node=4 train_lora.py --model "$MODEL" --train data/train.jsonl \
    --out "adapters/$RUN" --epochs "${EPOCHS:-2}" --max-steps "${MAXSTEPS:--1}" --limit "${LIMIT:-0}"
echo exit=$?
