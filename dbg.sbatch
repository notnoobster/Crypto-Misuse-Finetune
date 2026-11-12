#!/bin/bash
#SBATCH --job-name=cmft-dbg
#SBATCH --nodes=1
#SBATCH --nodelist=gpu0
#SBATCH --partition=gpu
#SBATCH --time=00:40:00
#SBATCH --output=/home/%u/projects/crypto-misuse-ft/logs/dbg-%j.log
P="$HOME/projects/crypto-misuse-ft"; LLM="$HOME/projects/llm"; MODEL="$LLM/models/Qwen3.8-27B"
module load gcc/15.2 2>/dev/null || true
export CC="$(command -v gcc)" CXX="$(command -v g++)"
PY_HDR="$LLM/python/include/python3.12"
export C_INCLUDE_PATH="$PY_HDR:$C_INCLUDE_PATH" CPLUS_INCLUDE_PATH="$PY_HDR:$CPLUS_INCLUDE_PATH"
export HF_HUB_OFFLINE=1 TOKENIZERS_PARALLELISM=false
cd "$P"
for bsz in 1 8; do
  "$P/ft-env/bin/torchrun" --nproc_per_node=1 eval_hf.py --model "$MODEL" --adapter adapters/run1 \
      --split data/debug_iid.jsonl --out results/dbg_bsz$bsz --bsz $bsz
  "$P/ft-env/bin/python" score.py data/debug_iid.jsonl "dbg_bsz$bsz" results/dbg_bsz$bsz | head -1
done
echo dbg_done
