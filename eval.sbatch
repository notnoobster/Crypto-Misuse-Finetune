#!/bin/bash
#SBATCH --job-name=cmft-eval
#SBATCH --nodes=1
#SBATCH --nodelist=gpu0
#SBATCH --partition=gpu
#SBATCH --time=04:00:00
#SBATCH --output=/home/%u/projects/crypto-misuse-ft/logs/eval-%j.log
# One process per GPU (CUDA_VISIBLE_DEVICES), each loads the model once per mode and loops over splits.
# Env: RUN (adapter dir name), TAG (result prefix), MODES ("base tuned"), SPLITS, BSZ
P="$HOME/projects/crypto-misuse-ft"; LLM="$HOME/projects/llm"
RUN="${RUN:-run1}"; TAG="${TAG:-$RUN}"; MODEL="${MODEL:-$LLM/models/Qwen3.8-27B}"
module load gcc/15.2 2>/dev/null || true
export CC="$(command -v gcc)" CXX="$(command -v g++)"
PY_HDR="$LLM/python/include/python3.12"
export C_INCLUDE_PATH="$PY_HDR:$C_INCLUDE_PATH" CPLUS_INCLUDE_PATH="$PY_HDR:$CPLUS_INCLUDE_PATH"
export HF_HUB_OFFLINE=1 TOKENIZERS_PARALLELISM=false PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
cd "$P"; mkdir -p results
SPLITS="${SPLITS:-test_iid test_ood test_natural}"
LIST=""; for s in $SPLITS; do [ -f "data/$s.jsonl" ] && LIST="$LIST,data/$s.jsonl"; done; LIST="${LIST#,}"
for mode in ${MODES:-base tuned}; do
  AD=""; [ "$mode" = "tuned" ] && AD="--adapter adapters/$RUN"
  for i in 0 1 2 3; do
    CUDA_VISIBLE_DEVICES=$i "$P/ft-env/bin/python" eval_hf.py --model "$MODEL" $AD --shard $i --nshards 4 \
        --bsz "${BSZ:-8}" --splits "$LIST" --out-prefix "results/preds_${TAG}_${mode}" &
  done
  wait
  for s in $SPLITS; do
    [ -f "data/$s.jsonl" ] || continue
    "$P/ft-env/bin/python" score.py "data/$s.jsonl" "${mode}_${s}" "results/preds_${TAG}_${mode}_${s}" "results/score_${TAG}_${mode}_${s}.json"
  done
done
echo eval_done
