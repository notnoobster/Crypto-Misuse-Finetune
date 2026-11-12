#!/bin/bash
#SBATCH --job-name=cmft-natural
#SBATCH --nodes=1
#SBATCH --nodelist=gpu0
#SBATCH --partition=gpu
#SBATCH --time=02:00:00
#SBATCH --output=/home/%u/projects/crypto-misuse-ft/logs/natural-%j.log
# Serve Qwen3.6-35B-A3B with vLLM, generate the natural held-out set, then exit.
LLM="$HOME/projects/llm"; P="$HOME/projects/crypto-misuse-ft"
export PATH="$LLM/vllm-env/bin:$PATH"
module load gcc/15.2 2>/dev/null || true
export CC="$(command -v gcc)" CXX="$(command -v g++)"
PY_HDR="$LLM/python/include/python3.12"
export C_INCLUDE_PATH="$PY_HDR:$C_INCLUDE_PATH" CPLUS_INCLUDE_PATH="$PY_HDR:$CPLUS_INCLUDE_PATH"
"$LLM/vllm-env/bin/python" -m vllm.entrypoints.openai.api_server \
    --model "$LLM/models/Qwen3.6-35B-A3B" --served-model-name gen \
    --tensor-parallel-size 4 --port 8000 --max-model-len 16384 --gpu-memory-utilization 0.9 \
    --trust-remote-code --enforce-eager --reasoning-parser qwen3 > "$P/logs/natural-vllm.log" 2>&1 &
PID=$!
for i in $(seq 1 180); do
    curl -s localhost:8000/v1/models > /dev/null && break
    kill -0 "$PID" 2>/dev/null || { echo "vLLM died"; exit 1; }
    sleep 10
done
echo "server up after $((i*10))s"
cd "$P"
[ -f data/test_natural.jsonl ] && mv data/test_natural.jsonl data/test_natural_v1.jsonl.bak
"$LLM/vllm-env/bin/python" gen_natural.py --n 1200 --out data
kill "$PID"; wait "$PID" 2>/dev/null
echo done
