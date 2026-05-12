#!/usr/bin/env bash
# Baixa modelos default no Ollama. Use após `make up`.
# RTX 4090 (24GB) suporta confortavelmente modelos 32B q4_K_M (~19GB).

set -euo pipefail

OLLAMA_URL="${OLLAMA_URL:-http://127.0.0.1:11434}"

# modelos sugeridos para 24GB VRAM
MODELS=(
  "qwen2.5:32b-instruct-q4_K_M"
  "qwen2.5:7b-instruct-q4_K_M"
)

# qwen2.5-coder:32b é alternativa pra análise técnica
# deepseek-r1:32b pra reasoning pesado

for m in "${MODELS[@]}"; do
  echo "==> Pulling $m"
  curl -sN -X POST "$OLLAMA_URL/api/pull" -d "{\"name\": \"$m\"}" | \
    while IFS= read -r line; do
      echo "  $line"
    done
done

echo "==> Modelos disponíveis:"
curl -s "$OLLAMA_URL/api/tags" | python3 -c "import json,sys; [print('  -', m['name']) for m in json.load(sys.stdin)['models']]" 2>/dev/null || true
