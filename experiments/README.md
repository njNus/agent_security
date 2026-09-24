# Benign end-to-end traces

These scripts run one harmless action through each target's real security path and into a controlled local sink. They require no model or API key.

## MAF FIDES

Run from the Week 1 repository root:

```bash
ROOT="$(pwd)"
OUT="$ROOT/results/week1/maf_fides_benign"
TARGET="$ROOT/targets/source/agent-framework"
mkdir -p "$OUT"
printf '%s\n' 'env -u VIRTUAL_ENV uv run --python 3.12 python experiments/maf_fides_benign.py' > "$OUT/command.txt"
cd "$TARGET/python"
set -o pipefail
env -u VIRTUAL_ENV uv run --python 3.12 python "$ROOT/experiments/maf_fides_benign.py" \
  --output "$OUT" --target "$TARGET" 2>&1 | tee "$OUT/stdout.log"
status=${PIPESTATUS[0]}
cd "$ROOT"
echo "$status" > "$OUT/exit-code.txt"
sha256sum "$OUT/command.txt" "$OUT/trace.jsonl" "$OUT/decision.json" \
  "$OUT/sink_receipt.json" "$OUT/stdout.log" "$OUT/NOTES.md" > "$OUT/sha256.txt"
```

## CaMeL

```bash
ROOT="$(pwd)"
OUT="$ROOT/results/week1/camel_benign"
TARGET="$ROOT/targets/source/camel-prompt-injection"
mkdir -p "$OUT"
printf '%s\n' 'env -u VIRTUAL_ENV uv run --python 3.12 python experiments/camel_benign.py' > "$OUT/command.txt"
cd "$TARGET"
set -o pipefail
env -u VIRTUAL_ENV uv run --python 3.12 python "$ROOT/experiments/camel_benign.py" \
  --output "$OUT" --target "$TARGET" 2>&1 | tee "$OUT/stdout.log"
status=${PIPESTATUS[0]}
cd "$ROOT"
echo "$status" > "$OUT/exit-code.txt"
sha256sum "$OUT/command.txt" "$OUT/trace.jsonl" "$OUT/decision.json" \
  "$OUT/sink_receipt.json" "$OUT/stdout.log" "$OUT/NOTES.md" > "$OUT/sha256.txt"
```

## Validate

Both `exit-code.txt` files must contain `0`. Then run:

```bash
python3 scripts/verify_week1.py --complete
```

Each trace must contain, in order: `input`, `check`, `decision`, `dispatch`, and `sink`.

