# Week 1 public reproduction runbook

This runbook lets any researcher reproduce the recorded Week 1 foundation on a Linux or SSH server. Run commands from the `week1__update` directory unless a step says otherwise.

Failed commands are results too. Preserve their exit codes and logs instead of reporting only a later successful run.

## 1. Clone the repository

```bash
git clone https://github.com/njNus/agent_security.git
cd agent_security/week1__update
```

Downloaded target repositories are stored under `targets/source/`. They are excluded from this repository because their exact upstream revisions are recorded in `targets/manifest.json`.

## 2. Check the required tools

Required versions:

- Git;
- `uv`;
- Python 3.12 for the recorded reproduction;
- Node.js 22.12 or newer; and
- npm.

```bash
git --version
uv --version
uv python install 3.12
uv run --python 3.12 python --version
node --version
npm --version
```

The original run used Python 3.12.13, uv 0.11.6, Node 22.23.3, npm 10.9.9, and Git 2.43.0. Later compatible versions may work, but any difference must be recorded.

## 3. Capture the environment

```bash
bash scripts/collect_env.sh

{
  echo "research_python=$(uv run --python 3.12 python --version 2>&1)"
  echo "node=$(node --version)"
  echo "npm=$(npm --version)"
  echo "uv=$(uv --version)"
} > results/week1/environment/research-toolchain.txt

sha256sum \
  results/week1/environment/system.txt \
  results/week1/environment/research-toolchain.txt \
  > results/week1/environment/sha256.txt
```

Check that the files contain version information and no secrets.

## 4. Fetch and verify the pinned targets

```bash
bash scripts/fetch_targets.sh \
  2>&1 | tee results/week1/environment/fetch-targets.log

for d in targets/source/*; do
  if [ -d "$d/.git" ]; then
    printf '%s %s\n' "$d" "$(git -C "$d" rev-parse HEAD)"
  fi
done | tee results/week1/environment/target-commits.txt

python3 scripts/verify_week1.py --foundation
```

Every printed revision must match `targets/manifest.json`.

## 5. Run the CaMeL baseline

```bash
ROOT="$(pwd)"
OUT="$ROOT/results/week1/baselines/camel"
TARGET="$ROOT/targets/source/camel-prompt-injection"
mkdir -p "$OUT"

{
  echo "target=CaMeL"
  echo "revision=$(git -C "$TARGET" rev-parse HEAD)"
  echo "python=$(uv run --python 3.12 python --version 2>&1)"
  echo "setup=uv sync --python 3.12"
  echo "test=uv run --python 3.12 pytest -q"
} > "$OUT/command.txt"

cd "$TARGET"
set -o pipefail
env -u VIRTUAL_ENV uv sync --python 3.12 2>&1 | tee "$OUT/setup.log"
echo "${PIPESTATUS[0]}" > "$OUT/setup-exit-code.txt"

env -u VIRTUAL_ENV uv run --python 3.12 pytest -q 2>&1 | tee "$OUT/pytest.log"
echo "${PIPESTATUS[0]}" > "$OUT/pytest-exit-code.txt"
cd "$ROOT"
```

Recorded result: setup exit code `0`, test exit code `0`, and 126 tests passed.

## 6. Run the MAF FIDES security baseline

```bash
ROOT="$(pwd)"
OUT="$ROOT/results/week1/baselines/maf-fides"
TARGET="$ROOT/targets/source/agent-framework"
mkdir -p "$OUT"

{
  echo "target=Microsoft Agent Framework FIDES"
  echo "revision=$(git -C "$TARGET" rev-parse HEAD)"
  echo "python=$(uv run --python 3.12 python --version 2>&1)"
  echo "test_file=python/packages/core/tests/test_security.py"
} > "$OUT/command.txt"

cd "$TARGET/python"
set -o pipefail
env -u VIRTUAL_ENV uv sync \
  --python 3.12 --all-packages --all-extras --all-groups \
  --frozen --prerelease=if-necessary \
  2>&1 | tee "$OUT/setup.log"
echo "${PIPESTATUS[0]}" > "$OUT/setup-exit-code.txt"

env -u VIRTUAL_ENV uv run --python 3.12 \
  pytest packages/core/tests/test_security.py -m "not integration" -q \
  2>&1 | tee "$OUT/pytest.log"
echo "${PIPESTATUS[0]}" > "$OUT/pytest-exit-code.txt"
cd "$ROOT"
```

Recorded result: setup and test exit codes were `0`. FIDES emitted an `ExperimentalWarning` for `ContentVariableStore`; this is a recorded limitation rather than a test failure.

## 7. Run the MCP filesystem baseline

```bash
ROOT="$(pwd)"
OUT="$ROOT/results/week1/baselines/mcp-filesystem"
TARGET="$ROOT/targets/source/mcp-servers"
mkdir -p "$OUT"

{
  echo "target=Official MCP filesystem server"
  echo "revision=$(git -C "$TARGET" rev-parse HEAD)"
  echo "node=$(node --version)"
  echo "npm=$(npm --version)"
  echo "package=@modelcontextprotocol/server-filesystem"
} > "$OUT/command.txt"

cd "$TARGET"
set -o pipefail
npm ci 2>&1 | tee "$OUT/setup.log"
echo "${PIPESTATUS[0]}" > "$OUT/setup-exit-code.txt"

npm run build --workspace @modelcontextprotocol/server-filesystem \
  2>&1 | tee "$OUT/build.log"
echo "${PIPESTATUS[0]}" > "$OUT/build-exit-code.txt"

npm test --workspace @modelcontextprotocol/server-filesystem \
  2>&1 | tee "$OUT/test.log"
echo "${PIPESTATUS[0]}" > "$OUT/test-exit-code.txt"
cd "$ROOT"
```

Recorded result: setup, build, and test exit codes were `0`; 10 test files and 168 tests passed.

## 8. Run the two benign end-to-end traces

The exact commands are in [`../experiments/README.md`](../experiments/README.md).

The MAF trace follows:

```text
fixture input
-> label tracking
-> PolicyEnforcementFunctionMiddleware
-> allow decision
-> FunctionTool.invoke
-> controlled file sink
```

The CaMeL trace follows:

```text
fixture input
-> CaMeL parser and interpreter
-> SecurityPolicyEngine.check_policy
-> allow decision
-> AgentDojoFunction.call
-> FunctionsRuntime.run_function
-> controlled file sink
```

The programs require no model service or API key. Each program checks the pinned revision, five-event order, unchanged action hash, and existence of the harmless sink file.

## 9. Verify the result files

```bash
cat results/week1/maf_fides_benign/exit-code.txt
cat results/week1/camel_benign/exit-code.txt
cat results/week1/maf_fides_benign/decision.json
cat results/week1/camel_benign/decision.json
cat results/week1/maf_fides_benign/sink_receipt.json
cat results/week1/camel_benign/sink_receipt.json

python3 scripts/verify_week1.py --complete
```

Both exit codes must be `0`, both decisions must be `allow`, both sink receipts must contain `"exists": true`, and the validator must report four `PASS` lines.

Verify file integrity:

```bash
for name in maf_fides_benign camel_benign; do
  (
    cd "results/week1/$name"
    sha256sum -c sha256.txt
  )
done
```

## 10. Interpret the Week 1 result

Passing baselines show that the pinned targets run correctly before research mutations. Passing benign traces show that the complete security path is observable in two independently implemented systems and that a real controlled effect can be measured.

These outputs establish the foundation needed for later tests. They do not show a security violation because both harmless actions were correctly allowed and remained unchanged.

## Next research stage

After reproducing Week 1, change one boundary at a time:

1. **Source-evidence tests:** serialize and rebuild values, rename or merge fields, and save or restore state. Check whether all known untrusted influences remain visible.
2. **Meaning tests:** vary path forms, URLs, encodings, aliases, duplicate fields, and defaults. Compare what the check saw with the sink receipt.
3. **Binding tests:** test changes after checking, approval replay, retries, and resumed execution. Compare checked, approved, dispatched, and executed action hashes.

Each experiment family needs a harmless control, a policy-denied control, and a known injected mismatch that proves the measurement code can detect a failure.

