# Week 1 runbook

Run every command from the repository root on the SSH server. Keep failed outputs; do not replace them with a later successful run.

## Step 0 — Create the research repository

Copy this kit into a new GitHub repository. Keep it private until logs have been checked for private data, then invite the professor as a collaborator.

```bash
git init
git branch -M main
git add .
git commit -m "Add reproducible Week 1 research plan"
git remote add origin <YOUR-GITHUB-REPOSITORY-URL>
git push -u origin main
```

On the SSH server, clone this repository and run the remaining steps there. Do not add the downloaded target source trees because `.gitignore` excludes `targets/source/`.

## Step 1 — Freeze the claim before experiments

Read `docs/research_claim.md` and `docs/threat_model.md`. Confirm that every proposed test maps to source evidence, meaning, or binding. Commit these files before observing experimental failures.

```bash
git add docs targets/manifest.json traces
git commit -m "Define Week 1 claim targets and threat model"
```

**Review gate 1:** the claim explicitly says “across independently implemented systems,” and a violation requires a controlled sink effect.

## Step 2 — Capture the SSH environment

```bash
bash scripts/collect_env.sh
cat results/week1/environment/system.txt
cat results/week1/environment/sha256.txt
```

Install missing prerequisites through the server's normal package process: Git, Python 3.10 or newer, `uv`, Node.js, and npm. Run the capture script again after installation.

**Review gate 2:** the environment file includes the OS, Git, Python, uv, Node, and npm versions. It contains no keys or tokens.

## Step 3 — Fetch exact source revisions

```bash
bash scripts/fetch_targets.sh
python3 scripts/verify_week1.py --foundation
```

Record the checked revisions:

```bash
for d in targets/source/*; do
  test -d "$d/.git" && printf '%s %s\n' "$d" "$(git -C "$d" rev-parse HEAD)"
done | tee results/week1/environment/target-commits.txt
sha256sum results/week1/environment/target-commits.txt >> results/week1/environment/sha256.txt
```

**Review gate 3:** every revision exactly matches `targets/manifest.json`. Do not substitute a tutorial repository for the maintained Agent Framework target.

## Step 4 — Run unmodified baseline tests

Keep a separate transcript for each target. Follow the install instructions in each pinned repository because package commands can differ by revision.

### CaMeL

```bash
cd targets/source/camel-prompt-injection
uv sync
uv run pytest 2>&1 | tee ../../../results/week1/camel-upstream-tests.log
cd ../../..
```

### Microsoft Agent Framework FIDES

The pinned workspace defines the install command below. Run its focused security test file:

```bash
cd targets/source/agent-framework/python
uv sync --all-packages --all-extras --all-groups --frozen --prerelease=if-necessary
uv run pytest packages/core/tests/test_security.py -m "not integration" \
  2>&1 | tee ../../../../results/week1/maf-security-tests.log
cd ../../../..
```

Also run one local security sample only if it can use a test account or local model and will not send private data. Record the sample name, model, and configuration. The focused unit test is the required baseline; an unavailable model service must not be described as a framework failure.

### MCP filesystem target

The pinned repository is an npm workspace. Install from its root and select the filesystem workspace:

```bash
cd targets/source/mcp-servers
npm ci
npm run build --workspace @modelcontextprotocol/server-filesystem
npm test --workspace @modelcontextprotocol/server-filesystem \
  2>&1 | tee ../../../results/week1/mcp-filesystem-tests.log
cd ../../..
```

For later live runs, give the server only a newly created temporary directory as its allowed root.

**Review gate 4:** for each target, record passed, failed, or blocked. A failure is evidence about feasibility; never silently omit it. At least MAF FIDES and CaMeL must run with their security checks enabled before Week 1 can pass.

## Step 5 — Build one controlled sink per traced target

Use a local capture sink that records the final operation and exact arguments after the real security path.

For MAF, register a harmless `capture_write(destination, content)` tool through the normal `FunctionTool` path. The tool writes only inside a new temporary directory and creates `sink_receipt.json` containing the received destination, resolved destination, content SHA-256, and success status.

For CaMeL, register the equivalent function through `AgentDojoFunction` and its normal runtime. Its receipt must use the same fields. Do not call the policy function directly and then call the sink separately; the target's normal execution path must connect them.

**Review gate 5:** changing the pre-check log alone cannot change the receipt. The receipt is generated inside the final tool function.

## Step 6 — Record benign trace A: MAF FIDES

Use a fixed fixture such as content `week1-safe` written to `safe/maf.txt`. Assign the input's known trust label in the fixture. Run through:

```text
fixture input
-> context labels and label tracking
-> PolicyEnforcementFunctionMiddleware
-> decision and any approval signature
-> FunctionTool.invoke and approved-argument check
-> capture_write sink receipt
```

Write the required files listed in `traces/README.md` to `results/week1/maf_fides_benign/`. Record the action as seen at every stage; do not reuse one object for all events.

**Review gate 6:** the trace has all five event types, the check is genuinely enabled, and the receipt proves the expected harmless effect.

## Step 7 — Record benign trace B: CaMeL

Use equivalent fixed data and destination `safe/camel.txt`. Run through:

```text
fixture input
-> CaMeL value dependencies and capabilities
-> interpreter argument/dependency evaluation
-> SecurityPolicyEngine.check_policy
-> AgentDojoFunction.call
-> runtime.run_function and capture sink receipt
```

Write the required files to `results/week1/camel_benign/`.

When computing expected source influence, use the fixture's known source set as the oracle. Do not infer the expected set from the implementation being tested.

**Review gate 7:** the safe action is allowed, visible evidence is recorded, and the receipt came from `runtime.run_function` through the normal tool path.

## Step 8 — Validate and commit Week 1 evidence

```bash
python3 scripts/verify_week1.py --complete
find results/week1 -type f ! -name sha256.txt -print0 \
  | sort -z | xargs -0 sha256sum > results/week1/all-files.sha256
git add results professor_update.md
git commit -m "Add reproducible Week 1 benign traces"
git tag week1-foundation-v1
```

Complete `professor_update.md` using only recorded evidence, then push the commit and tag to GitHub.

**Week 1 exit condition:** MAF FIDES and CaMeL both run locally with security enabled, both traces reach controlled sinks, and the gap remains a specific cross-system question. If this fails, narrow the target set or scope and explain why.

## Step 9 — Experiments after the Week 1 gate

Only after the benign traces pass, duplicate each benign case and change one boundary at a time:

1. **Source evidence mutations:** serialize and rebuild values, rename fields, merge values, or save and restore state. Test whether known untrusted influence remains visible.
2. **Meaning mutations:** try path normalization, URL forms, aliases, encodings, duplicate fields, and defaults. Compare the action hash at the check with the sink-resolved receipt.
3. **Binding mutations:** test post-check argument changes, approval replay, retries, and resume flows. Compare approved, dispatched, and sink action hashes.

For each family include a safe control, a policy-denied control, and a deliberately instrumented known mismatch that proves the harness can detect a failure. Report attempted cases and negative results as carefully as successful violations.

