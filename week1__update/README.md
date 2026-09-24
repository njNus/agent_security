# Week 1: Cross-component semantic integrity foundation

This directory contains the reproducible Week 1 foundation for studying security checks across independently implemented tool-using agent systems.

## Research question

Across more than one independently implemented secured agent system, can a normal component boundary cause:

1. the security check to receive incomplete or incorrect source evidence;
2. the security check and final sink to understand an action differently; or
3. an action to change after it has been checked or approved?

The study does not claim that labels, provenance, canonical actions, or approval binding are individually new. It tests a common method for finding and comparing these failures across existing systems.

## Completed Week 1 evidence

| Requirement | Status | Evidence | What it establishes |
|---|---:|---|---|
| Three exact targets | Complete | [`targets/manifest.json`](targets/manifest.json) | The systems and source revisions are fixed. |
| Security checks and sinks | Complete | [`targets/manifest.json`](targets/manifest.json) | Each target has an identifiable check and final effect. |
| Research claim | Complete | [`docs/research_claim.md`](docs/research_claim.md) | The proposed gap is stated as a cross-system question. |
| Threat model | Complete | [`docs/threat_model.md`](docs/threat_model.md) | Attacker control and a successful violation are defined. |
| SSH environment | Complete | [`results/week1/environment/`](results/week1/environment/) | The execution platform and tool versions are recorded. |
| CaMeL baseline | Passed | [`results/week1/baselines/camel/`](results/week1/baselines/camel/) | The pinned CaMeL target passed 126 tests. |
| MAF FIDES baseline | Passed | [`results/week1/baselines/maf-fides/`](results/week1/baselines/maf-fides/) | The pinned FIDES security test suite completed with exit code 0. |
| MCP filesystem baseline | Passed | [`results/week1/baselines/mcp-filesystem/`](results/week1/baselines/mcp-filesystem/) | The pinned filesystem target passed 168 tests. |
| MAF benign trace | Passed | [`results/week1/maf_fides_benign/`](results/week1/maf_fides_benign/) | A harmless action passed through FIDES and reached the controlled sink. |
| CaMeL benign trace | Passed | [`results/week1/camel_benign/`](results/week1/camel_benign/) | A harmless action passed through CaMeL and reached the controlled sink. |
| Trace structure | Passed | `python3 scripts/verify_week1.py --complete` | Both traces contain input, check, decision, dispatch, and sink events. |

These results establish feasibility and end-to-end observability. They do not establish a security violation. Mutation experiments are the next research stage.

## Complete reproduction order

The detailed commands and expected evidence are in [`docs/week1_runbook.md`](docs/week1_runbook.md). The full order is:

1. Clone the public repository and enter `week1__update`.
2. Check Git, Python, `uv`, Node.js, and npm.
3. Capture the environment.
4. Fetch and verify the exact target revisions.
5. Run the CaMeL baseline tests.
6. Run the MAF FIDES security baseline tests.
7. Build and test the MCP filesystem server.
8. Run the MAF FIDES benign trace.
9. Run the CaMeL benign trace.
10. Verify hashes, trace order, decisions, and sink receipts.

Start with:

```bash
git clone https://github.com/njNus/agent_security.git
cd agent_security/week1__update

git --version
uv --version
uv python install 3.12
uv run --python 3.12 python --version
node --version
npm --version

bash scripts/collect_env.sh
bash scripts/fetch_targets.sh
python3 scripts/verify_week1.py --foundation
```

Continue with the three baseline sections and two trace sections in the runbook. Finish with:

```bash
python3 scripts/verify_week1.py --complete
```

Expected final output:

```text
PASS: target manifest has three pinned, inspectable targets
PASS: maf_fides_benign contains a complete ordered trace
PASS: camel_benign contains a complete ordered trace
PASS: Week 1 completion structure is present
```

## Evidence rule

Every traced action records the same five points:

```text
known input source
    -> action presented to the security check
    -> security decision
    -> action sent for execution
    -> effect observed at the controlled sink
```

The same action representation and comparison rule are used for both systems. System-specific code only extracts each target's native evidence.

## Repository layout

```text
docs/                  research claim, threat model, and full runbook
experiments/           executable benign trace programs
results/week1/          recorded environment, baselines, traces, and receipts
scripts/                environment, target-fetch, and validation scripts
targets/manifest.json  exact versions, checks, sinks, and setup information
traces/                common trace schema and evidence format
```

## Public-data rule

The repository may contain exact commands, revisions, test logs, sanitized traces, sink receipts, and hashes. It must not contain API keys, `.env` files, access tokens, private prompts, user data, or unrestricted server content. Downloaded target source trees remain local under `targets/source/` and are excluded by `.gitignore`.

