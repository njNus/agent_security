# Week 1: Cross-component semantic integrity foundation

This folder is the reproducible Week 1 record for studying security checks in several independently built tool-using agent systems.

## Research question

Across more than one independently implemented secured agent system, can normal component boundaries cause:

1. the security check to receive incomplete or wrong source evidence;
2. the security check and the final effect to interpret an action differently; or
3. an approved action to change before it is executed?

The study does **not** claim that labels, provenance, canonical actions, or approval binding are individually new. The contribution being tested is one common method for finding and comparing these failures across existing systems.

## What Week 1 must establish

| Output | What it establishes |
|---|---|
| Novelty matrix | The cross-system question is specific and is not fully answered by the compared work. |
| Target manifest | Real systems, exact source versions, security checks, and final effects are identifiable. |
| Threat model | Attacker control and the meaning of a security violation are fixed before testing. |
| Two benign traces | At least two systems run with security enabled and the whole check-to-effect path is observable. |

The novelty matrix is maintained in the accompanying Week 1 report. This repository records the experimental foundation.

## Current evidence status

- [x] Three accessible targets selected and pinned in `targets/manifest.json`.
- [x] Genuine security check and final sink identified in source for each target.
- [x] Threat model and common trace record defined.
- [x] Exact SSH environment captured.
- [x] Upstream security-enabled baselines passed on the SSH server.
- [x] Microsoft Agent Framework benign trace recorded.
- [x] CaMeL benign trace recorded.
- [x] Trace files and sink receipts checked with `scripts/verify_week1.py --complete`.

Unchecked items are planned work and must not be reported as completed.

## Run order

On the SSH server:

```bash
git clone <YOUR-RESEARCH-REPOSITORY-URL>
cd <YOUR-RESEARCH-REPOSITORY>
bash scripts/collect_env.sh
bash scripts/fetch_targets.sh
python3 scripts/verify_week1.py --foundation
```

Then follow `docs/week1_runbook.md` in order. Stop at every review gate and commit the evidence before continuing.

## Evidence rule

Every traced action must record the same five points:

```text
known input source
    -> action presented to the security check
    -> security decision
    -> action sent for execution
    -> effect observed at the controlled sink
```

System-specific adapters may translate native events into the common trace format. They must not change the test oracle.

## Repository layout

```text
docs/                  claim, threat model, and runbook
targets/manifest.json  exact versions, checks, sinks, and setup
traces/                common trace schema and recording guide
results/week1/          measured outputs only
scripts/                setup, environment capture, and validation
professor_update.md     evidence-linked Week 1 update template
```

## Reproducibility and privacy

Commit commands, exact revisions, configuration files, sanitized logs, trace files, and hashes. Never commit API keys, `.env` files, access tokens, private prompts, user data, or unrestricted server paths.

