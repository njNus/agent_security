# Week 1 update

## One-paragraph result

I studied the existing systems and fixed a specific question: across independently implemented secured agent systems, can source information, the meaning of an action, or the approved arguments change between the security check and the final effect? The novelty matrix shows that earlier work contains related protections and individual tests, with CXI being the closest, but does not already provide this common cross-system empirical study. I pinned three accessible targets and identified a genuine security check and final sink in each. On the SSH server, **[state exact baseline result]**. I traced **[target 1]** and **[target 2]** from fixed benign input through the enabled security check to a controlled sink, producing **[link to trace directories]**. These outputs establish **[only the supported claim: feasibility and observability]**; they do not yet establish a security violation. The next step is to apply the same controlled boundary mutations to all targets and compare the check-visible action with the sink receipt.

## Evidence table

| Requirement | Evidence link | Observed result | What it establishes |
|---|---|---|---|
| Exact targets | `targets/manifest.json` | [fill] | The study uses reproducible real systems and versions. |
| Threat model | `docs/threat_model.md` | Fixed before mutation tests | Success and attacker control are defined in advance. |
| MAF baseline and trace | [fill link] | [fill] | MAF security path can be executed and observed end to end. |
| CaMeL baseline and trace | [fill link] | [fill] | CaMeL security path can be executed and observed end to end. |
| Validation | [link to validation output] | [fill] | Both traces contain the required input-to-sink evidence. |

## Limitations and next action

[List failed tests, missing instrumentation, model or API dependence, and any scope reduction.] Next, I will run source-evidence, meaning, and binding mutation families with safe, denied, and known-mismatch controls.

