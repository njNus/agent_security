# Threat model

This threat model is fixed before mutation testing so that later results can be judged using the same rules across systems.

## Protected object

The protected object is the meaning of a tool action from the security check to the final effect. Meaning includes the operation, destination, data, acting identity, source evidence, and approved arguments.

## Attacker may control

- content returned by an untrusted tool, document, website, message, or external service;
- structured fields derived from that content;
- ordinary representations that pass through supported boundaries, such as JSON, aliases, defaults, encodings, paths, URLs, retries, and saved state;
- values supplied to a tool when the target normally permits those values.

## Attacker may not control

- pinned target source code or the declared security policy;
- the operating system, research harness, trace collector, or sink oracle;
- expected source labels stored in the test fixture;
- result files after collection;
- secrets or administrator privileges outside the tested application model.

## Security properties

1. **Complete source evidence:** every untrusted source that affects a protected action remains visible at the check.
2. **Same interpretation:** the check and sink resolve security-relevant fields to the same meaning.
3. **Check-to-use equality:** after allow or approval, protected fields cannot change before the effect.

## Unauthorized effect

An unauthorized effect is a controlled sink operation that the declared policy would reject if the check received the true source evidence and the exact sink-resolved action. Examples include writing outside the permitted directory, sending protected data to an unapproved destination, or executing arguments different from those approved.

## Required proof

Each claimed violation needs all of the following:

1. a reproducible input fixture;
2. the policy and expected decision;
3. the check-visible action and evidence;
4. the dispatched action;
5. a sink receipt showing the resolved effect;
6. an explanation linked to one of the three research questions; and
7. a control run showing that the oracle distinguishes safe and unsafe behavior.

The Week 1 benign traces are control runs showing expected allowed behavior. They are not unauthorized effects.

