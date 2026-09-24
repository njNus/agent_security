# Research claim and decision rules

## Unified claim

Existing systems protect tool use in different ways, but we do not yet have a reusable empirical method that tests, across several independently implemented systems, whether security meaning remains unchanged from input evidence through the security check to the final effect.

## Questions

For each system and test action:

1. **Source evidence:** Does the check see every untrusted source that influenced the action?
2. **Meaning:** Does the check understand the same destination, operation, and data that the sink later uses?
3. **Binding:** Is the executed action exactly the action that was checked or approved?

## Common observations

Each run records:

- fixture-defined input and its known source;
- the action and evidence visible to the security check;
- allow, deny, or approval decision;
- the action dispatched after the decision; and
- a receipt from a controlled final sink.

## What counts as evidence of a violation

A result supports one of the three questions only when the controlled sink observes a real effect and the trace proves at least one of these conditions:

- **source failure:** a known untrusted influence is absent or incorrectly trusted at the check;
- **meaning failure:** the checked action and the sink-resolved action differ in a security-relevant field; or
- **binding failure:** the dispatched or executed action differs from the approved action.

A suspicious string, a blocked request, a model response, or a parser difference without an effect is not a security violation.

## Scope guardrail

One failure in one product is a useful case study. The broader claim needs the same failure class or the same effective test method to work in at least two independently implemented systems. Negative results remain publishable evidence if target coverage, test generation, and oracles are strong and fully reported.

