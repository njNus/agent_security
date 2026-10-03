# Week 2 boundary inventory

This inventory identifies the important handoffs between input, security
tracking, policy checking, execution, and the final effect in the three
selected systems.

The complete inventory is in
[`week2_boundary_inventory.csv`](week2_boundary_inventory.csv).

## Meaning of a boundary

A boundary is a point where one component gives an action or value to another
component. A security problem may occur if the receiving component sees a
different operation, destination, content, source, or trust label from the
one that was checked.

Each inventory row records:

- who produces the value;
- who receives it;
- its data form;
- the function that parses or changes it;
- which component owns its trust information;
- which fields must remain unchanged;
- which security check protects it;
- how much an attacker may control;
- the final effect connected to it;
- whether it has been traced, inspected in source, or only exercised by an
  upstream baseline.

## Current evidence

MAF FIDES and CaMeL have complete benign allow traces and genuine deny
controls. Their policy decisions and controlled sinks are observable.

The MCP Filesystem server has a passing upstream baseline and an inspected
path from a `write_file` request through path validation to the filesystem.
A complete research trace for this target still needs to be added. The
inventory marks this difference rather than reporting MCP as fully traced.

## Important mutation candidates

The most useful early boundaries are:

1. **MAF M03-M07:** hidden-reference expansion, security snapshots, policy
   decisions, and the final dispatch guard.
2. **CaMeL C03-C07:** tool-return sources, source propagation through
   transformations, the policy view, and runtime dispatch.
3. **MCP P04-P06:** request decoding, path validation, and the use of the
   validated path during the filesystem write.

Some MAF late-mutation and MCP path or symlink cases already have upstream
tests. Those cases should first be used as negative controls. A result is
interesting only when a new mutation is accepted or handled differently
across systems and produces an unauthorized final effect.

## Rule for later findings

A changed label, hash, representation, or decision is not by itself a
vulnerability. A real finding requires all of the following:

1. the action passes the relevant security check;
2. the executed action differs in a security-relevant field;
3. the action reaches a real controlled sink;
4. the observed effect violates the stated policy;
5. the behavior occurs on a normal target execution path;
6. the result is repeatable and is not caused only by the research fixture.
