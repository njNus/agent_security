# How to record a trace

Create one JSON object per line in `trace.jsonl`. A benign trace must contain ordered events for `input`, `check`, `decision`, `dispatch`, and `sink`.

For every event:

- derive `known_sources` from the fixed test fixture;
- copy `visible_sources` from what the target actually exposes at that point;
- convert the action into stable JSON with sorted keys and no extra spaces;
- hash that exact byte sequence with SHA-256;
- preserve the native target event separately when useful.

Each result directory must contain:

```text
command.txt          exact command used
config/              sanitized policy and fixture configuration
trace.jsonl          common ordered trace
decision.json        native and normalized decision
sink_receipt.json    effect observed by the controlled sink
stdout.log           sanitized program output
sha256.txt           hashes of the files above
NOTES.md              expected result, observed result, and deviations
```

The sink receipt must be produced by the final controlled effect, not copied from the pre-check request. For a file operation it should include the resolved path, whether the file exists, and the content hash. For a capture tool it should include the operation and exact received arguments.

