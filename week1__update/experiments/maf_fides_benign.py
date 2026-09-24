#!/usr/bin/env python3
"""Run one benign MAF FIDES invocation through middleware to a local sink."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any

from pydantic import BaseModel

from agent_framework import FunctionInvocationContext
from agent_framework._middleware import FunctionMiddlewarePipeline
from agent_framework._tools import FunctionTool
from agent_framework.security import LabelTrackingFunctionMiddleware, PolicyEnforcementFunctionMiddleware

REVISION = "669c8b95e774f298012a55bc0afe19826fd20aba"


def stable(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    return hashlib.sha256(stable(value).encode()).hexdigest()


def mapped(arguments: Any) -> dict[str, Any]:
    if isinstance(arguments, BaseModel):
        return arguments.model_dump()
    return dict(arguments)


async def run(output: Path, target: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "config").mkdir(exist_ok=True)
    sandbox = (output / "sandbox").resolve()
    sandbox.mkdir(exist_ok=True)
    events: list[dict[str, Any]] = []
    run_id = "maf-fides-benign-001"
    case_id = "trusted-local-write"

    def event(kind: str, component: str, boundary: str, arguments: dict[str, Any], **extra: Any) -> None:
        action = {
            "operation": "capture_write",
            "destination": arguments.get("destination"),
            "arguments": arguments,
            "canonical_sha256": digest(arguments),
        }
        record = {
            "schema_version": "1.0",
            "run_id": run_id,
            "event_index": len(events),
            "target_id": "maf-fides",
            "target_revision": REVISION,
            "case_id": case_id,
            "component": component,
            "boundary": boundary,
            "event_type": kind,
            "action": action,
            "evidence": {
                "known_sources": ["fixture:trusted-user"],
                "visible_sources": extra.pop("visible_sources", []),
                "labels": extra.pop("labels", {}),
            },
            **extra,
        }
        events.append(record)

    class WriteArgs(BaseModel):
        destination: str
        content: str

    receipt: dict[str, Any] = {}

    async def capture_write(destination: str, content: str) -> str:
        resolved = (sandbox / destination).resolve()
        if sandbox not in resolved.parents:
            raise ValueError("destination escaped controlled sandbox")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding="utf-8")
        receipt.update({
            "operation": "capture_write",
            "requested_destination": destination,
            "resolved_destination": str(resolved),
            "content_sha256": hashlib.sha256(content.encode()).hexdigest(),
            "exists": resolved.is_file(),
        })
        args = {"destination": destination, "content": content}
        event(
            "sink", "capture_write", "FunctionTool function -> filesystem",
            args, visible_sources=["fixture:trusted-user"], sink_receipt_sha256=digest(receipt),
        )
        return "written"

    class RecordingPolicy(PolicyEnforcementFunctionMiddleware):
        async def process(self, context: FunctionInvocationContext, call_next: Any) -> None:
            args = mapped(context.arguments)
            label = context.metadata.get("context_label")
            label_data = label.to_dict() if label is not None else {}
            event(
                "check", self.__class__.__name__, "label tracker -> policy",
                args, visible_sources=[f"label:{label_data.get('integrity', 'missing')}"], labels=label_data,
            )

            async def after_allow() -> None:
                event(
                    "decision", self.__class__.__name__, "policy -> execution pipeline",
                    mapped(context.arguments), visible_sources=[f"label:{label_data.get('integrity', 'missing')}"],
                    labels=label_data, decision="allow", policy_id="MAF-FIDES-default-policy",
                )
                await call_next()

            await super().process(context, after_allow)

    arguments = {"destination": "safe/maf.txt", "content": "week1-safe"}
    fixture = {
        "case_id": case_id,
        "known_source": "fixture:trusted-user",
        "expected_decision": "allow",
        "expected_destination": "safe/maf.txt",
        "expected_content_sha256": hashlib.sha256(b"week1-safe").hexdigest(),
    }
    (output / "config" / "fixture.json").write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8")
    event("input", "research fixture", "fixture -> FunctionInvocationContext", arguments,
          visible_sources=["fixture:trusted-user"])

    tool = FunctionTool(
        func=capture_write,
        name="capture_write",
        description="Write harmless test content inside a controlled directory",
        input_model=WriteArgs,
        additional_properties={"source_integrity": "trusted"},
    )
    context = FunctionInvocationContext(function=tool, arguments=arguments)
    tracker = LabelTrackingFunctionMiddleware()
    policy = RecordingPolicy(block_on_violation=True)

    async def execute(current: FunctionInvocationContext) -> Any:
        call_args = mapped(current.arguments)
        event(
            "dispatch", "FunctionMiddlewarePipeline", "policy -> FunctionTool.invoke",
            call_args, visible_sources=["fixture:trusted-user"]
        )
        return await tool.invoke(arguments=current.arguments, context=current)

    await FunctionMiddlewarePipeline(tracker, policy).execute(context, execute)

    actual_revision = subprocess.check_output(
        ["git", "-C", str(target), "rev-parse", "HEAD"], text=True
    ).strip()
    if actual_revision != REVISION:
        raise RuntimeError(f"wrong target revision: {actual_revision}")
    if not receipt.get("exists"):
        raise RuntimeError("controlled sink did not observe the file")
    if [item["event_type"] for item in events] != ["input", "check", "decision", "dispatch", "sink"]:
        raise RuntimeError("trace events are incomplete or out of order")
    hashes = {item["action"]["canonical_sha256"] for item in events}
    if len(hashes) != 1:
        raise RuntimeError("benign action changed between components")

    (output / "trace.jsonl").write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in events), encoding="utf-8"
    )
    (output / "decision.json").write_text(
        json.dumps({"decision": "allow", "policy": "MAF-FIDES-default-policy"}, indent=2) + "\n",
        encoding="utf-8",
    )
    (output / "sink_receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    (output / "NOTES.md").write_text(
        "# MAF FIDES benign trace\n\nExpected and observed: a trusted harmless write was allowed, "
        "the action stayed identical, and the controlled sink created the file.\n",
        encoding="utf-8",
    )
    print("PASS: MAF FIDES benign action reached the controlled sink")
    print(f"action_sha256={events[0]['action']['canonical_sha256']}")
    print(f"sink={receipt['resolved_destination']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(run(args.output.resolve(), args.target.resolve()))


if __name__ == "__main__":
    main()
