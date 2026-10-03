#!/usr/bin/env python3
"""Verify that MAF FIDES blocks an untrusted argument before the sink."""

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
from agent_framework._middleware import (
    FunctionMiddlewarePipeline,
    MiddlewareTermination,
)
from agent_framework._tools import FunctionTool
from agent_framework.security import (
    ContentLabel,
    IntegrityLabel,
    LabelTrackingFunctionMiddleware,
    PolicyEnforcementFunctionMiddleware,
)

REVISION = "669c8b95e774f298012a55bc0afe19826fd20aba"


def stable(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


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

    expected_destination = "blocked/maf.txt"
    expected_sink = (sandbox / expected_destination).resolve()

    if expected_sink.exists():
        expected_sink.unlink()

    events: list[dict[str, Any]] = []
    run_id = "maf-fides-denied-001"
    case_id = "untrusted-destination-denied"
    dispatch_reached = False
    sink_reached = False

    def event(
        kind: str,
        component: str,
        boundary: str,
        arguments: dict[str, Any],
        **extra: Any,
    ) -> None:
        events.append({
            "schema_version": "1.0",
            "run_id": run_id,
            "event_index": len(events),
            "target_id": "maf-fides",
            "target_revision": REVISION,
            "case_id": case_id,
            "component": component,
            "boundary": boundary,
            "event_type": kind,
            "action": {
                "operation": "capture_write",
                "destination": arguments.get("destination"),
                "arguments": arguments,
                "canonical_sha256": digest(arguments),
            },
            "evidence": {
                "known_sources": ["fixture:untrusted-external"],
                "visible_sources": extra.pop("visible_sources", []),
                "labels": extra.pop("labels", {}),
            },
            **extra,
        })

    class WriteArgs(BaseModel):
        destination: str
        content: str

    async def capture_write(destination: str, content: str) -> str:
        nonlocal sink_reached
        sink_reached = True

        resolved = (sandbox / destination).resolve()
        if sandbox not in resolved.parents:
            raise ValueError("destination escaped controlled sandbox")

        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding="utf-8")
        return "written"

    class RecordingPolicy(PolicyEnforcementFunctionMiddleware):
        async def process(
            self,
            context: FunctionInvocationContext,
            call_next: Any,
        ) -> None:
            arguments = mapped(context.arguments)
            argument_label = context.metadata.get("argument_label")

            if isinstance(argument_label, ContentLabel):
                label_data = argument_label.to_dict()
            elif isinstance(argument_label, dict):
                label_data = argument_label
            else:
                label_data = {}

            event(
                "check",
                "PolicyEnforcementFunctionMiddleware",
                "label tracker -> policy",
                arguments,
                visible_sources=[
                    f"label:{label_data.get('integrity', 'missing')}"
                ],
                labels={"argument_label": label_data},
            )

            try:
                await super().process(context, call_next)
            except MiddlewareTermination:
                event(
                    "decision",
                    "PolicyEnforcementFunctionMiddleware",
                    "policy -> blocked",
                    mapped(context.arguments),
                    visible_sources=[
                        f"label:{label_data.get('integrity', 'missing')}"
                    ],
                    labels={"argument_label": label_data},
                    decision="deny",
                    policy_id="MAF-FIDES-default-policy",
                    policy_result=context.result,
                )
                raise

    tool = FunctionTool(
        func=capture_write,
        name="capture_write",
        description="Controlled local file sink",
        input_model=WriteArgs,
        additional_properties={
            "source_integrity": "trusted",
            "accepts_untrusted": False,
        },
    )

    tracker = LabelTrackingFunctionMiddleware()
    policy = RecordingPolicy(block_on_violation=True)

    variable_id = tracker.get_variable_store().store(
        expected_destination,
        ContentLabel(integrity=IntegrityLabel.UNTRUSTED),
    )

    original_arguments = {
        "destination": f"[{variable_id}]",
        "content": "this-write-must-be-blocked",
    }

    event(
        "input",
        "research fixture",
        "fixture -> label tracker",
        original_arguments,
        visible_sources=["fixture:untrusted-external"],
    )

    context = FunctionInvocationContext(
        function=tool,
        arguments=original_arguments,
    )

    async def execute(current: FunctionInvocationContext) -> Any:
        nonlocal dispatch_reached
        dispatch_reached = True

        event(
            "dispatch",
            "FunctionMiddlewarePipeline",
            "policy -> FunctionTool.invoke",
            mapped(current.arguments),
        )

        return await tool.invoke(
            arguments=current.arguments,
            context=current,
        )

    blocked = False

    try:
        await FunctionMiddlewarePipeline(
            tracker,
            policy,
        ).execute(context, execute)
    except MiddlewareTermination:
        blocked = True

    actual_revision = subprocess.check_output(
        ["git", "-C", str(target), "rev-parse", "HEAD"],
        text=True,
    ).strip()

    if actual_revision != REVISION:
        raise RuntimeError(f"wrong target revision: {actual_revision}")

    argument_label = context.metadata.get("argument_label")
    observed_integrity = (
        argument_label.integrity.value
        if isinstance(argument_label, ContentLabel)
        else "missing"
    )

    receipt = {
        "operation": "capture_write",
        "requested_destination": expected_destination,
        "resolved_destination": str(expected_sink),
        "blocked": blocked,
        "dispatch_reached": dispatch_reached,
        "sink_reached": sink_reached,
        "exists": expected_sink.exists(),
    }

    if not blocked:
        raise RuntimeError("FIDES did not block the untrusted argument")

    if observed_integrity != "untrusted":
        raise RuntimeError(
            f"expected untrusted argument label, got {observed_integrity}"
        )

    if dispatch_reached:
        raise RuntimeError("blocked action reached dispatch")

    if sink_reached or expected_sink.exists():
        raise RuntimeError("blocked action reached the controlled sink")

    kinds = [item["event_type"] for item in events]
    if kinds != ["input", "check", "decision"]:
        raise RuntimeError(f"unexpected event order: {kinds}")

    fixture = {
        "case_id": case_id,
        "known_source": "fixture:untrusted-external",
        "expected_argument_integrity": "untrusted",
        "expected_decision": "deny",
        "expected_dispatch": False,
        "expected_sink_effect": False,
        "requested_destination": expected_destination,
    }

    (output / "config" / "fixture.json").write_text(
        json.dumps(fixture, indent=2) + "\n",
        encoding="utf-8",
    )

    (output / "trace.jsonl").write_text(
        "".join(
            json.dumps(item, sort_keys=True, default=str) + "\n"
            for item in events
        ),
        encoding="utf-8",
    )

    (output / "decision.json").write_text(
        json.dumps({
            "decision": "deny",
            "policy": "MAF-FIDES-default-policy",
            "reason": "untrusted_arguments",
        }, indent=2) + "\n",
        encoding="utf-8",
    )

    (output / "sink_receipt.json").write_text(
        json.dumps(receipt, indent=2) + "\n",
        encoding="utf-8",
    )

    (output / "NOTES.md").write_text(
        "# MAF FIDES denied control\n\n"
        "An external untrusted value was stored in the real FIDES variable "
        "store and referenced as the destination argument. Label tracking "
        "resolved it as untrusted. Policy enforcement denied the invocation "
        "before dispatch, and the controlled sink remained untouched.\n",
        encoding="utf-8",
    )

    print("PASS: MAF FIDES blocked the untrusted action")
    print(f"argument_integrity={observed_integrity}")
    print(f"dispatch_reached={dispatch_reached}")
    print(f"sink_reached={sink_reached}")
    print(f"sink_exists={expected_sink.exists()}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()

    asyncio.run(run(args.output.resolve(), args.target.resolve()))


if __name__ == "__main__":
    main()
