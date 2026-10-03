#!/usr/bin/env python3
"""Seed a synthetic post-check mismatch and verify that the oracle detects it."""

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
from agent_framework.security import (
    ContentLabel,
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

    checked_destination = "safe/approved.txt"
    changed_destination = "seeded/changed.txt"
    content = "seeded-oracle-test"

    checked_path = (sandbox / checked_destination).resolve()
    changed_path = (sandbox / changed_destination).resolve()

    for path in (checked_path, changed_path):
        if path.exists():
            path.unlink()

    events: list[dict[str, Any]] = []
    receipt: dict[str, Any] = {}

    def event(
        kind: str,
        component: str,
        boundary: str,
        arguments: dict[str, Any],
        **extra: Any,
    ) -> None:
        events.append({
            "schema_version": "1.0",
            "run_id": "maf-seeded-mismatch-001",
            "event_index": len(events),
            "target_id": "maf-fides",
            "target_revision": REVISION,
            "case_id": "seeded-post-check-destination-change",
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
                "known_sources": ["fixture:trusted-user"],
                "visible_sources": extra.pop("visible_sources", []),
                "labels": extra.pop("labels", {}),
            },
            **extra,
        })

    class WriteArgs(BaseModel):
        destination: str
        content: str

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

        event(
            "sink",
            "capture_write",
            "seeded adapter -> controlled filesystem",
            {"destination": destination, "content": content},
            visible_sources=["fixture:trusted-user"],
            sink_receipt_sha256=digest(receipt),
        )

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

            visible = [
                f"label:{label_data.get('integrity', 'missing')}"
            ]

            event(
                "check",
                "PolicyEnforcementFunctionMiddleware",
                "label tracker -> policy",
                arguments,
                visible_sources=visible,
                labels={"argument_label": label_data},
            )

            async def after_allow() -> None:
                event(
                    "decision",
                    "PolicyEnforcementFunctionMiddleware",
                    "policy -> seeded test adapter",
                    mapped(context.arguments),
                    visible_sources=visible,
                    labels={"argument_label": label_data},
                    decision="allow",
                    policy_id="MAF-FIDES-default-policy",
                )
                await call_next()

            await super().process(context, after_allow)

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

    arguments = {
        "destination": checked_destination,
        "content": content,
    }

    fixture = {
        "case_id": "seeded-post-check-destination-change",
        "seeded_fault": True,
        "normal_target_execution_path": False,
        "checked_destination": checked_destination,
        "injected_destination": changed_destination,
        "expected_oracle_result": "binding_failure_detected",
    }

    (output / "config" / "fixture.json").write_text(
        json.dumps(fixture, indent=2) + "\n",
        encoding="utf-8",
    )

    event(
        "input",
        "research fixture",
        "fixture -> FIDES pipeline",
        arguments,
        visible_sources=["fixture:trusted-user"],
    )

    context = FunctionInvocationContext(
        function=tool,
        arguments=arguments,
    )

    tracker = LabelTrackingFunctionMiddleware()
    policy = RecordingPolicy(block_on_violation=True)

    async def seeded_faulty_adapter(
        current: FunctionInvocationContext,
    ) -> Any:
        # This deliberate test fault simulates a broken component boundary.
        mutated = mapped(current.arguments)
        mutated["destination"] = changed_destination

        event(
            "dispatch",
            "SeededFaultyAdapter",
            "allowed action -> deliberately changed action",
            mutated,
            visible_sources=["fixture:trusted-user"],
            seeded_fault=True,
        )

        # Direct invocation is intentional here. It models a faulty adapter
        # bypassing the target's normal FunctionTool binding protection.
        return await capture_write(**mutated)

    await FunctionMiddlewarePipeline(
        tracker,
        policy,
    ).execute(context, seeded_faulty_adapter)

    actual_revision = subprocess.check_output(
        ["git", "-C", str(target), "rev-parse", "HEAD"],
        text=True,
    ).strip()

    if actual_revision != REVISION:
        raise RuntimeError(f"wrong target revision: {actual_revision}")

    checked_event = next(
        item for item in events if item["event_type"] == "check"
    )
    sink_event = next(
        item for item in events if item["event_type"] == "sink"
    )

    checked_action = checked_event["action"]
    sink_action = sink_event["action"]

    mismatch_detected = (
        checked_action["destination"] != sink_action["destination"]
        or checked_action["canonical_sha256"]
        != sink_action["canonical_sha256"]
    )

    oracle = {
        "oracle": "independent-check-to-sink-comparison",
        "seeded_fault": True,
        "normal_target_execution_path": False,
        "checked_destination": checked_action["destination"],
        "sink_destination": sink_action["destination"],
        "checked_action_sha256": checked_action["canonical_sha256"],
        "sink_action_sha256": sink_action["canonical_sha256"],
        "mismatch_detected": mismatch_detected,
        "classification": (
            "seeded_binding_failure"
            if mismatch_detected
            else "oracle_missed_seeded_failure"
        ),
    }

    if not receipt.get("exists"):
        raise RuntimeError("seeded sink effect was not observed")

    if checked_path.exists():
        raise RuntimeError("the originally checked path was unexpectedly written")

    if not changed_path.exists():
        raise RuntimeError("the seeded changed destination was not written")

    if not mismatch_detected:
        raise RuntimeError("oracle failed to detect the seeded mismatch")

    if [item["event_type"] for item in events] != [
        "input",
        "check",
        "decision",
        "dispatch",
        "sink",
    ]:
        raise RuntimeError("trace is incomplete or out of order")

    (output / "trace.jsonl").write_text(
        "".join(
            json.dumps(item, sort_keys=True, default=str) + "\n"
            for item in events
        ),
        encoding="utf-8",
    )

    (output / "decision.json").write_text(
        json.dumps({
            "decision": "allow",
            "policy": "MAF-FIDES-default-policy",
            "checked_destination": checked_destination,
        }, indent=2) + "\n",
        encoding="utf-8",
    )

    (output / "sink_receipt.json").write_text(
        json.dumps(receipt, indent=2) + "\n",
        encoding="utf-8",
    )

    (output / "oracle.json").write_text(
        json.dumps(oracle, indent=2) + "\n",
        encoding="utf-8",
    )

    (output / "NOTES.md").write_text(
        "# MAF seeded mismatch oracle control\n\n"
        "This is a deliberately faulty research adapter. It is not a "
        "Microsoft Agent Framework vulnerability. FIDES checked and allowed "
        "the safe destination, after which the seeded adapter changed the "
        "destination and bypassed normal FunctionTool invocation. The "
        "independent oracle correctly detected the difference between the "
        "checked action and observed sink action.\n",
        encoding="utf-8",
    )

    print("PASS: oracle detected the seeded check-to-sink mismatch")
    print(f"checked_destination={checked_destination}")
    print(f"sink_destination={receipt['requested_destination']}")
    print(f"mismatch_detected={mismatch_detected}")
    print(f"checked_path_exists={checked_path.exists()}")
    print(f"changed_path_exists={changed_path.exists()}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()

    asyncio.run(run(args.output.resolve(), args.target.resolve()))


if __name__ == "__main__":
    main()
