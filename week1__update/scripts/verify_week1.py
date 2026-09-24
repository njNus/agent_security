#!/usr/bin/env python3
"""Validate the Week 1 manifest and collected benign traces using Python stdlib."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_EVENTS = ["input", "check", "decision", "dispatch", "sink"]
REQUIRED_EVENT_FIELDS = {
    "schema_version", "run_id", "event_index", "target_id", "target_revision",
    "case_id", "component", "boundary", "event_type", "action", "evidence",
}
REQUIRED_RESULT_FILES = {
    "command.txt", "trace.jsonl", "decision.json", "sink_receipt.json",
    "stdout.log", "sha256.txt", "NOTES.md",
}


def fail(message: str) -> None:
    print(f"FAIL: {message}")
    raise SystemExit(1)


def validate_manifest() -> None:
    path = ROOT / "targets" / "manifest.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    targets = data.get("targets", [])
    if len(targets) != 3:
        fail("manifest must contain exactly three targets")
    ids = {target.get("id") for target in targets}
    expected = {"maf-fides", "camel", "mcp-filesystem"}
    if ids != expected:
        fail(f"target IDs differ: expected {sorted(expected)}, got {sorted(ids)}")
    for target in targets:
        for field in ("protected_object", "security_check", "execution_binding", "sink", "baseline"):
            if not target.get(field):
                fail(f"{target['id']} is missing {field}")
    print("PASS: target manifest has three pinned, inspectable targets")


def validate_trace(directory: Path, expected_target: str) -> None:
    missing_files = sorted(name for name in REQUIRED_RESULT_FILES if not (directory / name).is_file())
    if missing_files:
        fail(f"{directory.name} is missing: {', '.join(missing_files)}")

    events = []
    for line_number, line in enumerate((directory / "trace.jsonl").read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            fail(f"{directory.name}/trace.jsonl line {line_number}: {exc}")
        missing = REQUIRED_EVENT_FIELDS - event.keys()
        if missing:
            fail(f"{directory.name} event {line_number} missing {sorted(missing)}")
        if event["target_id"] != expected_target:
            fail(f"{directory.name} event {line_number} has target {event['target_id']}")
        if not {"operation", "canonical_sha256"} <= event["action"].keys():
            fail(f"{directory.name} event {line_number} has incomplete action")
        if not {"known_sources", "visible_sources"} <= event["evidence"].keys():
            fail(f"{directory.name} event {line_number} has incomplete evidence")
        events.append(event)

    kinds = [event["event_type"] for event in sorted(events, key=lambda item: item["event_index"])]
    positions = []
    for required in REQUIRED_EVENTS:
        if required not in kinds:
            fail(f"{directory.name} lacks {required} event")
        positions.append(kinds.index(required))
    if positions != sorted(positions):
        fail(f"{directory.name} events are not in input-to-sink order")
    print(f"PASS: {directory.name} contains a complete ordered trace")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--foundation", action="store_true")
    parser.add_argument("--complete", action="store_true")
    args = parser.parse_args()
    if not args.foundation and not args.complete:
        parser.error("choose --foundation or --complete")

    validate_manifest()
    if args.complete:
        validate_trace(ROOT / "results/week1/maf_fides_benign", "maf-fides")
        validate_trace(ROOT / "results/week1/camel_benign", "camel")
        print("PASS: Week 1 completion structure is present")


if __name__ == "__main__":
    main()

