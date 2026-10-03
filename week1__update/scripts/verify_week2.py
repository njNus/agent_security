#!/usr/bin/env python3
"""Validate the Week 2 security controls and seeded oracle evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEEK1 = ROOT / "results" / "week1"
WEEK2 = ROOT / "results" / "week2"


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def read_json(path: Path) -> dict:
    require(path.is_file(), f"missing {path.relative_to(ROOT)}")

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path.relative_to(ROOT)}: {exc}")


def read_trace(directory: Path) -> list[dict]:
    path = directory / "trace.jsonl"
    require(path.is_file(), f"missing {path.relative_to(ROOT)}")

    events: list[dict] = []

    for number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        1,
    ):
        if not line.strip():
            continue

        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as exc:
            fail(
                f"invalid trace JSON in "
                f"{path.relative_to(ROOT)} line {number}: {exc}"
            )

    indexes = [event.get("event_index") for event in events]
    require(
        indexes == list(range(len(events))),
        f"{directory.name}: incorrect event indexes {indexes}",
    )

    return events


def verify_hashes(directory: Path) -> None:
    manifest = directory / "sha256.txt"
    require(
        manifest.is_file(),
        f"{directory.name}: missing sha256.txt",
    )

    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue

        parts = line.split(maxsplit=1)
        require(
            len(parts) == 2,
            f"{directory.name}: malformed hash line",
        )

        expected, relative_name = parts
        relative_name = relative_name.lstrip("*")
        path = (directory / relative_name).resolve()

        require(
            directory.resolve() in path.parents,
            f"{directory.name}: unsafe hash path {relative_name}",
        )

        require(
            path.is_file(),
            f"{directory.name}: hashed file missing: {relative_name}",
        )

        observed = hashlib.sha256(path.read_bytes()).hexdigest()

        require(
            observed == expected,
            f"{directory.name}: hash mismatch for {relative_name}",
        )


def validate_benign(
    directory: Path,
    expected_target: str,
) -> None:
    events = read_trace(directory)
    kinds = [event["event_type"] for event in events]

    require(
        kinds == ["input", "check", "decision", "dispatch", "sink"],
        f"{directory.name}: incomplete benign trace {kinds}",
    )

    require(
        all(event["target_id"] == expected_target for event in events),
        f"{directory.name}: target ID mismatch",
    )

    decision = read_json(directory / "decision.json")
    receipt = read_json(directory / "sink_receipt.json")

    require(
        decision.get("decision") == "allow",
        f"{directory.name}: expected allow decision",
    )

    require(
        receipt.get("exists") is True,
        f"{directory.name}: benign sink effect missing",
    )

    print(f"PASS: {directory.name} benign allow control")


def validate_denied(
    directory: Path,
    expected_target: str,
) -> None:
    required = {
        "command.txt",
        "trace.jsonl",
        "decision.json",
        "sink_receipt.json",
        "stdout.log",
        "exit-code.txt",
        "NOTES.md",
        "sha256.txt",
    }

    missing = sorted(
        name
        for name in required
        if not (directory / name).is_file()
    )

    require(
        not missing,
        f"{directory.name}: missing {missing}",
    )

    require(
        (directory / "exit-code.txt").read_text().strip() == "0",
        f"{directory.name}: nonzero exit code",
    )

    events = read_trace(directory)
    kinds = [event["event_type"] for event in events]

    require(
        kinds == ["input", "check", "decision"],
        f"{directory.name}: unexpected denied trace {kinds}",
    )

    require(
        all(event["target_id"] == expected_target for event in events),
        f"{directory.name}: target ID mismatch",
    )

    decision = read_json(directory / "decision.json")
    receipt = read_json(directory / "sink_receipt.json")

    require(
        decision.get("decision") == "deny",
        f"{directory.name}: expected deny decision",
    )

    require(
        receipt.get("blocked") is True,
        f"{directory.name}: blocked flag missing",
    )

    require(
        receipt.get("dispatch_reached") is False,
        f"{directory.name}: blocked action reached dispatch",
    )

    require(
        receipt.get("sink_reached") is False,
        f"{directory.name}: blocked action reached sink",
    )

    require(
        receipt.get("exists") is False,
        f"{directory.name}: blocked sink file exists",
    )

    verify_hashes(directory)

    print(f"PASS: {directory.name} genuine deny control")


def validate_seeded_oracle(directory: Path) -> None:
    require(
        (directory / "exit-code.txt").read_text().strip() == "0",
        f"{directory.name}: nonzero exit code",
    )

    events = read_trace(directory)
    kinds = [event["event_type"] for event in events]

    require(
        kinds == ["input", "check", "decision", "dispatch", "sink"],
        f"{directory.name}: incomplete seeded trace {kinds}",
    )

    oracle = read_json(directory / "oracle.json")
    receipt = read_json(directory / "sink_receipt.json")

    require(
        oracle.get("seeded_fault") is True,
        f"{directory.name}: not marked as seeded",
    )

    require(
        oracle.get("normal_target_execution_path") is False,
        f"{directory.name}: synthetic path is not identified",
    )

    require(
        oracle.get("mismatch_detected") is True,
        f"{directory.name}: oracle missed mismatch",
    )

    require(
        oracle.get("classification") == "seeded_binding_failure",
        f"{directory.name}: incorrect classification",
    )

    require(
        oracle.get("checked_destination")
        != oracle.get("sink_destination"),
        f"{directory.name}: destinations did not differ",
    )

    require(
        receipt.get("exists") is True,
        f"{directory.name}: seeded sink effect missing",
    )

    verify_hashes(directory)

    print(
        "PASS: seeded MAF mismatch was independently detected "
        "and clearly marked synthetic"
    )


def main() -> None:
    validate_benign(
        WEEK1 / "maf_fides_benign",
        "maf-fides",
    )

    validate_benign(
        WEEK1 / "camel_benign",
        "camel",
    )

    validate_denied(
        WEEK2 / "maf_fides_denied",
        "maf-fides",
    )

    validate_denied(
        WEEK2 / "camel_denied",
        "camel",
    )

    validate_seeded_oracle(
        WEEK2 / "maf_seeded_mismatch",
    )

    print("PASS: Week 2 control foundation is complete")
    print("NOTE: No real vulnerability has been claimed")


if __name__ == "__main__":
    main()
