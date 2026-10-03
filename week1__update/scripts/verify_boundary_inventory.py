#!/usr/bin/env python3

import csv
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "docs" / "week2_boundary_inventory.csv"

REQUIRED_COLUMNS = {
    "boundary_id",
    "target",
    "producer",
    "consumer",
    "representation",
    "parser_or_function",
    "authority_owner",
    "transformation",
    "protected_fields",
    "security_check",
    "final_sink",
    "attacker_control",
    "trace_status",
    "source_file",
    "planned_mutation_family",
}

EXPECTED_TARGETS = {
    "MAF-FIDES",
    "CaMeL",
    "MCP-Filesystem",
}

VALID_CONTROL = {"yes", "partial", "no"}
VALID_STATUS = {"traced", "source_inspected", "baseline_only"}

if not INVENTORY.is_file():
    raise SystemExit(f"FAIL: missing {INVENTORY}")

with INVENTORY.open(newline="", encoding="utf-8") as handle:
    reader = csv.DictReader(handle)
    headers = set(reader.fieldnames or [])
    rows = list(reader)

missing_columns = REQUIRED_COLUMNS - headers
if missing_columns:
    raise SystemExit(
        "FAIL: missing columns: " + ", ".join(sorted(missing_columns))
    )

if len(rows) < 20:
    raise SystemExit(
        f"FAIL: only {len(rows)} boundaries recorded; approximately 20 are required"
    )

ids = [row["boundary_id"].strip() for row in rows]
if len(ids) != len(set(ids)):
    duplicates = sorted(
        boundary_id
        for boundary_id, count in Counter(ids).items()
        if count > 1
    )
    raise SystemExit(
        "FAIL: duplicate boundary IDs: " + ", ".join(duplicates)
    )

for line_number, row in enumerate(rows, start=2):
    for column in REQUIRED_COLUMNS:
        if not row[column].strip():
            raise SystemExit(
                f"FAIL: line {line_number} has an empty {column}"
            )

    if row["attacker_control"] not in VALID_CONTROL:
        raise SystemExit(
            f"FAIL: line {line_number} has invalid attacker_control"
        )

    if row["trace_status"] not in VALID_STATUS:
        raise SystemExit(
            f"FAIL: line {line_number} has invalid trace_status"
        )

    source_path = ROOT / row["source_file"]
    if not source_path.exists():
        raise SystemExit(
            f"FAIL: source evidence does not exist: {row['source_file']}"
        )

targets = {row["target"] for row in rows}
if targets != EXPECTED_TARGETS:
    raise SystemExit(
        f"FAIL: expected targets {sorted(EXPECTED_TARGETS)}, "
        f"found {sorted(targets)}"
    )

target_counts = Counter(row["target"] for row in rows)
status_counts = Counter(row["trace_status"] for row in rows)
control_counts = Counter(row["attacker_control"] for row in rows)

for target in sorted(EXPECTED_TARGETS):
    target_rows = [row for row in rows if row["target"] == target]

    if not any(row["security_check"].strip() for row in target_rows):
        raise SystemExit(f"FAIL: {target} has no security check")

    if not any(row["final_sink"].strip() for row in target_rows):
        raise SystemExit(f"FAIL: {target} has no final sink")

for target in ("MAF-FIDES", "CaMeL"):
    traced = sum(
        row["target"] == target and row["trace_status"] == "traced"
        for row in rows
    )
    if traced < 2:
        raise SystemExit(
            f"FAIL: {target} needs at least two traced boundaries"
        )

print(f"PASS: {len(rows)} meaningful boundaries recorded")

for target in sorted(target_counts):
    print(f"PASS: {target}: {target_counts[target]} boundaries")

print(
    "PASS: trace status: "
    + ", ".join(
        f"{name}={status_counts[name]}"
        for name in sorted(status_counts)
    )
)

print(
    "PASS: attacker control: "
    + ", ".join(
        f"{name}={control_counts[name]}"
        for name in sorted(control_counts)
    )
)

print("PASS: every boundary has source evidence, a security check, and a sink")
print("PASS: boundary inventory is ready for mutation-family selection")
