#!/usr/bin/env bash
set -u

out="results/week1/environment"
mkdir -p "$out"
report="$out/system.txt"

{
  echo "captured_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "kernel=$(uname -a)"
  [[ -f /etc/os-release ]] && sed -n 's/^\(NAME\|VERSION\|ID\)=/os_\1=/p' /etc/os-release
  command -v git >/dev/null && git --version
  command -v python3 >/dev/null && python3 --version
  command -v uv >/dev/null && uv --version
  command -v node >/dev/null && node --version
  command -v npm >/dev/null && npm --version
  command -v openssl >/dev/null && openssl version
  command -v nproc >/dev/null && echo "cpu_count=$(nproc)"
  command -v free >/dev/null && free -h
} > "$report" 2>&1

sha256sum "$report" > "$out/sha256.txt"
echo "Wrote $report"

