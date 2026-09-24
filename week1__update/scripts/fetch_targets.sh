#!/usr/bin/env bash
set -euo pipefail

root="${1:-targets/source}"
mkdir -p "$root"

clone_at() {
  local url="$1"
  local dir="$2"
  local revision="$3"

  if [[ ! -d "$dir/.git" ]]; then
    git clone --filter=blob:none --no-checkout "$url" "$dir"
  fi
  git -C "$dir" fetch --depth 1 origin "$revision"
  git -C "$dir" checkout --detach "$revision"
  actual="$(git -C "$dir" rev-parse HEAD)"
  if [[ "$actual" != "$revision" ]]; then
    echo "Revision mismatch for $dir: $actual" >&2
    exit 1
  fi
  echo "$dir $actual"
}

clone_at "https://github.com/microsoft/agent-framework.git" \
  "$root/agent-framework" "669c8b95e774f298012a55bc0afe19826fd20aba"
clone_at "https://github.com/google-research/camel-prompt-injection.git" \
  "$root/camel-prompt-injection" "f083b6b396399d3b3c7f2ddaf613a5945eaf32d8"
clone_at "https://github.com/modelcontextprotocol/python-sdk.git" \
  "$root/mcp-python-sdk" "6affe5c0d3588fd1705713b3703dc68015cfe3eb"
clone_at "https://github.com/modelcontextprotocol/servers.git" \
  "$root/mcp-servers" "d73f99efbfd40c3aa1b61e88728b3d49fb52608f"

