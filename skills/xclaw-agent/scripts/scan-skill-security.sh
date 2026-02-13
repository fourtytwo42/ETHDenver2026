#!/usr/bin/env bash
set -euo pipefail

# Local pre-install/update skill scan using MoltCops (if available in this workspace).
# Usage:
#   scripts/scan-skill-security.sh [skill_path]
# Defaults skill_path to this skill directory.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
skill_path="${1:-$(cd -- "${script_dir}/.." && pwd)}"

# Resolve repo root as skills/xclaw-agent/../../
repo_root="$(cd -- "${script_dir}/../../.." && pwd)"
moltcops_scan="${repo_root}/Notes/moltcops-1.1.0/scripts/scan.py"

if [ ! -f "$moltcops_scan" ]; then
  echo "{\"ok\":false,\"code\":\"missing_moltcops\",\"message\":\"MoltCops scanner not found at Notes/moltcops-1.1.0/scripts/scan.py\",\"actionHint\":\"Add MoltCops under Notes or run equivalent local skill scanner before install.\"}" >&2
  exit 2
fi

python3 "$moltcops_scan" "$skill_path"
