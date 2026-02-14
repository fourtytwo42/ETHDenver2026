#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${XCLAW_VERIFY_BASE_URL:-https://xclaw.trade}"
AGENT_ID="${XCLAW_VERIFY_AGENT_ID:-}"

routes=(
  "/"
  "/agents"
  "/status"
)

if [[ -n "$AGENT_ID" ]]; then
  routes+=("/agents/$AGENT_ID")
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

echo "[verify-static-assets] base url: $BASE_URL"
echo "[verify-static-assets] routes: ${routes[*]}"

extract_assets() {
  local html_file="$1"
  rg -o '/_next/static/[^"'\'' <>]+' "$html_file" \
    | sed -E 's/\\+$//' \
    | rg '\.(css|js)$' \
    | sort -u
}

check_asset() {
  local asset_path="$1"
  local asset_url="${BASE_URL}${asset_path}"
  local headers
  headers="$(curl -sSI "$asset_url")"
  local status
  status="$(printf '%s\n' "$headers" | awk 'toupper($1) ~ /^HTTP\// {print $2; exit}')"
  if [[ "$status" != "200" ]]; then
    echo "[verify-static-assets] FAIL $asset_path -> HTTP $status"
    return 1
  fi

  local content_type
  content_type="$(printf '%s\n' "$headers" | awk 'tolower($1)=="content-type:" {print tolower($2); exit}')"
  if [[ "$asset_path" == *.css* ]]; then
    [[ "$content_type" == text/css* ]] || { echo "[verify-static-assets] FAIL $asset_path -> content-type '$content_type'"; return 1; }
  fi
  if [[ "$asset_path" == *.js* ]]; then
    [[ "$content_type" == application/javascript* || "$content_type" == text/javascript* ]] || {
      echo "[verify-static-assets] FAIL $asset_path -> content-type '$content_type'"
      return 1
    }
  fi

  echo "[verify-static-assets] OK   $asset_path"
}

all_assets_file="$tmp_dir/all-assets.txt"
touch "$all_assets_file"

for route in "${routes[@]}"; do
  html_file="$tmp_dir/$(echo "$route" | tr '/' '_' | sed 's/^_$/root/').html"
  curl -fsS "${BASE_URL}${route}" > "$html_file"
  extract_assets "$html_file" >> "$all_assets_file"
done

sort -u "$all_assets_file" -o "$all_assets_file"

if [[ ! -s "$all_assets_file" ]]; then
  echo "[verify-static-assets] FAIL no /_next/static assets discovered"
  exit 1
fi

failed=0
while IFS= read -r asset; do
  if ! check_asset "$asset"; then
    failed=1
  fi
done < "$all_assets_file"

if [[ "$failed" -ne 0 ]]; then
  echo "[verify-static-assets] FAILED"
  exit 1
fi

echo "[verify-static-assets] PASSED"
