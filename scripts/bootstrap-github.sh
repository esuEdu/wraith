#!/usr/bin/env bash
# Creates or updates the repo's labels (.github/labels.yml) and milestones M0-M6.
# Safe to rerun. Needs the GitHub CLI, logged in with access to the repo.
set -euo pipefail

repo="${REPO:-esuEdu/wraith}"
root="$(cd "$(dirname "$0")/.." && pwd)"

# Labels: one "- {name: "...", color: "...", description: "..."}" per line.
grep -E '^- \{name:' "$root/.github/labels.yml" | while IFS= read -r line; do
  name="$(sed -E 's/.*name: "([^"]*)".*/\1/' <<<"$line")"
  color="$(sed -E 's/.*color: "([^"]*)".*/\1/' <<<"$line")"
  desc="$(sed -E 's/.*description: "([^"]*)".*/\1/' <<<"$line")"
  gh label create "$name" --repo "$repo" --color "$color" --description "$desc" --force >/dev/null
  echo "label    $name"
done

# Milestones from the main spec. Created once; existing ones are left alone.
existing="$(gh api "repos/$repo/milestones?state=all&per_page=100" --jq '.[].title')"
while IFS='|' read -r title desc; do
  if grep -qxF "$title" <<<"$existing"; then
    echo "exists   $title"
  else
    gh api -X POST "repos/$repo/milestones" -f title="$title" -f description="$desc" >/dev/null
    echo "created  $title"
  fi
done <<'EOF'
M0 Spike|Prove PID lookup for a simulator app's connection and an IP_BOUND_IF dial that escapes the VPN. Go/no-go for the design.
M1 Pass-through proxy|Listener, CONNECT splicing, system proxy set and restore with crash recovery (R4). v0.1.0.
M2 Decryption|CA, leaf issuing, HTTP/1.1 and HTTP/2 forwarding, simulator CA install, pinned fallback (R2). v0.2.0.
M3 Source filter|--source modes and the resolver (R1). v0.3.0.
M4 Bypass|Rules, interface detection, bound DNS, fail closed, doctor (R3). v0.4.0.
M5 TUI and export|Live view, filters, details, HAR and curl, --log mode (R5, R6). v0.5.0.
M6 Release|Tap repo, formula, tag-driven workflow, README (R7). v1.0.0.
EOF
