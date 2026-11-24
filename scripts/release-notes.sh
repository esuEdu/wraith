#!/usr/bin/env bash
# Prints release notes for a tag: the commits since the previous final release (vX.Y.Z,
# no suffix), grouped by Conventional Commit type. Used by .github/workflows/release.yml.
#   scripts/release-notes.sh v1.0.0
set -euo pipefail
tag=${1:?usage: release-notes.sh <tag>}
repo=${GITHUB_REPOSITORY:-esuEdu/wraith}

prev=$(git describe --tags --abbrev=0 --match 'v*' --exclude '*-*' "$tag^" 2>/dev/null || true)
range=$tag
[ -n "$prev" ] && range="$prev..$tag"
subjects=$(git log --no-merges --format='%s' "$range")

section() { # title, type
  local lines
  lines=$(printf '%s\n' "$subjects" | grep -E "^$2(\([^)]*\))?!?: " |
    sed -E 's/^[a-z]+(\(([^)]*)\))?(!)?: (.*)$/- \4/' || true)
  if [ -n "$lines" ]; then
    printf '## %s\n\n%s\n\n' "$1" "$lines"
  fi
}

if [ -n "$prev" ]; then
  printf 'Changes since %s.\n\n' "$prev"
else
  printf 'First release.\n\n'
fi
section "Features" feat
section "Bug fixes" fix
section "Security" sec
section "Performance" perf
cat <<NOTES
## Install

\`\`\`sh
brew install esuEdu/tap/wraith
\`\`\`

Docs: https://esuedu.github.io/wraith/

The formula builds wraith from the source tarball attached here. Check it against
\`checksums.txt\`, and its build provenance with:

\`\`\`sh
gh attestation verify wraith-$tag.tar.gz --repo $repo
\`\`\`
NOTES
