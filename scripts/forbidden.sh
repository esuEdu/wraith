#!/usr/bin/env bash
# Fails if non-test Go code uses a pattern the Security spec forbids:
#   S2.3  InsecureSkipVerify outside tests (the one exception is marked "allow: S2.4")
#   S4.2  running external tools through a shell
set -euo pipefail
cd "$(dirname "$0")/.."

pattern='InsecureSkipVerify|exec\.Command(Context)?\([^)]*"(/bin/)?(ba|z)?sh"'
hits="$(grep -rnE --include='*.go' --exclude='*_test.go' --exclude-dir=spike --exclude-dir=.git \
  "$pattern" . | grep -v 'allow: S2.4' || true)"

if [[ -n "$hits" ]]; then
  echo "$hits"
  echo "forbidden pattern found (S2.3 InsecureSkipVerify / S4.2 shell exec); see the Security spec" >&2
  exit 1
fi
