#!/usr/bin/env bash
# Updates SHA-256 checksums in README.md
# Run this after modifying any script or SKILL.md
#
# Usage: ./scripts/update-checksums.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
README="$PROJECT_DIR/README.md"

FILES=(
  scripts/env-scan.sh
  scripts/project-scan.sh
  scripts/ioc-scan.sh
  scripts/ioc-scan.ps1
  scripts/respond.sh
  SKILL.md
)

# Generate checksums to a temp file
TMPFILE=$(mktemp)
for f in "${FILES[@]}"; do
  hash=$(shasum -a 256 "$PROJECT_DIR/$f" | awk '{print $1}')
  echo "$hash  $f" >> "$TMPFILE"
done

# Replace between markers in README
python3 -c "
import sys

checksums_path = '$TMPFILE'
readme_path = '$README'

with open(checksums_path, 'r') as f:
    checksums = f.read()

with open(readme_path, 'r') as f:
    lines = f.readlines()

out = []
skip = False
for line in lines:
    if '<!-- CHECKSUMS-START -->' in line:
        out.append(line)
        out.append('\`\`\`\n')
        out.append(checksums)
        out.append('\`\`\`\n')
        skip = True
        continue
    if '<!-- CHECKSUMS-END -->' in line:
        out.append(line)
        skip = False
        continue
    if not skip:
        out.append(line)

with open(readme_path, 'w') as f:
    f.writelines(out)

print('Checksums updated in README.md')
"

rm -f "$TMPFILE"
