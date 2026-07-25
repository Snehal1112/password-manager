#!/usr/bin/env bash
# install-hooks.sh: points git at the repo-managed hooks directory and
# ensures the post-commit hook is executable.

set -euo pipefail

git config core.hooksPath scripts/hooks
chmod +x scripts/hooks/post-commit

echo "Installed git hooks from scripts/hooks (core.hooksPath set) - post-commit will warn when docs/usage-guide.md may be stale after a commit."
