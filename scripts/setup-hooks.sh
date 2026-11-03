#!/usr/bin/env bash
# Configures the local repository to use versioned Git hooks from .githooks/

set -e

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

if [ -d ".githooks" ]; then
    git config core.hooksPath .githooks
    chmod +x .githooks/* 2>/dev/null || true
    echo "✅ Successfully configured core.hooksPath to .githooks"
else
    echo "❌ Error: .githooks directory not found in $REPO_ROOT"
    exit 1
fi
