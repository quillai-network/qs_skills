#!/bin/bash
# QuillShield Skills Installer for Claude Code

set -e

COMMANDS_DIR="$HOME/.claude/commands"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGINS_DIR="$SCRIPT_DIR/plugins"

SKILLS=(
  "behavioral-state-analysis"
  "semantic-guard-analysis"
  "state-invariant-detection"
  "reentrancy-pattern-analysis"
  "oracle-flashloan-analysis"
  "proxy-upgrade-safety"
  "input-arithmetic-safety"
  "external-call-safety"
  "signature-replay-analysis"
  "dos-griefing-analysis"
)

echo "Installing QuillShield skills to Claude Code..."
mkdir -p "$COMMANDS_DIR"

count=0
for skill in "${SKILLS[@]}"; do
  src="$PLUGINS_DIR/$skill/skills/$skill/SKILL.md"
  dest="$COMMANDS_DIR/$skill.md"
  if [ -f "$src" ]; then
    cp "$src" "$dest"
    echo "  /$skill"
    count=$((count + 1))
  else
    echo "  [skip] $skill (SKILL.md not found)"
  fi
done

echo ""
echo "Done! $count skills installed."
echo "Type / in Claude Code to use them."
