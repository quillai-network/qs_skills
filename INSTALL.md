# Install QuillShield Skills in Claude Code

## One-Line Install

Clone the repo and run the install script:

```bash
git clone https://github.com/quillai-network/qs_skill.git
cd qs_skill && bash install.sh
```

## Manual Install

### Step 1: Create the commands directory

```bash
mkdir -p ~/.claude/commands
```

### Step 2: Copy all skills

```bash
cp plugins/behavioral-state-analysis/skills/behavioral-state-analysis/SKILL.md ~/.claude/commands/behavioral-state-analysis.md
cp plugins/semantic-guard-analysis/skills/semantic-guard-analysis/SKILL.md ~/.claude/commands/semantic-guard-analysis.md
cp plugins/state-invariant-detection/skills/state-invariant-detection/SKILL.md ~/.claude/commands/state-invariant-detection.md
cp plugins/reentrancy-pattern-analysis/skills/reentrancy-pattern-analysis/SKILL.md ~/.claude/commands/reentrancy-pattern-analysis.md
cp plugins/oracle-flashloan-analysis/skills/oracle-flashloan-analysis/SKILL.md ~/.claude/commands/oracle-flashloan-analysis.md
cp plugins/proxy-upgrade-safety/skills/proxy-upgrade-safety/SKILL.md ~/.claude/commands/proxy-upgrade-safety.md
cp plugins/input-arithmetic-safety/skills/input-arithmetic-safety/SKILL.md ~/.claude/commands/input-arithmetic-safety.md
cp plugins/external-call-safety/skills/external-call-safety/SKILL.md ~/.claude/commands/external-call-safety.md
cp plugins/signature-replay-analysis/skills/signature-replay-analysis/SKILL.md ~/.claude/commands/signature-replay-analysis.md
cp plugins/dos-griefing-analysis/skills/dos-griefing-analysis/SKILL.md ~/.claude/commands/dos-griefing-analysis.md
```

### Step 3: Verify

```bash
ls ~/.claude/commands/
```

You should see 10 `.md` files.

## Usage

In any Claude Code session, type `/` and select a skill:

| Command | What It Audits |
|---------|---------------|
| `/behavioral-state-analysis` | Full multi-dimensional security audit |
| `/semantic-guard-analysis` | Missing access controls & forgotten checks |
| `/state-invariant-detection` | Broken math relationships between state variables |
| `/reentrancy-pattern-analysis` | All reentrancy variants (classic, cross-function, read-only) |
| `/oracle-flashloan-analysis` | Oracle manipulation & flash loan vectors |
| `/proxy-upgrade-safety` | Storage collisions, uninitialized impls, selector clashes |
| `/input-arithmetic-safety` | Input validation, precision loss, ERC4626 inflation |
| `/external-call-safety` | Unchecked returns, fee-on-transfer, weird ERC20s |
| `/signature-replay-analysis` | Signature replay, EIP-712, ecrecover edge cases |
| `/dos-griefing-analysis` | Unbounded loops, gas griefing, force-feeding |

### Example

```
> /behavioral-state-analysis
> Audit this contract: [paste contract or file path]
```

## Uninstall

```bash
rm ~/.claude/commands/behavioral-state-analysis.md
rm ~/.claude/commands/semantic-guard-analysis.md
rm ~/.claude/commands/state-invariant-detection.md
rm ~/.claude/commands/reentrancy-pattern-analysis.md
rm ~/.claude/commands/oracle-flashloan-analysis.md
rm ~/.claude/commands/proxy-upgrade-safety.md
rm ~/.claude/commands/input-arithmetic-safety.md
rm ~/.claude/commands/external-call-safety.md
rm ~/.claude/commands/signature-replay-analysis.md
rm ~/.claude/commands/dos-griefing-analysis.md
```
