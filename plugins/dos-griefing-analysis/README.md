# DoS & Griefing Analysis

A specialized smart contract security skill for detecting Denial of Service and griefing vulnerabilities that can render contracts permanently unusable or allow attackers to harm other users at low cost.

## What It Does

1. **Detects unbounded loops** — Loops over dynamic arrays that grow with usage
2. **Identifies gas limit exhaustion** — Operations that exceed block gas limit as data grows
3. **Finds external call DoS** — Single revert in batch operations blocking all users
4. **Detects gas griefing** — 63/64 rule exploitation for insufficient gas attacks
5. **Identifies force-feeding** — `selfdestruct` ETH forcing that breaks balance checks
6. **Analyzes payment patterns** — Push vs pull and their DoS implications

## When to Use

- Auditing contracts with batch operations or loops over user data
- Reviewing reward distribution or dividend payment systems
- Analyzing contracts that rely on `address(this).balance` for logic
- Verifying that single-user failures don't block system-wide operations

## Structure

```
dos-griefing-analysis/
├── skills/
│   └── dos-griefing-analysis/
│       ├── SKILL.md                          # Core detection methodology
│       └── references/
│           ├── dos-patterns.md               # DoS attack pattern catalog
│           └── gas-griefing-vectors.md        # Gas manipulation techniques
├── .claude-plugin/
│   └── plugin.json
└── README.md
```

## Key Concepts

- **Unbounded Loops**: Loops whose iteration count grows with contract usage
- **Block Gas Limit**: ~30M gas per block; operations exceeding this permanently fail
- **63/64 Rule**: EIP-150 forwards only 63/64 of remaining gas to external calls
- **Force-Feeding**: Sending ETH to a contract without its consent via `selfdestruct`
