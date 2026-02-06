# State Invariant Detection

Automatically infers mathematical relationships between state variables in smart contracts, then finds functions that break those relationships.

## What It Does

Smart contracts maintain mathematical invariants between state variables (e.g., `totalSupply = sum(balances)`). This skill:

1. **Clusters** related state variables by co-modification frequency
2. **Infers** the mathematical relationship (sum, conservation, ratio, monotonic, sync)
3. **Detects** functions that violate those invariants
4. **Reports** the exact desynchronization with before/after analysis

## The Problem It Solves

65-70% of major DeFi hacks involve state invariant violations:
- Unauthorized minting (`totalSupply` drifts from `sum(balances)`)
- Broken tokenomics (conservation laws violated)
- Accounting desynchronization (aggregates don't match individuals)
- AMM constant product violations

Traditional tools check syntax — they can't detect that `adminBurn()` updates `balances` but forgets to update `totalSupply`.

## When to Use

- Auditing ERC20 tokens for supply/balance consistency
- Analyzing staking pools, vaults, AMMs for accounting errors
- Checking treasury/fund contracts for conservation law violations
- Verifying aggregate variables match individual records

## Structure

```
state-invariant-detection/
├── skills/
│   └── state-invariant-detection/
│       ├── SKILL.md                     # Core methodology
│       └── references/
│           ├── invariant-types.md       # Five relationship types with formulas
│           └── case-studies.md          # Real-world examples (DAO, Poly Network, etc.)
├── .claude-plugin/
│   └── plugin.json
└── README.md
```

## Five Invariant Types

1. **Sum (Aggregation):** `totalSupply = Σ balances`
2. **Conservation:** `total = available + locked`
3. **Ratio (Proportional):** `k = reserveA × reserveB`
4. **Monotonic (Ordering):** `nonce_new ≥ nonce_old`
5. **Synchronization (Coupling):** `if balance changes, totalSupply must change`
