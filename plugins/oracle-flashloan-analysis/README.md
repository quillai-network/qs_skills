# Oracle & Flash Loan Analysis

A specialized smart contract security skill for detecting price oracle manipulation vulnerabilities and flash loan attack vectors — the most common DeFi attack combination responsible for billions in losses.

## What It Does

1. **Classifies oracle trust models** — Chainlink, TWAP, spot price, custom oracles
2. **Detects manipulation resistance** — Can the price source be manipulated within a single block/transaction?
3. **Identifies stale price risks** — Missing heartbeat checks, sequencer downtime, round completeness
4. **Maps flash loan attack surfaces** — Which protocol operations can be exploited via atomicity?
5. **Detects circular dependencies** — Protocol pricing that depends on its own token/pool state

## When to Use

- Auditing DeFi protocols that depend on external price data (lending, DEX, derivatives)
- Reviewing oracle integrations (Chainlink, Uniswap TWAP, Band Protocol, custom)
- Analyzing protocols with flash loan interactions or large-value single-transaction operations
- Threat modeling for price manipulation and MEV attack vectors

## Structure

```
oracle-flashloan-analysis/
├── skills/
│   └── oracle-flashloan-analysis/
│       ├── SKILL.md                          # Core detection methodology
│       └── references/
│           ├── oracle-types.md               # Oracle classification and trust models
│           └── flash-loan-vectors.md         # Flash loan attack patterns
├── .claude-plugin/
│   └── plugin.json
└── README.md
```

## Key Concepts

- **Oracle Trust Model**: Classification of price sources by manipulation resistance
- **Spot Price vs TWAP**: Single-block manipulable vs time-weighted (harder but not impossible)
- **Flash Loan Atomicity**: Exploiting same-transaction execution for price manipulation
- **Circular Dependencies**: Protocol relying on its own state for pricing creates feedback loops
