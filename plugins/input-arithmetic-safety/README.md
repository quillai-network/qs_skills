# Input & Arithmetic Safety

A specialized smart contract security skill for detecting input validation failures (the #1 direct exploitation cause at 34.6% of cases) and arithmetic vulnerabilities that persist even with Solidity 0.8+ checked math.

## What It Does

1. **Detects missing input validation** — zero address, zero amount, bounds checking, array length
2. **Finds precision loss patterns** — division-before-multiplication, rounding direction exploitation
3. **Identifies unsafe casting** — uint256 to smaller types, signed/unsigned mismatches
4. **Detects share/price manipulation** — ERC4626 inflation attack, first-depositor attack
5. **Finds unchecked block risks** — Solidity 0.8+ unchecked blocks with dangerous arithmetic

## When to Use

- Auditing DeFi protocols with fee calculations, share pricing, or exchange rates
- Reviewing any contract with `unchecked` blocks
- Analyzing vault/staking contracts for rounding or inflation attacks
- Verifying input validation on public/external functions

## Structure

```
input-arithmetic-safety/
├── skills/
│   └── input-arithmetic-safety/
│       ├── SKILL.md                          # Core detection methodology
│       └── references/
│           ├── precision-patterns.md         # Precision loss patterns with proofs
│           └── validation-checklist.md       # Input validation checklist
├── .claude-plugin/
│   └── plugin.json
└── README.md
```

## Key Concepts

- **Division-Before-Multiplication**: Integer division truncates; doing it before multiplication amplifies the loss
- **Rounding Direction**: Protocols should round against the user (round down on deposit, round up on withdraw)
- **ERC4626 Inflation**: First depositor manipulates share price to steal subsequent deposits
- **Unsafe Casting**: Truncation when casting uint256 to smaller types without bounds checking
