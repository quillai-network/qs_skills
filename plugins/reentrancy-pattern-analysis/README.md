# Reentrancy Pattern Analysis

A specialized smart contract security skill for systematic detection of all reentrancy vulnerability variants — from classic single-function reentrancy to modern read-only and cross-contract patterns.

## What It Does

Instead of simple pattern matching for `call.value`, this skill:

1. **Classifies reentrancy type** — classic, cross-function, cross-contract, or read-only
2. **Builds a call graph** tracing all external calls and their positions relative to state changes
3. **Verifies CEI pattern compliance** (Checks-Effects-Interactions) for every state-modifying function
4. **Detects callback vectors** through ERC-777 hooks, ERC-1155 callbacks, and fallback functions
5. **Generates exploit scenarios** with step-by-step attack sequences

## When to Use

- Auditing any contract that makes external calls (ETH transfers, token transfers, cross-contract calls)
- Reviewing contracts that integrate with ERC-777, ERC-1155, or other callback-enabled tokens
- Analyzing DeFi protocols with complex multi-contract interactions
- Verifying that reentrancy guards are correctly applied across all entry points

## Structure

```
reentrancy-pattern-analysis/
├── skills/
│   └── reentrancy-pattern-analysis/
│       ├── SKILL.md                          # Core detection methodology
│       └── references/
│           ├── reentrancy-variants.md        # Taxonomy of all reentrancy types
│           └── case-studies.md               # Real-world exploits and detection
├── .claude-plugin/
│   └── plugin.json
└── README.md
```

## Key Concepts

- **CEI Verification**: Systematic check that all state updates occur before external calls
- **Call Graph Analysis**: Map every external call path and identify re-entry points
- **Callback Vector Detection**: Identify token standards and patterns that enable callbacks
- **Read-Only Reentrancy**: Detect view functions that return stale state during reentrancy
