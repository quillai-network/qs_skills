# Proxy & Upgrade Safety

A specialized smart contract security skill for detecting vulnerabilities in upgradeable proxy architectures. Over 54% of active Ethereum contracts use proxy patterns, and approximately 1.5 million contracts have at least one storage collision issue.

## What It Does

1. **Classifies proxy pattern** — Transparent, UUPS, Beacon, Diamond (EIP-2535), Minimal
2. **Detects storage layout collisions** — Between proxy and implementation, and between upgrade versions
3. **Verifies initialization safety** — Can `initialize()` be called on the implementation directly?
4. **Checks function selector clashing** — Proxy admin functions vs implementation functions
5. **Validates upgrade authorization** — Is the upgrade path properly protected?

## When to Use

- Auditing any upgradeable contract (proxy pattern)
- Reviewing implementation upgrades for storage compatibility
- Analyzing `delegatecall`-based architectures
- Verifying OpenZeppelin Upgrades plugin compliance
- Checking Diamond (EIP-2535) facet management

## Structure

```
proxy-upgrade-safety/
├── skills/
│   └── proxy-upgrade-safety/
│       ├── SKILL.md                              # Core detection methodology
│       └── references/
│           ├── proxy-patterns.md                 # All proxy standards compared
│           └── storage-collision-detection.md     # Storage layout analysis algorithm
├── .claude-plugin/
│   └── plugin.json
└── README.md
```

## Key Concepts

- **Storage Collision**: Proxy and implementation share storage via `delegatecall`; overlapping slots corrupt data
- **Uninitialized Implementation**: Calling `initialize()` directly on the implementation contract
- **Function Selector Clash**: 4-byte selector collision between proxy admin and implementation functions
- **Upgrade Path Safety**: Ensuring new implementations are storage-compatible with old ones
