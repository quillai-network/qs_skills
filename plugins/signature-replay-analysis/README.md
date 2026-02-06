# Signature & Replay Analysis

A specialized smart contract security skill for detecting signature replay vulnerabilities — a vulnerability class affecting nearly 1 in 5 contracts that use cryptographic signatures. Responsible for major exploits including the $190M Nomad Bridge hack.

## What It Does

1. **Classifies replay attack type** — same-chain, cross-chain, cross-contract, nonce-skip, expired-signature
2. **Verifies EIP-712 domain separator** — chainId, verifyingContract, name, version, salt completeness
3. **Analyzes nonce management** — sequential vs bitmap, per-user vs global, gap resistance
4. **Checks ecrecover safety** — address(0) return, signature malleability, s-value normalization
5. **Validates permit/permit2 implementations** — deadline enforcement, domain binding

## When to Use

- Auditing contracts that use `ecrecover`, ECDSA signatures, or EIP-712 typed data
- Reviewing permit/permit2 token implementations
- Analyzing meta-transaction and gasless relay systems
- Verifying signature-based authentication (multi-sig, governance voting, off-chain orders)

## Structure

```
signature-replay-analysis/
├── skills/
│   └── signature-replay-analysis/
│       ├── SKILL.md                          # Core detection methodology
│       └── references/
│           ├── replay-taxonomy.md            # Five replay types with heuristics
│           └── eip712-checklist.md           # EIP-712 verification checklist
├── .claude-plugin/
│   └── plugin.json
└── README.md
```

## Key Concepts

- **Signature Replay**: Using a valid signature more than once or in an unintended context
- **Domain Separation**: EIP-712 binding signatures to specific chain, contract, and version
- **Nonce Management**: Ensuring each signature can only be used once
- **Signature Malleability**: Creating alternate valid signatures without the private key
