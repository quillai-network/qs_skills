# External Call Safety

A specialized smart contract security skill for detecting unsafe external call patterns and token integration vulnerabilities. Covers the full spectrum from unchecked low-level calls to the "weird ERC20" token behaviors that break protocol assumptions.

## What It Does

1. **Detects unchecked external calls** — `call`, `delegatecall`, `staticcall` without return value verification
2. **Identifies token integration hazards** — fee-on-transfer, rebasing, missing return values, callbacks
3. **Finds unsafe approval patterns** — non-zero to non-zero approve race, infinite approvals
4. **Analyzes payment patterns** — push vs pull, gas stipend limitations, return data bombs
5. **Maps external call trust boundaries** — which contracts are trusted vs untrusted

## When to Use

- Auditing contracts that make external calls to other contracts
- Reviewing token integrations (especially supporting arbitrary ERC20 tokens)
- Analyzing ETH transfer patterns and payment distribution logic
- Verifying that all external call return values are properly handled

## Structure

```
external-call-safety/
├── skills/
│   └── external-call-safety/
│       ├── SKILL.md                          # Core detection methodology
│       └── references/
│           ├── weird-erc20.md                # Non-standard ERC20 behavior catalog
│           └── call-safety-patterns.md       # Safe vs unsafe call patterns
├── .claude-plugin/
│   └── plugin.json
└── README.md
```

## Key Concepts

- **Unchecked Return Values**: Low-level calls return success/failure boolean that MUST be checked
- **Fee-on-Transfer**: Tokens that deduct fees during transfer, breaking `amount` assumptions
- **Return Data Bomb**: Malicious contract returns massive data to consume caller's gas
- **Push vs Pull**: Direct send (push) vs user-initiated claim (pull) payment patterns
