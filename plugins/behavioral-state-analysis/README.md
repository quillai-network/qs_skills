# Behavioral State Analysis (BSA)

A comprehensive smart contract security auditing skill that uses multi-dimensional vulnerability detection through behavioral pattern analysis and state machine verification.

## What It Does

Instead of pattern matching or sequential analysis, BSA:

1. **Extracts behavioral intent** from code, comments, and naming conventions
2. **Runs parallel threat engines** across economic, access control, and state integrity dimensions
3. **Generates adversarial proofs** with executable Foundry/Hardhat test cases
4. **Scores findings** using Bayesian confidence for prioritization

## When to Use

- Starting a comprehensive smart contract audit
- Threat modeling DeFi protocols (DEXs, lending, staking, vaults)
- Analyzing cross-contract attack surfaces
- Generating exploit proof-of-concepts

## Structure

```
behavioral-state-analysis/
├── skills/
│   └── behavioral-state-analysis/
│       ├── SKILL.md                          # Core methodology
│       └── references/
│           ├── threat-engines.md             # Detailed threat engine specs
│           └── confidence-scoring.md         # Bayesian scoring reference
├── .claude-plugin/
│   └── plugin.json
└── README.md
```

## Key Concepts

- **Behavioral Decomposition**: Extract what the code is supposed to do before finding deviations
- **Multi-Dimensional Threat Modeling**: Simultaneous analysis across economic, access control, and state integrity
- **Adversarial Proof Generation**: Automated exploit scenarios with verifiable PoCs
- **Bayesian Confidence Scoring**: Mathematical prioritization of findings
