# Semantic Guard Analysis

Detects logic vulnerabilities by finding functions that violate the contract's own internal guard patterns using the Consistency Principle.

## What It Does

Traditional security tools check each function independently. This skill analyzes the **contract as a whole** to find inconsistencies:

- If 9 out of 10 functions check `!paused` before modifying `balance`, the 1 that doesn't is statistically anomalous
- This anomaly likely indicates a vulnerability that traditional tools miss entirely

## The Core Idea

> "A smart contract is its own specification."

Instead of checking against external rule databases, we analyze what the contract **claims to enforce**, then systematically find where it **breaks its own rules**.

## When to Use

- Auditing contracts where traditional tools report no issues
- Looking for missing `require` checks and forgotten modifiers
- Analyzing emergency/admin functions for safety bypasses
- Detecting "syntactically correct but semantically dangerous" code

## Structure

```
semantic-guard-analysis/
├── skills/
│   └── semantic-guard-analysis/
│       ├── SKILL.md                      # Core methodology
│       └── references/
│           ├── detection-algorithm.md    # Formal algorithm & math
│           └── case-studies.md           # Real-world examples
├── .claude-plugin/
│   └── plugin.json
└── README.md
```

## Key Innovation

**Proportionality Analysis:** The ability to modify State A should be consistently proportional to checking State B. When this proportionality breaks, you've found a vulnerability.
