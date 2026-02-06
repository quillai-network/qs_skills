---
name: oracle-flashloan-analysis
description: Detects price oracle manipulation and flash loan attack vectors in DeFi smart contracts. Classifies oracle trust models (Chainlink, TWAP, spot price, custom), identifies stale price risks, circular price dependencies, and flash loan atomicity exploitation patterns. Use when auditing DeFi protocols that depend on price data, oracle integrations, lending protocols, DEXs, derivatives, or any contract where flash loans could manipulate state within a single transaction.
---

# Oracle & Flash Loan Analysis

Detect vulnerabilities where **external price data can be manipulated** or **flash loans can exploit protocol logic** within a single transaction. These two attack vectors are often combined and represent the most common DeFi attack pattern.

## When to Use

- Auditing any DeFi protocol that reads external price data (lending, DEX, derivatives, yield aggregators)
- Reviewing Chainlink, Uniswap TWAP, Band Protocol, or custom oracle integrations
- Analyzing protocols that interact with or are accessible via flash loans
- Threat modeling for MEV, sandwich attacks, and price manipulation
- When a protocol uses `balanceOf()`, pool reserves, or spot prices for critical calculations

## When NOT to Use

- Contracts with no price dependencies or external data feeds
- Pure access control analysis (use semantic-guard-analysis)
- State-to-state invariant checking (use state-invariant-detection)

## Core Concept: The Oracle Trust Hierarchy

Not all price sources are equally secure. Oracle vulnerabilities stem from the gap between **assumed trust** and **actual manipulation resistance**.

```
Trust Level (highest to lowest):
┌─────────────────────────────────────────────┐
│ Level 5: Multi-oracle consensus + circuit    │
│          breakers + TWAP + staleness checks  │
├─────────────────────────────────────────────┤
│ Level 4: Chainlink with full validation      │
│          (staleness, sequencer, min answers)  │
├─────────────────────────────────────────────┤
│ Level 3: Uniswap V3 TWAP (long window)      │
│          Multi-block manipulation cost        │
├─────────────────────────────────────────────┤
│ Level 2: Uniswap V2 TWAP (short window)     │
│          or Chainlink WITHOUT staleness check │
├─────────────────────────────────────────────┤
│ Level 1: Spot price from single pool         │ ← Manipulable via flash loan
│          or balanceOf() for pricing           │
└─────────────────────────────────────────────┘
```

## The Four-Phase Detection Architecture

### Phase 1: Oracle Source Identification

Locate every point where the contract reads external price/value data.

**Search for these patterns:**

| Pattern | Oracle Type | Risk Level |
|---------|------------|------------|
| `latestRoundData()` | Chainlink | Medium (depends on validation) |
| `latestAnswer()` | Chainlink (deprecated) | HIGH (no round validation) |
| `observe()` / `consult()` | Uniswap TWAP | Medium (depends on window) |
| `getReserves()` | AMM spot price | **CRITICAL** (flash-loan manipulable) |
| `balanceOf(address(this))` | Self-balance | **CRITICAL** (donation attack) |
| `slot0()` / `sqrtPriceX96` | Uniswap V3 spot | **CRITICAL** (single-block manipulable) |
| Custom `getPrice()` | Unknown | Requires investigation |

**Build an Oracle Dependency Map:**

```
Contract: LendingPool
├── borrowLimit() → uses getCollateralPrice()
│   └── getCollateralPrice() → calls chainlinkOracle.latestRoundData()
├── liquidate() → uses getDebtPrice()
│   └── getDebtPrice() → calls uniswapPool.slot0() ← SPOT PRICE!
└── calculateInterest() → uses getUtilizationRate()
    └── getUtilizationRate() → reads internal state (safe)
```

### Phase 2: Oracle Validation Verification

For each oracle source, verify that proper safety checks are in place.

**Chainlink Validation Checklist:**

```solidity
// COMPLETE Chainlink integration
(uint80 roundId, int256 price, , uint256 updatedAt, uint80 answeredInRound) =
    priceFeed.latestRoundData();

require(price > 0, "Invalid price");                    // Check 1: Non-negative
require(updatedAt > 0, "Round not complete");            // Check 2: Round complete
require(answeredInRound >= roundId, "Stale price");      // Check 3: Not stale
require(block.timestamp - updatedAt < HEARTBEAT,         // Check 4: Fresh
        "Price too old");

// L2-specific
require(!sequencerFeed.isDown(), "Sequencer down");      // Check 5: L2 sequencer
require(block.timestamp - sequencerUptime > GRACE,       // Check 6: Grace period
        "Grace period");
```

**Missing Check Severity:**

| Missing Check | Severity | Impact |
|---------------|----------|--------|
| `price > 0` | HIGH | Zero/negative price → infinite borrowing or free liquidations |
| `updatedAt > 0` | MEDIUM | Incomplete round data used |
| `answeredInRound >= roundId` | HIGH | Stale price from previous round |
| Heartbeat/freshness | HIGH | Hours-old price during volatile markets |
| L2 sequencer check | HIGH | Stale price during L2 outage → unfair liquidations |
| Price deviation bounds | MEDIUM | Extreme outlier not filtered |

**TWAP Validation:**

```
Window length analysis:
  - < 10 minutes: HIGH RISK — manipulable with moderate capital
  - 10-30 minutes: MEDIUM RISK — expensive but feasible multi-block manipulation
  - 30+ minutes: LOWER RISK — requires sustained pool manipulation
  - Check: Is the TWAP window configurable? Can governance reduce it?
```

### Phase 3: Flash Loan Attack Surface Analysis

Identify operations that can be exploited via flash loan atomicity.

**Flash Loan Attack Model:**

```
Single Transaction:
  1. Borrow N tokens via flash loan (Aave, dYdX, Balancer)
  2. Manipulate price source (swap in pool, donate to contract)
  3. Exploit protocol at manipulated price (borrow, liquidate, swap)
  4. Reverse manipulation (swap back)
  5. Repay flash loan + fee
  6. Profit = exploited_value - flash_loan_fee - gas
```

**Detection Algorithm:**

```
For each function F that reads price/value data:
  1. Identify the price source S
  2. Can S be manipulated within a single transaction?
     - Spot price from AMM → YES (swap in same tx)
     - balanceOf(address(this)) → YES (donate tokens)
     - Chainlink feed → NO (off-chain updates)
     - TWAP → DEPENDS (short window = risky)
  3. What does F do with the price?
     - Determines borrowing limit → CRITICAL
     - Triggers liquidation → CRITICAL
     - Sets exchange rate → HIGH
     - Informational only → LOW
  4. Is the manipulation profitable?
     - value_extracted - (flash_loan_fee + slippage + gas) > 0 → EXPLOIT VIABLE
```

**Common Flash Loan Attack Patterns:**

| Pattern | Target | Method |
|---------|--------|--------|
| Oracle manipulation | Lending protocol | Flash swap in pool → inflate collateral price → over-borrow |
| Governance attack | DAO/voting | Flash borrow governance tokens → vote → execute → return |
| Liquidation manipulation | Lending protocol | Flash swap to crash price → liquidate at discount |
| Share price inflation | Vault/ERC4626 | Flash loan → donate to vault → inflate share price → front-run deposit |
| Arbitrage amplification | AMM/DEX | Flash loan amplifies existing price discrepancy |

### Phase 4: Circular Dependency Detection

Find cases where a protocol's pricing depends on its own state, creating exploitable feedback loops.

**Circular Dependency Pattern:**

```
Protocol A uses Token X price → from Pool P
Pool P contains Token X + Token Y
Protocol A issues Token X (or affects its supply)

→ CIRCULAR: Protocol A's actions change Token X supply
            → changes Pool P reserves
            → changes Token X price
            → changes Protocol A's valuations
```

**Detection:**

```
For each price oracle call in the contract:
  1. What token/asset is being priced?
  2. Does THIS contract mint, burn, or distribute that token?
  3. Does THIS contract add/remove liquidity from the pricing pool?
  4. Does any action in THIS contract affect the reserves of the pricing pool?

  If YES to any → CIRCULAR DEPENDENCY
  Severity: CRITICAL if the circular path can be exploited atomically
```

## Workflow

```
Task Progress:
- [ ] Step 1: Identify all oracle/price data sources in the contract
- [ ] Step 2: Classify each source by trust level (Chainlink, TWAP, spot, custom)
- [ ] Step 3: Verify validation checks for each oracle source
- [ ] Step 4: Map flash loan attack surfaces (which operations use manipulable prices?)
- [ ] Step 5: Detect circular price dependencies
- [ ] Step 6: Estimate manipulation cost vs profit (feasibility analysis)
- [ ] Step 7: Score findings and generate report
```

## Output Format

```markdown
## Oracle & Flash Loan Analysis Report

### Finding: [Title]

**Function:** `functionName()` at `Contract.sol:L42`
**Category:** [Oracle Manipulation | Stale Price | Flash Loan | Circular Dependency]
**Severity:** [CRITICAL | HIGH | MEDIUM]

**Oracle Source:** `[oracle contract/function]`
**Trust Level:** [1-5 from hierarchy]

**Vulnerability:**
[Description of how the price source can be manipulated or is insufficiently validated]

**Attack Scenario:**
1. Attacker obtains flash loan of [X tokens] from [source]
2. Swaps [amount] in [pool] to manipulate price of [token]
3. Calls `functionName()` which reads manipulated price
4. Extracts [value] from protocol at wrong price
5. Reverses manipulation and repays flash loan
6. Net profit: [amount]

**Missing Validations:**
- [ ] Price > 0 check
- [ ] Staleness check (heartbeat)
- [ ] Round completeness check
- [ ] L2 sequencer check
- [ ] Price deviation bounds

**Recommendation:**
[Specific fix — add TWAP, add Chainlink validation, implement circuit breaker]
```

## Quick Detection Checklist

- [ ] Does any function use `getReserves()`, `slot0()`, or `balanceOf()` for pricing? (Flash-loan manipulable)
- [ ] Does Chainlink integration check for `price > 0`, staleness, and round completeness?
- [ ] Is the TWAP window long enough to resist multi-block manipulation (> 30 min)?
- [ ] Does the protocol's own token appear in its pricing oracle's pool? (Circular dependency)
- [ ] Can any critical operation (borrow, liquidate, swap) be called in the same transaction as a flash loan?
- [ ] Are there price deviation circuit breakers for extreme moves?
- [ ] On L2: Is the sequencer uptime checked before using price data?

For oracle type details, see [{baseDir}/references/oracle-types.md]({baseDir}/references/oracle-types.md).
For flash loan attack patterns, see [{baseDir}/references/flash-loan-vectors.md]({baseDir}/references/flash-loan-vectors.md).

## Rationalizations to Reject

- "We use Chainlink, so it's safe" → Only if ALL validation checks are implemented; partial integration is common
- "Flash loans can't affect our protocol" → Any protocol using manipulable price sources is affected
- "The TWAP window is 10 minutes" → Multi-block manipulation is feasible for well-funded attackers
- "Our oracle is a trusted admin feed" → Admin key compromise → arbitrary price → instant drain
- "The pool is too large to manipulate" → Flash loans provide unlimited capital for single-transaction manipulation
- "We check if price is non-zero" → Non-zero is necessary but not sufficient; stale/manipulated non-zero prices are dangerous
