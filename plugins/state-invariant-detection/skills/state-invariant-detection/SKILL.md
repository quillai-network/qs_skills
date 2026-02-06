---
name: state-invariant-detection
description: Detects broken mathematical relationships between state variables in smart contracts. Automatically infers invariants (totalSupply = sum(balances), conservation laws, ratio constraints) then finds functions that violate them. Catches unauthorized minting, broken tokenomics, accounting desynchronization, and state drift. Use when auditing for state-state invariant violations, broken accounting, supply mismatches, desynchronized state variables, or conservation law violations in smart contracts.
---

# State Invariant Detection

Automatically infer mathematical relationships between state variables, then find functions that **break those relationships**. Catches the most devastating DeFi vulnerabilities: unauthorized minting, broken tokenomics, accounting discrepancies, and state desynchronization.

## When to Use

- Auditing token contracts for supply/balance mismatches
- Analyzing staking, vault, or pool contracts for accounting errors
- Detecting conservation law violations in treasury/fund management
- Finding AMM/DEX constant product violations
- Verifying that aggregate variables stay synchronized with individual records

## When NOT to Use

- Guard-state consistency analysis (use semantic-guard-analysis)
- Full multi-dimensional audit (use behavioral-state-analysis)
- Entry point identification only (use entry-point-analyzer)

## Core Concept: State Variable Proportionality

**Hypothesis:** In well-designed contracts, state variables maintain mathematical relationships (invariants) that should never be violated.

When a function modifies one side of a relationship without updating the other, the invariant breaks — creating exploitable accounting errors.

## Five Types of State Relationships

### Type 1: Sum Relationships (Aggregation)

```
totalSupply = Σ balance[i] for all users i
```

**Found in:** ERC20 tokens, staking pools, vaults, share systems

### Type 2: Difference Relationships (Conservation)

```
totalFunds = availableFunds + lockedFunds
```

**Found in:** Treasuries, liquidity pools, vesting contracts

### Type 3: Ratio Relationships (Proportional)

```
k = reserveA × reserveB  (constant product)
sharePrice = totalAssets / totalShares
```

**Found in:** AMMs, DEXs, vault share pricing, collateralization

### Type 4: Monotonic Relationships (Ordering)

```
newValue ≥ oldValue  (only increases)
```

**Found in:** Timestamps, nonces, accumulated rewards, total distributions

### Type 5: Synchronization Relationships (Coupling)

```
If stateA changes, stateB must change correspondingly
```

**Found in:** Deposit/mint pairs, burn/release pairs, collateral/borrowing power

For detailed definitions and examples, see [{baseDir}/references/invariant-types.md]({baseDir}/references/invariant-types.md).

## The Three-Phase Detection Architecture

### Phase 1: State Variable Clustering

Group state variables that appear to be related.

**Algorithm:**

```
For each pair of state variables (A, B):
  1. Track all functions that modify A
  2. Track all functions that modify B
  3. Calculate co-modification frequency:

     CoMod(A, B) = |Functions modifying both A and B| / |Functions modifying A or B|

  4. If CoMod(A, B) > 0.6 → A and B are likely related
```

**Example:**

```solidity
// mint() modifies BOTH totalSupply and balances → co-modified
// burn() modifies BOTH totalSupply and balances → co-modified
// transfer() modifies ONLY balances → does not co-modify

CoMod(totalSupply, balances) = 2/3 = 66.7%
Cluster identified: (totalSupply, balances)
```

### Phase 2: Invariant Inference

Determine the mathematical relationship between clustered variables.

**Method 1 — Delta Pattern Matching:**

```
mint():     Δtotal = +amount, Δbalance = +amount  → Same direction, same magnitude
burn():     Δtotal = -amount, Δbalance = -amount  → Same direction, same magnitude
transfer(): Δbalance1 = -x, Δbalance2 = +x       → Net zero change

Inference: totalSupply = Σ balances (Aggregation invariant)
```

**Method 2 — Delta Correlation:**

```
If ΔA = ΔB in all cases      → Direct proportional (A = B + constant)
If ΔA = -ΔB in all cases     → Inverse proportional (A + B = constant)
If ΔA × constant = ΔB        → Ratio relationship
If ΔA occurs whenever ΔB     → Synchronization invariant
```

**Method 3 — Expression Mining:**

Parse actual code operations:

```solidity
// Code: totalSupply += amount; balances[user] += amount;
// Extracted: Δtotal = Δbalance
// Inferred: total = Σ balances

// Code: available = total - locked;
// Extracted: available + locked = total
// Inferred: Conservation law
```

**Invariant Confidence:**

```
Confidence(I) = |functions preserving I| / |functions modifying variables in I|
```

| Confidence | Classification |
|-----------|---------------|
| ≥ 90% | STRONG invariant |
| 70-89% | MODERATE invariant |
| < 70% | WEAK/NO invariant |

### Phase 3: Invariant Violation Detection

Find functions that break established relationships.

**Algorithm:**

```
For each inferred invariant I(stateA, stateB):
  For each function F that modifies stateA or stateB:

    Before: Capture (stateA, stateB)
    Simulate: Execute F
    After: Capture (stateA', stateB')

    If I(stateA, stateB) = True AND I(stateA', stateB') = False:
      → F is VULNERABLE
```

**Vulnerability Set:**

```
V_I = {F ∈ Functions | ∃σ : I(σ) = True ∧ I(F(σ)) = False}
```

## Workflow

```
Task Progress:
- [ ] Step 1: Identify all state variables in the contract
- [ ] Step 2: Build co-modification matrix for all variable pairs
- [ ] Step 3: Cluster related variables (CoMod > 0.6)
- [ ] Step 4: Infer invariant type for each cluster (delta patterns)
- [ ] Step 5: Test each function against inferred invariants
- [ ] Step 6: Apply temporal filtering (only flag persistent violations)
- [ ] Step 7: Score severity and generate report
```

## Dual-Layer Integration

This skill is **Layer 2** of the Semantic State Protocol. For maximum coverage, combine with **Layer 1** (semantic-guard-analysis):

| Layer 1 Violation | Layer 2 Violation | Combined Severity |
|-------------------|-------------------|-------------------|
| Missing Guard | Breaks Invariant | **CRITICAL** |
| Missing Guard | No Invariant Break | **HIGH** |
| No Guard Issue | Breaks Invariant | **HIGH** |
| No Guard Issue | No Invariant Break | **LOW/INFO** |

## Output Format

```markdown
## State-State Invariant Violation Report

### Finding: [Title]

**Function:** `functionName()` at `Contract.sol:L42`
**Severity:** [CRITICAL | HIGH | MEDIUM]
**Invariant:** `[mathematical expression]`

**Before Execution:**
  stateA = [value], stateB = [value]
  Invariant: [expression] = True ✓

**After Execution:**
  stateA = [value'], stateB = [value']
  Invariant: [expression] = False ✗

**Root Cause:**
[Which state variable was modified without updating its counterpart]

**Impact:**
[Accounting errors, inflated supply, broken pricing, exploitable drift]

**Attack Scenario:**
1. [Step-by-step exploit leveraging the desynchronization]

**Recommendation:**
[Specific fix — add the missing state update]
```

## Quick Detection Checklist

When analyzing a contract, immediately check:

- [ ] Does every function that modifies `balances` also update `totalSupply` (or have a valid reason not to)?
- [ ] Does every function that moves between `available` and `locked` maintain `total = available + locked`?
- [ ] Does every swap/trade function maintain the constant product `k = reserveA * reserveB`?
- [ ] Do aggregate counters (`totalStaked`, `totalRewards`) stay synchronized with per-user mappings?
- [ ] Are monotonic variables (nonces, timestamps) ever decremented?

For detailed case studies, see [{baseDir}/references/case-studies.md]({baseDir}/references/case-studies.md).

## Rationalizations to Reject

- "The totalSupply is just for display" → Protocols use totalSupply for share pricing, voting power, market cap — drift is exploitable
- "Admin functions can bypass invariants" → Admin functions that break accounting create permanent protocol insolvency
- "The difference is small" → Small accounting errors compound over time and transactions
- "It's an emergency function" → Emergency functions that break state invariants create worse emergencies
- "Transfer doesn't need to update totalSupply" → Correct, but verify the NET change in sum(balances) is zero
