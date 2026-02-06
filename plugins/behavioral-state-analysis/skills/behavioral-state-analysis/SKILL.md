---
name: behavioral-state-analysis
description: Performs multi-dimensional smart contract security auditing using Behavioral State Analysis (BSA). Extracts behavioral intent, models state machines, runs parallel threat engines (economic, access control, state integrity), generates adversarial proofs, and scores findings with Bayesian confidence. Use when auditing smart contracts, performing security reviews, threat modeling DeFi protocols, or when asked to find vulnerabilities across economic, access control, and state integrity dimensions.
---

# Behavioral State Analysis (BSA)

Systematically audit smart contracts by understanding **behavioral intent first**, then exploring how it can be broken across multiple security dimensions simultaneously.

## When to Use

- Starting a comprehensive smart contract security audit
- Threat modeling DeFi protocols, staking systems, AMMs, vaults
- Analyzing cross-contract attack surfaces
- Generating adversarial exploit scenarios with proof-of-concepts
- Scoring and prioritizing vulnerability findings

## When NOT to Use

- Pure context building without vulnerability detection (use audit-context-building)
- Only identifying entry points (use entry-point-analyzer)
- Single-dimension analysis only (use semantic-guard-analysis or state-invariant-detection directly)

## Core Philosophy

Traditional auditing either pattern-matches (missing novel vulns), builds structural maps (missing behavioral anomalies), or analyzes sequentially (missing cross-function vectors).

BSA asks three questions **simultaneously**:

1. **What should happen?** (Specification extraction)
2. **What can happen?** (State space exploration)
3. **What shouldn't happen but can?** (Vulnerability detection)

## The 4-Phase Audit Pipeline

### Phase 1: Behavioral Decomposition

Extract the intended behavior model from code and documentation.

**Step 1 - Semantic Parsing:**
- Analyze function signatures, NatSpec comments, variable naming
- Extract business logic intent (e.g., "allows users to withdraw vested tokens")
- Create a Behavioral Specification Document per contract

**Step 2 - Invariant Extraction:**
- Mathematical invariants: `totalSupply == sum(balances)`
- Economic invariants: "User cannot withdraw more than deposited"
- Access control policies: "Only owner can pause"

**Step 3 - State Machine Construction:**
- Model every contract as a state machine
- States: Contract configurations (paused/active, initialized/uninitialized)
- Transitions: Functions that modify state
- Output: Formal state transition diagram

**Expected Output:**

```
Contract: StakingPool
States: [Uninitialized, Active, Paused, Emergency]
Invariants:
  - totalStaked >= sum(userStakes)
  - rewardRate > 0 when Active
  - Emergency can only be entered by Owner
```

### Phase 2: Multi-Dimensional Threat Modeling

Run three specialized analysis engines **in parallel**:

#### Economic Threat Engine (ETE)

Focus: Money flow, token economics, value extraction.

1. **Value Flow Tracing** - Trace every path where value can enter/leave; build a Value Flow Tree; identify value sinks and unexpected value sources
2. **Economic Invariant Verification** - Test `sum(deposits) == sum(withdrawals) + contractBalance`; check inflation/deflation; simulate price manipulation
3. **Incentive Analysis** - Model rational actor behavior; identify MEV opportunities; detect game-theoretic vulnerabilities (griefing)

#### Access Control Threat Engine (ACTE)

Focus: Permission boundaries, privilege escalation, role management.

1. **Role Hierarchy Mapping** - Identify all roles; map privilege relationships; detect unprotected privileged functions
2. **Permission Boundary Testing** - For each function: "Who can call this and when?"; test all combinations of `User A calling Function X in State Y`
3. **Privilege Escalation Simulation** - Find sequences: `User → [Actions] → Admin`; test `msg.sender` vs `tx.origin` confusion; check signature replay

#### State Integrity Threat Engine (SITE)

Focus: State consistency, atomicity, sequence vulnerabilities.

1. **State Transition Validation** - Verify atomic state updates; check for partial updates; identify race conditions
2. **Sequence Vulnerability Detection** - Test unexpected call ordering; check initialization bypass
3. **Cross-Contract State Sync** - Verify consistency when Contract A depends on Contract B; test stale data; identify timestamp manipulation

For detailed engine specifications, see [{baseDir}/references/threat-engines.md]({baseDir}/references/threat-engines.md).

### Phase 3: Adversarial Simulation & Proof Generation

For each hypothesis from Phase 2:

1. **Exploit Scenario Construction** - Build attack sequences; use symbolic execution to find satisfying conditions; generate transaction sequences `[tx1, tx2, tx3, ...]`
2. **Proof-of-Concept Generation** - Write Foundry/Hardhat test cases; include exact calldata and expected outcomes; measure impact
3. **Impact Quantification**:
   - **Critical**: Loss of all funds or complete system compromise
   - **High**: Significant loss or unauthorized access
   - **Medium**: Griefing, temporary DOS, minor leaks
   - **Low**: Informational or best practice violations

### Phase 4: Confidence Scoring & Prioritization

Score every finding using:

```
Confidence = (Evidence_Strength x Exploit_Feasibility x Impact_Severity) / False_Positive_Rate
```

| Factor | 1.0 | 0.7 | 0.4 | 0.1 |
|--------|-----|-----|-----|-----|
| Evidence | Concrete code path, no deps | Depends on specific state | Pattern-based theory | Heuristic only |
| Feasibility | PoC confirmed | Achievable specific state | Requires external conditions | Practically infeasible |

| Impact | Score | Description |
|--------|-------|-------------|
| Complete loss | 5 | All funds or system compromise |
| Partial loss | 4 | Partial fund loss or privilege escalation |
| Griefing | 3 | Temporary DOS |
| Info leak | 2 | Minor inconsistency |
| Best practice | 1 | No direct security impact |

For confidence scoring details, see [{baseDir}/references/confidence-scoring.md]({baseDir}/references/confidence-scoring.md).

## Workflow

```
Task Progress:
- [ ] Phase 1: Behavioral Decomposition (semantic parse → invariants → state machine)
- [ ] Phase 2a: Economic Threat Engine analysis
- [ ] Phase 2b: Access Control Threat Engine analysis
- [ ] Phase 2c: State Integrity Threat Engine analysis
- [ ] Phase 3: Adversarial Simulation & PoC generation
- [ ] Phase 4: Confidence scoring & prioritization
- [ ] Generate final report
```

## Report Structure

Each finding must include:

1. **Title**: Clear, descriptive name
2. **Severity**: Critical / High / Medium / Low
3. **Confidence Score**: Percentage from Phase 4 formula
4. **Affected Code**: Exact line numbers and function names
5. **Root Cause**: Technical explanation of why the bug exists
6. **Exploit Scenario**: Step-by-step attack sequence
7. **Proof-of-Concept**: Runnable Foundry/Hardhat test
8. **Impact Assessment**: Quantified risk (funds at risk, affected users)
9. **Remediation**: Specific code fix with before/after comparison
10. **References**: Similar vulnerabilities in other contracts

## Advanced Detection Mechanisms

### Cross-Contract Attack Surface

1. Map all external calls: `A → B → C`
2. Identify trust boundaries
3. Test transitive vulnerabilities (if B is vulnerable, can A be exploited through it?)
4. Test composition vulnerabilities (two "safe" contracts creating vulns together)

### Time-Based Vulnerabilities

1. Test `block.timestamp` manipulation
2. Check expired action execution
3. Test signature replay after expiration
4. Verify sequence-dependent function ordering

### Upgrade & Migration Safety

1. Detect storage collisions between implementation versions
2. Ensure `initialize()` can only be called once
3. Verify migration atomicity (old and new contracts cannot both be active)

## Rationalizations to Reject

- "This function looks standard" → Standard functions can have non-standard behavior in context
- "The admin is trusted" → Model admin compromise; check if admin powers are excessive
- "This is a known pattern" → Known patterns can have novel interactions in specific contexts
- "The value is small" → Small values compound; griefing attacks scale
- "External calls are to trusted contracts" → Trust boundaries shift; verify the actual code
