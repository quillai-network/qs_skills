# Guard-State Detection Algorithm — Detailed Reference

## Formal Definition

### Universe of Functions

Let F = {f1, f2, ..., fn} be all functions in the contract.

### State Variable

Let s be a critical state variable (balance, owner, etc.).

### Modifying Functions

```
M_target = {f ∈ F | f writes to s}
```

### Guard Functions

```
G_required = {g1, g2, ..., gk}
```

Where each guard gi represents a security check (require statement, modifier, conditional).

## The Consistency Invariant

**For a logically consistent contract:**

```
∀f ∈ M_target : f applies all guards in G_required
```

**Formal notation:**

```
M_target ⊆ G_required
```

## Vulnerability Detection

**The Vulnerability Set:**

```
V = M_target \ G_required

Where:
- M_target = All functions modifying a critical variable
- G_required = Guards that should protect it (inferred from patterns)
- V = Vulnerability set (functions that bypass guards)
```

**Interpretation:**

- If V = ∅ (empty set): Contract is internally consistent
- If V ≠ ∅: Functions in V are potential vulnerabilities

## Confidence Score Formula

```
Confidence(g → s) = |{f ∈ M_s | f applies g}| / |M_s|

Where:
- M_s = functions that modify state s
- Confidence ranges from 0.0 to 1.0
```

## Vulnerability Severity Score

```
Severity(v) = Confidence(g → s) × Impact(s)

Where:
- v is a function in vulnerability set V
- Impact(s) is the criticality of state variable s (1-10 scale)
```

### Impact Scale for State Variables

| Variable Type | Impact Score | Examples |
|---------------|-------------|----------|
| Financial balances | 10 | `balance`, `deposits`, `stakes` |
| Supply controls | 9 | `totalSupply`, `mintable` |
| Access control | 8 | `owner`, `admin`, `roles` |
| Protocol parameters | 7 | `feeRate`, `interestRate` |
| Operational state | 6 | `paused`, `initialized` |
| Configuration | 4 | `maxLimit`, `threshold` |
| Metadata | 2 | `name`, `symbol`, `uri` |

## Handling Complex Scenarios

### Multi-Guard Dependencies

Real contracts often require multiple guards simultaneously:

```solidity
function criticalOperation() public {
    require(msg.sender == owner, "Not owner");        // Guard 1
    require(block.timestamp >= unlockTime, "Locked");  // Guard 2
    require(!paused, "Contract paused");               // Guard 3
    // Perform operation
}
```

**Composite Intersection:**

```
G_composite = G_owner ∩ G_time ∩ G_paused
```

A function is flagged only if it fails to satisfy ALL guards in the composite set.

### Guard Hierarchy Detection

```
Level 1: Critical Guards (must always apply)
  - paused
  - initialized

Level 2: Context Guards (apply in specific scenarios)
  - owner (for admin functions)
  - timelock (for financial operations)

Level 3: Situational Guards (optional)
  - cooldown periods
  - rate limits
```

### Dependency Chain Analysis

```
If function modifies: balance
Then check for guards in order:
  1. Is contract paused? (Critical)
  2. Is sender authorized? (Context)
  3. Has cooldown passed? (Situational)
```

## Cross-Contract Analysis Extension

```
Contract A calls Contract B.updateState()
  ↓
Analyze if guards in A should propagate to B
  ↓
Detect if B performs unguarded operations on behalf of A
```

**Use Cases:**
- Proxy pattern security
- Upgradeable contract consistency
- Multi-contract protocol analysis
- Library safety verification
