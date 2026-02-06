---
name: semantic-guard-analysis
description: Detects logic vulnerabilities in smart contracts by analyzing guard-state consistency patterns. Identifies functions that bypass security checks (require, modifiers) that other functions consistently apply. Uses the Consistency Principle — a contract is its own specification. Use when auditing smart contracts for missing access controls, inconsistent pause checks, logic bugs, forgotten modifiers, or when traditional tools report no issues but logic errors may exist.
---

# Semantic Guard Analysis

Detect logic vulnerabilities by finding functions that **violate the contract's own internal guard patterns**. Unlike pattern-matching tools, this approach uses the contract's consistent behavior as its specification.

## When to Use

- Auditing smart contracts where traditional tools find nothing suspicious
- Looking for missing `require` checks, forgotten modifiers, inconsistent access control
- Analyzing contracts with emergency/admin functions that might bypass safety mechanisms
- Detecting logic bugs that are syntactically correct but semantically dangerous
- When you suspect "forgotten check" vulnerabilities

## When NOT to Use

- Pure state-state invariant analysis (use state-invariant-detection)
- Full multi-dimensional audit (use behavioral-state-analysis)
- Code quality or gas optimization reviews

## Core Principle: The Consistency Hypothesis

> **"A smart contract is its own specification."**

Instead of checking against external rules, analyze what the contract **claims to enforce**, then find where it **breaks its own rules**.

> If a critical state variable (like user balances) is protected by a security check (like a pause mechanism) in 90% of functions, the 10% without that check are likely vulnerabilities.

## The Three-Phase Detection Architecture

### Phase 1: AST Extraction & State Mapping

Parse the Solidity code and build a **State Interaction Matrix**.

**For each state variable, track every function that touches it:**

```
State Variable: balance
├─ deposit()        → [WRITE] + Guards: [paused, initialized]
├─ withdraw()       → [WRITE] + Guards: [paused, initialized]
├─ transfer()       → [WRITE] + Guards: [paused]
└─ emergencyWithdraw() → [WRITE] + Guards: [] ⚠️
```

**For each function-variable interaction, record:**

| Attribute | Description |
|-----------|-------------|
| Write Access | Does the function modify this variable? |
| Guard Access | Does the function check this variable in `require()` or `if()`? |
| Read Access | Does the function only read this variable? |

**Extract guard sources:**
- Modifier chains (`onlyOwner`, `nonReentrant`, `whenNotPaused`)
- Explicit `require` statements
- Conditional branches gating state changes
- External calls affecting state
- Event emissions signaling state changes

### Phase 2: Dependency Graph Construction

Build a mathematical model of how variables protect each other.

**Guard Relationship:** If Variable A is checked before Variable B is modified:

```
A → B (A guards B)
```

**Example:**

```
paused ──────┐
             ├──→ balance
initialized ─┘

owner ───→ paused
owner ───→ totalSupply
```

**Frequency Weighting:** Each guard relationship gets a confidence score:

```
Confidence(guard → state) = |functions applying guard| / |functions modifying state|
```

- `paused` guards `balance` in 9/10 functions → 90% confidence
- `owner` guards `totalSupply` in 3/10 functions → 30% confidence (weak)

**Composite Dependencies:** Track multi-variable guards:

```
(owner AND timeLock) → criticalFunction
(paused OR emergency) → userAccess
```

### Phase 3: Anomaly Detection (The Solver)

Identify functions that violate established patterns.

**Algorithm:**

```
For each state variable S that can be modified:
  1. M = all functions that write to S
  2. G = common guards across those functions (above threshold)
  3. V = M \ G (functions that modify without guards)
  4. V is the vulnerability set
```

**Threshold-Based Inference:**

| Guard Frequency | Classification | Action |
|-----------------|---------------|--------|
| ≥ 80% | Strong Invariant | Flag violations as HIGH/CRITICAL |
| 50-79% | Weak Invariant | Flag violations as MEDIUM |
| < 50% | No Pattern | Ignore (too inconsistent) |

**Severity Classification:**

| Bypass Type | Severity |
|-------------|----------|
| Strong invariant on financial state (`balance`, `totalSupply`) | **Critical** |
| Strong invariant on access control (`owner`, admin roles) | **High** |
| Weak invariant on any state | **Medium** |
| Inconsistent pattern with no security implications | **Low/Info** |

**Context-Aware Filtering:**
- Constructor and `initialize()` functions may legitimately bypass patterns
- `view`/`pure` functions cannot modify state — skip
- Proxy pattern `delegatecall` requires special handling
- Emergency functions may intentionally bypass some guards

## Workflow

```
Task Progress:
- [ ] Step 1: Parse contract AST and build State Interaction Matrix
- [ ] Step 2: Identify all state variables and their modifying functions
- [ ] Step 3: Map guards (requires, modifiers) for each function-state pair
- [ ] Step 4: Build dependency graph with frequency weighting
- [ ] Step 5: Run anomaly detection (identify V = M \ G)
- [ ] Step 6: Apply privilege overlay (filter legitimate bypasses)
- [ ] Step 7: Score and report findings
```

## Privilege Overlay System

Not all "bypasses" are vulnerabilities. Apply role-based filtering:

**Role Classification:**

| Role Level | Scrutiny | Rationale |
|------------|----------|-----------|
| Public functions | Highest | Must follow all established patterns |
| Owner/Admin functions | Medium | May bypass operational guards, must be consistent with each other |
| Emergency functions | Lower | Designed for exceptional cases |
| Internal functions | Context-dependent | Analyze based on callers |

**Filtering Rule:**

```
For each function f in vulnerability set V:
  1. Identify function privileges (modifiers, access controls)
  2. Compare with other functions at the SAME privilege level
  3. Flag only if bypass is inconsistent WITHIN privilege tier
```

## Output Format

```markdown
## Guard-State Anomaly Report

### Finding: [Title]

**Function:** `functionName()` at `Contract.sol:L145`
**Severity:** [CRITICAL | HIGH | MEDIUM | LOW]
**Confidence:** [Percentage]

**Issue:** Modifies `[state variable]` without checking `[guard]`

**Pattern Evidence:**
- `function1()` checks `[guard]` before modifying `[state]` ✓
- `function2()` checks `[guard]` before modifying `[state]` ✓
- `functionName()` does NOT check `[guard]` before modifying `[state]` ✗

**Guard Frequency:** X out of Y functions (Z%)

**Security Impact:**
[Explanation of what an attacker can do by exploiting this inconsistency]

**Attack Scenario:**
1. [Step-by-step exploit]

**Recommendation:**
Add `require([guard], "[message]")` before modifying `[state]`,
or document why this function intentionally bypasses the check.
```

## Case Study: The "Forgotten Check"

```solidity
contract Vault {
    mapping(address => uint256) public balance;
    bool public paused;

    function deposit() public payable {
        require(!paused, "Contract paused");       // ✓ checks paused
        balance[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(!paused, "Contract paused");       // ✓ checks paused
        balance[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function adminWithdraw(address user) public onlyOwner {
        // ✗ Missing paused check!
        uint256 amount = balance[user];
        balance[user] = 0;
        payable(owner).transfer(amount);
    }
}
```

**Detection:**

```
M_balance = {deposit, withdraw, adminWithdraw}
G_paused = {deposit, withdraw}
V = {adminWithdraw}

Result: adminWithdraw() modifies balance without checking paused
Confidence: 66.7% (2/3 functions check paused)
Severity: HIGH (financial state + admin bypass of safety mechanism)
```

For more case studies, see [{baseDir}/references/case-studies.md]({baseDir}/references/case-studies.md).
For the full detection algorithm, see [{baseDir}/references/detection-algorithm.md]({baseDir}/references/detection-algorithm.md).

## Rationalizations to Reject

- "The admin is trusted, so skipping the check is fine" → Compromised admin + missing pause check = unstoppable drain
- "This function is only called internally" → Verify all callers; internal doesn't mean safe
- "The pattern only appears in 2 functions" → Even 2/3 consistency is a signal worth investigating
- "It's an emergency function" → Emergency functions should be MORE carefully guarded, not less
- "Traditional tools said it's fine" → Traditional tools check syntax, not semantic consistency
