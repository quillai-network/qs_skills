---
name: reentrancy-pattern-analysis
description: Systematically detects all reentrancy vulnerability variants in smart contracts — classic, cross-function, cross-contract, and read-only reentrancy. Builds call graphs, verifies CEI (Checks-Effects-Interactions) pattern compliance, traces state changes relative to external calls, and identifies callback vectors through ERC-777/ERC-1155 hooks. Use when auditing contracts that make external calls, transfer ETH or tokens, interact with callback-enabled standards, or have complex multi-contract architectures.
---

# Reentrancy Pattern Analysis

Systematically detect **all variants** of reentrancy vulnerabilities by mapping the relationship between external calls and state changes across the entire contract system.

## When to Use

- Auditing any contract that makes external calls (ETH transfers, token interactions, cross-contract calls)
- Reviewing contracts integrating with callback-enabled token standards (ERC-777, ERC-1155)
- Analyzing DeFi protocols with multi-contract architectures
- Verifying reentrancy guard coverage across all entry points
- When traditional tools only check for classic reentrancy but miss cross-function or read-only variants

## When NOT to Use

- Pure state variable analysis without external calls (use state-invariant-detection)
- Access control consistency checking (use semantic-guard-analysis)
- Full multi-dimensional audit (use behavioral-state-analysis, which orchestrates this skill)

## Core Concept: The CEI Invariant

**Checks-Effects-Interactions (CEI)** is the fundamental safety pattern:

```
1. CHECKS   — Validate all conditions (require statements, access control)
2. EFFECTS  — Update all state variables
3. INTERACTIONS — Make external calls (ETH transfers, token calls, cross-contract)
```

**Any function that performs INTERACTIONS before completing all EFFECTS is potentially vulnerable to reentrancy.**

## The Five Reentrancy Variants

### Variant 1: Classic Single-Function Reentrancy

The original and most well-known pattern. A function makes an external call before updating its own state, allowing the callee to re-enter the same function.

```solidity
// VULNERABLE
function withdraw(uint256 amount) public {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}(""); // INTERACTION before EFFECT
    require(success);
    balances[msg.sender] -= amount; // State update AFTER external call
}
```

**Detection**: Find functions where state writes to variables used in `require` checks occur AFTER external calls.

### Variant 2: Cross-Function Reentrancy

Two or more functions share state, and an attacker re-enters through a DIFFERENT function than the one making the external call.

```solidity
function withdraw(uint256 amount) public {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount;
}

// Attacker re-enters HERE during withdraw's external call
function transfer(address to, uint256 amount) public {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    balances[to] += amount;
}
```

**Detection**: For each external call in function F, check if any OTHER public function reads/writes the same state variables that F modifies after the call.

### Variant 3: Cross-Contract Reentrancy

The re-entry occurs through a different contract that shares state or trust relationships with the vulnerable contract.

```solidity
// Contract A
function withdrawFromVault() public {
    uint256 shares = vault.balanceOf(msg.sender);
    vault.burn(msg.sender, shares);
    // External call — attacker can re-enter Contract B
    (bool success, ) = msg.sender.call{value: shares * pricePerShare}("");
    require(success);
}

// Contract B (attacker re-enters here)
function borrow() public {
    uint256 collateral = vault.balanceOf(msg.sender); // Reads stale state!
    // Shares not yet burned, so collateral appears inflated
    uint256 loanAmount = collateral * maxLTV;
    token.transfer(msg.sender, loanAmount);
}
```

**Detection**: Map all cross-contract dependencies. For each external call, identify which other contracts read the state that should have been updated.

### Variant 4: Read-Only Reentrancy

A view/pure function returns stale state during a reentrancy callback. No state is modified during re-entry — the attacker exploits the READING of inconsistent state by a third-party contract.

```solidity
// Pool contract
function removeLiquidity() external {
    uint256 shares = balances[msg.sender];
    // Burns LP tokens (updates internal accounting)
    _burn(msg.sender, shares);
    // External call BEFORE updating reserves
    (bool success, ) = msg.sender.call{value: ethAmount}("");
    // Reserves updated AFTER the call
    totalReserves -= ethAmount;
}

// This view function returns stale data during the callback
function getRate() public view returns (uint256) {
    return totalReserves / totalSupply(); // totalReserves not yet updated!
}

// Third-party contract reads the inflated rate
function priceOracle() external view returns (uint256) {
    return pool.getRate(); // Returns wrong value during reentrancy
}
```

**Detection**: For each external call, identify view functions that read state variables modified AFTER the call. Check if any external protocol depends on those view functions.

### Variant 5: ERC-777 / ERC-1155 Callback Reentrancy

Token standards with built-in callback hooks that execute arbitrary code on the receiver during transfers.

```solidity
// ERC-777: tokensReceived() hook called on recipient
// ERC-1155: onERC1155Received() hook called on recipient
// ERC-721: onERC721Received() hook called on recipient

function deposit(uint256 amount) public {
    token.transferFrom(msg.sender, address(this), amount); // Triggers callback!
    // If token is ERC-777, msg.sender's tokensReceived() runs HERE
    balances[msg.sender] += amount; // State update after callback
}
```

**Detection**: Identify all token `transfer`/`transferFrom`/`safeTransfer` calls. Check if the token could be ERC-777/ERC-1155/ERC-721. Verify state updates happen before the transfer.

## Three-Phase Detection Architecture

### Phase 1: Call Graph Construction

Build a complete map of all external interactions.

**For each function, extract:**

```
Function: withdraw()
├── External Calls:
│   ├── msg.sender.call{value: amount}("") at line 45
│   ├── token.transfer(user, amount) at line 48
│   └── oracle.getPrice() at line 42
├── State Writes:
│   ├── balances[msg.sender] -= amount at line 50
│   └── totalWithdrawn += amount at line 51
├── State Reads (in requires):
│   └── balances[msg.sender] at line 41
└── Modifiers:
    └── nonReentrant: NO
```

**Call Classification:**

| Call Type | Reentrancy Risk | Examples |
|-----------|----------------|---------|
| ETH transfer via `call` | HIGH | `addr.call{value: x}("")` |
| Token `transfer`/`transferFrom` | MEDIUM-HIGH | ERC-777 hooks, ERC-1155 callbacks |
| `safeTransferFrom` (NFT) | MEDIUM | ERC-721 `onERC721Received` callback |
| Cross-contract function call | MEDIUM | `otherContract.doSomething()` |
| `staticcall` / view calls | LOW | Cannot modify state but can trigger read-only reentrancy in callers |
| `delegatecall` | HIGH | Executes in caller's context |

### Phase 2: CEI Violation Detection

For each function with external calls, verify CEI ordering.

**Algorithm:**

```
For each function F with external calls:
  1. E = set of all state variables written by F
  2. C = set of all state variables read in require/if checks
  3. I = position of each external call in F
  4. For each external call at position P:
     a. W_after = state writes that occur AFTER position P
     b. If W_after ∩ (E ∪ C) ≠ ∅:
        → CEI VIOLATION: state modified after external call
     c. Classify violation:
        - W_after ∩ C ≠ ∅ → Classic reentrancy (check variable modified after call)
        - W_after ∩ E ≠ ∅ → State inconsistency window
```

**Cross-Function Extension:**

```
For each external call in function F at position P:
  W_before = state variables NOT yet updated at position P
  For each OTHER public function G:
    R_G = state variables read by G
    W_G = state variables written by G
    If R_G ∩ W_before ≠ ∅ OR W_G ∩ W_before ≠ ∅:
      → CROSS-FUNCTION REENTRANCY: G can be called during F's external call
         with inconsistent state
```

### Phase 3: Guard Coverage Verification

Check that reentrancy protections are correctly applied.

**Guard Types:**

| Guard | Coverage | Limitations |
|-------|----------|-------------|
| `nonReentrant` modifier (OpenZeppelin) | Single contract, all functions with modifier | Does not protect cross-contract reentrancy |
| CEI pattern compliance | Per-function | Must be verified for every function individually |
| `transfer()` / `send()` (2300 gas) | Limits callback gas | NOT safe — EIP-1884 changed gas costs; don't rely on this |
| Pull payment pattern | Eliminates external calls from state changes | Requires architectural change |

**Verification:**

```
For each function F with CEI violations:
  1. Check if F has nonReentrant modifier → Mitigated (single-contract only)
  2. Check if ALL functions sharing state also have nonReentrant → Mitigated (cross-function)
  3. Check if cross-contract consumers are protected → Requires manual review
  4. If no guard → VULNERABLE
```

## Workflow

```
Task Progress:
- [ ] Step 1: Identify all external calls in every function (ETH transfers, token calls, cross-contract)
- [ ] Step 2: Build call graph with state read/write positions relative to each call
- [ ] Step 3: Detect CEI violations (state writes after external calls)
- [ ] Step 4: Detect cross-function reentrancy (shared state across functions)
- [ ] Step 5: Detect callback vectors (ERC-777, ERC-1155, ERC-721 token interactions)
- [ ] Step 6: Detect read-only reentrancy (view functions reading stale state)
- [ ] Step 7: Verify guard coverage (nonReentrant, CEI compliance, pull patterns)
- [ ] Step 8: Score findings and generate report
```

## Output Format

```markdown
## Reentrancy Analysis Report

### Finding: [Title]

**Function:** `functionName()` at `Contract.sol:L42`
**Variant:** [Classic | Cross-Function | Cross-Contract | Read-Only | Callback]
**Severity:** [CRITICAL | HIGH | MEDIUM]
**Guard Status:** [Unguarded | Partially Guarded | Guarded]

**CEI Violation:**
  - External call at line [X]: `[call expression]`
  - State write AFTER call at line [Y]: `[state variable] = [expression]`

**Re-Entry Path:**
  1. Attacker calls `functionName()`
  2. External call triggers callback to attacker contract
  3. Attacker re-enters via `[re-entry function]`
  4. State variable `[name]` still has pre-update value
  5. [Exploit consequence]

**Impact:**
[Funds drained, state corrupted, price manipulated, etc.]

**Recommendation:**
[Specific fix — reorder state updates, add nonReentrant, use pull pattern]
```

## Severity Classification

| Variant | State Modified | Funds at Risk | Severity |
|---------|---------------|---------------|----------|
| Classic — ETH drain | Yes | Yes | **CRITICAL** |
| Cross-function — balance manipulation | Yes | Yes | **CRITICAL** |
| Cross-contract — oracle/price manipulation | Indirectly | Yes | **HIGH** |
| Read-only — stale price in third-party | No (view only) | Possibly | **HIGH** |
| Callback — ERC-777 deposit inflation | Yes | Possibly | **HIGH** |
| Any variant with nonReentrant on target | Mitigated | No | **LOW/INFO** |

## Advanced Detection: Transitive Reentrancy

Trace reentrancy through multiple contract hops:

```
Contract A calls Contract B
Contract B calls Contract C
Contract C calls back to Contract A (or reads A's stale state)

Detection: Build transitive call graph across all contracts in scope.
For each call chain A → B → ... → X:
  If X can call back to any contract in the chain → TRANSITIVE REENTRANCY
```

## Quick Detection Checklist

When analyzing a contract, immediately check:

- [ ] Does any function make an external call (ETH transfer, token transfer, cross-contract) BEFORE completing all state updates?
- [ ] Are there multiple public functions that modify the same state variables, where at least one makes an external call?
- [ ] Does the contract interact with ERC-777, ERC-1155, or ERC-721 tokens (callback hooks)?
- [ ] Do view functions read state that is only partially updated during an external call?
- [ ] Is `nonReentrant` applied to ALL functions that share state with a function making external calls, not just the calling function itself?
- [ ] Does the contract rely on `transfer()` or `send()` for reentrancy protection? (Unsafe assumption)

For detailed variant taxonomy, see [{baseDir}/references/reentrancy-variants.md]({baseDir}/references/reentrancy-variants.md).
For real-world case studies, see [{baseDir}/references/case-studies.md]({baseDir}/references/case-studies.md).

## Rationalizations to Reject

- "We use `transfer()` so reentrancy is impossible" → EIP-1884 changed gas costs; `transfer` is no longer considered safe
- "The function has `nonReentrant`" → Check cross-function and cross-contract paths; one modifier doesn't protect everything
- "It's just a view function" → Read-only reentrancy can manipulate prices and oracles in third-party contracts
- "We only interact with standard ERC20 tokens" → ERC-777 is backward-compatible with ERC20; token type may change
- "The external call is to a trusted contract" → Trust boundaries shift; verify the actual code path through all intermediaries
- "State is updated right after the call" → "Right after" is too late; the call already happened
