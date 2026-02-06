# Reentrancy Case Studies

## Case Study 1: The DAO Hack (2016) — Classic Reentrancy

### Overview

- **Loss:** $60 million (3.6M ETH)
- **Variant:** Classic single-function reentrancy
- **Root Cause:** ETH sent before balance updated in `splitDAO()`

### Vulnerable Pattern

```solidity
function splitDAO(uint _proposalID, address _newCurator) {
    // ... checks ...

    uint fundsToBeMoved = (balances[msg.sender] * p.splitData[0].totalSupply) /
                           p.splitData[0].totalSupply;

    // INTERACTION before EFFECT
    if (!p.splitData[0].newDAO.createTokenProxy.value(fundsToBeMoved)(msg.sender)) {
        throw;
    }

    // EFFECT after INTERACTION — too late
    balances[msg.sender] = 0;
}
```

### Attack Sequence

```
1. Attacker creates a proposal to split DAO
2. Calls splitDAO() → sends ETH to attacker contract
3. Attacker's fallback() re-enters splitDAO()
4. balances[attacker] still > 0 (not yet zeroed)
5. Repeats until contract drained
6. Stack unwinds, balances[attacker] = 0 (only once)
```

### Detection

```
State variable: balances[msg.sender]
External call: createTokenProxy.value(fundsToBeMoved)(msg.sender)
State write: balances[msg.sender] = 0

Call position: BEFORE state write
→ CLASSIC REENTRANCY DETECTED
```

### Lesson

This hack led to the Ethereum/Ethereum Classic fork and the creation of the CEI pattern as a fundamental security principle.

---

## Case Study 2: Curve Pool Read-Only Reentrancy (2023)

### Overview

- **Loss:** ~$70 million across multiple protocols
- **Variant:** Read-only reentrancy
- **Root Cause:** Vyper compiler bug in reentrancy locks + stale `get_virtual_price()` during callback

### Vulnerable Pattern

```python
# Vyper (Curve pool)
@external
def remove_liquidity(amount: uint256):
    # Burns LP tokens (updates totalSupply)
    self._burn(msg.sender, amount)

    # Sends ETH — callback opportunity
    raw_call(msg.sender, b"", value=eth_amount)

    # Updates reserves AFTER the call
    self.balances[0] -= eth_amount

@view
@external
def get_virtual_price() -> uint256:
    # During callback: totalSupply decreased, balances NOT yet
    # Returns INFLATED price
    return self._get_virtual_price()
```

### Attack Sequence

```
1. Attacker calls remove_liquidity() on Curve pool
2. LP tokens burned (totalSupply decreases)
3. ETH sent to attacker → triggers fallback
4. In fallback, attacker calls a lending protocol
5. Lending protocol calls pool.get_virtual_price() for collateral pricing
6. get_virtual_price() returns inflated value (reserves not yet decreased)
7. Attacker borrows against inflated collateral
8. remove_liquidity() completes, reserves decrease
9. Attacker's collateral now worth less than borrowed amount
```

### Detection

```
Function: remove_liquidity()
State update after external call: self.balances[0] -= eth_amount
View function reading stale state: get_virtual_price() reads self.balances

→ READ-ONLY REENTRANCY WINDOW in get_virtual_price()
→ Any protocol using get_virtual_price() for pricing is vulnerable
```

### Lesson

Read-only reentrancy is invisible to traditional tools that only check for state modifications during re-entry. The vulnerability exists in the VIEW function, not the state-modifying function.

---

## Case Study 3: Fei Protocol / Rari Capital (2022)

### Overview

- **Loss:** $80 million
- **Variant:** Classic reentrancy in a Compound fork
- **Root Cause:** Missing reentrancy protection on borrow function with CEI violation

### Vulnerable Pattern

```solidity
// Compound-style cToken
function borrow(uint256 amount) external {
    // Check
    require(getAccountLiquidity(msg.sender) >= amount);

    // Interaction BEFORE Effect
    underlying.transfer(msg.sender, amount); // External call

    // Effect AFTER Interaction
    accountBorrows[msg.sender] += amount;
    totalBorrows += amount;
}
```

### Attack Sequence

```
1. Attacker deposits collateral
2. Calls borrow() on vulnerable cToken
3. Token transfer triggers attacker's callback
4. accountBorrows not yet updated — liquidity check passes again
5. Attacker calls borrow() again (and again)
6. Each call passes liquidity check because borrows not recorded
7. Drains pool far beyond collateral value
```

### Detection

```
Function: borrow()
External call: underlying.transfer(msg.sender, amount) at position P
State writes after P:
  - accountBorrows[msg.sender] += amount
  - totalBorrows += amount

Both state writes are read in getAccountLiquidity() require check
→ CLASSIC REENTRANCY: check variable updated after external call
```

---

## Case Study 4: Cream Finance via ERC-777 (2021)

### Overview

- **Loss:** $18.8 million
- **Variant:** ERC-777 callback reentrancy
- **Root Cause:** AMP token (ERC-777 compatible) triggered `tokensReceived` hook during supply

### Vulnerable Pattern

```solidity
function borrow(uint256 amount) external {
    require(getAccountLiquidity(msg.sender) > 0);

    // AMP token is ERC-777 — triggers tokensReceived on recipient
    ampToken.transfer(msg.sender, amount);

    // State update after ERC-777 callback
    accountBorrows[msg.sender] += amount;
}
```

### Attack Sequence

```
1. Attacker deposits ETH as collateral
2. Calls borrow() for AMP tokens
3. AMP.transfer() triggers tokensReceived() on attacker
4. In tokensReceived(), attacker calls borrow() AGAIN
5. accountBorrows not yet updated — liquidity still shows positive
6. Second borrow also succeeds
7. Repeat until pool drained
```

### Detection

```
Token interaction: ampToken.transfer(msg.sender, amount)
Token type: ERC-777 (has tokensReceived hook)
State write after transfer: accountBorrows[msg.sender] += amount

→ ERC-777 CALLBACK REENTRANCY
→ Severity: CRITICAL (funds at risk)
```

### Lesson

Any protocol that integrates with ERC-777 tokens must treat `transfer()` as an external call with callback potential. ERC-777 is backward-compatible with ERC-20, so a token that appears to be ERC-20 may actually have callback hooks.

---

## Case Study 5: Lendf.Me / imBTC (2020)

### Overview

- **Loss:** $25 million
- **Variant:** ERC-777 callback reentrancy on `supply()`
- **Root Cause:** imBTC (ERC-777) used in Compound fork without reentrancy protection

### Attack Flow

```
1. Attacker supplies imBTC (ERC-777 token) as collateral
2. transferFrom() triggers tokensToSend() hook on sender
3. In callback, attacker withdraws their supply
4. Original supply() continues, crediting attacker again
5. Result: Double-counted collateral → borrow against phantom collateral
```

### Detection Pattern

```
Token: imBTC (ERC-777)
Function: supply() calls token.transferFrom()
ERC-777 hook: tokensToSend() on sender during transferFrom()
State write after transferFrom(): accountSupply[user] += amount

→ CALLBACK REENTRANCY via ERC-777 tokensToSend hook
```

---

## Summary: Detection Patterns Across Cases

| Case | Year | Loss | Variant | Key Signal |
|------|------|------|---------|------------|
| The DAO | 2016 | $60M | Classic | Balance zeroed after ETH send |
| Lendf.Me | 2020 | $25M | ERC-777 callback | transferFrom before supply accounting |
| Cream Finance | 2021 | $18.8M | ERC-777 callback | ERC-777 transfer before borrow accounting |
| Fei/Rari | 2022 | $80M | Classic | Token transfer before borrow accounting |
| Curve pools | 2023 | $70M | Read-only | View function returns stale reserves |

**Common pattern across ALL cases:** State update occurs AFTER an external call that can trigger attacker-controlled code.
