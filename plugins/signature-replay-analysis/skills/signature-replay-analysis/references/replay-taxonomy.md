# Signature Replay Taxonomy — Detailed Reference

## Type 1: Same-Chain Replay

### Definition
The identical signature is submitted to the same contract on the same chain multiple times.

### Prerequisites for Exploitation
- No nonce in signed message, OR
- Nonce not incremented after use, OR
- Nonce checked but not atomically consumed

### Detection Heuristic

```
For each signature verification function:
  1. Extract all fields included in the signed hash
  2. Check if a nonce is included
  3. If no nonce → SAME-CHAIN REPLAY (CRITICAL)
  4. If nonce exists:
     a. Is nonce incremented BEFORE or AFTER state change?
     b. Is nonce increment atomic with verification?
     c. Can the function be called again before nonce increment?
     If after or non-atomic → SAME-CHAIN REPLAY (HIGH)
```

### Example Vulnerability

```solidity
// Nonce checked but not consumed before external call
function executeMetaTx(uint256 nonce, bytes memory sig) external {
    require(nonce == nonces[signer], "Bad nonce");
    address signer = ECDSA.recover(hash, sig);

    // External call BEFORE nonce increment — reentrancy can replay!
    (bool success, ) = target.call(data);

    nonces[signer]++; // Too late if target re-enters
}
```

---

## Type 2: Cross-Chain Replay

### Definition
A signature valid on Chain A is replayed on Chain B where the same (or similar) contract exists.

### Prerequisites for Exploitation
- No `chainId` in signed message or domain separator
- Hardcoded `chainId` that doesn't update on fork
- Same contract deployed at same address on multiple chains

### Real-World Case: Post-Fork Replay (Ethereum / Ethereum Classic)

```
Before EIP-155:
  Transactions on Ethereum were valid on Ethereum Classic (and vice versa)
  Any signed transaction could be replayed on the other chain

EIP-155 added chainId to transaction signatures
But APPLICATION-LEVEL signatures (EIP-712) must ALSO include chainId
```

### Detection Heuristic

```
For each signature verification:
  1. Does the signed hash include block.chainid?
  2. Does the EIP-712 domain separator include chainId field?
  3. Is chainId hardcoded or dynamic?

  If no chainId → CROSS-CHAIN REPLAY (HIGH)
  If hardcoded chainId:
    Is domain separator recalculated when block.chainid changes?
    If not → FORK REPLAY (MEDIUM)
```

### Correct Implementation

```solidity
// Cache domain separator for gas efficiency, but recalculate on fork
bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;
uint256 private immutable _CACHED_CHAIN_ID;

function DOMAIN_SEPARATOR() public view returns (bytes32) {
    if (block.chainid == _CACHED_CHAIN_ID) {
        return _CACHED_DOMAIN_SEPARATOR;
    }
    return _buildDomainSeparator(); // Recalculate with new chainId
}
```

---

## Type 3: Cross-Contract Replay

### Definition
A signature intended for Contract A is replayed on Contract B (same chain) when both accept the same message format.

### Prerequisites for Exploitation
- No `verifyingContract` (address(this)) in signed message
- Multiple contracts with identical signature verification logic
- Same signer address used across contracts

### Detection Heuristic

```
For each signature verification:
  1. Does the signed hash include address(this)?
  2. Does the EIP-712 domain separator include verifyingContract?

  If neither → CROSS-CONTRACT REPLAY (HIGH)
```

### Example

```solidity
// Contract A: Token Bridge
function processWithdrawal(address to, uint256 amount, bytes memory sig) external {
    bytes32 hash = keccak256(abi.encodePacked(to, amount, nonces[to]++));
    require(ECDSA.recover(hash, sig) == bridge_admin);
    token.transfer(to, amount);
}

// Contract B: Different Token Bridge (same admin, same chain)
function processWithdrawal(address to, uint256 amount, bytes memory sig) external {
    bytes32 hash = keccak256(abi.encodePacked(to, amount, nonces[to]++));
    require(ECDSA.recover(hash, sig) == bridge_admin); // SAME admin!
    otherToken.transfer(to, amount);
}

// If nonces are synchronized, a signature for A can be replayed on B
```

---

## Type 4: Nonce-Skip Replay

### Definition
The nonce system allows gaps, enabling a "saved" nonce to be used at an arbitrary future time.

### Sequential vs Bitmap Nonces

```
Sequential: nonce must be exactly currentNonce + 1
  - Strict ordering: 0, 1, 2, 3, ...
  - A skipped nonce is LOST (can never be used)
  - Pro: Simple, prevents out-of-order execution
  - Con: One stuck transaction blocks all subsequent ones

Bitmap: Any unused nonce in the bitmap can be used
  - Flexible ordering: 5, 2, 8, 1, ...
  - Each nonce can be used independently
  - Pro: Out-of-order execution, no blocking
  - Con: Signed messages with unused nonces remain valid indefinitely
```

### Detection Heuristic

```
For bitmap nonce systems:
  1. Can a signed message with nonce N be held and executed later?
  2. Is there a deadline that limits the validity window?
  3. Can the signer cancel/invalidate a specific nonce?

  If no deadline AND no cancellation → NONCE-SKIP REPLAY (MEDIUM)
  Impact depends on whether delayed execution is harmful
```

---

## Type 5: Expired-Signature Replay

### Definition
A signature without a time limit is executed long after it was created, when the signer's intent has changed.

### Prerequisites for Exploitation
- No `deadline` or `expiry` field in signed message
- No time-based validation in verification function

### Example Scenario

```
1. User signs a permit() for 1000 USDC to DEX contract
2. User cancels the trade (off-chain)
3. Weeks later, token price has changed dramatically
4. Attacker submits the stored permit at unfavorable time
5. DEX uses the permit to execute a swap at bad price
```

### Detection Heuristic

```
For each signature verification:
  1. Is there a deadline/expiry parameter?
  2. Is deadline checked: require(block.timestamp <= deadline)?
  3. Is the deadline a reasonable duration (not type(uint256).max)?

  If no deadline → EXPIRED-SIGNATURE REPLAY (MEDIUM-HIGH)
  If deadline = type(uint256).max commonly used → EFFECTIVELY NO DEADLINE (MEDIUM)
```

---

## Complete Replay Protection Checklist

| Protection | Same-Chain | Cross-Chain | Cross-Contract | Nonce-Skip | Expired |
|------------|-----------|-------------|----------------|------------|---------|
| Sequential nonce | YES | NO | NO | YES | NO |
| Bitmap nonce | YES | NO | NO | NO | NO |
| chainId in domain | NO | YES | NO | NO | NO |
| address(this) in domain | NO | NO | YES | NO | NO |
| Deadline/expiry | NO | NO | NO | PARTIAL | YES |
| Full EIP-712 domain | NO | YES | YES | NO | NO |
| **All of the above** | **YES** | **YES** | **YES** | **YES** | **YES** |

**Minimum required for complete protection:**
1. Nonce (sequential or bitmap + deadline)
2. EIP-712 domain separator with chainId and verifyingContract
3. Deadline/expiry timestamp
