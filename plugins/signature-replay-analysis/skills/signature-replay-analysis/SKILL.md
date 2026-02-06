---
name: signature-replay-analysis
description: Detects signature replay vulnerabilities in smart contracts — affecting 19.63% of signature-using contracts. Covers five replay types (same-chain, cross-chain, cross-contract, nonce-skip, expired-signature), EIP-712 domain separator verification, nonce management analysis, ecrecover edge cases (address(0), malleability, s-value), permit/permit2 safety, ERC-1271 contract wallet support, and meta-transaction security. Use when auditing contracts with ecrecover, ECDSA, EIP-712, permit, meta-transactions, multi-sig, or any off-chain signature verification.
---

# Signature & Replay Analysis

Detect vulnerabilities where **cryptographic signatures can be reused**, replayed across chains/contracts, or exploited through implementation flaws. Research shows 19.63% of Ethereum contracts using signatures contain replay vulnerabilities.

## When to Use

- Auditing contracts that verify signatures (`ecrecover`, ECDSA, EIP-712)
- Reviewing ERC-20 `permit()` / Uniswap Permit2 implementations
- Analyzing meta-transaction / gasless relay systems
- Verifying multi-sig signature aggregation
- Checking off-chain order books or signed message execution

## When NOT to Use

- Contracts without any signature verification
- Pure on-chain access control (use semantic-guard-analysis)
- Token standard compliance (use external-call-safety)

## Core Concept: The Signature Trust Model

A signature proves that a specific private key holder authorized a specific action. For this to be secure, the signature must be:

1. **Bound to context** — specific chain, contract, and version (domain separation)
2. **Used exactly once** — nonce prevents replay
3. **Time-limited** — deadline/expiry prevents late execution
4. **Correctly verified** — ecrecover edge cases handled

Any gap in this model creates a replay vulnerability.

## The Five Replay Types

### Type 1: Same-Chain Replay

The exact same signature is submitted multiple times to the same contract on the same chain.

```solidity
// VULNERABLE: No nonce — same signature works forever
function executeWithSig(address to, uint256 amount, bytes memory signature) external {
    bytes32 hash = keccak256(abi.encodePacked(to, amount));
    address signer = ECDSA.recover(hash, signature);
    require(signer == admin, "Invalid signer");
    token.transfer(to, amount);
    // Attacker can submit this same signature again and again!
}

// SAFE: Use nonce
mapping(address => uint256) public nonces;

function executeWithSig(address to, uint256 amount, uint256 nonce, bytes memory signature) external {
    require(nonce == nonces[admin], "Invalid nonce");
    bytes32 hash = keccak256(abi.encodePacked(to, amount, nonce));
    address signer = ECDSA.recover(hash, signature);
    require(signer == admin, "Invalid signer");
    nonces[admin]++;
    token.transfer(to, amount);
}
```

### Type 2: Cross-Chain Replay

A signature valid on one chain (e.g., Ethereum) is replayed on another chain (e.g., Polygon, Arbitrum) where the same contract is deployed.

```solidity
// VULNERABLE: No chainId in signed message
bytes32 hash = keccak256(abi.encodePacked(to, amount, nonce));
// This hash is identical on Ethereum, Polygon, Arbitrum, etc.

// SAFE: Include chainId (via EIP-712 domain separator)
bytes32 DOMAIN_SEPARATOR = keccak256(abi.encode(
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
    keccak256(bytes("MyContract")),
    keccak256(bytes("1")),
    block.chainid,
    address(this)
));
```

### Type 3: Cross-Contract Replay

A signature for Contract A is replayed on Contract B (same chain) if both accept the same message format without contract-specific binding.

```solidity
// VULNERABLE: No contract address in signed message
bytes32 hash = keccak256(abi.encodePacked(to, amount, nonce, block.chainid));
// Same hash for any contract on this chain

// SAFE: Include verifyingContract (via EIP-712)
// The domain separator includes address(this), binding to this specific contract
```

### Type 4: Nonce-Skip Replay

Nonce implementation allows gaps or out-of-order execution, enabling skipped nonces to be replayed later.

```solidity
// VULNERABLE: Bitmap nonce without invalidation
mapping(uint256 => bool) public usedNonces;

function execute(uint256 nonce, ...) external {
    require(!usedNonces[nonce], "Used");
    usedNonces[nonce] = true;
    // If nonces 1, 2, 3 are used but 4 is skipped,
    // nonce 4 can be used anytime in the future
    // This may be intentional OR a vulnerability depending on context
}

// SAFER for strict ordering: Sequential nonce
mapping(address => uint256) public nonces;

function execute(uint256 nonce, ...) external {
    require(nonce == nonces[signer], "Invalid nonce");
    nonces[signer]++;
}
```

### Type 5: Expired-Signature Replay

A signature without a deadline can be held and executed at an arbitrary future time when conditions have changed.

```solidity
// VULNERABLE: No deadline — signature valid forever
function permit(address owner, address spender, uint256 value, uint8 v, bytes32 r, bytes32 s) external {
    bytes32 hash = keccak256(abi.encodePacked(owner, spender, value, nonces[owner]++));
    require(ecrecover(hash, v, r, s) == owner, "Invalid");
    allowance[owner][spender] = value;
    // This permit can be executed weeks later when user doesn't expect it
}

// SAFE: Include deadline
function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
    require(block.timestamp <= deadline, "Expired");
    // ... rest of verification
}
```

## ecrecover Safety

### Edge Case 1: Returns address(0)

`ecrecover` returns `address(0)` for invalid signatures instead of reverting.

```solidity
// VULNERABLE: address(0) accepted as valid signer
address signer = ecrecover(hash, v, r, s);
require(signer == owner, "Invalid");
// If owner == address(0) AND signature is invalid → passes!

// SAFE: Explicit zero check
address signer = ecrecover(hash, v, r, s);
require(signer != address(0), "Invalid signature");
require(signer == owner, "Wrong signer");

// SAFEST: Use OpenZeppelin's ECDSA.recover() — reverts on address(0)
address signer = ECDSA.recover(hash, signature);
```

### Edge Case 2: Signature Malleability

For every valid ECDSA signature (r, s, v), there exists a second valid signature (r, s', v') for the same message. This allows anyone to create an alternate valid signature without the private key.

```solidity
// The Ethereum standard: s must be in the lower half of the curve
// s' = secp256k1n - s (the "flipped" signature)

// VULNERABLE: Accepts both s values
address signer = ecrecover(hash, v, r, s); // Works for both s and s'
// If used as a unique identifier, the same message has TWO valid signatures

// SAFE: Enforce lower-s (OpenZeppelin's ECDSA library does this)
require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "Invalid s");
```

### Edge Case 3: v Value

```solidity
// v should be 27 or 28 (Ethereum standard)
// Some implementations use 0 or 1 (subtract 27)
// Not normalizing v can cause signature verification to fail

require(v == 27 || v == 28, "Invalid v");
```

## EIP-712 Domain Separator Verification

### Complete Domain

```solidity
bytes32 constant DOMAIN_TYPEHASH = keccak256(
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
);

bytes32 DOMAIN_SEPARATOR = keccak256(abi.encode(
    DOMAIN_TYPEHASH,
    keccak256(bytes(name)),        // Contract name
    keccak256(bytes(version)),     // Version string
    block.chainid,                 // Chain ID — prevents cross-chain replay
    address(this)                  // Contract address — prevents cross-contract replay
));
```

### Required Fields

| Field | Purpose | Missing = |
|-------|---------|-----------|
| `name` | Identifies the signing domain | MEDIUM risk |
| `version` | Prevents replay across upgrades | MEDIUM risk |
| `chainId` | **Prevents cross-chain replay** | HIGH risk |
| `verifyingContract` | **Prevents cross-contract replay** | HIGH risk |
| `salt` (optional) | Additional disambiguation | LOW risk |

### Common Mistakes

```solidity
// MISTAKE 1: Hardcoded chainId (doesn't update on chain forks)
uint256 immutable CHAIN_ID = 1;
// After a fork, signatures valid on both chains!

// SAFE: Use block.chainid at verification time, or recalculate domain separator
function DOMAIN_SEPARATOR() public view returns (bytes32) {
    if (block.chainid == INITIAL_CHAIN_ID) return _DOMAIN_SEPARATOR;
    return _calculateDomainSeparator(); // Recalculate for new chain
}

// MISTAKE 2: Empty name/version
keccak256(bytes("")) // Valid but weak — same across all contracts with empty name

// MISTAKE 3: Missing struct type hash in message
// EIP-712 requires: hashStruct(message) = keccak256(typeHash + encodeData(message))
// Omitting typeHash weakens the domain binding
```

## Permit and Permit2 Verification

### ERC-2612 Permit Checklist

```
- [ ] Uses EIP-712 domain separator with chainId and verifyingContract
- [ ] Includes per-user sequential nonce
- [ ] Includes deadline with block.timestamp check
- [ ] Uses ECDSA.recover (not raw ecrecover)
- [ ] Checks recovered address != address(0)
- [ ] Checks recovered address == owner parameter
- [ ] Nonce incremented BEFORE any state change
- [ ] Domain separator recalculated on chain fork
```

### Permit2 Considerations

```
- Permit2 uses nonce-bitmap approach (unordered nonces)
- Supports batch permits and transfer-with-permit
- Still requires deadline, domain separator, nonce management
- Contracts integrating Permit2 must verify the permit2 contract address
```

## Workflow

```
Task Progress:
- [ ] Step 1: Find all signature verification code (ecrecover, ECDSA.recover, EIP-712)
- [ ] Step 2: Check for same-chain replay protection (nonce management)
- [ ] Step 3: Check for cross-chain replay protection (chainId in domain/message)
- [ ] Step 4: Check for cross-contract replay protection (address(this) in domain/message)
- [ ] Step 5: Check deadline/expiry enforcement
- [ ] Step 6: Verify ecrecover safety (address(0) check, s-value, v-value)
- [ ] Step 7: Verify EIP-712 domain separator completeness
- [ ] Step 8: Check ERC-1271 support for contract wallets (if applicable)
- [ ] Step 9: Score findings and generate report
```

## Output Format

```markdown
## Signature & Replay Analysis Report

### Finding: [Title]

**Function:** `functionName()` at `Contract.sol:L42`
**Replay Type:** [Same-Chain | Cross-Chain | Cross-Contract | Nonce-Skip | Expired]
**Severity:** [CRITICAL | HIGH | MEDIUM]

**Issue:**
[Description of the replay vulnerability or signature verification flaw]

**Signed Message Fields:**
- [x] to/from addresses
- [x] amount/value
- [ ] chainId ← MISSING
- [ ] verifyingContract ← MISSING
- [x] nonce
- [ ] deadline ← MISSING

**Attack Scenario:**
1. User signs message for [intended purpose]
2. Attacker captures signature from [source]
3. Attacker replays on [target chain/contract/time]
4. [Unauthorized action occurs]

**Recommendation:**
[Add EIP-712 domain separator, add nonce, add deadline, use ECDSA.recover]
```

## Quick Detection Checklist

- [ ] Does every signature include a nonce? (Prevents same-chain replay)
- [ ] Does the signed message include `chainId`? (Prevents cross-chain replay)
- [ ] Does the signed message include `address(this)`? (Prevents cross-contract replay)
- [ ] Is there a deadline/expiry with `block.timestamp` check? (Prevents late execution)
- [ ] Is `ecrecover` result checked against `address(0)`?
- [ ] Is the s-value enforced to be in the lower half? (Prevents malleability)
- [ ] Is the domain separator recalculated on chain fork? (Prevents fork replay)
- [ ] Is OpenZeppelin's ECDSA library used instead of raw `ecrecover`?
- [ ] For permit: Is the nonce incremented before state changes?
- [ ] For contract wallets: Is ERC-1271 `isValidSignature` supported?

For replay type details, see [{baseDir}/references/replay-taxonomy.md]({baseDir}/references/replay-taxonomy.md).
For EIP-712 checklist, see [{baseDir}/references/eip712-checklist.md]({baseDir}/references/eip712-checklist.md).

## Rationalizations to Reject

- "We use nonces so replay is impossible" → Check for cross-chain and cross-contract replay (nonce doesn't prevent those)
- "No one would replay on another chain" → Attackers monitor all chains; automated bots scan for replayable signatures
- "ecrecover is a built-in, so it's safe" → It returns address(0) on failure, not revert; it doesn't enforce s-value
- "The signature includes all the parameters" → Without chainId and contract address, it's still replayable
- "We hardcoded chainId = 1" → Chain forks create two live chains with the same chainId; use block.chainid
- "Permit is a standard, so it's safe" → The standard defines the interface, not the implementation; bugs are in how it's coded
