# EIP-712 Implementation Verification Checklist

## Domain Separator

### Required Fields

```solidity
bytes32 constant EIP712DOMAIN_TYPEHASH = keccak256(
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
);
```

| # | Check | Severity if Missing |
|---|-------|-------------------|
| 1 | `name` field present and meaningful | MEDIUM |
| 2 | `version` field present | MEDIUM |
| 3 | `chainId` field uses `block.chainid` | **HIGH** — cross-chain replay |
| 4 | `verifyingContract` uses `address(this)` | **HIGH** — cross-contract replay |
| 5 | Optional `salt` for additional disambiguation | LOW |

### Dynamic Chain ID Handling

```solidity
// CHECK: Is domain separator recalculated when chain ID changes (fork)?

// VULNERABLE: Computed once in constructor, never updated
constructor() {
    DOMAIN_SEPARATOR = keccak256(abi.encode(
        EIP712DOMAIN_TYPEHASH,
        keccak256(bytes(name)),
        keccak256(bytes(version)),
        block.chainid,           // Captured at deployment
        address(this)
    ));
}
// After a chain fork, DOMAIN_SEPARATOR is stale → cross-chain replay!

// SAFE: Recalculate when chainId changes
bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;
uint256 private immutable _CACHED_CHAIN_ID;

function DOMAIN_SEPARATOR() public view returns (bytes32) {
    return block.chainid == _CACHED_CHAIN_ID
        ? _CACHED_DOMAIN_SEPARATOR
        : _buildDomainSeparator();
}
```

| # | Check | Severity if Failing |
|---|-------|-------------------|
| 6 | Domain separator updates when `block.chainid` changes | **HIGH** |
| 7 | Cached for gas efficiency on normal path | LOW (gas) |

---

## Struct Type Hash

### Correct Pattern

```solidity
// Each signed struct needs its own type hash
bytes32 constant PERMIT_TYPEHASH = keccak256(
    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
);
```

| # | Check | Severity if Failing |
|---|-------|-------------------|
| 8 | Type hash string matches actual struct fields exactly | HIGH |
| 9 | Type hash includes ALL security-relevant fields (nonce, deadline) | **HIGH** |
| 10 | Type hash is a constant (not computed dynamically) | LOW |
| 11 | Nested structs use the correct encoding rules | MEDIUM |

---

## Hash Construction

### Correct Pattern

```solidity
bytes32 structHash = keccak256(abi.encode(
    PERMIT_TYPEHASH,
    owner,
    spender,
    value,
    nonces[owner],
    deadline
));

bytes32 digest = keccak256(abi.encodePacked(
    "\x19\x01",
    DOMAIN_SEPARATOR(),
    structHash
));
```

| # | Check | Severity if Failing |
|---|-------|-------------------|
| 12 | Uses `"\x19\x01"` prefix (EIP-191 version 1) | HIGH |
| 13 | Uses `abi.encode` (NOT `abi.encodePacked`) for struct hash | **HIGH** — collision risk |
| 14 | Domain separator comes BEFORE struct hash | HIGH |
| 15 | All fields in correct order matching type hash | HIGH |

### Common Mistake: abi.encodePacked vs abi.encode

```solidity
// VULNERABLE: abi.encodePacked can produce collisions for dynamic types
bytes32 hash = keccak256(abi.encodePacked(addr1, amount1, addr2, amount2));
// "addr1 = 0xAB, amount1 = 0xCD" produces same hash as
// "addr1 = 0xABCD, amount1 = 0x..." for certain values

// SAFE: abi.encode pads each value to 32 bytes
bytes32 hash = keccak256(abi.encode(addr1, amount1, addr2, amount2));
```

---

## Signature Recovery

| # | Check | Severity if Failing |
|---|-------|-------------------|
| 16 | Uses OpenZeppelin's ECDSA.recover (not raw ecrecover) | MEDIUM |
| 17 | Checks recovered address != address(0) | **CRITICAL** |
| 18 | Enforces lower-half s value (malleability protection) | MEDIUM |
| 19 | Validates v is 27 or 28 | LOW |
| 20 | Supports ERC-1271 for contract wallets (if needed) | MEDIUM |

### ERC-1271 Contract Wallet Support

```solidity
// For protocols that should support smart contract wallets (e.g., Gnosis Safe)
function isValidSignature(address signer, bytes32 hash, bytes memory signature) internal view returns (bool) {
    if (signer.code.length > 0) {
        // Contract wallet — use ERC-1271
        try IERC1271(signer).isValidSignature(hash, signature) returns (bytes4 magicValue) {
            return magicValue == IERC1271.isValidSignature.selector;
        } catch {
            return false;
        }
    } else {
        // EOA — use ECDSA
        return ECDSA.recover(hash, signature) == signer;
    }
}
```

---

## Nonce Management

| # | Check | Severity if Failing |
|---|-------|-------------------|
| 21 | Nonce included in signed message | **CRITICAL** — same-chain replay |
| 22 | Nonce incremented/consumed BEFORE any state change | HIGH |
| 23 | Nonce increment is atomic with verification | HIGH |
| 24 | Sequential nonces: checked against current value | MEDIUM |
| 25 | Bitmap nonces: deadline required to limit validity | MEDIUM |

---

## Deadline Enforcement

| # | Check | Severity if Failing |
|---|-------|-------------------|
| 26 | Deadline field exists in signed struct | HIGH |
| 27 | Checked: `require(block.timestamp <= deadline)` | **HIGH** |
| 28 | Deadline included in the signed hash (not just checked) | CRITICAL |
| 29 | Reasonable maximum deadline enforced | LOW |

---

## Permit-Specific Checks (ERC-2612)

| # | Check | Severity if Failing |
|---|-------|-------------------|
| 30 | `owner` parameter matches recovered signer | CRITICAL |
| 31 | `spender` is the intended approval target | N/A (design) |
| 32 | `value` is the approval amount | N/A (design) |
| 33 | Cannot permit to self (`owner != spender`) | LOW |
| 34 | Permit emits `Approval` event | LOW |
| 35 | `PERMIT_TYPEHASH` matches ERC-2612 specification | HIGH |

---

## Meta-Transaction Specific Checks

| # | Check | Severity if Failing |
|---|-------|-------------------|
| 36 | Relayer cannot profit by delaying execution | MEDIUM |
| 37 | Gas parameters included in signature (if relevant) | MEDIUM |
| 38 | Relayer cannot manipulate msg.value | HIGH |
| 39 | Target function cannot be called directly (bypass relay) | MEDIUM |
| 40 | Trusted forwarder address is validated | HIGH |

---

## Summary Scoring

| Score | Assessment |
|-------|-----------|
| 35-40 checks passing | Robust implementation |
| 25-34 checks passing | Acceptable with noted risks |
| 15-24 checks passing | Significant vulnerabilities likely |
| < 15 checks passing | **Critical — fundamental replay risks** |
