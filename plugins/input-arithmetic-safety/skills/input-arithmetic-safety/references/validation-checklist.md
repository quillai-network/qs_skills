# Input Validation Checklist — By Parameter Type

## Address Parameters

| Check | Severity | Code Pattern |
|-------|----------|-------------|
| Non-zero address | HIGH | `require(addr != address(0), "Zero address")` |
| Not self-address | MEDIUM | `require(addr != address(this), "Self reference")` |
| Not msg.sender (for recipients) | LOW | `require(addr != msg.sender, "Self transfer")` |
| Contract vs EOA check | MEDIUM | `require(addr.code.length > 0, "Not a contract")` |
| Whitelisted address | HIGH | `require(whitelist[addr], "Not whitelisted")` |

### Critical Address Parameters

```
- Admin/owner setters: MUST check != address(0)
- Token addresses: MUST check != address(0), ideally verify it's a contract
- Fee recipients: MUST check != address(0) (fees sent to zero = burned)
- Oracle addresses: MUST check != address(0) and verify interface
- Proxy implementation: MUST check != address(0) and is a contract
```

---

## Amount / Value Parameters

| Check | Severity | Code Pattern |
|-------|----------|-------------|
| Non-zero | MEDIUM | `require(amount > 0, "Zero amount")` |
| Upper bound | HIGH | `require(amount <= maxAmount, "Exceeds maximum")` |
| Sufficient balance | HIGH | `require(balances[user] >= amount, "Insufficient")` |
| Minimum threshold | MEDIUM | `require(amount >= minAmount, "Below minimum")` |
| Fits in target type | HIGH | `require(amount <= type(uint128).max, "Overflow")` |

### Critical Amount Parameters

```
- Deposit/withdraw amounts: Non-zero + sufficient balance
- Fee rates: Upper bound (e.g., max 10%)
- Interest rates: Upper bound + reasonable range
- Slippage tolerance: Upper bound (e.g., max 50%)
- Loan amounts: Against collateral ratio
- Mint amounts: Against supply cap
```

---

## Array Parameters

| Check | Severity | Code Pattern |
|-------|----------|-------------|
| Non-empty | MEDIUM | `require(arr.length > 0, "Empty array")` |
| Maximum length | HIGH | `require(arr.length <= MAX_LEN, "Too many")` |
| Matching lengths | CRITICAL | `require(a.length == b.length, "Mismatch")` |
| No duplicates | MEDIUM | Application-specific dedup logic |
| Valid elements | HIGH | Loop validation of each element |

### Critical Array Parameters

```
- Batch transfer recipients + amounts: MUST match lengths
- Merkle proof: Max reasonable length
- Signature arrays (multisig): Max signers, no duplicates
- Token lists: Max length to prevent gas DoS
```

---

## Percentage / Rate Parameters

| Check | Severity | Code Pattern |
|-------|----------|-------------|
| Non-negative | HIGH | Inherent for uint; check for int types |
| Maximum value | CRITICAL | `require(rate <= MAX_RATE, "Rate too high")` |
| Minimum value | MEDIUM | `require(rate >= MIN_RATE, "Rate too low")` |
| Basis points range | HIGH | `require(bps <= 10000, "Invalid BPS")` |
| Sum of parts | HIGH | `require(feeA + feeB + feeC <= TOTAL, "Sum exceeds 100%")` |

### Common Ranges

```
- Fee BPS: 0-10000 (0-100%), typically max 1000 (10%)
- Interest rate: 0-10000 BPS, with per-block/per-second conversion
- Collateral ratio: > 10000 BPS (> 100%), typically 15000 (150%)
- Slippage: 0-5000 BPS (0-50%), typically max 500 (5%)
- Liquidation bonus: 0-5000 BPS, typically 500-1500 (5-15%)
```

---

## Timestamp / Deadline Parameters

| Check | Severity | Code Pattern |
|-------|----------|-------------|
| Not expired | HIGH | `require(deadline >= block.timestamp, "Expired")` |
| Not too far future | MEDIUM | `require(deadline <= block.timestamp + MAX_DELAY)` |
| Reasonable range | MEDIUM | Application-specific bounds |
| Not in the past | HIGH | `require(startTime > block.timestamp, "Past")` |
| Start before end | HIGH | `require(startTime < endTime, "Invalid range")` |

---

## String / Bytes Parameters

| Check | Severity | Code Pattern |
|-------|----------|-------------|
| Non-empty | LOW | `require(bytes(str).length > 0, "Empty")` |
| Maximum length | MEDIUM | `require(bytes(str).length <= MAX_LEN)` |
| Valid encoding | LOW | Application-specific |
| Bytes length | MEDIUM | `require(data.length >= MIN_LEN, "Too short")` |
| Selector check | HIGH | `require(bytes4(data) == expectedSelector)` |

---

## Enum / State Parameters

| Check | Severity | Code Pattern |
|-------|----------|-------------|
| Valid enum value | HIGH | Solidity auto-checks in 0.8+ |
| Valid state transition | HIGH | `require(validTransition[current][next])` |
| Not current state | LOW | `require(newState != currentState, "Same")` |

---

## Function-Level Validation Patterns

### Constructor / Initialize

```solidity
constructor(
    address _admin,          // MUST: != address(0)
    address _token,          // MUST: != address(0), is contract
    uint256 _maxSupply,      // MUST: > 0
    uint256 _feeRate         // MUST: <= MAX_FEE
) {
    require(_admin != address(0), "Zero admin");
    require(_token != address(0) && _token.code.length > 0, "Invalid token");
    require(_maxSupply > 0, "Zero supply");
    require(_feeRate <= MAX_FEE_BPS, "Fee too high");
}
```

### Setter Functions

```solidity
function setConfig(
    address _oracle,         // != address(0), is contract
    uint256 _collateralRatio,// >= MIN_RATIO (e.g., 110%)
    uint256 _liquidationBonus// <= MAX_BONUS (e.g., 15%)
) external onlyAdmin {
    require(_oracle != address(0), "Zero oracle");
    require(_collateralRatio >= MIN_COLLATERAL_RATIO, "Ratio too low");
    require(_liquidationBonus <= MAX_LIQUIDATION_BONUS, "Bonus too high");
}
```

### Financial Functions

```solidity
function deposit(uint256 amount, address receiver) external {
    require(amount > 0, "Zero deposit");
    require(receiver != address(0), "Zero receiver");
    require(amount >= minDeposit, "Below minimum");
    require(totalDeposits + amount <= depositCap, "Cap exceeded");
}
```

---

## Validation Priority Matrix

| Parameter Context | Critical Checks | Priority |
|-------------------|----------------|----------|
| Fund transfer recipient | Non-zero address | P0 (MUST) |
| Admin/owner setter | Non-zero address | P0 (MUST) |
| Fee/rate configuration | Upper bound | P0 (MUST) |
| Batch operation arrays | Length match + max size | P0 (MUST) |
| Deposit/withdraw amount | Non-zero + balance | P0 (MUST) |
| Deadline/expiry | Not expired | P1 (SHOULD) |
| Oracle/external address | Non-zero + is contract | P1 (SHOULD) |
| Minimum thresholds | Minimum amount | P2 (NICE) |
| String/metadata | Max length | P2 (NICE) |
