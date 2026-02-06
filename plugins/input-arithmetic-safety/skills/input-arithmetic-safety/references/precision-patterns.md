# Precision Loss Patterns — Detailed Reference

## Pattern 1: Division-Before-Multiplication

### The Problem

Integer division in Solidity truncates (rounds toward zero). When division occurs before multiplication, the truncation error is amplified.

### Mathematical Proof

```
Let a = 1000, b = 3, c = 7

Division first:  (a / b) * c = (1000 / 3) * 7 = 333 * 7 = 2331
Multiply first:  (a * c) / b = (1000 * 7) / 3 = 7000 / 3 = 2333

Correct answer: 1000 * 7 / 3 = 2333.33...

Error (div first):  2333.33 - 2331 = 2.33 (0.1% loss)
Error (mul first):  2333.33 - 2333 = 0.33 (0.01% loss)
```

**The error from division-first is ~7x larger in this example.**

### Real-World Impact

```solidity
// Reward distribution in staking protocol
// 1M tokens distributed to 7 stakers

// VULNERABLE
uint256 rewardPerUser = totalRewards / numStakers;  // 1000000 / 7 = 142857
uint256 totalDistributed = rewardPerUser * numStakers; // 142857 * 7 = 999999
// LOST: 1 token per distribution round
// Over 365 days: 365 tokens lost

// SAFE
uint256 totalDistributed = totalRewards;
uint256 rewardPerUser = totalRewards / numStakers;
uint256 dust = totalRewards - (rewardPerUser * numStakers);
// Allocate dust to last user or accumulate for next round
```

### Detection Rule

```
For each expression containing both / and *:
  Parse operation order (respecting parentheses)
  If / appears before * in evaluation order:
    → PRECISION LOSS: division-before-multiplication
  Severity based on:
    - Financial context (fee, reward, price) → HIGH
    - Frequency of execution (per-block vs one-time) → Multiplier
    - Magnitude of typical values → Estimate actual loss
```

---

## Pattern 2: Phantom Overflow (Multiply-First Risk)

### The Problem

Multiplying first avoids precision loss but can cause overflow if intermediate values exceed `uint256.max`.

```solidity
// OVERFLOW RISK with multiply-first
uint256 result = (a * b) / c;
// If a = 2^200 and b = 2^100: a * b = 2^300 > 2^256 → OVERFLOW

// SAFE: Use mulDiv
uint256 result = FullMath.mulDiv(a, b, c); // Handles 512-bit intermediate
```

### When to Use mulDiv

```
If either operand could be > 2^128 (including prices with 18 decimals × amounts with 18 decimals):
  Use OpenZeppelin's Math.mulDiv() or Uniswap's FullMath.mulDiv()
  These compute (a × b) / c with 512-bit intermediate precision
```

---

## Pattern 3: Accumulated Rounding Error

### The Problem

Small rounding errors per operation compound over many operations.

```solidity
// Fee calculation per swap
uint256 fee = amount * FEE_RATE / FEE_DENOMINATOR;

// Example: amount = 100, FEE_RATE = 3, FEE_DENOMINATOR = 1000
// fee = 300 / 1000 = 0 (rounds to zero!)

// Over 1 million swaps of 100 tokens each:
// Expected fees: 1M * 100 * 0.3% = 300,000 tokens
// Actual fees: 0 (all rounded to zero)
```

### Mitigation

```solidity
// Option 1: Minimum fee
uint256 fee = amount * FEE_RATE / FEE_DENOMINATOR;
if (fee == 0 && amount > 0) fee = 1; // Minimum 1 wei fee

// Option 2: Accumulate fractional fees
uint256 accumulatedFee += amount * FEE_RATE; // Don't divide yet
if (accumulatedFee >= FEE_DENOMINATOR) {
    uint256 fee = accumulatedFee / FEE_DENOMINATOR;
    accumulatedFee %= FEE_DENOMINATOR;
}

// Option 3: Minimum transaction size
require(amount >= MIN_AMOUNT, "Below minimum");
```

---

## Pattern 4: Price/Share Calculation Precision

### Share Price Calculation

```solidity
// Standard share price: assets per share
uint256 sharePrice = totalAssets / totalShares;

// Problem: If totalAssets = 999 and totalShares = 1000
// sharePrice = 0 (shares appear worthless)

// SAFE: Use higher precision
uint256 sharePrice = totalAssets * PRECISION / totalShares;
// Where PRECISION = 1e18 or 1e27
```

### Deposit/Withdraw Precision

```solidity
// Deposit: How many shares for X assets?
uint256 shares = assets * totalShares / totalAssets;
// Rounds DOWN — user gets fewer shares (protocol-favorable ✓)

// Withdraw: How many assets for X shares?
uint256 assets = shares * totalAssets / totalShares;
// Rounds DOWN — user gets fewer assets (protocol-favorable ✓)

// DANGEROUS: Ceiling division on withdrawal
uint256 assets = (shares * totalAssets + totalShares - 1) / totalShares;
// Rounds UP — user gets more assets (user-favorable ✗)
// Repeated withdraw/deposit cycles drain the vault
```

---

## Pattern 5: Cross-Token Decimal Mismatch

### The Problem

Different tokens have different decimal places (USDC: 6, ETH: 18, WBTC: 8). Calculations mixing these without normalization produce wrong results.

```solidity
// VULNERABLE: Assumes both tokens have 18 decimals
uint256 value = tokenAmount * price / 1e18;

// If tokenAmount is USDC (6 decimals) and price is in 18 decimals:
// 1000000 (1 USDC) * 2000e18 / 1e18 = 2000000000 (way too much!)

// SAFE: Normalize by actual decimals
uint256 value = tokenAmount * price / (10 ** tokenDecimals);
```

### Detection

```
For each arithmetic operation involving token amounts:
  1. Identify the token(s) involved
  2. Check if decimal normalization is applied
  3. Verify the normalization factor matches the token's actual decimals
  4. Flag hardcoded 1e18 assumptions when token decimals could differ
```

---

## Pattern 6: Solidity-Specific Edge Cases

### Modulo Returns Zero for Power-of-Two Denominators

```solidity
// Note: This is correct behavior but can be surprising
uint256 result = 256 % 256; // = 0, not 256
```

### Negative Division Rounds Toward Zero

```solidity
int256 result = -7 / 2; // = -3 (not -4)
// This is "truncation toward zero", not "floor division"
```

### Type Coercion in Mixed Operations

```solidity
uint8 a = 255;
uint8 b = 1;
uint256 c = a + b; // In 0.8+: REVERTS (overflow in uint8 before casting)

// SAFE
uint256 c = uint256(a) + uint256(b); // Cast BEFORE arithmetic
```

---

## Precision Loss Severity Matrix

| Context | Loss per Operation | Frequency | Severity |
|---------|-------------------|-----------|----------|
| Share price calculation | ~1 wei | Per deposit/withdraw | HIGH (compounds) |
| Fee calculation | Up to full fee | Per transaction | CRITICAL if fee = 0 |
| Reward distribution | ~1 token | Per epoch | MEDIUM (dust) |
| Interest calculation | Variable | Per block/second | HIGH (compounds rapidly) |
| Exchange rate | ~1 wei | Per swap | MEDIUM |
| Voting power | ~1 wei | Per delegation | LOW |
