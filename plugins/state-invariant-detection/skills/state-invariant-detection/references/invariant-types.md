# State-State Invariant Types — Detailed Reference

## Type 1: Sum Relationships (Aggregation Invariants)

**Formula:**

```
s_total = Σᵢ sᵢ
```

**Pattern:** An aggregate variable equals the sum of all individual entries.

**Real-World Examples:**

| Protocol Type | Aggregate | Individual | Invariant |
|--------------|-----------|------------|-----------|
| ERC20 Token | `totalSupply` | `balances[user]` | `totalSupply = Σ balances` |
| Staking Pool | `totalStaked` | `userStake[user]` | `totalStaked = Σ userStakes` |
| Vault | `totalAssets` | `userDeposits[user]` | `totalAssets = Σ deposits` |
| Share System | `totalShares` | `shares[user]` | `totalShares = Σ shares` |
| Reward Pool | `totalRewards` | `userRewards[user]` | `totalRewards = Σ userRewards` |

**Valid Exception:** `transfer()` modifies individual balances without changing totalSupply — this is correct because the net change in sum(balances) is zero.

**Detection Signal:** If a function adds to a user's balance without incrementing the total (or vice versa), the invariant is broken.

---

## Type 2: Difference Relationships (Conservation Invariants)

**Formula:**

```
Σᵢ sᵢ = constant (within a transaction or epoch)
```

**Pattern:** Value is neither created nor destroyed, just moved between categories.

**Real-World Examples:**

| Protocol Type | Conservation Law |
|--------------|-----------------|
| Treasury | `totalFunds = available + locked` |
| Liquidity Pool | `totalLiquidity = active + reserved` |
| Vesting | `totalAllocated = vested + unvested` |
| Escrow | `totalDeposited = released + held` |
| Loan | `totalCollateral = free + pledged` |

**Detection Signal:** If a function increases one category without decreasing another (or without changing the total), conservation is violated.

---

## Type 3: Ratio Relationships (Proportional Invariants)

**Formula:**

```
s₁ / s₂ = k  (constant under specific operations)
```

Or product form:

```
s₁ × s₂ = k  (constant product)
```

**Real-World Examples:**

| Protocol Type | Ratio Invariant |
|--------------|----------------|
| AMM (Uniswap) | `k = reserveToken0 × reserveToken1` |
| Vault Shares | `sharePrice = totalAssets / totalShares` |
| Collateralized Debt | `collateralRatio = collateral / debt > 1.5` |
| Rebasing Token | `internalBalance = externalBalance × rebaseFactor` |

**Detection Signal:** If a function modifies one reserve without updating `k`, or changes assets without proportionally adjusting shares.

**Note:** The constant product `k` can legitimately change during `addLiquidity` and `removeLiquidity` — only swaps should preserve it.

---

## Type 4: Monotonic Relationships (Ordering Invariants)

**Formula:**

```
s_new ≥ s_old  for all state transitions (monotonically increasing)
s_new ≤ s_old  for all state transitions (monotonically decreasing)
```

**Real-World Examples:**

| Variable | Direction | Invariant |
|----------|-----------|-----------|
| `nonce` | Increasing | Never reused, always increments |
| `lastUpdateTime` | Increasing | Time only moves forward |
| `totalRewardsDistributed` | Increasing | Distributed rewards never decrease |
| `totalBurned` | Increasing | Cumulative burn count |
| `remainingAllocation` | Decreasing | Allocation depletes over time |

**Detection Signal:** If any function decrements a monotonically increasing variable, the invariant is broken.

---

## Type 5: Synchronization Relationships (Coupling Invariants)

**Formula:**

```
If Δs₁ ≠ 0, then Δs₂ must be f(Δs₁)
```

Where `f` is a deterministic function of the change.

**Real-World Examples:**

| Trigger Change | Required Corresponding Change |
|----------------|------------------------------|
| User balance increases | totalSupply increases by same amount |
| Collateral deposited | Borrowing power increases proportionally |
| Shares burned | Underlying assets released |
| Stake added | Reward rate recalculated |
| Liquidity added | LP tokens minted proportionally |
| Oracle price updated | Liquidation thresholds recalculated |

**Detection Signal:** If a function modifies the trigger variable without touching the coupled variable, the synchronization is broken.

---

## Invariant Inference Methods

### Method 1: Code Pattern Matching

Analyze how variables change together across functions:

```
mint():    totalSupply += x, balance += x    → Same direction, same magnitude
burn():    totalSupply -= x, balance -= x    → Same direction, same magnitude
transfer(): balance1 -= x, balance2 += x     → Zero-sum within balances
```

### Method 2: Delta Correlation

```python
For variables A and B that change together:
    deltas = []
    for each function F:
        delta_A = change_in(A)
        delta_B = change_in(B)
        if delta_B != 0:
            ratio = delta_A / delta_B
            deltas.append(ratio)

    if std_deviation(deltas) < threshold:
        coefficient = mean(deltas)
        invariant = f"A = {coefficient} × B"
```

### Method 3: Expression Mining

Parse code expressions to extract relationships:

```solidity
// Code: available = total - locked
// Extracted: available + locked = total
// Type: Conservation

// Code: shares = assets * PRECISION / sharePrice
// Extracted: shares * sharePrice = assets * PRECISION
// Type: Ratio
```

### Method 4: State Snapshot Analysis

```
Before function: [totalSupply = 1000, sum(balances) = 1000]
After function:  [totalSupply = 1100, sum(balances) = 1100]

Consistency: totalSupply == sum(balances) ✓

After 10+ functions:
  If holds 100%: STRONG invariant
  If holds 70-99%: MODERATE invariant
  If holds <70%: WEAK/NO invariant
```

---

## Cross-Function State Flow

Track state changes through internal call chains:

```
depositAssets() → mintShares() → [totalShares, userShares]

Transitive modifications:
- depositAssets directly modifies: totalAssets
- depositAssets indirectly modifies: totalShares, userShares

Invariant: If totalAssets changes, totalShares should also change
This holds even through indirect calls.
```

---

## Temporal Invariant Handling

Some invariants temporarily break during execution:

```solidity
function bid() public payable {
    highestBid = msg.value;          // Temporarily breaks invariant
    require(msg.value > highestBid); // Validates (reverts if broken)
    highestBidder = msg.sender;      // Restores invariant
}
```

**Rule:** Only flag violations that **persist at function exit** (successful completion). Reverts restore the invariant.
