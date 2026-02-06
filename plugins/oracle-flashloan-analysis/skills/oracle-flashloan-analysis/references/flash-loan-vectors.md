# Flash Loan Attack Vectors — Detailed Reference

## Flash Loan Mechanics

Flash loans allow borrowing unlimited capital with zero collateral, provided the loan is repaid within the same transaction. This creates a new attack class: **atomicity exploitation**.

### Available Flash Loan Sources

| Source | Max Amount | Fee | Notes |
|--------|-----------|-----|-------|
| Aave V3 | Pool liquidity | 0.05-0.09% | Most popular, multi-asset |
| Balancer | Pool liquidity | 0% (flash swaps) | Free flash loans |
| dYdX | Pool liquidity | 0 (+ 2 wei) | Near-zero cost |
| Uniswap V2/V3 | Pool liquidity | 0.3% (flash swap) | Swap-based |
| Maker | DAI supply | 0% | DAI only |
| Euler | Pool liquidity | 0% | Multi-asset |

### Attack Template

```solidity
contract FlashLoanAttack {
    function execute() external {
        // Step 1: Borrow via flash loan
        aave.flashLoan(address(this), token, amount, "");
    }

    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        // Step 2: Manipulate (swap, donate, deposit)
        manipulatePrice();

        // Step 3: Exploit at manipulated price
        exploitProtocol();

        // Step 4: Reverse manipulation
        reverseManipulation();

        // Step 5: Repay flash loan + fee
        IERC20(asset).approve(address(aave), amount + premium);
        return true;
    }
}
```

---

## Attack Vector 1: Oracle Price Manipulation

### Pattern

```
1. Flash borrow large amount of Token A
2. Swap Token A → Token B in target pool
   → Token A price drops, Token B price rises
3. Exploit protocol that uses this pool for pricing
   → Borrow against inflated collateral, OR
   → Liquidate positions at artificial prices
4. Reverse swap (Token B → Token A)
5. Repay flash loan
```

### Real-World Example: Euler Finance ($197M, March 2023)

```
Attack flow:
1. Flash borrowed 30M DAI from Aave
2. Deposited into Euler, received eDAI
3. Used eDAI as collateral to borrow 10x leverage
4. Triggered self-liquidation at manipulated internal price
5. Donated to reserves to manipulate book values
6. Withdrew at inflated valuations
7. Repaid flash loan with profit

Root cause: Internal accounting used manipulable book values
```

### Real-World Example: Mango Markets ($114M, October 2022)

```
Attack flow:
1. Opened large perpetual position on MNGO-PERP
2. Used a second account to massively buy MNGO spot
3. MNGO spot price pumped → Mango's oracle reported inflated price
4. Unrealized PnL on perp position inflated
5. Used inflated account value as collateral to borrow all available assets
6. Let MNGO price crash back → account underwater but already drained

Root cause: Spot-price-based oracle used for collateral valuation
```

---

## Attack Vector 2: Governance Flash Loan Attack

### Pattern

```
1. Flash borrow governance tokens
2. Create proposal (or vote on existing)
3. Execute proposal in same transaction (if no timelock)
4. Proposal drains treasury or changes critical parameters
5. Return governance tokens
```

### Detection

```
For governance contracts:
  - Can proposal creation + voting + execution happen in one transaction?
  - Is there a timelock between proposal and execution?
  - Does voting weight snapshot BEFORE the vote transaction?
  - Can delegated votes be flash-borrowed?

If snapshot is at vote time (not block-1):
  → FLASH LOAN GOVERNANCE ATTACK possible
```

---

## Attack Vector 3: Vault Share Price Manipulation (ERC4626 Inflation)

### Pattern

```
1. Be the first (or early) depositor in a vault
2. Deposit minimal amount (1 wei) → receive 1 share
3. Donate large amount of underlying tokens directly to vault
4. Share price inflated: totalAssets = donated + 1 wei, totalShares = 1
5. Next depositor: deposit / inflated_share_price rounds to 0 shares
6. Attacker withdraws: gets their share + victim's deposit

With flash loans:
  - Flash borrow the donation amount
  - Donate → front-run victim deposit → withdraw → repay
  - All in one transaction
```

### Mitigation Detection

Check for:
- Virtual shares/assets offset (OpenZeppelin's approach)
- Minimum deposit amount enforcement
- Dead shares (first deposit goes to zero address)
- Internal asset tracking vs `balanceOf` for `totalAssets`

---

## Attack Vector 4: Liquidation Manipulation

### Pattern

```
1. Flash borrow collateral tokens of target user
2. Swap to crash collateral price in oracle pool
3. Target user's position now appears undercollateralized
4. Liquidate target at discount
5. Reverse price manipulation
6. Repay flash loan, keep liquidation bonus
```

### Detection

```
For lending/borrowing protocols:
  - Can collateral price be manipulated within one transaction?
  - Is there a liquidation delay or grace period?
  - Does the protocol use spot price or TWAP for liquidation triggers?
  - Is the liquidation bonus larger than manipulation cost?

If spot_price AND no_delay AND bonus > cost:
  → LIQUIDATION MANIPULATION viable
```

---

## Attack Vector 5: Circular Flash Loan (Amplification)

### Pattern

```
1. Flash borrow Token A
2. Deposit Token A into Protocol X → receive receipt token rA
3. Use rA as collateral in Protocol Y → borrow Token B
4. Swap Token B → Token A
5. Repeat (amplify position across protocols)
6. Eventually extract value from mispricing between protocols
7. Unwind and repay flash loan
```

### Detection

```
For protocols that accept other protocols' receipt tokens as collateral:
  → Map all cross-protocol deposit/borrow chains
  → Detect cycles: A → receipt → B → borrow → A
  → CIRCULAR FLASH LOAN possible if cycle exists
```

---

## Flash Loan Feasibility Assessment

For each potential flash loan attack, evaluate:

```
Profitability = Extracted_Value - (Flash_Fee + Gas + Slippage + Reversal_Loss)

Where:
  Flash_Fee: 0-0.09% of borrowed amount (often 0 via Balancer)
  Gas: ~500K-2M gas for complex attacks
  Slippage: Price impact of manipulation swaps
  Reversal_Loss: Cost of reversing manipulation (may not be exactly equal)

If Profitability > 0 → Attack is VIABLE
```

### Capital Requirements

```
Required capital ≈ Pool_Liquidity × Desired_Price_Impact

For a $10M liquidity pool and 50% price impact:
  Required capital ≈ $10M × 0.5 = $5M flash loan
  Available from: Aave ($Billions), Balancer (free), Uniswap
  → ALWAYS AVAILABLE for any pool that exists on-chain
```

---

## Combination Attack Patterns

| Primary Vector | Secondary Vector | Combined Effect |
|---------------|-----------------|-----------------|
| Oracle manipulation | Liquidation | Forced liquidation at artificial price |
| Oracle manipulation | Borrowing | Over-borrowing against inflated collateral |
| Share inflation | Front-running | Steal victim's deposit via rounding |
| Governance | Treasury drain | Flash-vote to extract protocol funds |
| Price crash | Short position | Profit from intentionally caused crash |
| Donation attack | Price inflation | Inflate balanceOf-based pricing |
