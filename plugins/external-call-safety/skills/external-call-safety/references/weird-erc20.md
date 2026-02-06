# Weird ERC20 Token Behaviors — Catalog

## Category 1: Missing Return Values

### Behavior
`transfer()`, `transferFrom()`, and `approve()` don't return a boolean, violating the ERC20 standard. Calling code that expects a return value will revert.

### Affected Tokens
- **USDT** (Tether) — the most widely used stablecoin
- **BNB** (Binance Coin)
- **OMG** (OmiseGO)
- **KNC** (Kyber Network, legacy version)

### Impact on Protocols

```solidity
// This REVERTS when called with USDT:
bool success = IERC20(usdt).transfer(recipient, amount);

// This works because SafeERC20 handles missing return:
using SafeERC20 for IERC20;
IERC20(usdt).safeTransfer(recipient, amount);
```

### Detection
Flag any direct `.transfer()`, `.transferFrom()`, or `.approve()` call that doesn't use SafeERC20 wrapper.

---

## Category 2: Fee-on-Transfer

### Behavior
A percentage of every transfer is deducted as a fee. The recipient receives less than the specified `amount`.

### Affected Tokens
- **STA** (Statera) — 1% deflationary fee
- **PAXG** (Pax Gold) — 0.02% transfer fee
- **USDT** — fee mechanism exists (currently set to 0, can be activated)
- **SAFEMOON** and all RFI forks — typically 5-10% fee
- **Reflect Finance (RFI)** — 1% redistributed to holders

### Impact on Protocols

```solidity
// Protocol credits 100 tokens but only receives 99
function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount); // Receives 99
    balances[msg.sender] += amount; // Credits 100!
    // Accounting error: protocol is 1 token short per deposit
    // Over many deposits, protocol becomes insolvent
}
```

### Detection
Check if deposit/stake functions compare `amount` parameter directly vs checking actual balance change.

---

## Category 3: Rebasing (Supply-Adjusting)

### Behavior
Token balances change for ALL holders without transfers. Can increase (positive rebase) or decrease (negative rebase).

### Affected Tokens
- **stETH** (Lido Staked ETH) — daily positive rebase from staking rewards
- **AMPL** (Ampleforth) — daily rebase targeting $1 price
- **OHM** (Olympus) — rebase from protocol emissions
- **YAM** — rebase mechanism
- **BASED** — rebase mechanism

### Impact on Protocols

```solidity
// User deposits 100 stETH
deposits[user] = 100 ether;

// Next day: stETH rebases +0.01%
// User's actual balance: 100.01 stETH
// Protocol records: still 100 stETH
// Difference accumulates forever

// WORSE: Negative rebase
// If AMPL rebases -10%, user has 90 AMPL
// But protocol still shows 100 — user can withdraw more than exists
```

### Detection
Check if the protocol stores absolute token amounts (vulnerable) or shares/ratios (safe).

---

## Category 4: Approval Race Condition

### Behavior
Standard `approve()` has a known race condition. Some tokens (USDT) additionally revert if you try to change a non-zero allowance to another non-zero value.

### Affected Tokens (revert on non-zero to non-zero)
- **USDT**
- **KNC** (legacy)

### Impact on Protocols

```solidity
// Step 1: Set allowance to 100
token.approve(spender, 100);

// Step 2: Try to change allowance to 200
token.approve(spender, 200); // REVERTS with USDT!

// Must do:
token.approve(spender, 0);   // Reset first
token.approve(spender, 200); // Then set new
```

### Detection
Flag any `approve()` call that doesn't first reset to zero, especially if the protocol supports USDT.

---

## Category 5: Tokens with Hooks/Callbacks

### Behavior
Token transfers trigger callback functions on sender and/or recipient, enabling reentrancy.

### Affected Standards
- **ERC-777** — `tokensToSend()` on sender, `tokensReceived()` on recipient
- **ERC-1155** — `onERC1155Received()` on recipient
- **ERC-721** — `onERC721Received()` on recipient (via `safeTransferFrom`)

### Impact
Any state change after a token transfer that triggers callbacks is vulnerable to reentrancy.

### Detection
Cross-reference with reentrancy-pattern-analysis skill.

---

## Category 6: Tokens with Blacklists/Pausable

### Behavior
Certain addresses can be blacklisted, causing all transfers to/from those addresses to revert. Token can also be globally paused.

### Affected Tokens
- **USDC** (Centre) — blacklist controlled by Centre consortium
- **USDT** (Tether) — blacklist and pausable
- **TUSD** (TrueUSD) — blacklist
- **BUSD** (Binance USD) — blacklist

### Impact on Protocols

```solidity
// If a user gets blacklisted after depositing:
function withdraw(uint256 amount) external {
    balances[msg.sender] -= amount;
    token.transfer(msg.sender, amount); // REVERTS — user is blacklisted
    // Funds permanently locked in protocol!
}

// Impact on batch operations:
function distributeRewards(address[] calldata users) external {
    for (uint i = 0; i < users.length; i++) {
        token.transfer(users[i], rewards[i]); // One blacklisted user blocks ALL
    }
}
```

### Detection
Check if the protocol has fallback mechanisms for failed transfers (try/catch, pull pattern).

---

## Category 7: Tokens with Transfer Limits

### Behavior
Maximum amount that can be transferred in a single transaction, or maximum balance an address can hold.

### Affected Tokens
- Many "anti-whale" tokens
- Various meme tokens with anti-dump mechanisms

### Impact
Protocols that batch transfers or accumulate large balances may silently hit limits.

---

## Category 8: Tokens with Multiple Entry Points

### Behavior
Some tokens have multiple addresses or proxy contracts that all reference the same underlying token.

### Affected Tokens
- Upgradeable token proxies
- Tokens with migration contracts

### Impact
Protocol may treat the same token as two different tokens, creating accounting errors.

---

## Category 9: Low-Decimal Tokens

### Behavior
Tokens with very few decimals (0-6) amplify rounding errors.

### Affected Tokens
- **USDC** — 6 decimals
- **USDT** — 6 decimals
- **WBTC** — 8 decimals
- **GUSD** — 2 decimals
- Some tokens — 0 decimals

### Impact
Precision loss in calculations is much worse with fewer decimals. A rounding error of 1 unit in GUSD (2 decimals) is $0.01 per operation.

---

## Category 10: High-Decimal Tokens

### Behavior
Tokens with more than 18 decimals can cause overflow in calculations that assume 18 decimals.

### Affected Tokens
- **YAM-V2** — 24 decimals

### Impact
`amount * price` may overflow uint256 when both have high decimals.

---

## Compatibility Matrix

| Token Behavior | SafeERC20 | Balance Before/After | Pull Pattern | Wrap Token |
|----------------|-----------|---------------------|-------------|-----------|
| Missing returns | FIXES | N/A | N/A | N/A |
| Fee-on-transfer | N/A | FIXES | N/A | FIXES |
| Rebasing | N/A | PARTIAL | N/A | FIXES (wstETH) |
| Approve race | PARTIAL (forceApprove) | N/A | N/A | N/A |
| Callbacks/hooks | N/A | N/A | N/A | Reentrancy guard needed |
| Blacklists | N/A | N/A | HELPS | N/A |
| Transfer limits | N/A | N/A | HELPS | N/A |
