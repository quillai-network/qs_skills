# Reentrancy Variant Taxonomy — Detailed Reference

## Variant 1: Classic Single-Function Reentrancy

### Pattern

```
Function F:
  1. Read state S
  2. Check condition on S
  3. Make external call (INTERACTION)
  4. Update state S (EFFECT after INTERACTION — violation)
```

### Vulnerable Code Example

```solidity
function withdraw() public {
    uint256 bal = balances[msg.sender];
    require(bal > 0, "No balance");

    // INTERACTION — external call BEFORE state update
    (bool success, ) = msg.sender.call{value: bal}("");
    require(success);

    // EFFECT — too late, attacker already re-entered
    balances[msg.sender] = 0;
}
```

### Fixed Code

```solidity
function withdraw() public {
    uint256 bal = balances[msg.sender];
    require(bal > 0, "No balance");

    // EFFECT — update state FIRST
    balances[msg.sender] = 0;

    // INTERACTION — external call AFTER state update
    (bool success, ) = msg.sender.call{value: bal}("");
    require(success);
}
```

### Detection Heuristic

```
For function F:
  If ∃ external_call at position P AND ∃ state_write at position Q
  WHERE Q > P AND state_write.variable ∈ F.require_variables
  → CLASSIC REENTRANCY
```

---

## Variant 2: Cross-Function Reentrancy

### Pattern

```
Function F (makes external call):
  1. Read state S
  2. Make external call → attacker callback
  3. Update state S

Function G (re-entry target):
  1. Read SAME state S (still has pre-update value)
  2. Perform action based on stale S
```

### Vulnerable Code Example

```solidity
contract Vulnerable {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        // External call — attacker re-enters transfer()
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }

    function transfer(address to, uint256 amount) public {
        // During reentrancy, balances[msg.sender] is NOT yet decremented
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
```

### Attack Sequence

```
1. Attacker has 10 ETH balance
2. Calls withdraw(10 ETH)
3. Contract sends 10 ETH → triggers attacker's receive()
4. In receive(), attacker calls transfer(accomplice, 10 ETH)
   → balances[attacker] is still 10 (not yet decremented)
   → Transfer succeeds
5. withdraw() resumes: balances[attacker] -= 10
   → balances[attacker] = 0 (but accomplice already has 10)
6. Result: 10 ETH withdrawn + 10 ETH transferred = 20 ETH extracted from 10 ETH deposit
```

### Detection Heuristic

```
For function F with external_call at position P:
  S_pending = state variables written AFTER P in F
  For each OTHER public function G:
    If G reads or writes any variable in S_pending:
      → CROSS-FUNCTION REENTRANCY between F and G
```

### Key Insight

`nonReentrant` on `withdraw()` alone is NOT sufficient. The modifier must ALSO be on `transfer()` (or any function sharing state).

---

## Variant 3: Cross-Contract Reentrancy

### Pattern

```
Contract A:
  1. Updates partial state
  2. Makes external call to user/contract
  3. Updates remaining state

Contract B (depends on Contract A):
  1. Reads Contract A's state (partially updated)
  2. Makes decisions based on stale/inconsistent data
```

### Vulnerable Code Example

```solidity
// Lending Protocol
contract LendingPool {
    mapping(address => uint256) public collateral;

    function withdrawCollateral(uint256 amount) public {
        require(collateral[msg.sender] >= amount);
        collateral[msg.sender] -= amount;

        // External call — attacker callback here
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);

        // No more state to update — but damage is elsewhere
    }
}

// Separate borrowing contract that reads LendingPool state
contract BorrowingModule {
    LendingPool pool;

    function borrow(uint256 amount) public {
        // Reads collateral — but during reentrancy from withdrawCollateral,
        // collateral IS already decremented (CEI followed in LendingPool)
        // ... unless the architecture has other stale dependencies
        uint256 col = pool.collateral(msg.sender);
        require(col * LTV >= amount, "Undercollateralized");
        // Issue: What if there's a different state dependency?
    }
}
```

### Real Cross-Contract Pattern

The more dangerous pattern involves contracts that cache or snapshot state:

```solidity
contract VaultShares {
    function getSharePrice() public view returns (uint256) {
        return totalAssets / totalShares; // Read during callback = stale
    }

    function withdraw(uint256 shares) external {
        uint256 assets = shares * getSharePrice();
        _burn(msg.sender, shares);
        // totalShares updated, but totalAssets NOT yet
        asset.transfer(msg.sender, assets); // Callback opportunity
        totalAssets -= assets; // Updated AFTER transfer
    }
}

contract LendingMarket {
    VaultShares vault;

    function liquidate(address user) external {
        uint256 collateralValue = vault.balanceOf(user) * vault.getSharePrice();
        // During reentrancy: getSharePrice() returns inflated value
        // because totalAssets not yet decremented
    }
}
```

### Detection Heuristic

```
For each contract C in scope:
  For each external call in C at position P:
    S_stale = state variables not yet updated at P
    For each OTHER contract D that reads C's state:
      If D reads any variable in S_stale (directly or via view functions):
        → CROSS-CONTRACT REENTRANCY: D sees inconsistent state from C
```

---

## Variant 4: Read-Only Reentrancy

### Pattern

```
Contract A:
  1. Updates some state
  2. Makes external call → attacker callback
  3. Updates remaining state

Contract A's view function:
  - Returns value based on partially-updated state
  - This value is WRONG during the callback window

Contract B (victim):
  - Calls Contract A's view function during the callback
  - Makes financial decisions based on wrong value
```

### Key Insight

No state is modified during re-entry. The attack purely exploits **reading inconsistent state** from a view function. `nonReentrant` on the view function would break legitimate callers.

### Vulnerable Code Example (Curve/Vyper Style)

```solidity
contract StablePool {
    uint256 public totalReserves;
    uint256 public totalLPTokens;

    function removeLiquidity(uint256 lpAmount) external {
        uint256 ethAmount = lpAmount * totalReserves / totalLPTokens;

        // Effect: burn LP tokens
        totalLPTokens -= lpAmount;

        // Interaction: send ETH (callback opportunity)
        (bool success, ) = msg.sender.call{value: ethAmount}("");
        require(success);

        // Effect: update reserves AFTER call
        totalReserves -= ethAmount;
    }

    // This view function returns WRONG value during the callback
    function getVirtualPrice() public view returns (uint256) {
        return totalReserves / totalLPTokens;
        // During callback: totalLPTokens decreased, totalReserves NOT yet
        // → Virtual price is INFLATED
    }
}

// Victim protocol
contract LendingProtocol {
    StablePool pool;

    function getCollateralValue(address user) public view returns (uint256) {
        return userLPBalance[user] * pool.getVirtualPrice();
        // Returns inflated value during reentrancy window
    }

    function borrow(uint256 amount) external {
        require(getCollateralValue(msg.sender) >= amount * RATIO);
        // Attacker borrows against inflated collateral value
        token.transfer(msg.sender, amount);
    }
}
```

### Detection Heuristic

```
For each function F with external call at position P:
  S_post = state variables updated AFTER P
  For each view/pure function V in the same contract:
    If V reads any variable in S_post:
      → READ-ONLY REENTRANCY WINDOW: V returns stale value during F's callback
  Flag severity based on:
    - Does any external protocol depend on V?
    - Is V used for pricing, collateral valuation, or access control?
```

---

## Variant 5: Token Callback Reentrancy

### ERC-777 `tokensReceived` Hook

```solidity
// ERC-777 automatically calls tokensReceived() on the recipient
contract Vulnerable {
    function deposit(uint256 amount) public {
        // This triggers tokensReceived() on msg.sender if token is ERC-777
        token.transferFrom(msg.sender, address(this), amount);
        // State update AFTER the callback
        balances[msg.sender] += amount;
    }
}

// Attacker contract
contract Attacker is IERC777Recipient {
    function tokensReceived(...) external override {
        // Re-enter deposit() or any other function
        // balances[attacker] not yet updated
        vulnerable.withdraw(previousBalance);
    }
}
```

### ERC-1155 `onERC1155Received` Hook

```solidity
contract NFTMarket {
    function buyNFT(uint256 tokenId) public payable {
        // safeTransferFrom triggers onERC1155Received on recipient
        nft.safeTransferFrom(seller, msg.sender, tokenId, 1, "");
        // State update after callback
        listings[tokenId].active = false;
    }
}
```

### ERC-721 `onERC721Received` Hook

```solidity
contract NFTStaking {
    function stake(uint256 tokenId) public {
        // safeTransferFrom triggers onERC721Received
        nft.safeTransferFrom(msg.sender, address(this), tokenId);
        stakedBy[tokenId] = msg.sender;
        totalStaked += 1;
    }
}
```

### Detection Heuristic

```
For each token interaction:
  If function calls:
    - ERC777.send() or ERC777.transfer() → tokensReceived callback
    - ERC1155.safeTransferFrom() → onERC1155Received callback
    - ERC721.safeTransferFrom() → onERC721Received callback
    - ERC721.safeMint() → onERC721Received callback
  Check if state updates occur AFTER the token call
  → TOKEN CALLBACK REENTRANCY
```

---

## Guard Effectiveness Matrix

| Guard | Classic | Cross-Function | Cross-Contract | Read-Only | Callback |
|-------|---------|----------------|----------------|-----------|----------|
| `nonReentrant` on calling function | YES | NO (unless on ALL shared functions) | NO | NO | YES |
| `nonReentrant` on ALL public functions | YES | YES | NO | NO | YES |
| CEI pattern compliance | YES | YES | PARTIAL | NO | YES |
| Pull payment pattern | YES | YES | YES | NO | YES |
| `transfer()`/`send()` (2300 gas) | UNRELIABLE | UNRELIABLE | NO | NO | NO |
| OpenZeppelin ReentrancyGuard (global) | YES | YES | NO | NO | YES |

### Recommendation Priority

1. **Always follow CEI pattern** — prevents most variants
2. **Apply `nonReentrant` to all state-modifying functions** — catches cross-function
3. **Audit view functions for stale state during callbacks** — catches read-only
4. **Map cross-contract dependencies** — catches cross-contract
5. **Never rely on gas limits for safety** — EIP changes can break this assumption
