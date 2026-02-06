# DoS Attack Patterns — Categorized Reference

## Category 1: Gas-Based DoS

### Pattern 1.1: Unbounded Loop Exhaustion

```solidity
// VULNERABLE
function processAll() external {
    for (uint i = 0; i < users.length; i++) {
        processUser(users[i]); // O(n) gas cost
    }
}
```

| Gas per iteration | Max iterations (30M limit) | Users until DoS |
|-------------------|---------------------------|-----------------|
| 3,000 gas | 10,000 | 10,000 |
| 10,000 gas | 3,000 | 3,000 |
| 50,000 gas | 600 | 600 |
| 100,000 gas (w/ transfer) | 300 | 300 |

**Mitigation:** Pagination, pull pattern, or fixed-size batches.

### Pattern 1.2: Quadratic Gas Cost (Nested Loops)

```solidity
// VULNERABLE: O(n^2) gas
function findDuplicates() external {
    for (uint i = 0; i < arr.length; i++) {
        for (uint j = i + 1; j < arr.length; j++) {
            if (arr[i] == arr[j]) revert("Duplicate");
        }
    }
}
// 100 elements = 10,000 iterations
// 1000 elements = 1,000,000 iterations → likely exceeds gas limit
```

**Mitigation:** Use mapping for O(1) lookup instead of nested loops.

### Pattern 1.3: String/Bytes Operations

```solidity
// VULNERABLE: String concatenation in loop
function buildList() external returns (string memory) {
    string memory result = "";
    for (uint i = 0; i < items.length; i++) {
        result = string(abi.encodePacked(result, items[i]));
        // Each concatenation copies the entire string — O(n^2) gas
    }
    return result;
}
```

---

## Category 2: External Call DoS

### Pattern 2.1: Revert Propagation

```solidity
// VULNERABLE: One revert blocks all
function payAll() external {
    for (uint i = 0; i < recipients.length; i++) {
        // If recipients[i] is a contract with a reverting receive():
        payable(recipients[i]).transfer(amounts[i]); // Reverts ALL
    }
}
```

**Malicious Receiver:**

```solidity
contract Blocker {
    receive() external payable {
        revert("I don't accept payments");
        // Now no one in the recipients array gets paid
    }
}
```

### Pattern 2.2: Gas Consumption Attack

```solidity
contract GasWaster {
    receive() external payable {
        // Consume all forwarded gas
        while (true) {}
    }
}
```

### Pattern 2.3: Return Data Bomb DoS

```solidity
contract DataBomber {
    fallback() external payable {
        assembly {
            return(0, 10000000) // Return 10MB of data
        }
    }
}
// Caller pays gas to copy this data
```

**Mitigation:** Use `(bool success, ) = addr.call{value: amount}("")` — the comma ignores return data.

---

## Category 3: State Manipulation DoS

### Pattern 3.1: Auction Griefing (Always Outbid)

```solidity
// VULNERABLE: Highest bidder refund can be blocked
function bid() external payable {
    require(msg.value > highestBid, "Too low");

    // Refund previous highest bidder
    payable(highestBidder).transfer(highestBid); // If this reverts → stuck

    highestBidder = msg.sender;
    highestBid = msg.value;
}
```

**Attack:** Previous bidder is a contract that reverts on receive. New bids can never be placed because refund always fails.

**Mitigation:**

```solidity
mapping(address => uint256) public pendingReturns;

function bid() external payable {
    require(msg.value > highestBid);
    pendingReturns[highestBidder] += highestBid; // Pull pattern
    highestBidder = msg.sender;
    highestBid = msg.value;
}

function withdraw() external {
    uint256 amount = pendingReturns[msg.sender];
    pendingReturns[msg.sender] = 0;
    payable(msg.sender).transfer(amount);
}
```

### Pattern 3.2: Queue/List Poisoning

```solidity
// VULNERABLE: Attacker fills withdrawal queue with tiny amounts
function requestWithdrawal(uint256 amount) external {
    withdrawalQueue.push(WithdrawalRequest(msg.sender, amount));
    // No minimum amount — attacker adds 10,000 requests of 1 wei
}

function processWithdrawals(uint256 count) external {
    for (uint i = 0; i < count; i++) {
        WithdrawalRequest storage req = withdrawalQueue[i];
        // Processing 10,000 1-wei requests consumes all gas
    }
}
```

### Pattern 3.3: Mapping Key Collision Griefing

```solidity
// VULNERABLE: Attacker can create entries in victim's mapping
function stake(address onBehalf) external payable {
    stakes[onBehalf] += msg.value; // Attacker stakes 1 wei for victim
    stakeHistory[onBehalf].push(block.timestamp);
    // Attacker bloats victim's stakeHistory array
}
```

---

## Category 4: Economic DoS

### Pattern 4.1: Front-Running Prevention DoS

```solidity
// VULNERABLE: Attacker front-runs to prevent legitimate transactions
function claimReward(uint256 expectedReward) external {
    require(calculateReward(msg.sender) == expectedReward, "Reward changed");
    // Attacker front-runs with a small action that changes reward
    // Legitimate user's transaction always reverts
}
```

### Pattern 4.2: Minimum Stake/Deposit Griefing

```solidity
// VULNERABLE: No minimum deposit allows 1-wei griefing
function deposit() external payable {
    require(msg.value > 0);
    balances[msg.sender] += msg.value;
    // Attacker makes millions of 1-wei deposits to bloat state
    // Each deposit costs gas but creates permanent storage entries
}
```

---

## Severity Classification

| Pattern | Reversible? | Cost to Attacker | Impact | Severity |
|---------|-------------|------------------|--------|----------|
| Unbounded loop → permanent DoS | NO | Zero (organic growth) | CRITICAL | **CRITICAL** |
| External call revert DoS | MAYBE | Low (deploy one contract) | HIGH | **HIGH** |
| Auction griefing | NO (unless pull pattern) | Bid amount | HIGH | **HIGH** |
| Gas griefing (63/64) | YES (retry possible) | Gas cost | MEDIUM | **MEDIUM** |
| Storage bloat | NO (permanent) | Gas for writes | HIGH | **HIGH** |
| Timestamp griefing | YES (wait it out) | Minimal | MEDIUM | **MEDIUM** |
| Force-fed ETH | NO (permanent) | selfdestruct ETH | HIGH | **HIGH** |
| Block stuffing | YES (temporary) | Block fees | MEDIUM | **MEDIUM** |
