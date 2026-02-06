# Gas Griefing Vectors — Detailed Reference

## The 63/64 Gas Rule (EIP-150)

### How It Works

When contract A calls contract B, only 63/64 of remaining gas is forwarded. The remaining 1/64 is reserved for A to complete execution after B returns.

```
A has 1,000,000 gas remaining before calling B:
  Gas forwarded to B: 1,000,000 * 63/64 = 984,375
  Gas reserved for A:  1,000,000 * 1/64  = 15,625
```

### Exploitation

An attacker (often a relayer) can provide just enough gas so that:
1. The outer function has enough gas to complete (post-call operations)
2. The inner call runs out of gas and fails
3. The outer function doesn't check the inner call's success
4. State is permanently changed based on the "failed" call

```solidity
// VULNERABLE: Meta-transaction relayer
function relay(address target, bytes calldata data, uint256 gasLimit) external {
    (bool success, ) = target.call{gas: gasLimit}(data);
    // If attacker provides exactly enough gas:
    //   - relay() succeeds (marks tx as processed)
    //   - target.call fails (out of gas)
    //   - Meta-tx is "used" but never executed

    nonces[sender]++; // Nonce consumed regardless of success!
    // Can never be replayed — permanently lost meta-tx
}
```

### Safe Pattern

```solidity
function relay(address target, bytes calldata data, uint256 gasLimit) external {
    // Ensure enough gas for the call + post-call overhead
    require(gasleft() >= gasLimit + 50000, "Insufficient gas");

    (bool success, bytes memory result) = target.call{gas: gasLimit}(data);
    require(success, string(result)); // MUST check success

    nonces[sender]++;
}
```

---

## Gas Estimation for External Calls

### Formula

```
Required gas for caller = call_gas * 64/63 + post_call_operations

Where:
  call_gas = gas needed by the target function
  64/63 multiplier = accounts for EIP-150 reservation
  post_call_operations = gas for operations after the call returns
```

### Example

```
Target needs: 100,000 gas
Post-call operations: 10,000 gas (state updates, events)

Required gas = 100,000 * 64/63 + 10,000
             = 101,587 + 10,000
             = 111,587 gas minimum
```

---

## selfdestruct Force-Feeding

### Mechanism

```solidity
contract ForceSender {
    constructor(address target) payable {
        // selfdestruct sends ALL balance to target
        // Target's receive/fallback is NOT called
        // Target CANNOT refuse the ETH
        selfdestruct(payable(target));
    }
}

// Attack:
new ForceSender{value: 1 ether}(victimAddress);
// Victim now has extra 1 ETH in their balance
```

### Post-EIP-6780 (Dencun Upgrade)

EIP-6780 limits `selfdestruct` to only destroy contracts in the same transaction they were created. However:
- ETH is STILL transferred to the target even if the contract isn't destroyed
- Force-feeding ETH remains possible
- The restriction only affects storage clearing

### Vulnerable Patterns

```solidity
// VULNERABLE: Strict equality check
require(address(this).balance == expectedBalance, "Balance mismatch");
// Force-fed ETH permanently breaks this

// VULNERABLE: Assumes balance only changes via deposit()
function getExcessETH() public view returns (uint256) {
    return address(this).balance - totalDeposits;
    // Force-fed ETH creates "phantom excess"
}

// VULNERABLE: Refund calculation based on balance
function refundAll() external {
    uint256 perUser = address(this).balance / userCount;
    // Force-fed ETH inflates refund amount
}
```

### Safe Patterns

```solidity
// SAFE: Use internal accounting, not balance
uint256 public totalDeposits;

function deposit() external payable {
    totalDeposits += msg.value;
}

function getTotalFunds() public view returns (uint256) {
    return totalDeposits; // Not address(this).balance
}
```

---

## Timestamp Manipulation Vectors

### block.timestamp Properties

```
- Can be slightly manipulated by block proposers (~12 seconds on Ethereum)
- Always increases (never goes backward)
- Post-Merge: exactly 12 seconds per slot
- NOT suitable for precise timing (use block numbers for that)
```

### Griefing via Timestamp Reset

```solidity
// VULNERABLE: 1-wei deposit resets lock timer
function deposit() external payable {
    require(msg.value > 0);
    balances[msg.sender] += msg.value;
    lastDepositTime[msg.sender] = block.timestamp;
}

function withdraw() external {
    require(block.timestamp > lastDepositTime[msg.sender] + 30 days, "Locked");
    // Attacker: deposits 1 wei every 29 days → victim can never withdraw
    // (only if deposit can be made for other users)
}
```

### Griefing via Timestamp Dependence

```solidity
// VULNERABLE: Auction end time can be blocked
function bid() external payable {
    require(block.timestamp < auctionEnd, "Ended");
    // Block proposers can slightly delay including this transaction
    // to push it past auctionEnd
}
```

---

## Block Gas Limit Analysis

### Current Limits

| Chain | Gas Limit | Notes |
|-------|-----------|-------|
| Ethereum | ~30M | Adjustable via governance |
| Polygon | ~30M | Similar to Ethereum |
| Arbitrum | Much higher | L2 has different gas model |
| Optimism | ~30M (L2 gas) | L1 data gas is separate |
| BSC | ~140M | Higher than Ethereum |

### Gas Cost Estimation for Loops

```
Per-iteration costs:
  SLOAD (cold): 2,100 gas
  SLOAD (warm): 100 gas
  SSTORE (new): 22,100 gas
  SSTORE (update): 5,000 gas
  External call (cold): 2,600 gas + execution
  External call (warm): 100 gas + execution
  ERC20 transfer: ~65,000 gas (cold) / ~30,000 gas (warm)

Example: Reward distribution loop
  Per iteration: 1 SLOAD + 1 ERC20 transfer = 2,100 + 65,000 = 67,100 gas (cold)
  Max iterations (30M): 30,000,000 / 67,100 ≈ 447 users

  After 447 users, distributeRewards() permanently fails!
```

---

## Economical Griefing Analysis

### Cost-Benefit for Attacker

```
Griefing ratio = (Victim's loss) / (Attacker's cost)

High ratio = Cheap to grief
  - Storage bloat: Create entries for pennies, cause permanent DoS
  - selfdestruct: Send 1 wei, break balance checks permanently
  - Timestamp reset: 1 wei deposit, reset lock for 30 days

Low ratio = Expensive to grief (less likely)
  - Block stuffing: Fill entire blocks, only delays by seconds/minutes
  - Gas price spiking: Temporary, costs attacker more than victim
```

### Detection Priority

```
Priority 1 (CRITICAL): Griefing ratio > 1000x
  - 1 wei attack causes permanent DoS
  - Minimal deposit blocks withdrawals forever
  - Force-fed ETH breaks invariant permanently

Priority 2 (HIGH): Griefing ratio > 100x
  - Small storage writes cause expensive iterations
  - Single contract deployment blocks batch operations
  - Minimal cost resets timing mechanisms

Priority 3 (MEDIUM): Griefing ratio > 10x
  - Moderate cost causes significant delays
  - Repeated small attacks compound over time
```
