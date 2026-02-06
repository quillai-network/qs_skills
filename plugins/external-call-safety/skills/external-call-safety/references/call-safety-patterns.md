# External Call Safety Patterns — Reference

## Low-Level Call Types

### `call` — General Purpose External Call

```solidity
// Pattern: (bool success, bytes memory data) = target.call{value: v, gas: g}(payload)

// UNSAFE: Return not checked
target.call{value: amount}("");

// UNSAFE: Success checked but data ignored when it matters
(bool success, ) = target.call{value: amount}("");
require(success); // OK for ETH transfer

// SAFE: Full check
(bool success, bytes memory data) = target.call(
    abi.encodeWithSelector(IERC20.transfer.selector, recipient, amount)
);
require(success && (data.length == 0 || abi.decode(data, (bool))), "Transfer failed");

// SAFEST: Use high-level call or SafeERC20
token.safeTransfer(recipient, amount);
```

### `delegatecall` — Execute in Caller's Context

```solidity
// CRITICAL: delegatecall runs target's code with OUR storage, msg.sender, msg.value
// Should ONLY be used with immutable, trusted contracts

// DANGEROUS: User-supplied target
function execute(address target, bytes calldata data) external {
    target.delegatecall(data); // Attacker can overwrite ANY storage slot
}

// SAFE: Only to known, immutable implementation
function _delegate(address implementation) internal {
    assembly {
        calldatacopy(0, 0, calldatasize())
        let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
        returndatacopy(0, 0, returndatasize())
        switch result
        case 0 { revert(0, returndatasize()) }
        default { return(0, returndatasize()) }
    }
}
```

### `staticcall` — Read-Only External Call

```solidity
// staticcall prevents state modification in the called contract
// SAFE for reading data, but:
// - Can still consume gas (DoS vector)
// - Return data can be arbitrarily large (return data bomb)
// - Reverts in called contract bubble up

(bool success, bytes memory data) = target.staticcall(
    abi.encodeWithSelector(IERC20.balanceOf.selector, address(this))
);
```

---

## ETH Transfer Patterns

### Pattern Comparison

| Method | Gas Forwarded | On Failure | Safety |
|--------|-------------|------------|--------|
| `transfer()` | 2300 (fixed) | Reverts | UNSAFE (gas limit) |
| `send()` | 2300 (fixed) | Returns false | UNSAFE (gas limit + often unchecked) |
| `call{value: x}("")` | All remaining | Returns false | SAFE (if checked) |

### Recommended Pattern

```solidity
// For sending ETH to a single recipient
function sendETH(address payable recipient, uint256 amount) internal {
    (bool success, ) = recipient.call{value: amount}("");
    require(success, "ETH transfer failed");
}

// For sending ETH to multiple recipients (pull pattern preferred)
mapping(address => uint256) public pendingWithdrawals;

function withdraw() external {
    uint256 amount = pendingWithdrawals[msg.sender];
    require(amount > 0, "Nothing to withdraw");
    pendingWithdrawals[msg.sender] = 0;
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Withdraw failed");
}
```

---

## Token Interaction Patterns

### Safe ERC20 Usage

```solidity
using SafeERC20 for IERC20;

// Transfer
token.safeTransfer(recipient, amount);

// TransferFrom
token.safeTransferFrom(sender, recipient, amount);

// Approve (handles USDT non-zero to non-zero issue)
token.forceApprove(spender, amount); // OZ v5
// or
token.safeApprove(spender, 0);
token.safeApprove(spender, amount);

// Increase/Decrease allowance
token.safeIncreaseAllowance(spender, amount);
token.safeDecreaseAllowance(spender, amount);
```

### Fee-on-Transfer Safe Deposit

```solidity
function deposit(IERC20 token, uint256 amount) external {
    uint256 balanceBefore = token.balanceOf(address(this));
    token.safeTransferFrom(msg.sender, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - balanceBefore;

    // Use 'received' not 'amount' for accounting
    deposits[msg.sender] += received;
    totalDeposits += received;
}
```

### Rebasing Token Wrapper

```solidity
// Pattern: Wrap rebasing token into non-rebasing shares
// Example: stETH → wstETH

interface IWrapperToken {
    function wrap(uint256 amount) external returns (uint256 shares);
    function unwrap(uint256 shares) external returns (uint256 amount);
}

// Protocol only stores and operates on wrapped (share) amounts
```

---

## Push vs Pull Payment Patterns

### Push Pattern (DANGEROUS)

```solidity
// DANGEROUS: One failed transfer blocks all
function distributeRewards(address[] calldata users, uint256[] calldata amounts) external {
    for (uint i = 0; i < users.length; i++) {
        // If ANY user is a contract that reverts → entire distribution fails
        payable(users[i]).transfer(amounts[i]);
    }
}
```

### Pull Pattern (SAFE)

```solidity
// SAFE: Each user claims independently
mapping(address => uint256) public pendingRewards;

function addRewards(address[] calldata users, uint256[] calldata amounts) external onlyAdmin {
    for (uint i = 0; i < users.length; i++) {
        pendingRewards[users[i]] += amounts[i];
    }
}

function claimReward() external {
    uint256 reward = pendingRewards[msg.sender];
    require(reward > 0, "Nothing to claim");
    pendingRewards[msg.sender] = 0;
    (bool success, ) = msg.sender.call{value: reward}("");
    require(success, "Claim failed");
}
```

---

## Return Data Bomb Protection

### The Attack

```solidity
// Malicious contract returns massive data
contract MaliciousReceiver {
    fallback() external payable {
        assembly {
            // Return 1MB of data — costs caller gas to copy
            return(0, 1048576)
        }
    }
}
```

### Protection

```solidity
// Option 1: Ignore return data
(bool success, ) = target.call{value: amount}(""); // data not copied

// Option 2: Limit return data in assembly
assembly {
    let success := call(gas(), target, amount, 0, 0, 0, 0) // outSize = 0
    if iszero(success) {
        // Handle failure
        let size := returndatasize()
        if gt(size, 256) { size := 256 } // Cap error message
        returndatacopy(0, 0, size)
        revert(0, size)
    }
}
```

---

## External Call Risk Classification

| Call Target | Risk Level | Required Checks |
|-------------|-----------|-----------------|
| Known trusted contract (immutable) | LOW | Return value check |
| Known trusted contract (upgradeable) | MEDIUM | Return value + interface verification |
| User-supplied address | HIGH | Return value + gas limit + return data limit |
| Arbitrary contract via delegatecall | CRITICAL | Should NOT be allowed |
| Token contract (standard ERC20) | MEDIUM | SafeERC20 wrapper |
| Token contract (unknown/arbitrary) | HIGH | SafeERC20 + balance-before-after + blacklist handling |
