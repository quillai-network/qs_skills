# Guard-State Analysis Case Studies

## Case Study 1: The Forgotten Pause Check

### Contract

```solidity
contract Vault {
    mapping(address => uint256) public balance;
    bool public paused;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function deposit() public payable {
        require(!paused, "Contract paused");
        balance[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(!paused, "Contract paused");
        require(balance[msg.sender] >= amount);
        balance[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function adminWithdraw(address user) public onlyOwner {
        // VULNERABILITY: Missing paused check
        uint256 amount = balance[user];
        balance[user] = 0;
        payable(owner).transfer(amount);
    }
}
```

### Analysis

**Phase 1: State Interaction Matrix**

```
State Variable: balance
├─ deposit()        → WRITE + Guards: [paused]
├─ withdraw()       → WRITE + Guards: [paused]
└─ adminWithdraw()  → WRITE + Guards: [owner]
```

**Phase 2: Pattern Recognition**

```
Functions modifying 'balance': {deposit, withdraw, adminWithdraw}
Guard frequency:
  - paused: 2/3 functions (66.7%)
  - owner: 1/3 functions (33.3%)

Inferred: balance → paused (Moderate confidence)
```

**Phase 3: Solver**

```
M_target = {deposit, withdraw, adminWithdraw}
G_required = {deposit, withdraw}
V = {adminWithdraw}
```

**Result:**

```
VULNERABILITY DETECTED
Function: adminWithdraw()
Severity: HIGH
Issue: Modifies 'balance' without checking 'paused'
Confidence: 66.7%
```

**Attack Scenario:**
1. Security team detects an active exploit
2. Contract is paused to stop operations
3. Attacker (with compromised admin access) uses `adminWithdraw()` to drain funds
4. Pause mechanism rendered useless

---

## Case Study 2: Inconsistent Role Checks in Governance

### Contract

```solidity
contract Governance {
    mapping(uint256 => Proposal) public proposals;
    mapping(address => bool) public isVoter;
    uint256 public quorum;
    address public admin;

    function createProposal(bytes calldata data) public {
        require(isVoter[msg.sender], "Not a voter");
        // Creates proposal...
    }

    function vote(uint256 proposalId) public {
        require(isVoter[msg.sender], "Not a voter");
        // Records vote...
    }

    function executeProposal(uint256 proposalId) public {
        require(isVoter[msg.sender], "Not a voter");
        require(proposals[proposalId].votes >= quorum, "No quorum");
        // Executes...
    }

    function cancelProposal(uint256 proposalId) public {
        // VULNERABILITY: Missing voter check!
        // Anyone can cancel any proposal
        proposals[proposalId].cancelled = true;
    }

    function setQuorum(uint256 newQuorum) public {
        require(msg.sender == admin, "Not admin");
        quorum = newQuorum;
    }
}
```

### Analysis

```
State Variable: proposals
├─ createProposal()  → WRITE + Guards: [isVoter]
├─ vote()           → WRITE + Guards: [isVoter]
├─ executeProposal() → WRITE + Guards: [isVoter, quorum]
└─ cancelProposal()  → WRITE + Guards: [] ⚠️

Guard frequency for isVoter → proposals:
  3/4 functions = 75% (Weak-to-Moderate invariant)

VULNERABILITY: cancelProposal() bypasses voter check
Severity: HIGH (governance manipulation)
Impact: Any address can cancel any proposal, blocking governance
```

---

## Case Study 3: Multi-Guard Composite Bypass

### Contract

```solidity
contract TimelockVault {
    mapping(address => uint256) public locked;
    mapping(address => uint256) public unlockTime;
    bool public paused;
    address public owner;

    function lock(uint256 amount, uint256 duration) public {
        require(!paused, "Paused");
        locked[msg.sender] += amount;
        unlockTime[msg.sender] = block.timestamp + duration;
    }

    function unlock() public {
        require(!paused, "Paused");
        require(block.timestamp >= unlockTime[msg.sender], "Still locked");
        uint256 amount = locked[msg.sender];
        locked[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    function adminUnlock(address user, uint256 amount) public {
        require(msg.sender == owner, "Not owner");
        // VULNERABILITY: Skips BOTH paused AND timelock checks
        locked[user] -= amount;
        payable(user).transfer(amount);
    }
}
```

### Analysis

```
State Variable: locked
├─ lock()        → WRITE + Guards: [paused]
├─ unlock()      → WRITE + Guards: [paused, unlockTime]
└─ adminUnlock() → WRITE + Guards: [owner]

Composite guard analysis:
  paused → locked: 2/3 = 66.7%
  unlockTime → locked: 1/3 = 33.3% (weak, timelock only for user unlock)

VULNERABILITY: adminUnlock() bypasses paused check
Severity: HIGH
Note: Timelock bypass may be intentional for admin override,
      but paused bypass is dangerous — admin can drain during emergency pause
```

---

## Pattern: Traditional Tool vs Semantic Analysis

| Scenario | Traditional Tool Result | Semantic Guard Analysis |
|----------|----------------------|------------------------|
| Missing pause in admin function | PASS (valid syntax) | VULNERABILITY (inconsistent guard) |
| Missing voter check in cancel | PASS (no known pattern) | VULNERABILITY (breaks 75% pattern) |
| Admin bypassing timelock + pause | PASS (has onlyOwner) | VULNERABILITY (breaks composite guard) |
