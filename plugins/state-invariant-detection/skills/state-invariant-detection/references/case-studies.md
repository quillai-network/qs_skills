# State Invariant Detection Case Studies

## Case Study 1: The Broken Totalizer (ERC20 Token)

### Contract

```solidity
contract BrokenToken {
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    function mint(address to, uint256 amount) public {
        totalSupply += amount;      // ✓ Updates total
        balances[to] += amount;     // ✓ Updates balance
    }

    function burn(address from, uint256 amount) public {
        totalSupply -= amount;      // ✓ Updates total
        balances[from] -= amount;   // ✓ Updates balance
    }

    function transfer(address to, uint256 amount) public {
        balances[msg.sender] -= amount;   // ✓ Net-zero change
        balances[to] += amount;           // ✓ in sum(balances)
    }

    function adminBurn(address from, uint256 amount) public onlyAdmin {
        // VULNERABILITY: Updates balance but NOT totalSupply
        balances[from] -= amount;
    }
}
```

### Detection

**Phase 1 — Clustering:**

```
Functions modifying totalSupply: {mint, burn}
Functions modifying balances: {mint, burn, transfer, adminBurn}
CoMod(totalSupply, balances) = 2/4 = 50%
```

**Phase 2 — Invariant Inference:**

```
mint():     Δtotal = +amount, Δbalance = +amount → Same direction
burn():     Δtotal = -amount, Δbalance = -amount → Same direction
transfer(): Δtotal = 0, net Δbalance = 0 → Consistent

Inferred: totalSupply = Σ balances
Confidence: HIGH (holds in 3/3 analyzed functions)
```

**Phase 3 — Violation Detection:**

```
Testing adminBurn():
  Before: totalSupply = 1000, Σbalances = 1000 → 1000 = 1000 ✓
  Execute: adminBurn(alice, 100)
  After:  totalSupply = 1000, Σbalances = 900 → 1000 ≠ 900 ✗

VULNERABILITY DETECTED!
Severity: CRITICAL
Invariant broken: totalSupply = Σ balances
```

**Impact:**
- Protocol reports incorrect market cap
- Share price calculations become wrong
- Users can claim more value than exists
- Accounting permanently desynchronized

---

## Case Study 2: The Desynced Staking Pool

### Contract

```solidity
contract StakingPool {
    uint256 public totalStaked;
    uint256 public totalRewards;
    mapping(address => uint256) public userStake;
    mapping(address => uint256) public userRewards;

    function stake(uint256 amount) public {
        totalStaked += amount;
        userStake[msg.sender] += amount;
    }

    function unstake(uint256 amount) public {
        totalStaked -= amount;
        userStake[msg.sender] -= amount;
    }

    function distributeRewards() public {
        uint256 reward = calculateReward(msg.sender);
        userRewards[msg.sender] += reward;
        totalRewards += reward;
    }

    function emergencySlash(address user, uint256 penalty) public onlyAdmin {
        // VULN 1: Reduces user stake but not totalStaked
        userStake[user] -= penalty;
    }

    function compoundRewards() public {
        uint256 reward = userRewards[msg.sender];
        userRewards[msg.sender] = 0;      // Clears rewards
        userStake[msg.sender] += reward;   // Adds to stake
        // VULN 2: Increases stake without updating totalStaked
        // VULN 3: Reduces rewards without updating totalRewards
    }
}
```

### Detection

**Two invariants detected:**

```
Invariant 1: totalStaked = Σ userStake
Invariant 2: totalRewards = Σ userRewards
```

**Three violations found:**

```
VULN 1: emergencySlash() breaks Invariant 1
  Before: totalStaked=10000, Σstakes=10000 ✓
  After:  totalStaked=10000, Σstakes=9500  ✗

VULN 2: compoundRewards() breaks Invariant 1
  Before: totalStaked=10000, Σstakes=10000 ✓
  After:  totalStaked=10000, Σstakes=10500 ✗

VULN 3: compoundRewards() breaks Invariant 2
  Before: totalRewards=2000, Σrewards=2000 ✓
  After:  totalRewards=2000, Σrewards=1500 ✗
```

---

## Case Study 3: The Broken AMM Pool

### Contract

```solidity
contract SimpleDEX {
    uint256 public reserveA;
    uint256 public reserveB;
    uint256 public kLast;

    function addLiquidity(uint256 amountA, uint256 amountB) public {
        reserveA += amountA;
        reserveB += amountB;
        kLast = reserveA * reserveB;    // ✓ Updates k
    }

    function swap(uint256 amountAIn) public {
        uint256 amountBOut = getAmountOut(amountAIn);
        reserveA += amountAIn;
        reserveB -= amountBOut;
        kLast = reserveA * reserveB;    // ✓ Updates k
    }

    function adminAdjustReserve(uint256 newReserveA) public onlyAdmin {
        // VULN: Changes reserve without updating k
        reserveA = newReserveA;
    }

    function emergencyDrain(uint256 amount) public onlyAdmin {
        // VULN: Removes liquidity without maintaining k
        reserveB -= amount;
    }
}
```

### Detection

```
Detected Relationship:
  Type: RATIO INVARIANT
  Pattern: kLast = reserveA × reserveB
  Confidence: 100% (2/2 normal functions maintain it)

VULN 1: adminAdjustReserve()
  Before: reserveA=1000, reserveB=1000, k=1000000
  After:  reserveA=1500, reserveB=1000, k=1000000 (stale!)
  Expected k: 1500000

VULN 2: emergencyDrain()
  Before: reserveA=1000, reserveB=1000, k=1000000
  After:  reserveA=1000, reserveB=800,  k=1000000 (stale!)
  Expected k: 800000

Impact: Constant product broken → price manipulation → arbitrage exploit
```

---

## Case Study 4: The Conservation Law Violation

### Contract

```solidity
contract Treasury {
    uint256 public totalFunds;
    uint256 public availableFunds;
    uint256 public lockedFunds;

    function deposit(uint256 amount) public {
        totalFunds += amount;
        availableFunds += amount;
        // ✓ total = available + locked maintained
    }

    function lockFunds(uint256 amount) public {
        availableFunds -= amount;
        lockedFunds += amount;
        // ✓ total unchanged, conservation holds
    }

    function emergencyUnlock(uint256 amount) public onlyAdmin {
        // VULN: Increases available without decreasing locked
        availableFunds += amount;
    }
}
```

### Detection

```
Conservation invariant: totalFunds = availableFunds + lockedFunds

VULNERABILITY: emergencyUnlock()
  Before: total=1000, available=600, locked=400
          1000 = 600 + 400 ✓
  After:  total=1000, available=700, locked=400
          1000 ≠ 700 + 400 (1100) ✗

Impact: Funds created out of thin air! Available exceeds actual total.
```

---

## Real-World Historical Examples

### The DAO Hack (2016)

```
Invariant violated: contract_balance = Σ user_balances
Recursive call drained contract_balance without updating user_balances
Result: $60M loss
```

### Poly Network (2021)

```
Invariant violated: Cross-chain asset conservation
Tokens burned on chain A ≠ tokens minted on chain B
Result: $600M loss
```

### Indexed Finance (2021)

```
Invariant violated: Pool weight proportionality
Spot price used instead of TWAP for weight calculations
Result: $16M loss
```

### Audius (2022)

```
Invariant violated: Governance token supply conservation
Malicious proposal minted tokens without corresponding delegated votes
Result: $6M loss
```
