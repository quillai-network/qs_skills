---
name: input-arithmetic-safety
description: Detects input validation failures and arithmetic vulnerabilities in smart contracts. Covers missing zero-address and zero-amount checks, division-before-multiplication precision loss, rounding direction exploitation, ERC4626 vault share inflation attacks, unsafe integer casting, dust amount exploitation, and Solidity 0.8+ unchecked block edge cases. Use when auditing contracts with fee calculations, share pricing, exchange rates, unchecked blocks, or any public-facing functions that accept user input.
---

# Input & Arithmetic Safety

Detect **input validation failures** (the #1 direct exploitation cause at 34.6% of all contract exploits) and **arithmetic vulnerabilities** that persist even with Solidity 0.8+ checked math — precision loss, rounding exploitation, unsafe casting, and share price manipulation.

## When to Use

- Auditing any contract with public/external functions accepting user-supplied parameters
- Reviewing DeFi protocols with fee calculations, share pricing, or exchange rates
- Analyzing vault/staking contracts for rounding or first-depositor attacks
- Checking contracts with `unchecked` blocks for overflow/underflow risks
- Verifying arithmetic in token minting, burning, and distribution logic

## When NOT to Use

- Access control analysis (use semantic-guard-analysis)
- Reentrancy detection (use reentrancy-pattern-analysis)
- Full multi-dimensional audit (use behavioral-state-analysis)

## Part 1: Input Validation Analysis

### Critical Missing Validations

**Zero Address Check:**

```solidity
// VULNERABLE: No zero address check
function setAdmin(address newAdmin) external onlyOwner {
    admin = newAdmin; // Can set admin to address(0) — locking out admin forever
}

// SAFE
function setAdmin(address newAdmin) external onlyOwner {
    require(newAdmin != address(0), "Zero address");
    admin = newAdmin;
}
```

**Zero Amount Check:**

```solidity
// VULNERABLE: Allows zero-amount operations
function deposit(uint256 amount) external {
    balances[msg.sender] += amount;
    emit Deposit(msg.sender, amount);
    // Zero deposit: wastes gas, pollutes events, may affect accounting
}

// SAFE
function deposit(uint256 amount) external {
    require(amount > 0, "Zero amount");
    balances[msg.sender] += amount;
}
```

**Array Length Validation:**

```solidity
// VULNERABLE: No length check
function batchTransfer(address[] calldata recipients, uint256[] calldata amounts) external {
    for (uint i = 0; i < recipients.length; i++) {
        transfer(recipients[i], amounts[i]); // Out-of-bounds if arrays differ in length
    }
}

// SAFE
function batchTransfer(address[] calldata recipients, uint256[] calldata amounts) external {
    require(recipients.length == amounts.length, "Length mismatch");
    require(recipients.length <= MAX_BATCH_SIZE, "Batch too large");
    // ...
}
```

**Bounds Checking:**

```solidity
// VULNERABLE: No upper bound on fee
function setFee(uint256 newFee) external onlyOwner {
    fee = newFee; // Owner can set 100% fee, stealing all user funds
}

// SAFE
function setFee(uint256 newFee) external onlyOwner {
    require(newFee <= MAX_FEE, "Fee too high"); // e.g., MAX_FEE = 1000 (10%)
    fee = newFee;
}
```

### Input Validation Detection Algorithm

```
For each public/external function F:
  For each parameter P:
    1. Is P an address? → Check for require(P != address(0))
    2. Is P an amount/value? → Check for require(P > 0) if zero is invalid
    3. Is P an array? → Check for length validation and max size
    4. Is P a percentage/rate? → Check for upper bound
    5. Is P used as an index? → Check for bounds checking
    6. Is P a deadline/timestamp? → Check for require(P > block.timestamp)

  Flag any parameter without appropriate validation as:
    - CRITICAL if parameter controls fund flow or access
    - HIGH if parameter affects protocol state
    - MEDIUM if parameter affects non-critical functionality
```

## Part 2: Arithmetic Vulnerability Analysis

### Pattern 1: Division-Before-Multiplication (Precision Loss)

```solidity
// VULNERABLE: Division first truncates, then multiplication amplifies error
uint256 result = (amount / totalShares) * price;
// If amount = 100, totalShares = 3: 100/3 = 33 (truncated from 33.33)
// 33 * price = less than expected

// SAFE: Multiply first, then divide
uint256 result = (amount * price) / totalShares;
// 100 * price / 3 = more precise (only one truncation at the end)
```

**Detection:**

```
For each arithmetic expression:
  If division (/) appears BEFORE multiplication (*) in the same expression:
    → PRECISION LOSS: division-before-multiplication
  Exception: If the division result is stored and intentionally used as a floored value
```

### Pattern 2: Rounding Direction Exploitation

In financial protocols, rounding direction determines who benefits:

```
Protocol-favorable rounding:
  - Deposits: round DOWN shares (user gets fewer shares)
  - Withdrawals: round DOWN assets (user gets fewer assets)
  - Fees: round UP fee amount (protocol collects more)

User-favorable rounding (VULNERABLE to extraction):
  - Deposits: round UP shares → user gets more than entitled
  - Withdrawals: round UP assets → user extracts more than entitled
  - Fees: round DOWN → protocol collects less
```

```solidity
// VULNERABLE: Rounds in user's favor on withdrawal
function withdraw(uint256 shares) external returns (uint256 assets) {
    assets = (shares * totalAssets()) / totalSupply(); // Rounds DOWN — correct for withdrawal
    // BUT if this rounds UP somehow (e.g., via ceiling division):
    assets = (shares * totalAssets() + totalSupply() - 1) / totalSupply(); // Rounds UP — BAD
}

// SAFE: Use mulDiv with explicit rounding direction
assets = shares.mulDiv(totalAssets(), totalSupply(), Math.Rounding.Down); // For withdrawals
shares = assets.mulDiv(totalSupply(), totalAssets(), Math.Rounding.Up);   // For deposits
```

### Pattern 3: ERC4626 Vault Share Inflation Attack

```solidity
// Attack on first deposit
contract VulnerableVault is ERC4626 {
    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this)); // Manipulable via donation!
    }

    // No virtual shares offset
    function _convertToShares(uint256 assets) internal view returns (uint256) {
        uint256 supply = totalSupply();
        return supply == 0 ? assets : assets.mulDiv(supply, totalAssets());
    }
}
```

**Attack Sequence:**

```
1. Vault is empty (totalSupply = 0, totalAssets = 0)
2. Attacker deposits 1 wei → receives 1 share
3. Attacker donates 1000 tokens directly to vault (not via deposit)
4. totalAssets = 1000e18 + 1, totalSupply = 1
5. Victim deposits 500 tokens:
   shares = 500e18 * 1 / (1000e18 + 1) = 0 (rounds to zero!)
6. Victim gets ZERO shares, their 500 tokens are trapped
7. Attacker withdraws 1 share → gets all 1500+ tokens
```

**Detection:**

```
For ERC4626 vaults:
  1. Does totalAssets() use balanceOf(address(this))? → Donation-attackable
  2. Is there a virtual shares/assets offset? → Missing = VULNERABLE
  3. Is there a minimum first deposit? → Missing = VULNERABLE
  4. Does the vault use OpenZeppelin's _decimalsOffset()? → Present = Mitigated
```

### Pattern 4: Unsafe Integer Casting

```solidity
// VULNERABLE: Silent truncation
uint256 largeValue = 2**200;
uint128 smallValue = uint128(largeValue); // Truncated! No revert in 0.8+

// VULNERABLE: Signed/unsigned confusion
int256 negative = -1;
uint256 converted = uint256(negative); // = type(uint256).max in 0.8+

// SAFE: Use SafeCast
uint128 smallValue = SafeCast.toUint128(largeValue); // Reverts if overflow
```

**Detection:**

```
For each type cast operation:
  If casting from larger to smaller type (e.g., uint256 → uint128):
    Check if preceded by bounds validation
    If no bounds check → UNSAFE CASTING
  If casting between signed and unsigned:
    Check if value can be negative
    If possible → SIGN CONFUSION
```

### Pattern 5: Unchecked Block Risks

```solidity
// Solidity 0.8+: checked math by default, but unchecked{} disables it
unchecked {
    // VULNERABLE: Overflow/underflow silently wraps
    uint256 result = a - b; // If b > a: wraps to huge number
    uint256 sum = a + b;    // If a + b > type(uint256).max: wraps to small number
}

// SAFE use of unchecked (when overflow is impossible):
unchecked {
    ++i; // In a bounded for loop — i cannot overflow uint256
}
```

**Detection:**

```
For each unchecked block:
  For each arithmetic operation inside:
    1. Can the operation overflow/underflow?
    2. Is there a pre-condition that guarantees safety?
    3. If no guarantee → UNCHECKED OVERFLOW/UNDERFLOW risk

  Common safe patterns (don't flag):
    - Loop counter increment: unchecked { ++i; } in for loop with bounded length
    - Post-require subtraction: require(a >= b); unchecked { a - b; }
```

### Pattern 6: Dust Amount Exploitation

```solidity
// VULNERABLE: Tiny amounts bypass fee logic
function swap(uint256 amountIn) external {
    uint256 fee = amountIn * FEE_BPS / 10000;
    // If amountIn = 1 and FEE_BPS = 30: fee = 30/10000 = 0
    // Zero fee! Attacker makes many tiny swaps to avoid fees
    uint256 amountOut = amountIn - fee;
}
```

**Detection:**

```
For each fee/tax calculation:
  If fee = amount * rate / denominator:
    Can amount * rate < denominator? (making fee = 0)
    If yes → DUST AMOUNT EXPLOITATION: zero-fee transactions possible
```

## Workflow

```
Task Progress:
- [ ] Step 1: Audit all public/external function parameters for missing validation
- [ ] Step 2: Find division-before-multiplication patterns
- [ ] Step 3: Verify rounding direction in share/price calculations (protocol-favorable)
- [ ] Step 4: Check ERC4626 vaults for inflation attack protection
- [ ] Step 5: Identify all type casting operations and verify bounds
- [ ] Step 6: Analyze all unchecked blocks for overflow/underflow risks
- [ ] Step 7: Check fee calculations for dust amount exploitation
- [ ] Step 8: Score findings and generate report
```

## Output Format

```markdown
## Input & Arithmetic Safety Report

### Finding: [Title]

**Function:** `functionName()` at `Contract.sol:L42`
**Category:** [Missing Validation | Precision Loss | Rounding | Inflation | Unsafe Cast | Unchecked | Dust]
**Severity:** [CRITICAL | HIGH | MEDIUM | LOW]

**Issue:**
[Description of the input validation or arithmetic vulnerability]

**Vulnerable Code:**
[Code snippet showing the issue]

**Exploit Scenario:**
1. [Step-by-step exploitation]

**Mathematical Proof:**
  Input: [values]
  Expected: [correct result]
  Actual: [incorrect result due to precision/rounding]
  Difference: [loss amount]

**Recommendation:**
[Specific fix — add validation, reorder operations, use SafeCast, add rounding]
```

## Quick Detection Checklist

- [ ] Do all public functions validate address parameters against `address(0)`?
- [ ] Do all amount parameters check for `> 0` where zero is invalid?
- [ ] Are array parameters checked for equal lengths and maximum size?
- [ ] Do all percentage/rate parameters have upper bounds?
- [ ] Is division always performed AFTER multiplication (not before)?
- [ ] Does rounding favor the protocol (down on deposits, down on withdrawals of assets)?
- [ ] Do ERC4626 vaults use virtual shares/assets offset against inflation?
- [ ] Are all downcasts (uint256 → smaller) protected by SafeCast or bounds checks?
- [ ] Are `unchecked` blocks only used where overflow/underflow is mathematically impossible?
- [ ] Can fee calculations produce zero for small but valid amounts?

For precision patterns, see [{baseDir}/references/precision-patterns.md]({baseDir}/references/precision-patterns.md).
For validation checklist, see [{baseDir}/references/validation-checklist.md]({baseDir}/references/validation-checklist.md).

## Rationalizations to Reject

- "Solidity 0.8+ has checked math" → `unchecked` blocks exist; precision loss and rounding are NOT overflow
- "The fee is too small to matter" → Millions of small transactions compound; zero-fee dust swaps are profitable
- "No one would deposit 1 wei" → ERC4626 inflation attack uses exactly this; front-runners are automated
- "The admin wouldn't set a bad value" → Admin key compromise + no bounds = instant parameter manipulation
- "Rounding errors are just 1 wei" → 1 wei per transaction × millions of transactions = significant loss
- "Zero address can't sign transactions" → But setting admin to zero address locks out all admin functions permanently
