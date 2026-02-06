# Multi-Dimensional Threat Engines — Detailed Reference

## Economic Threat Engine (ETE)

### Value Flow Tracing

Trace every path where value (ETH, tokens, NFTs) can enter or leave the contract system.

**Build a Value Flow Tree:**

```
Contract Entry Points:
├─ deposit() → ETH/Token IN
├─ stake() → Token IN
├─ withdraw() → ETH/Token OUT
├─ claimRewards() → Token OUT (minted or from pool)
├─ liquidate() → Token redistribution
└─ emergencyDrain() → ETH/Token OUT (admin)
```

**Identify anomalies:**
- **Value sinks**: Where funds can be trapped with no exit path
- **Value sources**: Unexpected minting or value creation
- **Circular flows**: Value loops that can be amplified (flash loan vectors)

### Economic Invariant Verification

For each contract, verify:

```
sum(deposits) == sum(withdrawals) + contractBalance
```

Test under all conditions:
- Normal operations
- Extreme values (near uint256 max)
- Concurrent transactions
- Price oracle manipulation (for DEX/AMM)
- Flash loan scenarios

### Incentive Analysis

Model rational actor behavior:

```
For each public function F:
  If I call F with parameters P:
    Cost = gas + any required deposit
    Benefit = any extractable value
    If Benefit > Cost → potential exploit vector
```

Detect:
- MEV (Miner Extractable Value) opportunities
- Sandwich attack vectors
- Front-running profitable transactions
- Griefing attacks (harm others at low cost)

---

## Access Control Threat Engine (ACTE)

### Role Hierarchy Mapping

Build the complete role graph:

```
Owner (deployer)
├── Admin (granted by owner)
│   ├── Pauser (granted by admin)
│   └── FeeManager (granted by admin)
├── Governance (timelock)
│   └── Executor (timelock-controlled)
└── Guardian (emergency multisig)
```

For each function, verify:
- Which roles can call it
- Whether the role check is correctly implemented
- Whether role assignment/revocation is properly controlled

### Permission Boundary Testing Matrix

```
| Function        | Public | User  | Admin | Owner | Governance |
|-----------------|--------|-------|-------|-------|------------|
| deposit()       | ✓      | ✓     | ✓     | ✓     | ✓          |
| withdraw()      | ✓      | ✓     | ✓     | ✓     | ✓          |
| setFee()        | ✗      | ✗     | ✓     | ✓     | ✓          |
| pause()         | ✗      | ✗     | ✗     | ✓     | ✓          |
| upgradeImpl()   | ✗      | ✗     | ✗     | ✗     | ✓          |
```

Flag any cell where the actual access differs from the expected pattern.

### Privilege Escalation Paths

Test multi-step attack sequences:

1. Can a user grant themselves admin rights?
2. Can an admin bypass governance timelocks?
3. Can role confusion (msg.sender vs tx.origin) be exploited?
4. Can signature replay grant unauthorized access?
5. Can initialization be called post-deployment to reset roles?

---

## State Integrity Threat Engine (SITE)

### State Transition Validation

For each state-modifying function, verify:

```
All modified state variables are updated atomically:
  ✓ balance[user] decremented
  ✓ totalBalance decremented
  ✓ lastWithdrawTime updated
  ✗ pendingWithdrawals NOT updated ← VULNERABILITY
```

### Sequence Vulnerability Detection

Test unexpected call orderings:

```
Expected: initialize() → deposit() → stake() → withdraw()
Test:
  - deposit() before initialize() → should revert
  - withdraw() before deposit() → should revert
  - stake() after pause() → should revert
  - initialize() after initialize() → should revert (re-init attack)
```

### Cross-Contract State Synchronization

When Contract A depends on Contract B:

```
A.getPrice() calls B.latestAnswer()
  - What if B returns stale data?
  - What if B is paused?
  - What if B returns 0?
  - What if B reverts?
  - What if B is upgraded to return manipulated data?
```

Verify all edge cases are handled in Contract A's logic.

---

## Detection Output Format

For each engine finding:

```
Finding: [Descriptive title]
Dimension: [Economic | Access Control | State Integrity]
Evidence:
  - [Concrete code evidence]
  - [State condition that enables exploit]
  - [Impact description]
Exploit Path: [Step-by-step attack sequence]
Confidence: [Score from Phase 4]
```
