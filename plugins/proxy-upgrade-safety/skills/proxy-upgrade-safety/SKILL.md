---
name: proxy-upgrade-safety
description: Detects vulnerabilities in upgradeable proxy smart contracts including storage layout collisions, uninitialized implementations, function selector clashing, delegatecall context issues, and upgrade path safety. Covers Transparent Proxy, UUPS (EIP-1822), Beacon, Diamond (EIP-2535), and Minimal Proxy (EIP-1167) patterns. Use when auditing upgradeable contracts, reviewing implementation upgrades, analyzing delegatecall architectures, or verifying proxy pattern compliance.
---

# Proxy & Upgrade Safety

Detect vulnerabilities specific to **upgradeable proxy architectures** — the most widely deployed contract pattern on Ethereum (54.2% of contracts). Proxy bugs cause storage corruption, unauthorized upgrades, and complete contract takeover.

## When to Use

- Auditing any contract using proxy/implementation pattern (Transparent, UUPS, Beacon, Diamond)
- Reviewing implementation contract upgrades for storage layout compatibility
- Analyzing `delegatecall`-based architectures and library usage
- Verifying initialization safety (can `initialize()` be front-run?)
- Checking Diamond (EIP-2535) facet management for selector collisions

## When NOT to Use

- Non-upgradeable contracts without proxy patterns
- Pure logic audits without proxy architecture (use behavioral-state-analysis)
- Token standard compliance (use external-call-safety)

## Core Concept: The Delegatecall Storage Model

When Proxy calls Implementation via `delegatecall`:

```
┌─────────────────────┐     delegatecall     ┌─────────────────────┐
│       PROXY         │ ──────────────────→   │   IMPLEMENTATION    │
│                     │                       │                     │
│ Storage:            │  Implementation code  │ Code only:          │
│   slot 0: admin     │  executes in proxy's  │   No persistent     │
│   slot 1: impl addr │  storage context      │   storage           │
│   slot 2: user data │                       │                     │
│   slot 3: user data │                       │                     │
└─────────────────────┘                       └─────────────────────┘
```

**Key Rule:** The implementation's code reads/writes the PROXY's storage slots. If storage layouts don't match, data corruption occurs.

## Five Vulnerability Classes

### Class 1: Storage Layout Collision

**Between Proxy and Implementation:**

```solidity
// Proxy contract
contract Proxy {
    address public admin;           // slot 0
    address public implementation;  // slot 1

    fallback() external payable {
        delegatecall(implementation);
    }
}

// Implementation contract
contract ImplementationV1 {
    uint256 public totalSupply;     // slot 0 — COLLIDES with admin!
    mapping(address => uint256) public balances; // slot 1 — COLLIDES with implementation!
}
```

**Detection:** Compare storage slot assignments between proxy and implementation. Any overlap = CRITICAL vulnerability.

**Between Implementation Versions:**

```solidity
// V1
contract ImplementationV1 {
    uint256 public totalSupply;     // slot 0
    address public owner;           // slot 1
    mapping(address => uint256) balances; // slot 2
}

// V2 — DANGEROUS: inserted variable before existing ones
contract ImplementationV2 {
    bool public paused;             // slot 0 — COLLIDES with totalSupply!
    uint256 public totalSupply;     // slot 1 — COLLIDES with owner!
    address public owner;           // slot 2 — COLLIDES with balances!
    mapping(address => uint256) balances; // slot 3
}
```

**Safe V2:**

```solidity
contract ImplementationV2 {
    uint256 public totalSupply;     // slot 0 — same
    address public owner;           // slot 1 — same
    mapping(address => uint256) balances; // slot 2 — same
    bool public paused;             // slot 3 — NEW, appended at end
}
```

### Class 2: Uninitialized Implementation

Proxy pattern uses `initialize()` instead of `constructor()`. If the implementation contract itself is not initialized, an attacker can call `initialize()` directly on it.

```solidity
contract ImplementationV1 is Initializable {
    address public owner;

    function initialize(address _owner) external initializer {
        owner = _owner;
    }

    function selfDestruct() external {
        require(msg.sender == owner);
        selfdestruct(payable(msg.sender));
    }
}
```

**Attack:**

```
1. Implementation deployed but initialize() not called on impl itself
2. Attacker calls implementation.initialize(attacker_address)
3. Attacker is now owner of the IMPLEMENTATION contract
4. Attacker calls selfDestruct() on implementation
5. Proxy now delegatecalls to destroyed contract
6. ALL proxy calls return empty data — contract bricked
```

**Detection:**

```
For each implementation contract:
  1. Does it have initialize() or any initializer function?
  2. Was initialize() called on the implementation address (not just the proxy)?
  3. Does the constructor call _disableInitializers()?
  4. If no → UNINITIALIZED IMPLEMENTATION vulnerability
```

### Class 3: Function Selector Clashing

Solidity function selectors are only 4 bytes. Collisions between proxy admin functions and implementation functions cause unexpected behavior.

```solidity
// Proxy has admin function
function upgrade(address newImpl) external;  // selector: 0x0900f010

// Implementation has user function with SAME selector
function collide(uint256 amount) external;   // selector: 0x0900f010

// When user calls collide(), proxy intercepts it as upgrade()!
```

**Transparent Proxy Mitigation:** Admin can only call admin functions; users can only call implementation functions. But this must be correctly implemented.

**Detection:**

```
For each function in the proxy:
  selector_proxy = keccak256(signature)[:4]
  For each function in the implementation:
    selector_impl = keccak256(signature)[:4]
    If selector_proxy == selector_impl:
      → FUNCTION SELECTOR CLASH
```

### Class 4: Missing Upgrade Authorization

**UUPS Pattern:** The upgrade logic lives in the implementation, not the proxy. If `_authorizeUpgrade()` is not properly protected, anyone can upgrade.

```solidity
// VULNERABLE: Missing access control on upgrade
contract ImplementationV1 is UUPSUpgradeable {
    function _authorizeUpgrade(address newImplementation) internal override {
        // NO ACCESS CHECK! Anyone can upgrade!
    }
}

// SAFE
contract ImplementationV1 is UUPSUpgradeable, OwnableUpgradeable {
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        // Only owner can upgrade
    }
}
```

**Detection:**

```
For UUPS proxies:
  1. Find _authorizeUpgrade() function
  2. Check for access control (onlyOwner, onlyRole, require(msg.sender == admin))
  3. If no access control → CRITICAL: unauthorized upgrade
  4. Also check: Can _authorizeUpgrade be removed in a new version?
     → If V2 doesn't inherit UUPSUpgradeable → proxy becomes non-upgradeable (bricked)
```

### Class 5: Delegatecall Context Confusion

Code executing via `delegatecall` runs with the caller's `msg.sender`, `msg.value`, and storage. Misunderstanding this context creates vulnerabilities.

```solidity
// Implementation stores admin in its own constructor
contract Implementation {
    address public admin;

    constructor() {
        admin = msg.sender; // Sets admin in IMPLEMENTATION storage
        // When called via delegatecall, this is proxy's storage
        // BUT constructor only runs during deployment, not via proxy!
    }
}
```

**Key Rule:** Constructors NEVER run via delegatecall. Any state set in the constructor exists only in the implementation's own storage, not the proxy's.

## Three-Phase Detection Architecture

### Phase 1: Proxy Pattern Classification

Identify which proxy pattern is used.

| Pattern | Key Indicator | Upgrade Location |
|---------|--------------|-----------------|
| Transparent (EIP-1967) | `_IMPLEMENTATION_SLOT` at `keccak256('eip1967.proxy.implementation') - 1` | Proxy contract |
| UUPS (EIP-1822) | `proxiableUUID()` in implementation | Implementation contract |
| Beacon | `_BEACON_SLOT` at `keccak256('eip1967.proxy.beacon') - 1` | Beacon contract |
| Diamond (EIP-2535) | `diamondCut()` function, facet registry | Diamond contract |
| Minimal (EIP-1167) | Clone bytecode pattern `363d3d373d3d3d363d73...` | Not upgradeable |

### Phase 2: Storage Layout Analysis

Build the complete storage map for proxy and all implementation versions.

**Algorithm:**

```
For each contract C (proxy, impl_v1, impl_v2, ...):
  storage_map[C] = {}
  slot = 0
  For each state variable V in C (in declaration order):
    storage_map[C][slot] = V
    slot += size_of(V)  // Consider packing for <32 byte types

For each slot S:
  If storage_map[proxy][S] conflicts with storage_map[impl][S]:
    → PROXY-IMPL COLLISION at slot S
  If storage_map[impl_v1][S] != storage_map[impl_v2][S]:
    → UPGRADE COLLISION at slot S
```

**Special Cases:**

- Mappings and dynamic arrays: hash-based slot calculation
- Struct packing: multiple variables per slot
- Inherited contracts: storage order follows C3 linearization
- Gap variables (`uint256[50] private __gap`): reserved space for upgrades

### Phase 3: Initialization & Upgrade Path Verification

```
Initialization Checks:
  1. Does implementation use Initializable?
  2. Is initialize() protected by initializer modifier?
  3. Does constructor call _disableInitializers()?
  4. Can initialize() be called more than once? (reinitializer)
  5. Was initialize() called on impl address directly?

Upgrade Path Checks:
  1. Is upgrade function access-controlled?
  2. Does new impl maintain storage layout compatibility?
  3. Does new impl still support upgrades? (UUPS: must inherit UUPSUpgradeable)
  4. Is there a timelock on upgrades?
  5. Can upgrade + initialize race condition occur?
```

## Workflow

```
Task Progress:
- [ ] Step 1: Identify proxy pattern (Transparent, UUPS, Beacon, Diamond, Minimal)
- [ ] Step 2: Map storage layout of proxy contract
- [ ] Step 3: Map storage layout of all implementation versions
- [ ] Step 4: Check for storage collisions (proxy-impl and version-version)
- [ ] Step 5: Verify initialization safety (disableInitializers, initializer modifier)
- [ ] Step 6: Check function selector clashing (proxy admin vs impl functions)
- [ ] Step 7: Verify upgrade authorization (access control on upgrade path)
- [ ] Step 8: Check delegatecall context safety
- [ ] Step 9: Score findings and generate report
```

## Output Format

```markdown
## Proxy & Upgrade Safety Report

### Finding: [Title]

**Contract:** `ContractName` at `Contract.sol:L42`
**Proxy Pattern:** [Transparent | UUPS | Beacon | Diamond | Minimal]
**Class:** [Storage Collision | Uninitialized Impl | Selector Clash | Missing Auth | Context Confusion]
**Severity:** [CRITICAL | HIGH | MEDIUM]

**Issue:**
[Description of the proxy-specific vulnerability]

**Storage Layout:**
  Proxy slot 0: `[proxy variable]`
  Impl  slot 0: `[impl variable]` ← COLLISION

**Attack Scenario:**
1. [Step-by-step exploit]

**Impact:**
[Storage corruption, unauthorized upgrade, contract bricked, etc.]

**Recommendation:**
[Use EIP-1967 slots, add _disableInitializers, add access control, append-only storage]
```

## Quick Detection Checklist

- [ ] Does the proxy store admin/implementation at standard EIP-1967 slots (not regular slots)?
- [ ] Does the implementation's `constructor()` call `_disableInitializers()`?
- [ ] Does `initialize()` use the `initializer` modifier?
- [ ] Do implementation upgrades ONLY append new state variables (never insert or reorder)?
- [ ] Is there a `__gap` variable for future storage expansion in base contracts?
- [ ] For UUPS: Does `_authorizeUpgrade()` have proper access control?
- [ ] For UUPS: Does every new implementation still inherit `UUPSUpgradeable`?
- [ ] Are there any function selector collisions between proxy and implementation?
- [ ] Is there a timelock or multisig on the upgrade path?

For proxy pattern details, see [{baseDir}/references/proxy-patterns.md]({baseDir}/references/proxy-patterns.md).
For storage collision detection, see [{baseDir}/references/storage-collision-detection.md]({baseDir}/references/storage-collision-detection.md).

## Rationalizations to Reject

- "We use OpenZeppelin's proxy" → OZ provides the framework, but storage layout compatibility is YOUR responsibility
- "The implementation is initialized" → Was it initialized on the IMPLEMENTATION address, or only through the proxy?
- "Constructor sets the admin" → Constructors don't run via delegatecall; admin is only set in impl's own storage
- "We tested the upgrade" → Did you verify storage layout slot-by-slot? One reordered variable corrupts everything
- "UUPS is safer than Transparent" → Only if `_authorizeUpgrade` is properly protected AND maintained across upgrades
- "The gap variable protects us" → Only if inherited contracts also have gaps and you never exceed the gap size
