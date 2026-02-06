# Proxy Patterns — Detailed Comparison

## Pattern 1: Transparent Proxy (EIP-1967)

### Architecture

```
┌──────────────┐     delegatecall      ┌──────────────────┐
│    Proxy     │ ───────────────────→   │  Implementation  │
│              │                        │                  │
│ EIP-1967     │  Admin calls:          │  Business logic  │
│ storage slots│  → handled by proxy    │  No upgrade logic│
│              │  User calls:           │                  │
│              │  → delegated to impl   │                  │
└──────────────┘                        └──────────────────┘
```

### Storage Slots (EIP-1967)

```solidity
// Implementation address stored at:
bytes32 constant IMPLEMENTATION_SLOT =
    bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
// = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc

// Admin address stored at:
bytes32 constant ADMIN_SLOT =
    bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);
// = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
```

### How It Works

```solidity
contract TransparentProxy {
    fallback() external payable {
        if (msg.sender == admin) {
            // Admin functions: upgrade, changeAdmin
            _handleAdmin();
        } else {
            // User functions: delegate to implementation
            _delegate(implementation);
        }
    }
}
```

### Security Properties

| Property | Status | Notes |
|----------|--------|-------|
| Storage collision prevention | YES | EIP-1967 uses hashed slots |
| Admin/user separation | YES | Admin can't call impl functions |
| Upgrade authorization | Proxy-controlled | Admin address in proxy |
| Self-destruct risk | LOW | Upgrade in proxy, not impl |
| Gas overhead | HIGHER | Admin check on every call |

### Vulnerability Checklist

- [ ] Is admin stored at EIP-1967 slot (not slot 0)?
- [ ] Can admin accidentally call implementation functions? (Should NOT be possible)
- [ ] Is admin address a multisig or governance contract?
- [ ] Can admin be changed? Is `changeAdmin()` access-controlled?

---

## Pattern 2: UUPS (EIP-1822)

### Architecture

```
┌──────────────┐     delegatecall      ┌──────────────────┐
│    Proxy     │ ───────────────────→   │  Implementation  │
│              │                        │                  │
│ Minimal proxy│  ALL calls delegated   │  Business logic  │
│ No admin     │  to implementation     │  + upgrade logic │
│ logic        │                        │  _authorizeUpgrade│
└──────────────┘                        └──────────────────┘
```

### Key Difference from Transparent

Upgrade logic lives in the **implementation**, not the proxy. This makes the proxy simpler and cheaper, but introduces new risks.

### Security Properties

| Property | Status | Notes |
|----------|--------|-------|
| Storage collision prevention | YES | EIP-1967 slots |
| Upgrade authorization | **Implementation-controlled** | Must be in every version |
| Self-destruct risk | **HIGH** | If impl has selfdestruct, proxy breaks |
| Gas overhead | LOWER | No admin check per call |
| Upgrade continuity | **RISKY** | New impl MUST inherit UUPSUpgradeable |

### Critical Risks

```solidity
// RISK 1: Missing access control
function _authorizeUpgrade(address) internal override {
    // No check! Anyone can upgrade!
}

// RISK 2: Forgetting UUPSUpgradeable in new version
contract V2 { // Does NOT inherit UUPSUpgradeable
    // Proxy can never be upgraded again — BRICKED
}

// RISK 3: Selfdestruct on implementation
contract V1 is UUPSUpgradeable {
    function destroy() external onlyOwner {
        selfdestruct(payable(owner));
        // Destroys implementation → proxy broken forever
    }
}
```

### Vulnerability Checklist

- [ ] Does `_authorizeUpgrade()` have access control (onlyOwner/onlyRole)?
- [ ] Does every implementation version inherit `UUPSUpgradeable`?
- [ ] Is there a `selfdestruct` or `delegatecall` in the implementation?
- [ ] Does the constructor call `_disableInitializers()`?
- [ ] Can the upgrade function be front-run during deployment?

---

## Pattern 3: Beacon Proxy

### Architecture

```
┌──────────┐     ┌──────────┐     ┌──────────────────┐
│ Proxy A  │──→  │  Beacon  │──→  │  Implementation  │
├──────────┤     │          │     │                  │
│ Proxy B  │──→  │ Returns  │     │  Shared logic    │
├──────────┤     │ impl     │     │  for all proxies │
│ Proxy C  │──→  │ address  │     │                  │
└──────────┘     └──────────┘     └──────────────────┘
```

### How It Works

Multiple proxies point to a single beacon. The beacon stores the implementation address. Upgrading the beacon upgrades ALL proxies simultaneously.

### Security Properties

| Property | Status | Notes |
|----------|--------|-------|
| Batch upgrade | YES | One beacon update → all proxies upgraded |
| Individual proxy upgrade | NO | All proxies share same impl |
| Beacon authorization | CRITICAL | Must be tightly controlled |
| Gas overhead | MEDIUM | Extra SLOAD for beacon address |

### Vulnerability Checklist

- [ ] Who controls the beacon? Is it a multisig/governance?
- [ ] Can individual proxies be pointed to a different beacon?
- [ ] Is the beacon upgrade timelocked?
- [ ] What happens if the beacon is destroyed?

---

## Pattern 4: Diamond (EIP-2535)

### Architecture

```
┌──────────────┐     ┌─────────────────────────────┐
│   Diamond    │     │  Facets (multiple impls)     │
│              │     │                              │
│ Function     │     │  Facet A: functions 1-5      │
│ selector →   │──→  │  Facet B: functions 6-10     │
│ facet map    │     │  Facet C: functions 11-15    │
│              │     │                              │
│ diamondCut() │     │  Each facet has own code     │
└──────────────┘     └─────────────────────────────┘
```

### Security Properties

| Property | Status | Notes |
|----------|--------|-------|
| Granular upgrades | YES | Individual functions upgradeable |
| Selector management | COMPLEX | Must track selector→facet mapping |
| Storage management | COMPLEX | App storage or diamond storage pattern |
| Size limit bypass | YES | No 24KB contract limit |

### Vulnerability Checklist

- [ ] Is `diamondCut()` access-controlled?
- [ ] Can selectors collide between facets?
- [ ] Is storage shared safely between facets? (Diamond Storage vs App Storage)
- [ ] Can a facet's `selfdestruct` affect other facets?
- [ ] Is there a loupe facet for introspection?

---

## Pattern 5: Minimal Proxy (EIP-1167 Clone)

### Architecture

```
┌──────────────────────────────────────┐
│ Clone (45 bytes of bytecode)         │
│ 363d3d373d3d3d363d73{impl}5af43d82  │
│                                      │
│ Hardcoded implementation address     │
│ NOT upgradeable                      │
└──────────────────────────────────────┘
```

### Security Notes

- **Not upgradeable** — implementation address is hardcoded in bytecode
- **Cheap to deploy** — only 45 bytes
- **Shares implementation** — all clones use same code
- **Independent storage** — each clone has own storage

### Vulnerability Checklist

- [ ] Is the implementation contract safe from selfdestruct?
- [ ] Is the implementation properly initialized?
- [ ] Does each clone properly initialize its own state?

---

## Cross-Pattern Comparison

| Feature | Transparent | UUPS | Beacon | Diamond | Minimal |
|---------|------------|------|--------|---------|---------|
| Upgradeable | YES | YES | YES | YES | NO |
| Upgrade location | Proxy | Implementation | Beacon | Diamond | N/A |
| Storage collision risk | LOW (EIP-1967) | LOW (EIP-1967) | LOW | MEDIUM | LOW |
| Self-destruct risk | LOW | **HIGH** | LOW | MEDIUM | MEDIUM |
| Gas per call | Higher | Lower | Medium | Medium | Lowest |
| Complexity | Medium | Medium | Medium | **High** | Low |
| Multiple impls | NO | NO | NO | **YES** | NO |
| Batch upgrade | NO | NO | **YES** | NO | NO |
