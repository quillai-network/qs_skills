# Storage Collision Detection — Algorithm Reference

## Solidity Storage Layout Rules

### Basic Types

| Type | Size | Slots Used |
|------|------|------------|
| `bool` | 1 byte | 1 (packed with adjacent small types) |
| `uint8`-`uint256` | 1-32 bytes | 1 slot for 32 bytes; smaller types pack |
| `int8`-`int256` | 1-32 bytes | Same as uint |
| `address` | 20 bytes | 1 (can pack with 12 bytes of others) |
| `bytes1`-`bytes32` | 1-32 bytes | 1 slot |
| `enum` | 1 byte (usually) | Packed |

### Complex Types

| Type | Slot Calculation |
|------|-----------------|
| Fixed array `T[N]` | N consecutive slots (or packed) |
| Dynamic array `T[]` | Length at slot `p`; elements at `keccak256(p) + i` |
| `mapping(K => V)` | Slot `p` unused; value at `keccak256(k . p)` |
| `struct` | Members packed sequentially starting at struct's slot |
| `string` / `bytes` | Short (≤31 bytes): stored in slot `p`; Long: length at `p`, data at `keccak256(p)` |

### Packing Rules

Variables are packed into a single 32-byte slot when possible:

```solidity
contract Packed {
    uint128 a;  // slot 0, bytes 0-15
    uint128 b;  // slot 0, bytes 16-31  (packed with a)
    uint256 c;  // slot 1 (too large to pack)
    uint8 d;    // slot 2, byte 0
    address e;  // slot 2, bytes 1-20 (packed with d)
    bool f;     // slot 2, byte 21 (packed with d and e)
    uint256 g;  // slot 3
}
```

---

## Storage Layout Extraction Algorithm

### Step 1: Parse Contract Hierarchy

```
For contract C:
  1. Resolve inheritance chain via C3 linearization
  2. Process state variables in order: base → derived
  3. Include all inherited contracts' state variables

Example:
  contract A { uint256 x; }           // slot 0
  contract B is A { uint256 y; }      // slot 1
  contract C is B { uint256 z; }      // slot 2

  C's layout: [x @ slot 0, y @ slot 1, z @ slot 2]
```

### Step 2: Build Slot Map

```python
def build_storage_layout(contract):
    layout = {}
    current_slot = 0
    current_offset = 0  # bytes within current slot

    for var in contract.state_variables_in_order():
        size = get_byte_size(var.type)

        # Check if variable fits in current slot
        if current_offset + size > 32:
            current_slot += 1
            current_offset = 0

        layout[var.name] = {
            'slot': current_slot,
            'offset': current_offset,
            'size': size,
            'type': var.type
        }

        # Special handling for complex types
        if is_dynamic_array(var.type) or is_mapping(var.type):
            current_slot += 1  # These take a full slot (length or unused)
            current_offset = 0
        elif is_struct(var.type):
            current_slot += struct_slots(var.type)
            current_offset = 0
        else:
            current_offset += size
            if current_offset >= 32:
                current_slot += 1
                current_offset = 0

    return layout
```

### Step 3: Compare Layouts

```python
def detect_collisions(layout_a, layout_b):
    collisions = []

    for var_a_name, var_a in layout_a.items():
        for var_b_name, var_b in layout_b.items():
            if var_a['slot'] == var_b['slot']:
                # Same slot — check for overlap
                a_start = var_a['offset']
                a_end = a_start + var_a['size']
                b_start = var_b['offset']
                b_end = b_start + var_b['size']

                if a_start < b_end and b_start < a_end:
                    # Overlapping bytes in same slot
                    if var_a['type'] != var_b['type'] or var_a_name != var_b_name:
                        collisions.append({
                            'slot': var_a['slot'],
                            'var_a': var_a_name,
                            'var_b': var_b_name,
                            'type_a': var_a['type'],
                            'type_b': var_b['type'],
                            'severity': classify_severity(var_a, var_b)
                        })

    return collisions
```

---

## Collision Severity Classification

| Collision Type | Severity | Impact |
|---------------|----------|--------|
| Admin/owner slot vs user data | CRITICAL | Attacker can overwrite admin |
| Implementation slot vs user data | CRITICAL | Attacker can change implementation |
| Financial variable vs any variable | CRITICAL | Balance/supply corruption |
| Same-type reordering | HIGH | Data read from wrong variable |
| Type mismatch (same semantics) | HIGH | Truncation, misinterpretation |
| Gap variable collision | MEDIUM | Reserved space violated |
| Metadata collision | LOW | Non-critical data corruption |

---

## Gap Pattern for Safe Upgrades

### Standard Gap Pattern

```solidity
contract BaseContractV1 {
    uint256 public value;
    address public admin;

    // Reserve 50 slots for future variables
    uint256[48] private __gap; // 50 - 2 used = 48 remaining
}

contract BaseContractV2 {
    uint256 public value;      // slot 0 — unchanged
    address public admin;      // slot 1 — unchanged
    bool public paused;        // slot 2 — NEW (was first __gap slot)

    uint256[47] private __gap; // 50 - 3 used = 47 remaining
}
```

### Gap Verification Algorithm

```python
def verify_gap_safety(v1_layout, v2_layout):
    # 1. All V1 variables must be in same position in V2
    for var_name, var_v1 in v1_layout.items():
        if var_name == '__gap':
            continue
        if var_name not in v2_layout:
            return Error(f"Variable {var_name} removed in V2")
        var_v2 = v2_layout[var_name]
        if var_v1['slot'] != var_v2['slot']:
            return Error(f"Variable {var_name} moved from slot {var_v1['slot']} to {var_v2['slot']}")
        if var_v1['type'] != var_v2['type']:
            return Error(f"Variable {var_name} type changed: {var_v1['type']} → {var_v2['type']}")

    # 2. New variables must be in gap space or after all V1 slots
    # 3. Gap must be reduced by exactly the number of new slots used
    # 4. Total slots (variables + gap) must remain constant
```

---

## EIP-1967 Slot Verification

### Standard Slots

```solidity
// Implementation slot
keccak256("eip1967.proxy.implementation") - 1
= 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc

// Admin slot
keccak256("eip1967.proxy.admin") - 1
= 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103

// Beacon slot
keccak256("eip1967.proxy.beacon") - 1
= 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50
```

### Verification

```
For each proxy contract:
  1. Check if implementation is stored at EIP-1967 slot (not slot 0/1/2)
  2. If stored at regular slot → HIGH RISK of collision with implementation variables
  3. Verify admin is stored at EIP-1967 admin slot
  4. For beacon proxies: verify beacon at EIP-1967 beacon slot
```

---

## Common Collision Scenarios

### Scenario 1: Inherited Contract Reordering

```solidity
// V1
contract V1 is OwnableUpgradeable, PausableUpgradeable {
    uint256 public value; // After Ownable + Pausable slots
}

// V2 — DANGEROUS: swapped inheritance order
contract V2 is PausableUpgradeable, OwnableUpgradeable {
    uint256 public value; // Ownable and Pausable slots are now different!
}
```

### Scenario 2: Struct Modification

```solidity
// V1
struct UserInfo {
    uint256 balance;
    uint256 lastUpdate;
}

// V2 — DANGEROUS: added field in middle of struct
struct UserInfo {
    uint256 balance;
    address token;      // NEW — shifts lastUpdate
    uint256 lastUpdate; // Now at wrong slot!
}
```

### Scenario 3: Enum Expansion

```solidity
// V1
enum Status { Active, Paused }  // 0, 1

// V2 — DANGEROUS if inserted before existing values
enum Status { Pending, Active, Paused }  // Pending=0, Active=1, Paused=2
// All stored Active (1) values now mean "Active" but were stored as Active in V1
// If insertion is at start, 0 (was Active) now means Pending
```

**Safe enum expansion:** Always append new values at the end.
