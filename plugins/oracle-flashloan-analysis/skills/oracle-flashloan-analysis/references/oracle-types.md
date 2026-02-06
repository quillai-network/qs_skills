# Oracle Types — Classification and Trust Models

## Type 1: Chainlink Price Feeds

### How It Works

Off-chain oracle nodes aggregate prices from multiple exchanges and submit on-chain via decentralized oracle network. Updates occur on deviation threshold (e.g., 1% price change) or heartbeat interval.

### Interface

```solidity
interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
    function decimals() external view returns (uint8);
}
```

### Required Validations

```solidity
function getPrice() public view returns (uint256) {
    (
        uint80 roundId,
        int256 price,
        ,
        uint256 updatedAt,
        uint80 answeredInRound
    ) = priceFeed.latestRoundData();

    // CHECK 1: Price is positive
    require(price > 0, "Invalid price");

    // CHECK 2: Round is complete
    require(updatedAt > 0, "Incomplete round");

    // CHECK 3: Answer is from current round (not stale)
    require(answeredInRound >= roundId, "Stale price data");

    // CHECK 4: Price is recent (heartbeat check)
    require(block.timestamp - updatedAt <= MAX_PRICE_AGE, "Price too old");

    return uint256(price);
}
```

### Common Vulnerabilities

| Issue | Code Pattern | Severity |
|-------|-------------|----------|
| Using deprecated `latestAnswer()` | `oracle.latestAnswer()` | HIGH — no round validation |
| Missing staleness check | No `updatedAt` comparison | HIGH — hours-old price used |
| Missing negative price check | No `price > 0` | HIGH — negative price breaks math |
| Missing round completeness | No `answeredInRound >= roundId` | MEDIUM — incomplete round |
| Hardcoded feed address | No updateability | MEDIUM — can't rotate if feed deprecated |
| Wrong decimals assumption | Assuming 8 decimals always | MEDIUM — different feeds have different decimals |

### L2-Specific Concerns

On Arbitrum, Optimism, and other L2s, the sequencer can go down, causing stale prices:

```solidity
// Sequencer uptime feed check
(, int256 answer, , uint256 startedAt, ) = sequencerFeed.latestRoundData();
bool isSequencerUp = answer == 0;
require(isSequencerUp, "Sequencer is down");

uint256 timeSinceUp = block.timestamp - startedAt;
require(timeSinceUp > GRACE_PERIOD, "Grace period not over");
```

---

## Type 2: Uniswap V3 TWAP Oracle

### How It Works

Time-Weighted Average Price computed from accumulated tick values over a specified observation window. Resistant to single-block manipulation but vulnerable to sustained multi-block attacks.

### Interface

```solidity
// Uniswap V3 Pool
function observe(uint32[] calldata secondsAgos)
    external view returns (
        int56[] memory tickCumulatives,
        uint160[] memory secondsPerLiquidityCumulativeX128s
    );
```

### Price Calculation

```solidity
function getTWAP(uint32 twapInterval) public view returns (uint256) {
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = twapInterval; // e.g., 1800 for 30-minute TWAP
    secondsAgos[1] = 0;

    (int56[] memory tickCumulatives, ) = pool.observe(secondsAgos);

    int56 tickCumulativeDelta = tickCumulatives[1] - tickCumulatives[0];
    int24 arithmeticMeanTick = int24(tickCumulativeDelta / int56(int32(twapInterval)));

    return OracleLibrary.getQuoteAtTick(arithmeticMeanTick, baseAmount, baseToken, quoteToken);
}
```

### Manipulation Cost Analysis

```
Cost to manipulate TWAP ≈ (pool_liquidity × price_deviation × window_length) / block_time

Example:
  Pool liquidity: $10M
  Desired manipulation: 10% price change
  TWAP window: 30 minutes (150 blocks at 12s)
  Approximate cost: $10M × 10% × (1/150) ≈ $6,667 per block of manipulation
  Total for 30-min TWAP: ~$1M in capital lockup + trading losses

  For 5-minute TWAP: ~$200K → much more feasible
```

### Window Length Risk Assessment

| Window | Risk Level | Notes |
|--------|-----------|-------|
| < 5 min | CRITICAL | Easily manipulated with moderate capital |
| 5-15 min | HIGH | Feasible for well-funded attackers |
| 15-30 min | MEDIUM | Expensive but possible |
| 30-60 min | LOW | Very expensive sustained manipulation |
| > 60 min | VERY LOW | Impractical for most attackers |

---

## Type 3: AMM Spot Price (CRITICAL RISK)

### How It Works

Reads current reserves from an AMM pool and calculates price as `reserveA / reserveB`. This is the **most dangerous** oracle type because it can be manipulated within a single transaction via flash loans.

### Vulnerable Patterns

```solidity
// DANGEROUS: Spot price from Uniswap V2
function getPrice() public view returns (uint256) {
    (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
    return uint256(reserve1) * 1e18 / uint256(reserve0);
}

// DANGEROUS: Spot price from Uniswap V3
function getPrice() public view returns (uint256) {
    (uint160 sqrtPriceX96, , , , , , ) = pool.slot0();
    return (uint256(sqrtPriceX96) ** 2 * 1e18) >> 192;
}

// DANGEROUS: Price from contract balance
function getPrice() public view returns (uint256) {
    return address(this).balance * 1e18 / totalSupply;
}
```

### Why It's Dangerous

```
Normal state:
  Pool: 1000 ETH + 2,000,000 USDC → Price = 2000 USDC/ETH

Flash loan attack (single transaction):
  1. Flash borrow 10,000 ETH
  2. Swap 9,000 ETH into pool → Pool: 10,000 ETH + 220,000 USDC
  3. Spot price now: 22 USDC/ETH (90% drop!)
  4. Exploit protocol using crashed price
  5. Swap back, repay flash loan
  6. All in one transaction, one block
```

---

## Type 4: Custom / Admin-Controlled Oracle

### Pattern

```solidity
contract CustomOracle {
    address public admin;
    mapping(address => uint256) public prices;

    function setPrice(address token, uint256 price) external {
        require(msg.sender == admin, "Not admin");
        prices[token] = price;
    }

    function getPrice(address token) external view returns (uint256) {
        return prices[token];
    }
}
```

### Risks

| Risk | Severity | Description |
|------|----------|-------------|
| Admin key compromise | CRITICAL | Attacker sets arbitrary prices → instant protocol drain |
| No update mechanism | HIGH | Price goes stale if admin fails to update |
| Single point of failure | HIGH | One admin controls all pricing |
| No validation | MEDIUM | Admin can set zero or extreme prices |
| No timelock | MEDIUM | Price changes take effect immediately |

---

## Type 5: On-Chain Calculated Price (Self-Referencing)

### Pattern

```solidity
function getSharePrice() public view returns (uint256) {
    return totalAssets() / totalSupply();
}

function totalAssets() public view returns (uint256) {
    return asset.balanceOf(address(this)); // Donation-attackable!
}
```

### Risks

- **Donation attack**: Attacker sends tokens directly to contract, inflating `totalAssets` without minting shares
- **First depositor attack (ERC4626 inflation)**: Attacker manipulates share price for rounding exploitation
- **Self-referencing**: Protocol actions (deposit/withdraw) change the price used by the protocol itself

---

## Oracle Comparison Matrix

| Oracle Type | Flash Loan Resistant | Multi-Block Resistant | Decentralized | Cost |
|-------------|---------------------|----------------------|---------------|------|
| Chainlink (validated) | YES | YES | YES | Feed fees |
| Uniswap V3 TWAP (30m+) | YES | MOSTLY | YES | Gas only |
| Uniswap V2 TWAP (short) | YES | NO | YES | Gas only |
| AMM spot price | **NO** | **NO** | YES | Gas only |
| balanceOf() pricing | **NO** | **NO** | N/A | Gas only |
| Admin-controlled | YES (if honest) | YES (if honest) | **NO** | Manual |
| Multi-oracle consensus | YES | YES | YES | Highest |
