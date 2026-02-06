# Bayesian Confidence Scoring — Detailed Reference

## Formula

```
Confidence = (Evidence_Strength × Exploit_Feasibility × Impact_Severity) / False_Positive_Rate
```

## Evidence Strength (0-1)

| Score | Criteria | Example |
|-------|----------|---------|
| 1.0 | Concrete code path identified with no external dependencies | Direct reentrancy with no guard |
| 0.7 | Code path depends on specific but achievable state conditions | Reentrancy requiring specific balance threshold |
| 0.4 | Theoretical vulnerability based on code patterns | Potential front-running based on transaction ordering |
| 0.1 | Heuristic suggestion without concrete evidence | "This pattern sometimes leads to issues" |

## Exploit Feasibility (0-1)

| Score | Criteria | Example |
|-------|----------|---------|
| 1.0 | Auto-generated PoC successfully executes | Foundry test passes, funds drained |
| 0.7 | Exploit requires specific contract state but is achievable | Needs specific liquidity ratio |
| 0.4 | Exploit requires external conditions | Needs oracle manipulation or MEV infrastructure |
| 0.1 | Theoretically possible but practically infeasible | Requires 51% hash power |

## Impact Severity (1-5)

| Score | Level | Description | Examples |
|-------|-------|-------------|----------|
| 5 | Critical | Complete loss of funds or system compromise | Contract drain, proxy takeover |
| 4 | High | Significant loss or privilege escalation | Partial drain, admin access gained |
| 3 | Medium | Griefing, temporary DOS | Block operations temporarily, grief users |
| 2 | Low | Information leakage or minor inconsistency | Leak internal state, minor accounting drift |
| 1 | Info | Best practice violation | Missing events, suboptimal patterns |

## False Positive Rate Estimation

Estimate based on:

- **Pattern strength**: How many similar patterns are confirmed vulnerabilities historically?
- **Context specificity**: Is this specific to this contract's design, or a generic pattern?
- **Compensating controls**: Are there other mechanisms that mitigate the risk?

Typical false positive rates:
- Well-known patterns (reentrancy without guard): 5%
- Moderate patterns (access control gaps): 15%
- Weak patterns (potential front-running): 40%
- Heuristic suggestions: 60%

## Scoring Examples

### Example 1: High Confidence

```
Finding: Reentrancy in withdraw()
Evidence_Strength: 1.0 (concrete code path, ETH sent before balance update)
Exploit_Feasibility: 1.0 (PoC confirmed in Foundry)
Impact_Severity: 5 (complete contract drain)
False_Positive_Rate: 0.05
Confidence: (1.0 × 1.0 × 5) / 0.05 = 100 → capped at 99%
```

### Example 2: Medium Confidence

```
Finding: Potential front-running in auction
Evidence_Strength: 0.7 (depends on mempool visibility)
Exploit_Feasibility: 0.6 (requires MEV infrastructure)
Impact_Severity: 3 (user griefing)
False_Positive_Rate: 0.3
Confidence: (0.7 × 0.6 × 3) / 0.3 = 4.2 → normalize to 42%
```

### Example 3: Low Confidence

```
Finding: Gas optimization suggestion
Evidence_Strength: 0.4 (pattern-based)
Exploit_Feasibility: 0.1 (no exploit, just inefficiency)
Impact_Severity: 1 (info only)
False_Positive_Rate: 0.5
Confidence: (0.4 × 0.1 × 1) / 0.5 = 0.08 → 8%
```

## Prioritization Rules

1. **Report all findings** with Confidence ≥ 10%
2. **Highlight Critical** findings with Confidence ≥ 70%
3. **Flag for Review** findings between 30-70%
4. **Appendix** findings below 30%
5. **Never suppress** any finding with Impact_Severity ≥ 4, regardless of confidence
