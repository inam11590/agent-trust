# Loop & Depth Protection Specifications

## Threat Model
In autonomous agent ecosystems, agent delegation and service chains can inadvertently form recursion cycles:
- Direct recursion: Agent A invokes Agent A.
- Mutual recursion: Agent A invokes Agent B, which invokes Agent A.
- Multi-hop cycle: $A \to B \to C \to D \to A$.

These cycles lead to resource exhaustion, runaway API billing, and deadlocks.

## Prevention Mechanism
### 1. Provable Call Chain Header
Every agent invocation carries an immutable provenance header:
```http
X-AgentTrust-Call-Chain: agt_coordinator,agt_analyzer,agt_db_reader
```
When an agent attempts to invoke a target, the gateway inspects the call chain. If the target agent ID is already an element in the chain, execution is blocked immediately:
- **Status Code**: `409 Conflict`
- **Error Code**: `CALL_LOOP_DETECTED`
- **Security Center Event**: `call_loop_detected` emitted with high severity.

### 2. Bounded Call Depth
To prevent arbitrarily deep call chains that degrade performance, every request tracks depth:
```http
X-AgentTrust-Depth: 3
```
- Maximum permitted depth: **5** (configurable).
- Any call with `depth >= 5` is rejected:
  - **Status Code**: `429 Too Many Requests`
  - **Error Code**: `MAX_CALL_DEPTH_EXCEEDED`
  - **Security Center Event**: `call_depth_exceeded`.
