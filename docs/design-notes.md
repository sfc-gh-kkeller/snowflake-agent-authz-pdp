# Design notes

## 1. Three ways to connect an external PDP to Snowflake, and why this demo combines two

| Pattern | How | Strength | Weakness |
|---|---|---|---|
| **A. Decision at the gateway** | PEP calls the PDP per tool call, then queries Snowflake | Finest granularity; full request context (purpose, approval) | Only as strong as the gateway; bypassable with a valid token |
| **B. Decision at token issuance** | PDP shapes the token (role scope, OAuth token exchange with a Restricted Session Scope) | Snowflake enforces it natively; no runtime dependency | Session-level only; cannot express per-column, per-purpose decisions |
| **C. Decisions as data in Snowflake** | PDP decisions are materialised in Snowflake and enforced by Horizon policies | Holds even if the gateway is bypassed; fail-closed in the engine | Needs a sync channel and freshness handling |

The demo uses **A + C**: the gateway asks at the finest granularity, and the PDP **pushes each permit as a session-bound decision grant** that Snowflake's tag-based masking and row access policies require. Pattern **B** is used where it fits: the role comes from the Entra token (`scp` / app roles, no role switching), and a read-only Restricted Session Scope caps every agent session regardless of what the PDP permits.

An earlier iteration compiled the Cedar policies into a static per-(agent, user) entitlement ceiling. That was dropped because a bypassing agent could still get everything in the ceiling, without the per-request purpose and approval checks.

## 2. Identity binding

- **Delegated agents.** Entra On-Behalf-Of produces a token with `appid` (the agent) and `upn` (the human). Snowflake maps `upn` to the human's `LOGIN_NAME`, so the session belongs to the human, is marked agentic, and runs with the agent's role. `CURRENT_USER()` is the human, and the agent is visible through `IS_AGENT_ACTIVATED`, the role and the PDP decision.
- **Autonomous agents.** Client-credentials tokens carry `sub` = the service principal's object id. Snowflake maps it to a `SERVICE_AGENT` user whose `LOGIN_NAME` is that object id.
- One External OAuth integration handles both modes: `EXTERNAL_OAUTH_TOKEN_USER_MAPPING_CLAIM = ('upn', 'sub')`.
- The PDP validates the same Entra token (signature, issuer, audience) and derives the principal from it. The AuthZEN `subject.id` must match the token's `appid`; the PEP cannot speak for another agent.
- The human's clearance comes from the PDP store, never from the request.
- Decision grants bind to `CURRENT_SESSION()`, the token identity (through `USER_DIRECTORY`) and `CURRENT_ROLE()`. A grant issued for one session does not unlock another.

Known gap, by design of the platform: an agent that logs in as a regular user with a password, PAT or key pair is **not** recognised as an agent. Route agents through agentic OAuth or `SERVICE_AGENT` users, and consider a Trust Center detection or authentication policy for that path.

## 3. Fail-closed semantics

| Layer | Behaviour when the PDP is unavailable |
|---|---|
| Gateway | `FailClosed`: no SQL is executed |
| PDP itself | If writing grants to Snowflake fails, every permit in that response is turned into a deny |
| Snowflake | No new grants; existing grants expire (`PDP_GRANT_TTL_SECONDS`, 300 s here); once `PDP_SYNC_STATE.LAST_HEARTBEAT` is older than `MAX_STALENESS_MINUTES` (2 here) all agent access is masked or filtered, including live grants |
| Humans | Unaffected: the policies only act when `IS_AGENT_ACTIVATED` is true |

## 4. Granularity

- **Columns:** one AuthZEN evaluation per column (`/access/v1/evaluations`, `execute_all`).
- **Rows:** one evaluation per row scope via AuthZEN resource search (`/access/v1/search/resource`). Row scopes come from the values of the column tagged `ROW_SCOPE_COLUMN` (region here).
- Purpose and human approval are per-request context, so the same agent can get different answers for the same column within a session.
- The row-scope column itself is not masked: it is a row access policy argument, and Snowflake does not allow a masked column there.

## 5. Classification as the source of resource attributes

The PDP is the system of record for *who may do what*. Snowflake Horizon is the system of record for *what the data is*:

- `DATA_SENSITIVITY` (owner-set) becomes `resource.sensitivity` (0–3; unclassified columns get 3).
- `SNOWFLAKE.CORE.PRIVACY_CATEGORY` (set by `SYSTEM$CLASSIFY`) becomes `resource.privacy_category`.
- `ALLOWED_PURPOSES` (owner-set) becomes `resource.allowed_purposes`.

`DATA_SENSITIVITY` uses `PROPAGATE = ON_DEPENDENCY_AND_DATA_MOVEMENT`, so classification follows data into derived tables. It is also the tag that carries the Data Movement Policy.

## 6. Production hardening checklist

- **PDP:** highly available (at least two instances), signed policy bundles, change control on `agents.cedar`, Cedar schema validation in CI, a policy test suite gate, mTLS between PEP and PDP.
- **Decision grants:** a hybrid table (low-latency point writes) where the account supports it; the demo account uses Tri-Secret Secure without dedicated storage, so it uses a standard table. A dedicated warehouse for the PDP sink. A clean-up task.
- **Approvals:** replace the `human_approval` boolean with a signed approval token (for example from the bank's workflow tool) verified by the PDP.
- **Directory:** feed `USER_DIRECTORY` and human clearances from SCIM / IGA rather than static data.
- **Sync:** run `horizon_to_pdp.py` on a schedule. Snowflake event-driven alternatives include a task on `INFORMATION_SCHEMA` changes.
- **Detection:** enable the Trust Center AI Security and Data Security scanner packages; alert on `DATA_MOVEMENT_VIOLATIONS`, on agent sessions with zero grants (bypass attempts), and on PDP heartbeat staleness.
- **Snowflake-native agents:** Cortex Agents and the managed MCP server are also marked agentic, so the same policies apply to them. Without a PEP in front they get no decision grants, so they see nothing until a PEP path is added (for example a custom tool procedure that calls the PDP through an external access integration).
