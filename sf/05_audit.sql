-- =====================================================================
-- Audit evidence (DORA Art. 9/12 ICT logging, EU AI Act Art. 12/19 logs)
--
-- One row per agent query, joining
--   * the PDP decision log  (who decided, which Cedar policy, policy hash)
--   * Snowflake QUERY_HISTORY (query, user, role, agent type)
--   * Snowflake ACCESS_HISTORY (objects/columns actually read, agent chain)
-- via the PDP batch ids the gateway puts in QUERY_TAG.
-- ACCOUNT_USAGE has ingestion latency (minutes to hours): use the
-- INFORMATION_SCHEMA variant in the live demo.
-- =====================================================================
USE ROLE AGENT_AUTHZ_ADMIN;
USE SCHEMA AGENT_AUTHZ_DEMO.GOVERNANCE;

CREATE OR REPLACE VIEW AGENT_AUDIT_TRAIL AS
WITH q AS (
  SELECT qh.query_id, qh.start_time, qh.user_name, qh.role_name, qh.agent_type,
         qh.query_text, qh.rows_produced,
         TRY_PARSE_JSON(qh.query_tag) AS tag
  FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY qh
  WHERE qh.database_name = 'AGENT_AUTHZ_DEMO'
    AND TRY_PARSE_JSON(qh.query_tag):pdp_batches IS NOT NULL
)
SELECT
  q.query_id, q.start_time, q.user_name, q.role_name, q.agent_type,
  q.tag:agent::STRING   AS agent,
  q.tag:purpose::STRING AS purpose,
  q.query_text, q.rows_produced,
  ah.agents_info,
  ah.base_objects_accessed,
  ARRAY_AGG(OBJECT_CONSTRUCT(
      'decision_id', d.decision_id, 'resource', d.resource_id, 'permit', d.decision,
      'policies', d.determining_policies)) AS pdp_decisions,
  ANY_VALUE(d.policy_hash)  AS policy_hash,
  ANY_VALUE(d.on_behalf_of) AS on_behalf_of,
  ANY_VALUE(d.risk_tier)    AS ai_act_risk_tier
FROM q
JOIN PDP_DECISIONS d
  ON ARRAY_CONTAINS(d.batch_id::VARIANT, q.tag:pdp_batches)
LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY ah
  ON ah.query_id = q.query_id
GROUP BY ALL;

-- Decisions per agent / policy: model-risk and AI Act post-market monitoring
CREATE OR REPLACE VIEW AGENT_DECISION_SUMMARY AS
SELECT agent, risk_tier, action, decision,
       f.value::STRING AS determining_policy,
       COUNT(*) AS decisions, MIN(ts) AS first_seen, MAX(ts) AS last_seen
FROM PDP_DECISIONS, LATERAL FLATTEN(input => determining_policies, outer => TRUE) f
GROUP BY ALL;
