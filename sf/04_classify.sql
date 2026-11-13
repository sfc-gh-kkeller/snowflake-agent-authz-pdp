-- =====================================================================
-- Horizon classification + directory upkeep (run as ACCOUNTADMIN by deploy).
-- =====================================================================
USE ROLE ACCOUNTADMIN;

-- Sync identity may stamp PDP_RESOURCE_ID on newly found columns so that
-- every column in governed schemas is covered by the PDP masking policy
-- (an unstamped column would otherwise be invisible to the PDP).
GRANT APPLY TAG ON ACCOUNT TO ROLE AGENT_AUTHZ_SYNC;
GRANT OWNERSHIP ON TABLE AGENT_AUTHZ_DEMO.GOVERNANCE.USER_DIRECTORY TO ROLE AGENT_AUTHZ_ADMIN COPY CURRENT GRANTS;

-- Directory of identities that may carry agent sessions. In production a
-- SCIM-provisioned set; here derived from the users the demo created.
USE ROLE AGENT_AUTHZ_ADMIN;
TRUNCATE TABLE AGENT_AUTHZ_DEMO.GOVERNANCE.USER_DIRECTORY;
INSERT INTO AGENT_AUTHZ_DEMO.GOVERNANCE.USER_DIRECTORY VALUES
  ('${DEMO_USER_UPN_UPPER}', '${DEMO_SNOWFLAKE_USER}'),
  ('${SENTINEL_SP_OID_UPPER}', 'FRAUD_SENTINEL_AGENT'),
  ('${GENIE_SP_OID_UPPER}',    'MARKETING_GENIE_AGENT');

-- Horizon sensitive-data classification: sets SNOWFLAKE.CORE.SEMANTIC_CATEGORY
-- and SNOWFLAKE.CORE.PRIVACY_CATEGORY system tags. The PDP harvests
-- PRIVACY_CATEGORY (IDENTIFIER / QUASI_IDENTIFIER / SENSITIVE) as an attribute.
CALL SYSTEM$CLASSIFY('AGENT_AUTHZ_DEMO.BANKING.CUSTOMERS',    {'auto_tag': true});
CALL SYSTEM$CLASSIFY('AGENT_AUTHZ_DEMO.BANKING.TRANSACTIONS', {'auto_tag': true});
