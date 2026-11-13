USE ROLE ACCOUNTADMIN;

-- ---------------------------------------------------------------------
-- Identity: one agentic External OAuth integration for Entra ID.
--   delegated tokens  -> map `upn` to the human's LOGIN_NAME
--   workload tokens   -> map `sub` (service principal object id)
--   IS_AGENTIC = TRUE -> every session is marked agent-driven, so
--                        IS_AGENT_ACTIVATED() is TRUE in policies.
-- Roles come from the token (scp / roles); role switching is disabled.
-- ---------------------------------------------------------------------
CREATE OR REPLACE SECURITY INTEGRATION AGENT_AUTHZ_ENTRA
  TYPE = EXTERNAL_OAUTH
  ENABLED = TRUE
  EXTERNAL_OAUTH_TYPE = AZURE
  EXTERNAL_OAUTH_ISSUER = 'https://sts.windows.net/${ENTRA_TENANT_ID}/'
  EXTERNAL_OAUTH_JWS_KEYS_URL = 'https://login.microsoftonline.com/${ENTRA_TENANT_ID}/discovery/v2.0/keys'
  EXTERNAL_OAUTH_AUDIENCE_LIST = ('${ENTRA_RESOURCE_APP_URI}')
  EXTERNAL_OAUTH_TOKEN_USER_MAPPING_CLAIM = ('upn', 'sub')
  EXTERNAL_OAUTH_SNOWFLAKE_USER_MAPPING_ATTRIBUTE = 'LOGIN_NAME'
  EXTERNAL_OAUTH_ANY_ROLE_MODE = 'DISABLE'
  EXTERNAL_OAUTH_ALLOWED_ROLES_LIST = ('AGENT_ADVISOR_COPILOT', 'AGENT_FRAUD_SENTINEL', 'AGENT_MARKETING_GENIE')
  IS_AGENTIC = TRUE
  COMMENT = 'Entra ID agents (OBO + client credentials) governed by the external PDP';

