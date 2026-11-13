// =====================================================================
// Agent authorization policies (Cedar).  The PDP is the system of record.
//
// Principals : Agent::"<entra app id>"     (the calling AI agent)
// Context    : on_behalf_of -> Human::"<upn>"   (only for delegated agents)
//              purpose      -> declared processing purpose (GDPR / AI Act)
//              human_approval -> true when a human approved this step
// Resources  : Column::"<TABLE>.<COLUMN>"   attributes come from Snowflake
//              RowScope::"<TABLE>/<REGION>" Horizon classification tags
// Actions    : read_column, read_rows
// =====================================================================

// ---------- 1. Agent registry gates (DORA ICT register / AI Act inventory)

// Kill switch: an agent that is not approved in the registry gets nothing.
@id("registry-kill-switch")
forbid (principal is Agent, action, resource)
when { !principal.approved };

// A delegated agent must always carry the human it acts for ...
@id("delegated-requires-human")
forbid (principal is Agent, action, resource)
when { principal.mode == "delegated" && !(context has on_behalf_of) };

// ... and an autonomous agent must never claim to act for a human
// (prevents confused-deputy privilege borrowing).
@id("autonomous-no-human")
forbid (principal is Agent, action, resource)
when { principal.mode == "autonomous" && context has on_behalf_of };

// ---------- 2. Column-level decisions

// Autonomous agents: bounded by their own registered ceiling.
@id("autonomous-column-read")
permit (principal is Agent, action == Action::"read_column", resource is Column)
when {
  principal.mode == "autonomous" &&
  principal.tables.contains(resource.table) &&
  resource.sensitivity <= principal.max_sensitivity
};

// Delegated agents: the INTERSECTION of agent ceiling and human clearance.
// An agent can never see more than the person it acts for.
@id("delegated-column-read")
permit (principal is Agent, action == Action::"read_column", resource is Column)
when {
  principal.mode == "delegated" &&
  context has on_behalf_of &&
  principal.tables.contains(resource.table) &&
  resource.sensitivity <= principal.max_sensitivity &&
  resource.sensitivity <= context.on_behalf_of.clearance
};

// Purpose limitation (GDPR Art. 5(1)(b)): personal data (Horizon privacy
// category IDENTIFIER / QUASI_IDENTIFIER) and any column with declared
// purposes only for a purpose the agent is registered for AND declared on
// this request. Personal data without declared purposes: never.
@id("purpose-limitation")
forbid (principal is Agent, action == Action::"read_column", resource is Column)
when {
  (resource.privacy_category == "IDENTIFIER" ||
   resource.privacy_category == "QUASI_IDENTIFIER" ||
   !resource.allowed_purposes.isEmpty()) &&
  !(context has purpose &&
    principal.purposes.contains(context.purpose) &&
    resource.allowed_purposes.contains(context.purpose))
};

// Human oversight (EU AI Act Art. 14): high-risk agents need an explicit
// human approval before touching the most sensitive data.
@id("ai-act-human-oversight")
forbid (principal is Agent, action == Action::"read_column", resource is Column)
when {
  principal.risk_tier == "high" &&
  resource.sensitivity >= 3 &&
  !(context has human_approval && context.human_approval)
};

// ---------- 3. Row-level decisions (data residency / book of business)

@id("autonomous-row-read")
permit (principal is Agent, action == Action::"read_rows", resource is RowScope)
when {
  principal.mode == "autonomous" &&
  principal.tables.contains(resource.table) &&
  principal.regions.contains(resource.region)
};

@id("delegated-row-read")
permit (principal is Agent, action == Action::"read_rows", resource is RowScope)
when {
  principal.mode == "delegated" &&
  context has on_behalf_of &&
  principal.tables.contains(resource.table) &&
  principal.regions.contains(resource.region) &&
  context.on_behalf_of.regions.contains(resource.region)
};
