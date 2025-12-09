// resources-server.js
// Lightweight HTTP API for SAIQUE AI (#1082) knowledge resources.
// Designed to run on Render / Railway / any Node host.

// 1) Setup
require("dotenv").config();
const express = require("express");
const cors = require("cors");

const app = express();

// Render (and most PaaS) provide PORT via env var
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

// Common metadata helper
function makeResponse(data, metaExtra = {}) {
  return {
    ok: true,
    data,
    meta: {
      source: "SAIQUE AI resources server",
      version: "1.0.0",
      ...metaExtra,
      timestamp_utc: new Date().toISOString()
    }
  };
}

// -------------------------------------------------------------
// In-memory “databases” for SAIQUE resources
// -------------------------------------------------------------

// 1) Vulnerability / finding knowledge base
// Keys are aligned with IDs used in seller.js (findings, threats, risks).
const VULN_DB = {
  // ---- Smart contract static pattern analysis ----
  missing_pragma: {
    id: "missing_pragma",
    title: "Solidity pragma version not specified",
    severity_default: "medium",
    description:
      "The contract does not declare a fixed Solidity pragma version, which can lead to different compiler behavior over time.",
    remediation:
      "Pin an explicit compiler version such as `pragma solidity 0.8.24;` and align it with your audit and build pipeline."
  },

  untrusted_delegatecall: {
    id: "untrusted_delegatecall",
    title: "Untrusted delegatecall target",
    severity_default: "critical",
    description:
      "Using delegatecall with untrusted or user-controlled target addresses can give attackers full control over contract storage and funds.",
    remediation:
      "Restrict delegatecall to immutable, audited implementations and never allow user-supplied delegatecall targets. Control upgrades via secure governance."
  },
  // Backwards-compat alias for older naming
  delegatecall_untrusted: {
    id: "delegatecall_untrusted",
    title: "Untrusted delegatecall target",
    severity_default: "critical",
    description:
      "Using delegatecall with untrusted or user-controlled target addresses can give attackers full control over contract storage and funds.",
    remediation:
      "Restrict delegatecall to immutable, audited implementations and never allow user-supplied delegatecall targets. Control upgrades via secure governance."
  },

  tx_origin_auth: {
    id: "tx_origin_auth",
    title: "Authorization using tx.origin",
    severity_default: "high",
    description:
      "Relying on tx.origin for authorization enables phishing-style attacks where a victim is tricked into calling a malicious contract.",
    remediation:
      "Always rely on msg.sender for authorization and use role-based access patterns such as Ownable or AccessControl. Avoid tx.origin in access control."
  },

  unrestricted_selfdestruct: {
    id: "unrestricted_selfdestruct",
    title: "Unrestricted selfdestruct",
    severity_default: "high",
    description:
      "Exposing selfdestruct in externally callable paths can permanently destroy a contract and its functionality, potentially locking or redirecting funds.",
    remediation:
      "Remove selfdestruct from production contracts, or gate it behind strict multi-sig governance and emergency procedures with clear criteria for use."
  },
  // Backwards-compat alias
  selfdestruct_unrestricted: {
    id: "selfdestruct_unrestricted",
    title: "Unrestricted selfdestruct",
    severity_default: "high",
    description:
      "Exposing selfdestruct in externally callable paths can permanently destroy a contract and its functionality, potentially locking or redirecting funds.",
    remediation:
      "Remove selfdestruct from production contracts, or gate it behind strict multi-sig governance and emergency procedures with clear criteria for use."
  },

  low_level_call_value: {
    id: "low_level_call_value",
    title: "Low-level call with value transfer",
    severity_default: "high",
    description:
      "Using low-level call with value transfer (`call{value: ...}` or `.call.value(...)`) can introduce reentrancy risks and complex error handling.",
    remediation:
      "Use checks-effects-interactions, consider ReentrancyGuard, validate call return values, and prefer pull-based withdrawal patterns where possible."
  },

  timestamp_dependency: {
    id: "timestamp_dependency",
    title: "Timestamp-dependent logic",
    severity_default: "medium",
    description:
      "Using block.timestamp/now for critical business logic or randomness can be abused by miners within a limited range.",
    remediation:
      "Avoid timestamps for randomness, and design time windows with documented assumptions and acceptable drift. Consider block.number-based windows where appropriate."
  },

  upgradeable_proxy: {
    id: "upgradeable_proxy",
    title: "Upgradeable proxy governance risk",
    severity_default: "medium",
    description:
      "Upgradeable proxy patterns centralize control over implementation logic, creating governance and key management risks.",
    remediation:
      "Control upgrades with a multi-sig or robust governance process, use timelocks for sensitive changes, and clearly document upgrade policies."
  },

  no_access_control_modifiers: {
    id: "no_access_control_modifiers",
    title: "Missing explicit access control modifiers",
    severity_default: "medium",
    description:
      "The contract does not appear to use standard access control modifiers like onlyOwner/onlyRole, increasing the risk of unintentionally exposed functions.",
    remediation:
      "Review all privileged functions, apply battle-tested access control (Ownable/AccessControl), and ensure tests enforce expected permissions."
  },

  potential_reentrancy_pattern: {
    id: "potential_reentrancy_pattern",
    title: "Potential reentrancy-sensitive pattern",
    severity_default: "medium",
    description:
      "The combination of external calls with state updates hints at a possible reentrancy risk, depending on call ordering and guards.",
    remediation:
      "Enforce checks-effects-interactions, add reentrancy guards where appropriate, and extend tests to cover reentry scenarios."
  },

  no_pattern_hits: {
    id: "no_pattern_hits",
    title: "No high-risk patterns detected by heuristic scan",
    severity_default: "info",
    description:
      "The static heuristic scan did not match typical high-risk Solidity patterns, but this does not guarantee the absence of vulnerabilities.",
    remediation:
      "Treat this as a starting point only: run deeper manual review, fuzzing, and consider a full audit for high-value contracts."
  },

  // ---- DevOps / CI-CD pipeline review ----
  privileged_containers: {
    id: "privileged_containers",
    title: "Privileged or privilege-escalating CI jobs",
    severity_default: "high",
    description:
      "CI jobs running with privileged containers or enabled privilege escalation can lead to host/runner compromise if abused.",
    remediation:
      "Remove privileged flags where possible, isolate runners handling untrusted workloads, and enforce least-privilege securityContext."
  },

  latest_image_tag: {
    id: "latest_image_tag",
    title: "Use of mutable :latest container tags",
    severity_default: "medium",
    description:
      "Using :latest in CI/CD reduces reproducibility and can silently change build environments when upstream images are updated.",
    remediation:
      "Pin container images to explicit versions or digests and update them on a controlled cadence with change review."
  },

  missing_security_scans: {
    id: "missing_security_scans",
    title: "Missing explicit security scanning stage",
    severity_default: "high",
    description:
      "The pipeline does not appear to contain SAST/DAST, dependency, or IaC security scans, allowing vulnerabilities to slip into production.",
    remediation:
      "Add dedicated security scanning stages (SAST, dependency, container, IaC) before promotion to production, and treat failures as blocking."
  },

  secrets_inline: {
    id: "secrets_inline",
    title: "Potential hard-coded secrets in pipeline configuration",
    severity_default: "high",
    description:
      "Secrets defined directly in pipeline YAML can leak through source control, logs, or screenshots and are hard to rotate.",
    remediation:
      "Move all secrets to a dedicated secret manager (GitHub Actions Secrets, Vault, AWS Secrets Manager, etc.) and reference them via environment injection."
  },

  no_manual_approval_in_prod: {
    id: "no_manual_approval_in_prod",
    title: "No explicit approval gate for production deployments",
    severity_default: "high",
    description:
      "Production-like deployments occur without manual approvals or protective gates, increasing the risk of accidental or malicious changes.",
    remediation:
      "Introduce manual approvals, environment protections, or change management workflows before production deployment steps."
  },

  no_high_risk_patterns_detected: {
    id: "no_high_risk_patterns_detected",
    title: "No obvious high-risk CI/CD misconfigurations detected",
    severity_default: "info",
    description:
      "The heuristic pipeline review did not find typical high-risk issues, but this does not replace a deeper organization-specific review.",
    remediation:
      "Validate runner isolation, branch protections, secret handling, and access control for modifying pipeline definitions."
  },

  // ---- Threat model generator ----
  tm_auth_token_misuse: {
    id: "tm_auth_token_misuse",
    title: "OAuth / token misuse and validation gaps",
    severity_default: "high",
    description:
      "Misconfigured OAuth/OIDC or JWT validation can let attackers forge or misuse tokens to impersonate users or escalate privileges.",
    remediation:
      "Enforce strict issuer/audience checks, validate signatures against trusted keys, limit token lifetimes, and secure redirect URIs and client secrets."
  },

  tm_file_upload_rce_xss: {
    id: "tm_file_upload_rce_xss",
    title: "Unsafe file upload leading to XSS or RCE",
    severity_default: "high",
    description:
      "Unvalidated file uploads can result in stored XSS, malware distribution, or remote code execution through vulnerable processing libraries.",
    remediation:
      "Apply strict allow-lists on MIME types and extensions, scan for malware, serve uploads from isolated domains, and sandbox high-risk processing."
  },

  tm_admin_rbac_bypass: {
    id: "tm_admin_rbac_bypass",
    title: "Admin RBAC bypass or weak authorization",
    severity_default: "high",
    description:
      "Weak or inconsistent RBAC in admin interfaces may allow regular users or attackers to perform privileged actions.",
    remediation:
      "Centralize RBAC checks, enforce least privilege, ensure all admin endpoints validate roles, and monitor/alert on admin actions."
  },

  tm_third_party_integrations: {
    id: "tm_third_party_integrations",
    title: "Third-party integration and webhook abuse",
    severity_default: "medium",
    description:
      "Unvalidated webhooks or over-privileged API keys can be abused to inject or manipulate data via third-party systems.",
    remediation:
      "Verify webhook signatures, scope API keys to minimal permissions, implement idempotency and sanity checks, and log external events."
  },

  tm_api_abuse: {
    id: "tm_api_abuse",
    title: "Public API abuse and enumeration",
    severity_default: "medium",
    description:
      "Public or partner APIs without robust auth, rate limiting, or input validation can be abused for scraping, brute force, or DoS.",
    remediation:
      "Require authentication for sensitive endpoints, add rate limiting and anomaly detection, and harden input validation and error messages."
  },

  tm_queue_poisoning: {
    id: "tm_queue_poisoning",
    title: "Message queue / event bus poisoning",
    severity_default: "medium",
    description:
      "Insufficient authentication or validation on messaging infrastructure can allow injection, replay, or flooding of events.",
    remediation:
      "Enforce IAM for producers/consumers, validate message schemas, implement dead-letter queues, and monitor volume and patterns."
  },

  tm_db_data_breach: {
    id: "tm_db_data_breach",
    title: "Database data breach or tampering",
    severity_default: "high",
    description:
      "Weak isolation, injection flaws, or misconfigured IAM can enable mass data exfiltration or tampering in the primary database.",
    remediation:
      "Use parameterized queries, role-based DB access, encryption for sensitive fields, and detailed monitoring of access patterns."
  },

  tm_generic: {
    id: "tm_generic",
    title: "Generic application threats",
    severity_default: "medium",
    description:
      "High-level threats around auth, authz, data validation, and logging apply even when no specific components are identified.",
    remediation:
      "Apply defense-in-depth: strong authn/z, input validation, least-privilege data access, centralized logging, and anomaly detection."
  },

  // ---- Deployment safety review ----
  missing_owner: {
    id: "missing_owner",
    title: "Owner/admin address missing or zero",
    severity_default: "high",
    description:
      "Lack of a clear owner/admin address makes governance, upgrades, and emergency actions ambiguous or impossible.",
    remediation:
      "Set an explicit owner/admin (ideally a multi-sig) and document responsibilities, key management, and handover procedures."
  },

  upgradeable_no_multisig: {
    id: "upgradeable_no_multisig",
    title: "Upgradeable contract without multisig control",
    severity_default: "high",
    description:
      "Upgradeable contracts controlled by a single key greatly increase the impact of key compromise or mistakes.",
    remediation:
      "Move upgrade authority to a battle-tested multi-sig with strict operational controls and change management."
  },

  no_emergency_pause: {
    id: "no_emergency_pause",
    title: "Missing emergency pause mechanism",
    severity_default: "medium",
    description:
      "Lack of a circuit-breaker or pause mechanism can slow response to critical vulnerabilities or incidents.",
    remediation:
      "Introduce a pause/guard mechanism governed by a multi-sig with documented criteria for activation and rollback."
  },

  non_stable_version: {
    id: "non_stable_version",
    title: "Non-stable or unspecified deployment version",
    severity_default: "medium",
    description:
      "Deploying alpha/beta/RC builds, or builds without clear versioning, increases the risk of unknown behaviors in production.",
    remediation:
      "Use well-tested, tagged releases for production, and reserve alpha/beta builds for testnets or internal environments."
  },

  basic_checks_passed: {
    id: "basic_checks_passed",
    title: "Basic deployment checks passed",
    severity_default: "info",
    description:
      "No major deployment safety risks were identified based on provided metadata, but this does not replace a full launch review.",
    remediation:
      "Still complete a full pre-deployment checklist, include an external reviewer, and ensure monitoring and rollback plans are in place."
  }
};

// 2) Severity standard
const SEVERITY_STANDARD = {
  critical: {
    level: "critical",
    score_range: "90–100",
    description:
      "Exploitable issue leading to catastrophic loss of funds, control or system integrity with minimal preconditions.",
    typical_actions:
      "Immediate hotfix, emergency pause, public disclosure strategy and full post-mortem."
  },
  high: {
    level: "high",
    score_range: "70–89",
    description:
      "Vulnerability that can lead to significant financial loss or privilege escalation under realistic assumptions.",
    typical_actions:
      "Prioritized patch, expedited release, risk communication with stakeholders."
  },
  medium: {
    level: "medium",
    score_range: "40–69",
    description:
      "Issue that may be exploitable in specific conditions or that increases impact of other bugs.",
    typical_actions:
      "Fix in upcoming release, add monitoring and regression tests."
  },
  low: {
    level: "low",
    score_range: "20–39",
    description:
      "Limited impact issue, minor misconfiguration or best-practice deviation.",
    typical_actions:
      "Address when convenient as part of refactoring or tech debt reduction."
  },
  info: {
    level: "info",
    score_range: "0–19",
    description:
      "Informational finding, documentation gap or non-security improvement suggestion.",
    typical_actions:
      "Evaluate and incorporate where appropriate; no urgent action required."
  }
};

// 3) Threat matrix
const THREAT_MATRIX = {
  base: {
    chain: "base",
    vectors: [
      {
        id: "base_defi_reentrancy",
        category: "DeFi protocol reentrancy",
        severity: "high",
        description:
          "Reentrancy in lending / AMM / vault contracts deployed on Base, especially with composable integrations.",
        recommended_controls: [
          "Use checks-effects-interactions and reentrancy guards",
          "Perform protocol-level audits and fuzzing",
          "Add on-chain monitoring for abnormal reentry patterns"
        ]
      },
      {
        id: "base_bridge_risk",
        category: "Bridge / cross-chain risk",
        severity: "high",
        description:
          "Risks from bridge contracts, message relays and cross-chain governance used with Base.",
        recommended_controls: [
          "Limit trust in third-party bridges",
          "Document threat model for cross-chain governance",
          "Use time-delayed upgrades and multi-sig approvals"
        ]
      }
    ]
  },
  ethereum: {
    chain: "ethereum-mainnet",
    vectors: [
      {
        id: "eth_governance_capture",
        category: "Governance capture",
        severity: "high",
        description:
          "Concentrated voting power or admin keys enabling hostile protocol changes.",
        recommended_controls: [
          "Timelocks on critical actions",
          "Diverse governance participation",
          "On-chain signaling + audits of governance contracts"
        ]
      }
    ]
  }
};

// 4) Solidity patterns catalog
const SOLIDITY_PATTERNS = [
  {
    id: "checks_effects_interactions",
    category: "defensive",
    description:
      "Update contract state before performing external calls to reduce reentrancy risk."
  },
  {
    id: "pull_over_push_payments",
    category: "defensive",
    description:
      "Let users withdraw funds instead of pushing Ether to them in arbitrary callbacks."
  },
  {
    id: "access_control_roles",
    category: "governance",
    description:
      "Use role-based access control (Ownable, AccessControl) for privileged operations."
  }
];

// 5) Pipeline baseline policies
const PIPELINE_BASELINES = {
  default: {
    environment: "default",
    controls: [
      "All secrets injected from a secret manager, not hard-coded",
      "No :latest tags for container images",
      "Dedicated security scanning stage before deployment",
      "Protected branches for main / production"
    ]
  },
  prod: {
    environment: "prod",
    controls: [
      "Manual approval or change management gate before production deploys",
      "Production runners isolated from untrusted workloads",
      "Audit logging for all deployment events"
    ]
  }
};

// 6) Deployment safety checklist templates
const DEPLOYMENT_CHECKLIST = {
  base: {
    network: "base",
    items: [
      "Verify proxy admin and implementation addresses are correct",
      "Confirm multisig ownership for upgradeable contracts",
      "Validate bytecode matches audited build",
      "Have emergency pause / kill-switch governed by multisig",
      "Run small-scale canary deployment before full rollout"
    ]
  },
  generic: {
    network: "generic-evm",
    items: [
      "Confirm owner/admin addresses",
      "Check constructor params and initialization order",
      "Ensure chain ID and RPC endpoints are correct",
      "Prepare rollback/hotfix procedures"
    ]
  }
};

// 7) Verification readiness templates
const VERIFICATION_TEMPLATES = {
  base: {
    chain: "base",
    steps: [
      "Collect full flattened source or multi-file metadata",
      "Record exact compiler version and optimizer settings",
      "Capture constructor arguments and any library addresses",
      "Rehearse verification on a test deployment"
    ]
  },
  "ethereum-mainnet": {
    chain: "ethereum-mainnet",
    steps: [
      "Ensure contracts are compiled with the correct production version",
      "Confirm license identifiers",
      "Use verified library addresses if linked",
      "Document sign-off requirements"
    ]
  }
};

// 8) Mitigation playbook
// Keyed by finding/threat/risk IDs (same IDs as in VULN_DB and seller.js)
const MITIGATION_PLAYBOOK = {
  // Smart contract
  untrusted_delegatecall: {
    key: "untrusted_delegatecall",
    category: "smart_contract",
    remediation:
      "Lock delegatecall targets behind immutable storage or strictly governed upgrade mechanisms. Never derive implementation addresses from user input. Document upgrade processes and require multi-sig approvals for any change."
  },
  tx_origin_auth: {
    key: "tx_origin_auth",
    category: "smart_contract",
    remediation:
      "Refactor authorization logic to use msg.sender and explicit role mappings. Add regression tests that confirm tx.origin is not relied on for access decisions."
  },
  unrestricted_selfdestruct: {
    key: "unrestricted_selfdestruct",
    category: "smart_contract",
    remediation:
      "Remove selfdestruct from production code or place it in a dedicated emergency function restricted to a multi-sig and protected by a time delay or off-chain governance process."
  },
  low_level_call_value: {
    key: "low_level_call_value",
    category: "smart_contract",
    remediation:
      "Replace low-level value transfers with pull-payment patterns where possible. When push is required, apply checks-effects-interactions and ReentrancyGuard, and validate the call’s success."
  },
  potential_reentrancy_pattern: {
    key: "potential_reentrancy_pattern",
    category: "smart_contract",
    remediation:
      "Identify all external calls that can reenter the contract and reorder logic so that all state changes and balance updates happen before these calls. Add unit and fuzz tests for reentrancy scenarios."
  },

  // CI/CD
  privileged_containers: {
    key: "privileged_containers",
    category: "cicd_security",
    remediation:
      "Audit all pipelines for privileged or root-level containers. Replace them with least-privilege configurations, isolate runners that must remain privileged, and restrict who can edit those pipelines."
  },
  secrets_inline: {
    key: "secrets_inline",
    category: "cicd_security",
    remediation:
      "Search for hard-coded secrets in pipeline YAML, repos, and configs. Rotate affected secrets, move them to a secret manager, and update pipelines to reference environment-injected secrets only."
  },
  missing_security_scans: {
    key: "missing_security_scans",
    category: "cicd_security",
    remediation:
      "Introduce a dedicated security stage that runs SAST, dependency scanning, and container/IaC checks. Define a minimal baseline policy where high-severity findings block releases."
  },
  no_manual_approval_in_prod: {
    key: "no_manual_approval_in_prod",
    category: "cicd_governance",
    remediation:
      "Define a production change management workflow with named approvers. Configure pipeline environments or deployment jobs to require manual approval or a ticket reference before executing."
  },

  // Threat model
  tm_auth_token_misuse: {
    key: "tm_auth_token_misuse",
    category: "threat_model",
    remediation:
      "Perform a focused review of OAuth/OIDC and JWT validation logic. Enforce strict issuer/audience checks, validate algorithms, disallow 'none', and configure token lifetimes and refresh logic according to risk."
  },
  tm_file_upload_rce_xss: {
    key: "tm_file_upload_rce_xss",
    category: "threat_model",
    remediation:
      "Implement allow-listed MIME types and extensions, size limits, and antivirus scanning. Serve uploads from a separate domain with safe content-type and content-disposition headers, and sandbox processing workers."
  },
  tm_admin_rbac_bypass: {
    key: "tm_admin_rbac_bypass",
    category: "threat_model",
    remediation:
      "Catalog all admin capabilities and map them to roles. Enforce authorization middleware on every admin endpoint and add audit logs with actor, action, and object for each privileged operation."
  },
  tm_third_party_integrations: {
    key: "tm_third_party_integrations",
    category: "threat_model",
    remediation:
      "Validate inbound webhooks with signatures and origin checks, scope outbound API keys, and monitor integration errors and unusual traffic. Introduce idempotency keys and sanity checks on side effects."
  },
  tm_api_abuse: {
    key: "tm_api_abuse",
    category: "threat_model",
    remediation:
      "Classify API endpoints by sensitivity, enforce authentication where needed, add per-user and global rate limits, and instrument metrics and alerts for brute-force or scraping patterns."
  },
  tm_queue_poisoning: {
    key: "tm_queue_poisoning",
    category: "threat_model",
    remediation:
      "Limit message publishing and consumption to authenticated services with scoped IAM roles, validate payload schemas, and use DLQs plus alerting for malformed or excessive messages."
  },
  tm_db_data_breach: {
    key: "tm_db_data_breach",
    category: "threat_model",
    remediation:
      "Ensure all data access uses parameterized queries or ORM, apply row/column-level controls for sensitive data, encrypt critical fields, and implement anomaly detection on read volume and patterns."
  },

  // Deployment
  missing_owner: {
    key: "missing_owner",
    category: "deployment_governance",
    remediation:
      "Designate a well-defined multi-sig or governance contract as the owner/admin. Document who controls its keys, backup policies, and what actions require consensus or timelock."
  },
  upgradeable_no_multisig: {
    key: "upgradeable_no_multisig",
    category: "deployment_governance",
    remediation:
      "Migrate ownership of proxy admin or upgrade roles to a multi-sig with appropriate quorum. Configure timelocks for high-risk upgrades and maintain a public changelog."
  },
  no_emergency_pause: {
    key: "no_emergency_pause",
    category: "deployment_safety",
    remediation:
      "Introduce a pause/guard mechanism to halt critical functionality on detection of severe issues. Ensure only a multi-sig can activate it, and rehearse pause/unpause procedures."
  },
  non_stable_version: {
    key: "non_stable_version",
    category: "deployment_safety",
    remediation:
      "Stabilize the release by addressing known issues, tagging a stable version, and restricting production deployments to versions that have passed a defined test and review pipeline."
  }
};

// -------------------------------------------------------------
// Routes
// -------------------------------------------------------------

// Health check
app.get("/", (req, res) => {
  res.json(
    makeResponse(
      {
        message: "SAIQUE AI resources API is alive.",
        endpoints: [
          "/resources/vuln-db",
          "/resources/mitigation-playbook",
          "/resources/severity-standard",
          "/resources/threat-matrix",
          "/resources/solidity-patterns",
          "/resources/pipeline-baselines",
          "/resources/deployment-safety-checklist",
          "/resources/verification-readiness-templates"
        ]
      },
      { route: "root" }
    )
  );
});

// -------------------------------------------------------------
// 1) Vulnerability DB
// -------------------------------------------------------------
app.get("/resources/vuln-db", (req, res) => {
  const { vuln } = req.query;

  if (vuln) {
    const record = VULN_DB[vuln];
    if (!record) {
      return res.status(404).json({
        ok: false,
        error: `Vulnerability '${vuln}' not found.`,
        meta: { timestamp_utc: new Date().toISOString() }
      });
    }
    return res.json(makeResponse(record, { route: "vuln-db", filter: vuln }));
  }

  res.json(
    makeResponse(
      { count: Object.keys(VULN_DB).length, entries: VULN_DB },
      { route: "vuln-db" }
    )
  );
});

// -------------------------------------------------------------
// 1b) Mitigation playbook
// -------------------------------------------------------------
app.get("/resources/mitigation-playbook", (req, res) => {
  const { key } = req.query;

  if (key) {
    const record = MITIGATION_PLAYBOOK[key];
    if (!record) {
      return res.status(404).json({
        ok: false,
        error: `Mitigation entry '${key}' not found.`,
        meta: { timestamp_utc: new Date().toISOString() }
      });
    }
    return res.json(
      makeResponse(record, { route: "mitigation-playbook", key })
    );
  }

  res.json(
    makeResponse(
      { count: Object.keys(MITIGATION_PLAYBOOK).length, entries: MITIGATION_PLAYBOOK },
      { route: "mitigation-playbook" }
    )
  );
});

// -------------------------------------------------------------
// 2) Severity Standard  (updated with overview support)
// -------------------------------------------------------------
app.get("/resources/severity-standard", (req, res) => {
  const { section } = req.query;

  // overview returns entire table
  if (section && section.toLowerCase() === "overview") {
    return res.json(
      makeResponse(SEVERITY_STANDARD, {
        route: "severity-standard",
        section: "overview"
      })
    );
  }

  // Specific section
  if (section) {
    const sec = SEVERITY_STANDARD[section.toLowerCase()];
    if (!sec) {
      return res.status(404).json({
        ok: false,
        error: `Severity section '${section}' not found.`,
        meta: { timestamp_utc: new Date().toISOString() }
      });
    }
    return res.json(
      makeResponse(sec, { route: "severity-standard", section })
    );
  }

  // No section → return entire table
  res.json(makeResponse(SEVERITY_STANDARD, { route: "severity-standard" }));
});

// -------------------------------------------------------------
// 3) Threat Matrix
// -------------------------------------------------------------
app.get("/resources/threat-matrix", (req, res) => {
  const chainKey = (req.query.chain || "base").toLowerCase();

  const mapping =
    chainKey === "base"
      ? THREAT_MATRIX.base
      : chainKey === "ethereum-mainnet" || chainKey === "ethereum"
      ? THREAT_MATRIX.ethereum
      : null;

  if (!mapping) {
    return res.status(404).json({
      ok: false,
      error: `No threat matrix for '${chainKey}'.`,
      meta: { timestamp_utc: new Date().toISOString() }
    });
  }

  res.json(makeResponse(mapping, { route: "threat-matrix", chain: chainKey }));
});

// -------------------------------------------------------------
// 4) Solidity Patterns
// -------------------------------------------------------------
app.get("/resources/solidity-patterns", (req, res) => {
  const { category } = req.query;

  if (category) {
    const filtered = SOLIDITY_PATTERNS.filter(
      (p) => p.category.toLowerCase() === category.toLowerCase()
    );
    return res.json(
      makeResponse(
        { count: filtered.length, patterns: filtered },
        { route: "solidity-patterns", category }
      )
    );
  }

  res.json(
    makeResponse(
      { count: SOLIDITY_PATTERNS.length, patterns: SOLIDITY_PATTERNS },
      { route: "solidity-patterns" }
    )
  );
});

// -------------------------------------------------------------
// 5) Pipeline Baselines
// -------------------------------------------------------------
app.get("/resources/pipeline-baselines", (req, res) => {
  const env = (req.query.environment || "default").toLowerCase();
  const baseline = PIPELINE_BASELINES[env] || PIPELINE_BASELINES.default;

  res.json(
    makeResponse(baseline, { route: "pipeline-baselines", environment: env })
  );
});

// -------------------------------------------------------------
// 6) Deployment Safety Checklist
// -------------------------------------------------------------
app.get("/resources/deployment-safety-checklist", (req, res) => {
  const networkKey = (req.query.network || "base").toLowerCase();

  const checklist =
    networkKey === "base"
      ? DEPLOYMENT_CHECKLIST.base
      : DEPLOYMENT_CHECKLIST.generic;

  res.json(
    makeResponse(checklist, {
      route: "deployment-safety-checklist",
      network: networkKey
    })
  );
});

// -------------------------------------------------------------
// 7) Verification Readiness Templates
// -------------------------------------------------------------
app.get("/resources/verification-readiness-templates", (req, res) => {
  const chainKey = (req.query.chain || "base").toLowerCase();

  let tmpl = null;
  if (chainKey === "base") tmpl = VERIFICATION_TEMPLATES.base;
  else if (chainKey === "ethereum-mainnet" || chainKey === "ethereum")
    tmpl = VERIFICATION_TEMPLATES["ethereum-mainnet"];

  if (!tmpl) {
    return res.status(404).json({
      ok: false,
      error: `No verification template for '${chainKey}'.`,
      meta: { timestamp_utc: new Date().toISOString() }
    });
  }

  res.json(
    makeResponse(tmpl, {
      route: "verification-readiness-templates",
      chain: chainKey
    })
  );
});

// -------------------------------------------------------------
// Start server
// -------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`🔌 SAIQUE resources server listening on port ${PORT}`);
});
