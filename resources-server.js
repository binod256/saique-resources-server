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

// 1) Vulnerability knowledge base
const VULN_DB = {
  delegatecall_untrusted: {
    id: "delegatecall_untrusted",
    title: "Untrusted delegatecall target",
    severity_default: "critical",
    description:
      "Using delegatecall with untrusted or user-controlled target addresses can give attackers full control over contract storage.",
    remediation:
      "Restrict delegatecall to immutable, audited implementations and never allow user-supplied delegatecall targets."
  },
  tx_origin_auth: {
    id: "tx_origin_auth",
    title: "Authorization using tx.origin",
    severity_default: "high",
    description:
      "Relying on tx.origin for authorization enables phishing-style attacks where a victim is tricked into calling a malicious contract.",
    remediation:
      "Always rely on msg.sender for authorization and use role-based access control patterns such as Ownable or AccessControl."
  },
  selfdestruct_unrestricted: {
    id: "selfdestruct_unrestricted",
    title: "Unrestricted selfdestruct",
    severity_default: "high",
    description:
      "Exposing selfdestruct in externally callable paths can permanently destroy a contract and its functionality.",
    remediation:
      "Remove selfdestruct in production contracts or restrict it to heavily governed emergency procedures."
  },
  timestamp_dependency: {
    id: "timestamp_dependency",
    title: "Timestamp-dependent logic",
    severity_default: "medium",
    description:
      "Using block.timestamp/now for critical logic or randomness can be abused by miners within a limited range.",
    remediation:
      "Avoid timestamps for randomness and design time windows with tolerant, documented assumptions."
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
// 2) Severity Standard  (updated with overview support)
// -------------------------------------------------------------
app.get("/resources/severity-standard", (req, res) => {
  const { section } = req.query;

  // NEW — overview returns entire table
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

  res.json(makeResponse(baseline, { route: "pipeline-baselines", environment: env }));
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

  res.json(makeResponse(checklist, { route: "deployment-safety-checklist", network: networkKey }));
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
