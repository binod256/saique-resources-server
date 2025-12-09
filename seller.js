require("dotenv").config();

const AcpClientModule = require("@virtuals-protocol/acp-node");
const AcpClient = AcpClientModule.default;
const { AcpContractClientV2 } = AcpClientModule;

// Cache job metadata so we can use it later when job.input is empty
const jobCache = new Map(); // key: job.id, value: { name, requirement }

// ---------------------------------------------------------------------------
// Resource config + helpers
// ---------------------------------------------------------------------------

const RESOURCES_BASE =
  process.env.SAIQUE_RESOURCES_BASE ||
  "https://saique-sentinel-resources.onrender.com/resources";

const vulnCache = new Map(); // key: vuln id -> meta
const mitigationCache = new Map(); // key: mitigation key -> meta

async function fetchJson(url) {
  try {
    const res = await fetch(url);
    if (!res.ok) {
      console.warn("⚠️ fetchJson non-OK response:", res.status, url);
      return null;
    }
    return await res.json();
  } catch (err) {
    console.warn("⚠️ fetchJson error for URL:", url, err.message || err);
    return null;
  }
}

async function fetchVulnMeta(vulnId) {
  if (!vulnId) return null;
  if (vulnCache.has(vulnId)) return vulnCache.get(vulnId);

  const url = `${RESOURCES_BASE}/vuln-db?vuln=${encodeURIComponent(vulnId)}`;
  const data = await fetchJson(url);
  if (data) {
    vulnCache.set(vulnId, data);
  }
  return data;
}

async function fetchMitigationMeta(key) {
  if (!key) return null;
  if (mitigationCache.has(key)) return mitigationCache.get(key);

  const url = `${RESOURCES_BASE}/mitigation-playbook?key=${encodeURIComponent(
    key
  )}`;
  const data = await fetchJson(url);
  if (data) {
    mitigationCache.set(key, data);
  }
  return data;
}

/**
 * Merge fields from src into dst, but do NOT overwrite existing non-empty values.
 */
function softMerge(dst, src) {
  if (!dst || !src) return;
  for (const [k, v] of Object.entries(src)) {
    if (v === undefined || v === null) continue;
    const existing = dst[k];
    const isEmptyString = typeof existing === "string" && existing.trim() === "";
    if (
      existing === undefined ||
      existing === null ||
      isEmptyString
    ) {
      dst[k] = v;
    }
  }
}

// ---------------------------------------------------------------------------
// Job type inference
// ---------------------------------------------------------------------------

/**
 * Infer job type from job name (offering name).
 */
function inferJobTypeFromName(name) {
  if (!name || typeof name !== "string") return null;
  const jt = name.trim().toLowerCase();

  if (jt.includes("smart_contract_static_pattern_analysis")) {
    return "smart_contract_static_pattern_analysis";
  }
  if (jt.includes("smart_contract_security_review")) {
    return "smart_contract_static_pattern_analysis";
  }
  if (jt.includes("devops_pipeline_security_review_v2")) {
    return "devops_pipeline_security_review_v2";
  }
  if (jt.includes("devops_pipeline_security_review")) {
    return "devops_pipeline_security_review_v2";
  }
  if (jt.includes("threat_model_generator")) {
    return "threat_model_generator";
  }
  if (jt.includes("deployment_safety_review")) {
    return "deployment_safety_review";
  }

  return null;
}

/**
 * Infer job type from input shape.
 */
function inferJobTypeFromInput(input) {
  if (!input || typeof input !== "object") return "unknown";

  // 1) Smart contract static pattern analysis: code + framework
  if (typeof input.code === "string" && typeof input.framework === "string") {
    return "smart_contract_static_pattern_analysis";
  }

  // 2) DevOps pipeline review: pipeline_yaml + environment
  if (
    typeof input.pipeline_yaml === "string" &&
    typeof input.environment === "string"
  ) {
    return "devops_pipeline_security_review_v2";
  }

  // Also accept common variations:
  if (
    typeof input.pipeline === "string" &&
    typeof input.environment === "string"
  ) {
    return "devops_pipeline_security_review_v2";
  }

  // 3) Threat model generator: architecture_summary
  if (typeof input.architecture_summary === "string") {
    return "threat_model_generator";
  }

  // 4) Deployment safety: network + settings
  if (
    typeof input.network === "string" &&
    typeof input.settings === "object" &&
    input.settings !== null
  ) {
    return "deployment_safety_review";
  }

  return "unknown";
}

/**
 * Fallback: if job type is unknown, still try to perform a meaningful
 * security review (prefer DevOps pipeline analysis).
 */
function fallbackBestEffortDeliverable(input) {
  console.log("⚠️ Fallback: job type unknown, attempting best-effort analysis…");

  if (!input || typeof input !== "object") {
    return {
      findings: [
        {
          id: "no_input",
          severity: "info",
          description:
            "No structured input was available to perform a detailed security review.",
          suggestion:
            "Ensure the job requirement contains the expected fields (pipeline_yaml, environment, code, etc.) before re-running the job."
        }
      ],
      severity_breakdown: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 1
      },
      timestamp_utc: new Date().toISOString()
    };
  }

  // Try to find a pipeline-like string
  let pipelineCandidate =
    input.pipeline_yaml ||
    input.pipeline ||
    input.yaml ||
    input.workflow ||
    "";

  const stringKeys = Object.keys(input).filter(
    (k) => typeof input[k] === "string"
  );

  if (!pipelineCandidate && stringKeys.length > 0) {
    // Pick the longest string as a pipeline candidate
    pipelineCandidate = stringKeys.reduce(
      (best, key) => {
        const val = input[key] || "";
        if (val.length > best.value.length) {
          return { key, value: val };
        }
        return best;
      },
      { key: "", value: "" }
    ).value;
  }

  const environment =
    input.environment || input.env || input.stage || "unknown";

  // Heuristic: if it smells like YAML pipeline, run DevOps analysis
  if (
    pipelineCandidate &&
    pipelineCandidate.length > 0 &&
    /jobs:|stages:|on:|\bgithub\.com\/actions\b/i.test(pipelineCandidate)
  ) {
    console.log("🧪 Fallback treating input as DevOps pipeline review.");
    return analyzeDevopsPipeline({
      pipeline_yaml: pipelineCandidate,
      environment
    });
  }

  // If it looks like smart contract
  if (typeof input.code === "string" && input.code.trim().length > 0) {
    console.log("🧪 Fallback treating input as smart contract analysis.");
    return analyzeSmartContractStatic({
      code: input.code,
      framework: input.framework || "solidity"
    });
  }

  // Absolute last resort: generic informational deliverable
  console.log("🧪 Fallback generic informational review.");
  return {
    findings: [
      {
        id: "generic_review",
        severity: "info",
        description:
          "The input did not clearly match any known schema, so a specific security review could not be performed.",
        suggestion:
          "Ensure that the input follows the expected schema for one of: smart_contract_static_pattern_analysis, devops_pipeline_security_review_v2, threat_model_generator, or deployment_safety_review."
      }
    ],
    severity_breakdown: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 1
    },
    timestamp_utc: new Date().toISOString()
  };
}

/**
 * Helper: severity weight & sorting
 */
function severityWeight(sev) {
  switch (sev) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    case "info":
      return 1;
    default:
      return 0;
  }
}

/**
 * 1) smart_contract_static_pattern_analysis
 */
function analyzeSmartContractStatic(input) {
  const code = input.code || "";
  const framework = (input.framework || "solidity").toLowerCase();

  /** @type {Array<{
   * id: string,
   * title?: string,
   * severity: "critical" | "high" | "medium" | "low" | "info",
   * description: string,
   * impact?: string,
   * likelihood?: string,
   * evidence?: string,
   * suggestion: string
   * }>} */
  const findings = [];

  const addFinding = (f) => findings.push(f);

  const coverage = {
    pragma_version: { checked: true, triggered: false },
    delegatecall_usage: { checked: true, triggered: false },
    tx_origin_usage: { checked: true, triggered: false },
    selfdestruct_usage: { checked: true, triggered: false },
    low_level_value_calls: { checked: true, triggered: false },
    timestamp_dependency: { checked: true, triggered: false },
    upgradeable_proxy_pattern: { checked: true, triggered: false },
    access_control_modifiers: { checked: true, triggered: false },
    basic_reentrancy_heuristics: { checked: true, triggered: false }
  };

  const pragmaMatch = code.match(/pragma\s+solidity\s+([^;]+);/i);
  const pragma = pragmaMatch ? pragmaMatch[1].trim() : null;

  if (!pragma) {
    coverage.pragma_version.triggered = true;
    addFinding({
      id: "missing_pragma",
      title: "Solidity pragma version not found",
      severity: "medium",
      description:
        "The contract does not declare an explicit Solidity pragma version.",
      impact:
        "Without a fixed pragma, the contract may compile differently across compiler versions, potentially introducing subtle bugs.",
      likelihood:
        "Medium – compilers evolve and change behavior, especially across major versions.",
      evidence: "No `pragma solidity` directive could be found in the code.",
      suggestion:
        "Add an explicit pragma such as `pragma solidity 0.8.24;` and pin it to a known-tested version for production deployments."
    });
  }

  if (code.includes("delegatecall")) {
    coverage.delegatecall_usage.triggered = true;
    addFinding({
      id: "untrusted_delegatecall",
      title: "Use of delegatecall",
      severity: "critical",
      description:
        "The contract uses `delegatecall`, which executes external code in the context of this contract.",
      impact:
        "If the target of `delegatecall` can be controlled or upgraded by an attacker, they can gain full control over this contract’s storage and funds.",
      likelihood:
        "High if the implementation address is upgradable or not strictly governed; otherwise medium.",
      evidence:
        "Found `delegatecall` usage. Review the implementation selection logic and access control on upgrade paths.",
      suggestion:
        "Restrict `delegatecall` to immutable, audited implementations controlled by robust governance. Never allow user-supplied addresses to be used as delegatecall targets."
    });
  }

  if (code.includes("tx.origin")) {
    coverage.tx_origin_usage.triggered = true;
    addFinding({
      id: "tx_origin_auth",
      title: "Authorization using tx.origin",
      severity: "high",
      description:
        "The contract uses `tx.origin` for authorization decisions.",
      impact:
        "Attackers can trick privileged users into calling malicious contracts that forward calls with `tx.origin` still set, bypassing intended access control.",
      likelihood:
        "Medium to high, especially for EOAs interacting via web UIs or wallet extensions.",
      evidence:
        "One or more occurrences of `tx.origin` were found in the code.",
      suggestion:
        "Use `msg.sender` instead of `tx.origin` for access control. Consider role-based access patterns such as Ownable or AccessControl."
    });
  }

  if (code.includes("selfdestruct(") || code.includes("suicide(")) {
    coverage.selfdestruct_usage.triggered = true;
    addFinding({
      id: "unrestricted_selfdestruct",
      title: "Potentially dangerous selfdestruct usage",
      severity: "high",
      description:
        "The contract contains `selfdestruct` or `suicide`, which can permanently destroy the contract and optionally redirect funds.",
      impact:
        "If reachable by unauthorized parties or insufficiently governed, this can lead to permanent loss of functionality and funds.",
      likelihood:
        "Depends on how `selfdestruct` is gated; high if callable by arbitrary users, lower if strongly access-controlled.",
      evidence:
        "Detected one or more calls to `selfdestruct` / `suicide` in the source code.",
      suggestion:
        "Restrict `selfdestruct` to heavily governed emergency paths, or remove it entirely for production deployments."
    });
  }

  if (code.includes(".call.value(") || code.includes(".call{value:")) {
    coverage.low_level_value_calls.triggered = true;
    addFinding({
      id: "low_level_call_value",
      title: "Low-level call with value transfer",
      severity: "high",
      description:
        "The contract sends Ether using low-level calls (`call{value:…}` or `.call.value(...)`).",
      impact:
        "This pattern can introduce reentrancy risks and makes error handling more complex.",
      likelihood:
        "Medium to high if state updates occur after the external call or if reentrancy guards are missing.",
      evidence:
        "One or more occurrences of `.call.value(...)` or `.call{value: ...}` were found.",
      suggestion:
        "Follow checks-effects-interactions, use `ReentrancyGuard` where appropriate, and always validate call return values."
    });
  }

  if (code.includes("block.timestamp") || code.includes("now")) {
    coverage.timestamp_dependency.triggered = true;
    addFinding({
      id: "timestamp_dependency",
      title: "Dependency on block timestamp",
      severity: "medium",
      description:
        "The contract uses `block.timestamp` or `now` for logic decisions.",
      impact:
        "Miners can influence the timestamp within a certain range, which can be problematic if used for randomness or critical time logic.",
      likelihood:
        "Medium – especially relevant for lotteries, auctions or expiry-based logic.",
      evidence:
        "Occurrences of `block.timestamp` or `now` detected in conditional logic.",
      suggestion:
        "Avoid using timestamps for randomness. For time windows, allow reasonable tolerances and document assumptions."
    });
  }

  if (/proxy/i.test(code) && /implementation/i.test(code)) {
    coverage.upgradeable_proxy_pattern.triggered = true;
    addFinding({
      id: "upgradeable_proxy",
      title: "Upgradeable proxy pattern detected",
      severity: "medium",
      description:
        "The contract appears to implement an upgradeable proxy or holds an `implementation` address.",
      impact:
        "Centralized upgrade authority can introduce governance and security risks if compromised.",
      likelihood:
        "Medium – depends on how upgrade is controlled and how keys are managed.",
      evidence:
        "References to `proxy` and `implementation` suggest an upgradeable pattern.",
      suggestion:
        "Document governance processes for upgrades, ensure multi-sig or timelocked control, and communicate upgrade risks to stakeholders."
    });
  }

  if (!/onlyOwner|onlyRole|AccessControl/i.test(code)) {
    coverage.access_control_modifiers.triggered = true;
    addFinding({
      id: "no_access_control_modifiers",
      title: "No explicit access control modifiers detected",
      severity: "medium",
      description:
        "The contract does not appear to use common access control modifiers such as `onlyOwner` or `onlyRole`.",
      impact:
        "Sensitive functions may be callable by any address if access control is not enforced elsewhere.",
      likelihood:
        "Medium – depends on whether access control is implemented via custom patterns not detected here.",
      evidence:
        "No references to `onlyOwner`, `onlyRole`, or `AccessControl` were found in the code.",
      suggestion:
        "Ensure that all privileged operations are protected by well-defined access control, and consider using battle-tested patterns like Ownable or AccessControl."
    });
  }

  if (
    /call{value:|call.value\(|transfer\(|send\(/.test(code) &&
    /(balance|balances)\s*\[/.test(code)
  ) {
    coverage.basic_reentrancy_heuristics.triggered = true;
    addFinding({
      id: "potential_reentrancy_pattern",
      title: "Potential reentrancy-sensitive pattern detected",
      severity: "medium",
      description:
        "The contract appears to combine external calls with balance or mapping updates, which may be sensitive to reentrancy.",
      impact:
        "If state changes are made after external calls or without reentrancy guards, attackers may exploit reentrant flows.",
      likelihood:
        "Medium – depends on exact ordering of state updates and call patterns.",
      evidence:
        "Detected external calls with value along with balance/mapping updates in the source.",
      suggestion:
        "Review all external calls that interact with user balances, apply checks-effects-interactions, and consider using a reentrancy guard."
    });
  }

  if (findings.length === 0) {
    addFinding({
      id: "no_pattern_hits",
      title: "No high-risk patterns detected by static heuristic scan",
      severity: "info",
      description:
        "The heuristic scan did not detect any of the typical high-risk patterns it looks for.",
      impact:
        "This does NOT mean the contract is safe; many vulnerabilities require deeper contextual or dynamic analysis.",
      likelihood: "N/A – this is an informational result.",
      evidence:
        "No occurrences of known patterns such as delegatecall, tx.origin, selfdestruct, or risky low-level calls were found.",
      suggestion:
        "Perform a full manual audit, extend test coverage, consider fuzzing and formal verification for high-value deployments."
    });
  }

  const severity_breakdown = {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length
  };

  const totalFindings = findings.length;
  const riskScore =
    severity_breakdown.critical * 5 +
    severity_breakdown.high * 4 +
    severity_breakdown.medium * 3 +
    severity_breakdown.low * 2 +
    severity_breakdown.info * 1;

  const overall_risk_level =
    riskScore >= 12
      ? "high"
      : riskScore >= 6
      ? "medium"
      : riskScore > 0
      ? "low"
      : "info";

  const sortedForRemediation = [...findings].sort(
    (a, b) => severityWeight(b.severity) - severityWeight(a.severity)
  );
  const remediation_plan = sortedForRemediation.slice(0, 5).map((f, idx) => ({
    id: f.id,
    title: f.title || f.id,
    priority: idx + 1,
    severity: f.severity,
    reason: `Prioritized because of ${f.severity} severity and potential impact.`
  }));

  const top_recommendations = remediation_plan.map(
    (r) =>
      `P${r.priority} – [${r.severity}] ${r.title}: ${
        findings.find((f) => f.id === r.id)?.suggestion || ""
      }`
  );

  const open_questions = [];
  if (coverage.upgradeable_proxy_pattern.triggered) {
    open_questions.push(
      "Who controls the upgrade admin for the proxy, and is it a multisig with clear governance?"
    );
  }
  if (coverage.delegatecall_usage.triggered) {
    open_questions.push(
      "Under what circumstances can the delegatecall target be changed, and how is this governed?"
    );
  }
  if (coverage.access_control_modifiers.triggered) {
    open_questions.push(
      "Which addresses are expected to perform privileged actions, and how are they protected operationally?"
    );
  }
  if (open_questions.length === 0) {
    open_questions.push(
      "What are the maximum expected value at risk and the threat model (retail users vs internal systems)?"
    );
  }

  return {
    summary: {
      framework,
      pragma,
      overall_risk_level,
      total_findings: totalFindings,
      risk_score: riskScore,
      top_recommendations
    },
    methodology:
      "Static heuristic scan focusing on common Solidity risk patterns (delegatecall, tx.origin, selfdestruct, low-level calls, timestamp use, upgradeability, access control, and simple reentrancy heuristics). No AST-level or dynamic analysis was performed.",
    findings,
    severity_breakdown,
    remediation_plan,
    coverage,
    open_questions,
    timestamp_utc: new Date().toISOString()
  };
}

/**
 * 2) devops_pipeline_security_review_v2
 */
function analyzeDevopsPipeline(input) {
  const pipeline = input.pipeline_yaml || input.pipeline || "";
  const env = (input.environment || "unknown").toLowerCase();
  const lower = pipeline.toLowerCase();

  /** @type {Array<{
   * id: string,
   * title?: string,
   * severity: "critical" | "high" | "medium" | "low" | "info",
   * description: string,
   * impact?: string,
   * likelihood?: string,
   * evidence?: string,
   * mitigation: string
   * }>} */
  const threats = [];

  const addThreat = (t) => threats.push(t);

  const isProd = env === "prod" || env === "production";

  const coverage = {
    privileged_containers: { checked: true, triggered: false },
    latest_tags: { checked: true, triggered: false },
    security_scanning: { checked: true, triggered: false },
    inline_secrets: { checked: true, triggered: false },
    prod_approval_gates: { checked: true, triggered: false }
  };

  if (
    lower.includes("privileged: true") ||
    lower.includes("allow_privilege_escalation: true")
  ) {
    coverage.privileged_containers.triggered = true;
    addThreat({
      id: "privileged_containers",
      title: "Privileged or privilege-escalating containers",
      severity: "high",
      description:
        "At least one job is configured to run in privileged mode or with privilege escalation enabled.",
      impact:
        "If an attacker gains code execution in such a job, they may escape the container and gain broader host or cluster control.",
      likelihood:
        "Medium to high depending on exposure of build agents and how untrusted code enters the pipeline.",
      evidence:
        "Found `privileged: true` or `allow_privilege_escalation: true` in the pipeline configuration.",
      mitigation:
        "Remove privileged flags where possible. Use least-privilege securityContext and isolate build agents that handle untrusted workloads."
    });
  }

  if (lower.includes(":latest")) {
    coverage.latest_tags.triggered = true;
    addThreat({
      id: "latest_image_tag",
      title: "Mutable :latest image tags",
      severity: "medium",
      description:
        "The pipeline uses container images tagged as `:latest`.",
      impact:
        "Reproducibility and auditability are reduced; upstream image changes can silently alter your CI environment.",
      likelihood: "High – image maintainers routinely update `:latest` tags.",
      evidence: "Occurrences of `:latest` tags in image references.",
      mitigation:
        "Pin images to explicit versions (e.g., `node:22.2`) or digests, and update them on a controlled cadence."
    });
  }

  const hasSecurityScan =
    lower.includes("snyk") ||
    lower.includes("trivy") ||
    lower.includes("bandit") ||
    lower.includes("semgrep") ||
    lower.includes("checkov") ||
    lower.includes("codeql") ||
    lower.includes("slither") ||
    lower.includes("mythril") ||
    lower.includes("security_scan");

  if (!hasSecurityScan) {
    coverage.security_scanning.triggered = true;
    addThreat({
      id: "missing_security_scans",
      title: "No explicit security scanning stage detected",
      severity: isProd ? "high" : "medium",
      description:
        "The pipeline does not appear to run SAST/DAST, dependency or IaC security scans.",
      impact:
        "Vulnerabilities may reach production undetected, especially in dependencies and infrastructure-as-code.",
      likelihood:
        "High over time, as dependencies and infrastructure frequently change.",
      evidence:
        "No references to common security tools (Trivy, Semgrep, CodeQL, etc.) found in the pipeline definition.",
      mitigation:
        "Add dedicated security steps (SAST, dependency, container and IaC scans) as part of the CI pipeline, gated before production promotion."
    });
  }

  const hasInlineSecrets =
    /password\s*=\s*["']?[A-Za-z0-9]/i.test(pipeline) ||
    /secret\s*=\s*["']?[A-Za-z0-9]/i.test(pipeline) ||
    /api[_-]?key\s*=\s*["']?[A-Za-z0-9]/i.test(pipeline) ||
    /token\s*=\s*["']?[A-Za-z0-9]/i.test(pipeline);

  if (hasInlineSecrets) {
    coverage.inline_secrets.triggered = true;
    addThreat({
      id: "secrets_inline",
      title: "Potential hard-coded secrets in pipeline definition",
      severity: "high",
      description:
        "The pipeline appears to define secrets (passwords, tokens or API keys) directly in the YAML.",
      impact:
        "Secrets can leak via source control, logs or screenshots, and are harder to rotate and audit.",
      likelihood:
        "High – source control usually has broad access and long-term retention.",
      evidence:
        "Key-value patterns like `password=...`, `secret=...`, `api_key=...` or `token=...` detected.",
      mitigation:
        "Move secrets into a dedicated secret manager (e.g., GitHub Actions Secrets, Vault, AWS Secrets Manager) and reference them via environment injection or secret variables."
    });
  }

  if (isProd) {
    const hasApproval =
      lower.includes("manual_approval") ||
      lower.includes("approval") ||
      lower.includes("environment: production") ||
      lower.includes("needs: [approval]") ||
      lower.includes("environment: prod");

    if (!hasApproval) {
      coverage.prod_approval_gates.triggered = true;
      addThreat({
        id: "no_manual_approval_in_prod",
        title: "No explicit approval gate for production",
        severity: "high",
        description:
          "The pipeline is targeting a production-like environment but no manual approval or protection was detected.",
        impact:
          "Accidental or malicious changes can be promoted to production without human review.",
        likelihood:
          "Medium – depends on how often pipeline definitions are changed and who can trigger deployments.",
        evidence:
          "Environment value suggests `prod` or `production` while common approval patterns were not found.",
        mitigation:
          "Introduce a manual approval or environment protection mechanism (protected branches, environment approvals, or deployment gates) before production deployments."
      });
    }
  }

  if (threats.length === 0) {
    addThreat({
      id: "no_high_risk_patterns_detected",
      title: "No obvious high-risk misconfigurations detected",
      severity: "info",
      description:
        "The static heuristic review did not find the typical high-risk CI/CD misconfigurations it checks for.",
      impact:
        "This does not guarantee the pipeline is secure; the analysis is pattern-based and context-agnostic.",
      likelihood: "N/A",
      evidence:
        "No privileged containers, :latest tags, inline secrets or missing security scans detected by the current heuristics.",
      mitigation:
        "Perform a deeper, organization-specific review including access controls on runners, branch protection rules, and secret management policies."
    });
  }

  const high = threats.filter(
    (t) => t.severity === "high" || t.severity === "critical"
  ).length;
  const medium = threats.filter((t) => t.severity === "medium").length;
  const low = threats.filter((t) => t.severity === "low").length;
  const info = threats.filter((t) => t.severity === "info").length;

  const issue_count = threats.length;
  const riskScore = high * 4 + medium * 3 + low * 2 + info * 1;

  const overall_risk_level =
    riskScore >= 10
      ? "high"
      : riskScore >= 5
      ? "medium"
      : riskScore > 0
      ? "low"
      : "info";

  const sortedForRemediation = [...threats].sort(
    (a, b) => severityWeight(b.severity) - severityWeight(a.severity)
  );
  const remediation_plan = sortedForRemediation.slice(0, 5).map((t, idx) => ({
    id: t.id,
    title: t.title || t.id,
    priority: idx + 1,
    severity: t.severity,
    reason: `Prioritized because of ${t.severity} severity and potential pipeline impact.`
  }));

  const top_recommendations = remediation_plan.map(
    (r) =>
      `P${r.priority} – [${r.severity}] ${r.title}: ${
        threats.find((t) => t.id === r.id)?.mitigation || ""
      }`
  );

  const open_questions = [];
  if (coverage.inline_secrets.triggered) {
    open_questions.push(
      "Which secrets are currently checked into the pipeline definition, and what is the plan for rotation once they are moved to a secrets manager?"
    );
  }
  if (coverage.privileged_containers.triggered) {
    open_questions.push(
      "Are privileged runners strictly isolated from internet-facing or untrusted workloads?"
    );
  }
  if (isProd && coverage.prod_approval_gates.triggered) {
    open_questions.push(
      "Who is responsible for approving production deployments and how is that process enforced today?"
    );
  }
  if (open_questions.length === 0) {
    open_questions.push(
      "What are the current controls around who can modify pipeline definitions and trigger production deployments?"
    );
  }

  return {
    summary: {
      environment: env,
      overall_risk_level,
      issue_count,
      risk_score: riskScore,
      top_recommendations
    },
    methodology:
      "Static text analysis of CI/CD configuration with focus on container privileges, image tags, secrets handling, environment gating and presence of security scanning.",
    threats,
    stats: {
      pipeline_length: pipeline.length,
      high,
      medium,
      low,
      informational: info
    },
    remediation_plan,
    coverage,
    open_questions,
    timestamp_utc: new Date().toISOString()
  };
}

/**
 * 3) threat_model_generator (architecture-aware)
 */
function analyzeThreatModel(input) {
  const architecture = input.architecture_summary || "";

  const lower = architecture.toLowerCase();

  const features = {
    hasOauth:
      /oauth|oidc|openid connect|sso|single sign[- ]on|identity provider|idp/.test(
        lower
      ),
    hasJwt: /jwt|json web token/.test(lower),
    hasFileUpload:
      /file upload|multipart|s3 bucket|blob storage|gcs bucket|upload endpoint|cdn upload/.test(
        lower
      ),
    hasAdminPanel:
      /admin panel|admin ui|backoffice|back office|staff console/.test(lower),
    hasRBAC: /rbac|role[- ]based access|roles? and permissions?/.test(lower),
    hasExternalApi:
      /stripe|paypal|slack|salesforce|webhook|web hook|third[- ]party api|external api|partner api/.test(
        lower
      ),
    hasQueue:
      /queue|kafka|rabbitmq|sqs|pubsub|pub\/sub|message bus|event bus/.test(
        lower
      ),
    hasDb:
      /database|db server|sql|postgres|mysql|dynamodb|mongodb|nosql|warehouse/.test(
        lower
      ),
    hasFrontend:
      /web app|frontend|spa|react|next\.js|vue|angular|browser client/.test(
        lower
      ),
    hasApi:
      /api gateway|rest api|graphql|grpc endpoint|backend api|bff/.test(lower)
  };

  const components = [];

  if (features.hasFrontend) {
    components.push({
      id: "frontend",
      name: "Web Frontend",
      type: "client",
      description:
        "Browser-based client used by end users to authenticate and interact with the application."
    });
  }

  if (features.hasApi) {
    components.push({
      id: "api",
      name: "Backend API / BFF",
      type: "service",
      description:
        "Backend API or backend-for-frontend that handles business logic and data access."
    });
  }

  if (features.hasOauth || features.hasJwt) {
    components.push({
      id: "authz",
      name: "Auth / OAuth / Identity Provider",
      type: "service",
      description:
        "Authentication and authorization layer using OAuth/OIDC/JWT tokens."
    });
  }

  if (features.hasAdminPanel || features.hasRBAC) {
    components.push({
      id: "admin",
      name: "Admin Panel with RBAC",
      type: "service",
      description:
        "Administrative or internal user interface with role-based access control over privileged actions."
    });
  }

  if (features.hasFileUpload) {
    components.push({
      id: "uploads",
      name: "File Upload & Storage",
      type: "service",
      description:
        "Endpoints and storage for user-uploaded files (e.g., S3 buckets, blob storage, CDN)."
    });
  }

  if (features.hasExternalApi) {
    components.push({
      id: "integrations",
      name: "External Integrations",
      type: "service",
      description:
        "Outbound / inbound integrations with third-party APIs (payments, notifications, CRMs, webhooks, etc.)."
    });
  }

  if (features.hasQueue) {
    components.push({
      id: "mq",
      name: "Message Queue / Event Bus",
      type: "infra",
      description:
        "Asynchronous messaging infrastructure used for background jobs, events, or decoupled services."
    });
  }

  if (features.hasDb) {
    components.push({
      id: "db",
      name: "Primary Database",
      type: "data",
      description:
        "Persistent storage for core application data (user accounts, configuration, business records)."
    });
  }

  if (components.length === 0) {
    components.push({
      id: "core",
      name: "Core Application",
      type: "service",
      description:
        "High-level system components were not clearly identifiable; treating the application as a single logical component."
    });
  }

  const assets = [];
  if (/user|customer|account/i.test(architecture)) {
    assets.push("User accounts, sessions, and personal data");
  }
  if (/payment|funds|wallet|token|invoice|billing/i.test(architecture)) {
    assets.push("Financial assets, payment info, and transactional records");
  }
  if (features.hasAdminPanel || features.hasRBAC) {
    assets.push("Administrative privileges and configuration state");
  }
  if (features.hasFileUpload) {
    assets.push("Uploaded files and associated metadata");
  }
  if (assets.length === 0) {
    assets.push("Core application data and service availability");
  }

  const attack_surfaces = [];

  if (features.hasFrontend) {
    attack_surfaces.push({
      id: "surface_frontend",
      name: "Public Web Frontend",
      description:
        "Browser-accessible pages and client-side code exposed to the internet."
    });
  }

  if (features.hasApi) {
    attack_surfaces.push({
      id: "surface_api",
      name: "Public / Partner API",
      description:
        "REST/GraphQL/gRPC endpoints accepting requests from clients or partners."
    });
  }

  if (features.hasFileUpload) {
    attack_surfaces.push({
      id: "surface_uploads",
      name: "File Upload Endpoints",
      description:
        "Endpoints that accept and process user-controlled files for storage or further processing."
    });
  }

  if (features.hasAdminPanel) {
    attack_surfaces.push({
      id: "surface_admin",
      name: "Admin Panel",
      description:
        "Privileged administrative interface accessible by staff or internal users."
    });
  }

  if (features.hasExternalApi) {
    attack_surfaces.push({
      id: "surface_integrations",
      name: "Third-Party Integrations / Webhooks",
      description:
        "Inbound webhooks and outbound calls to external SaaS APIs and partner systems."
    });
  }

  if (attack_surfaces.length === 0) {
    attack_surfaces.push({
      id: "surface_core",
      name: "Primary Application Entry Points",
      description:
        "Unspecified public interfaces used by users or systems to interact with the app."
    });
  }

  const threats = [];

  const addThreat = (t) => threats.push(t);

  if (features.hasOauth || features.hasJwt) {
    addThreat({
      id: "tm_auth_token_misuse",
      surface: "Auth / OAuth / Identity Provider",
      component_id: "authz",
      stride_category: "Spoofing / Elevation of Privilege",
      severity: "high",
      description:
        "Misconfigured OAuth/OIDC or JWT validation could allow attackers to forge or replay tokens to impersonate users or escalate privileges.",
      example_attack_paths: [
        "Attacker crafts or steals a JWT, bypasses audience/issuer checks, and calls backend APIs as a higher-privilege user."
      ],
      mitigation:
        "Enforce strict issuer/audience checks, validate token signatures against trusted keys, require short token lifetimes with refresh tokens, and lock down redirect URIs and client secrets."
    });
  }

  if (features.hasFileUpload) {
    addThreat({
      id: "tm_file_upload_rce_xss",
      surface: "File Upload Endpoints",
      component_id: "uploads",
      stride_category: "Tampering / Information Disclosure",
      severity: "high",
      description:
        "Unvalidated file uploads could lead to stored XSS, malware distribution, or remote code execution if files are processed insecurely.",
      example_attack_paths: [
        "Attacker uploads a crafted HTML/JS file that is served from the same origin without proper content-type and content-disposition headers, leading to stored XSS.",
        "Attacker uploads a malicious file that is processed by an image/PDF library with known vulnerabilities, leading to RCE on the worker."
      ],
      mitigation:
        "Enforce strict allow-lists on MIME types and extensions, scan uploads for malware, store files on isolated domains with safe content-types, and avoid passing user-controlled files directly to high-risk processing libraries."
    });
  }

  if (features.hasAdminPanel || features.hasRBAC) {
    addThreat({
      id: "tm_admin_rbac_bypass",
      surface: "Admin Panel",
      component_id: "admin",
      stride_category: "Elevation of Privilege / Tampering",
      severity: "high",
      description:
        "Weak or inconsistent RBAC in admin workflows could allow standard users to perform privileged actions or abuse hidden endpoints.",
      example_attack_paths: [
        "Attacker finds an admin-only API endpoint that only checks authentication but not role membership, and uses it to change configuration or user roles."
      ],
      mitigation:
        "Centralize RBAC checks, enforce least privilege roles, ensure every admin endpoint checks both authentication and authorization, and log/alert on unusual admin activity."
    });
  }

  if (features.hasExternalApi) {
    addThreat({
      id: "tm_third_party_integrations",
      surface: "Third-Party Integrations / Webhooks",
      component_id: "integrations",
      stride_category: "Tampering / Repudiation",
      severity: "medium",
      description:
        "Unverified webhooks or over-privileged outbound API keys can allow attackers or compromised SaaS providers to inject or manipulate data.",
      example_attack_paths: [
        "Attacker sends forged webhook requests without signature validation, causing unauthorized state changes (e.g., marking invoices as paid)."
      ],
      mitigation:
        "Validate webhook signatures and source IPs, scope third-party API keys to minimal permissions, and add idempotency and sanity checks to inbound events."
    });
  }

  if (features.hasApi) {
    addThreat({
      id: "tm_api_abuse",
      surface: "Public / Partner API",
      component_id: "api",
      stride_category: "Denial of Service / Information Disclosure",
      severity: "medium",
      description:
        "Public APIs without proper throttling, authentication, or authorization can be abused for data scraping, brute forcing, or DoS.",
      example_attack_paths: [
        "Attacker scripts high-volume requests to enumeration endpoints to scrape user data or exhaust backend resources."
      ],
      mitigation:
        "Enforce authentication and authorization on sensitive endpoints, add rate limiting and anomaly detection, and minimize verbose error responses."
    });
  }

  if (features.hasQueue) {
    addThreat({
      id: "tm_queue_poisoning",
      surface: "Message Queue / Event Bus",
      component_id: "mq",
      stride_category: "Tampering / Denial of Service",
      severity: "medium",
      description:
        "If message producers or consumers are insufficiently authenticated, attackers may inject or replay messages, causing inconsistent state or overload.",
      example_attack_paths: [
        "Compromised service credentials allow an attacker to flood the queue with bogus events, starving legitimate processing."
      ],
      mitigation:
        "Restrict queue access with strong IAM, validate message schemas, implement dead-letter queues, and monitor for unusual volume or patterns."
    });
  }

  if (features.hasDb) {
    addThreat({
      id: "tm_db_data_breach",
      surface: "Primary Database",
      component_id: "db",
      stride_category: "Information Disclosure / Tampering",
      severity: "high",
      description:
        "Weak segregation, injection vulnerabilities, or misconfigured IAM could lead to bulk extraction or modification of sensitive data.",
      example_attack_paths: [
        "SQL injection in API layer lets attacker dump the user table, including PII and auth data."
      ],
      mitigation:
        "Use parameterized queries/ORM, separate write/read roles, encrypt sensitive fields at rest, and monitor access patterns."
    });
  }

  if (threats.length === 0) {
    threats.push({
      id: "tm_generic",
      surface: "Primary Application Entry Points",
      component_id: components[0].id,
      stride_category: "Generic – multiple STRIDE categories",
      severity: "medium",
      description:
        "High-level threats exist around authentication, authorization, data validation and logging, but no specific patterns could be identified from the summary.",
      example_attack_paths: [],
      mitigation:
        "Apply defense-in-depth: strong authn/z, input validation, least privilege access to data stores, centralized logging, and alerting for anomalous activity."
    });
  }

  const attack_paths = [];

  if (features.hasFrontend && features.hasApi && features.hasDb) {
    attack_paths.push({
      id: "path_frontend_api_db",
      description:
        "Internet attacker compromises user via the frontend to reach sensitive data in the DB through the API.",
      steps: [
        "Attacker sends malicious input through the web frontend.",
        "Frontend forwards the request to the backend API.",
        "Backend API processes insufficiently validated input.",
        "Attacker exploits injection or authz flaws to read/modify records in the database."
      ],
      risk_level: "high"
    });
  }

  if (features.hasAdminPanel && features.hasOauth) {
    attack_paths.push({
      id: "path_oauth_admin_takeover",
      description:
        "Attacker abuses OAuth misconfiguration or token handling to gain access to the admin panel.",
      steps: [
        "Attacker obtains or forges an OAuth/JWT token due to configuration or validation flaws.",
        "Attacker uses the token to access the admin panel as a privileged user.",
        "Attacker changes roles, configuration, or user data through admin endpoints."
      ],
      risk_level: "high"
    });
  }

  if (features.hasFileUpload && features.hasExternalApi) {
    attack_paths.push({
      id: "path_upload_integrations",
      description:
        "Attacker leverages file uploads to trigger dangerous downstream processing or external integrations.",
      steps: [
        "Attacker uploads a crafted file via the file upload endpoint.",
        "Background workers process the file and trigger webhooks or external APIs based on its contents.",
        "Malformed content causes incorrect actions in external systems or data leaks."
      ],
      risk_level: "medium"
    });
  }

  if (attack_paths.length === 0) {
    attack_paths.push({
      id: "path_generic",
      description:
        "Generic path from an external attacker through exposed interfaces to core data or admin functions.",
      steps: [
        "Attacker interacts with exposed interface (web/API).",
        "Exploits validation/authn/authz gaps to gain broader access.",
        "Moves laterally to access sensitive data or privileged operations."
      ],
      risk_level: "medium"
    });
  }

  const overall_risk_level = threats.some((t) => t.severity === "high")
    ? "high"
    : "medium";

  const assumptions = [];
  if (/internet|public/i.test(architecture)) {
    assumptions.push(
      "System exposes at least some endpoints to the public internet and must assume fully untrusted traffic."
    );
  } else {
    assumptions.push(
      "System may be primarily internal, but insider threats and credential compromise must still be considered."
    );
  }
  if (/cloud|aws|gcp|azure/i.test(architecture)) {
    assumptions.push(
      "Cloud provider IAM and network-level controls are available for segmentation and least-privilege access."
    );
  }

  const open_questions = [
    "Which components are considered in-scope for initial rollout vs future phases?",
    "For admin and operational interfaces, which roles exist and what actions are considered most sensitive?",
    "Are there any regulatory drivers (e.g., GDPR, PCI, HIPAA) that change acceptable risk levels for specific data types?"
  ];

  return {
    summary: {
      key_assets: assets,
      primary_attack_surfaces: attack_surfaces.map((s) => s.name),
      overall_risk_level
    },
    methodology:
      "Heuristic STRIDE-style analysis using architecture text to infer concrete components (auth, uploads, admin RBAC, integrations, DB, queues) and build feature-specific threats, attack paths, and mitigations.",
    components,
    assets,
    attack_surfaces,
    threats,
    attack_paths,
    assumptions,
    open_questions,
    timestamp_utc: new Date().toISOString()
  };
}

/**
 * 4) deployment_safety_review
 */
function analyzeDeploymentSafety(input) {
  const network = input.network || "";
  const settings = input.settings || {};
  const risks = [];
  const checklist = [];

  const upgradeable = !!settings.upgradeable;
  const owner = settings.owner || "";
  const version = settings.version || "";
  const emergencyPause = !!settings.emergency_pause;
  const usesMultisig = !!settings.multisig_owner;

  const addRisk = (r) => risks.push(r);
  const addCheck = (c) => checklist.push(c);

  addCheck(
    "Confirm owner/admin and any multisig addresses are correct and securely stored."
  );
  addCheck(
    "Ensure deployment scripts are version-controlled, peer-reviewed and reproducible."
  );
  addCheck("Verify contract bytecode matches the audited and tested source.");
  addCheck(
    "Confirm a rollback or hotfix procedure exists and is documented."
  );
  addCheck(
    "Ensure monitoring/alerting is in place for key on-chain events and metrics."
  );

  if (!owner || owner === "0x0000000000000000000000000000000000000000") {
    addRisk({
      id: "missing_owner",
      severity: "high",
      description:
        "Owner/admin address is missing or the zero address, making governance and emergency actions unclear.",
      suggestion:
        "Set an explicit, well-governed owner or admin address, ideally a multisig with clear processes."
    });
  }

  if (upgradeable && !usesMultisig) {
    addRisk({
      id: "upgradeable_no_multisig",
      severity: "high",
      description:
        "Contract is upgradeable but upgrades do not appear to be controlled by a multisig.",
      suggestion:
        "Use a battle-tested multisig (e.g., Gnosis Safe) to control upgradeability, with clear signers and processes."
    });
  }

  if (!emergencyPause && upgradeable) {
    addRisk({
      id: "no_emergency_pause",
      severity: "medium",
      description:
        "No emergency pause/guard mechanism is indicated for an upgradeable or complex system.",
      suggestion:
        "Add a circuit-breaker or pause mechanism governed by a multisig, with clear criteria for activation."
    });
  }

  if (!version || /alpha|beta|rc/i.test(version)) {
    addRisk({
      id: "non_stable_version",
      severity: "medium",
      description:
        "Deployment version suggests a non-stable release (alpha/beta/RC) or was not specified.",
      suggestion:
        "Use stable, well-tested releases for production networks, and explicitly label non-production deployments."
    });
  }

  if (risks.length === 0) {
    addRisk({
      id: "basic_checks_passed",
      severity: "info",
      description:
        "No critical deployment safety issues detected based on the provided metadata.",
      suggestion:
        "Still perform a full pre-deployment checklist and have an external reviewer validate assumptions."
    });
  }

  const severity_breakdown = {
    critical: 0,
    high: risks.filter((r) => r.severity === "high").length,
    medium: risks.filter((r) => r.severity === "medium").length,
    low: risks.filter((r) => r.severity === "low").length,
    info: risks.filter((r) => r.severity === "info").length
  };

  const riskScore =
    severity_breakdown.high * 4 +
    severity_breakdown.medium * 3 +
    severity_breakdown.low * 2 +
    severity_breakdown.info * 1;

  const overall_risk_level =
    riskScore >= 8
      ? "high"
      : riskScore >= 4
      ? "medium"
      : riskScore > 0
      ? "low"
      : "info";

  const remediation_plan = [...risks]
    .sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity))
    .map((r, idx) => ({
      id: r.id,
      severity: r.severity,
      priority: idx + 1,
      reason: `Prioritized due to ${r.severity} severity and impact on governance or recoverability.`
    }));

  const assumptions = [];
  if (/mainnet|base/i.test(network)) {
    assumptions.push(
      "Deployment is expected to handle real-value transactions on a production-like network."
    );
  } else {
    assumptions.push(
      "Deployment may be on a test or staging network, but governance risks still apply."
    );
  }

  const open_questions = [
    "Who exactly will control the owner/admin and multisig keys, and how are those keys backed up and rotated?",
    "Is there a documented incident response plan if a critical vulnerability is discovered post-deployment?"
  ];

  return {
    summary: {
      network,
      overall_risk_level,
      risk_score: riskScore
    },
    checklist,
    risks,
    remediation_plan,
    severity_breakdown,
    assumptions,
    open_questions,
    timestamp_utc: new Date().toISOString()
  };
}

// ---------------------------------------------------------------------------
// Enrichment: call vuln_db + mitigation_playbook
// ---------------------------------------------------------------------------

async function enrichDeliverable(jobType, deliverable) {
  try {
    if (!deliverable || !jobType) return deliverable;

    if (jobType === "smart_contract_static_pattern_analysis") {
      const findings = deliverable.findings || [];
      await Promise.all(
        findings.map(async (f) => {
          const id = f.id;
          if (!id) return;

          const vulnMeta = await fetchVulnMeta(id);
          if (vulnMeta && typeof vulnMeta === "object") {
            softMerge(f, vulnMeta);
          }

          const mitMeta = await fetchMitigationMeta(id);
          if (mitMeta && typeof mitMeta === "object") {
            // Prefer remediation-related fields from mitigation_playbook
            softMerge(f, {
              suggestion:
                mitMeta.remediation ||
                mitMeta.mitigation ||
                f.suggestion ||
                undefined
            });
          }
        })
      );
    }

    if (jobType === "devops_pipeline_security_review_v2") {
      const threats = deliverable.threats || [];
      await Promise.all(
        threats.map(async (t) => {
          const id = t.id;
          if (!id) return;

          const vulnMeta = await fetchVulnMeta(id);
          if (vulnMeta && typeof vulnMeta === "object") {
            softMerge(t, vulnMeta);
          }

          const mitMeta = await fetchMitigationMeta(id);
          if (mitMeta && typeof mitMeta === "object") {
            softMerge(t, {
              mitigation:
                mitMeta.remediation ||
                mitMeta.mitigation ||
                t.mitigation ||
                undefined
            });
          }
        })
      );
    }

    if (jobType === "threat_model_generator") {
      const threats = deliverable.threats || [];
      await Promise.all(
        threats.map(async (t) => {
          const id = t.id;
          if (!id) return;

          const vulnMeta = await fetchVulnMeta(id);
          if (vulnMeta && typeof vulnMeta === "object") {
            softMerge(t, vulnMeta);
          }

          const mitMeta = await fetchMitigationMeta(id);
          if (mitMeta && typeof mitMeta === "object") {
            softMerge(t, {
              mitigation:
                mitMeta.remediation ||
                mitMeta.mitigation ||
                t.mitigation ||
                undefined
            });
          }
        })
      );
    }

    if (jobType === "deployment_safety_review") {
      const risks = deliverable.risks || [];
      await Promise.all(
        risks.map(async (r) => {
          const id = r.id;
          if (!id) return;

          const vulnMeta = await fetchVulnMeta(id);
          if (vulnMeta && typeof vulnMeta === "object") {
            softMerge(r, vulnMeta);
          }

          const mitMeta = await fetchMitigationMeta(id);
          if (mitMeta && typeof mitMeta === "object") {
            softMerge(r, {
              suggestion:
                mitMeta.remediation ||
                mitMeta.mitigation ||
                r.suggestion ||
                undefined
            });
          }
        })
      );
    }

    return deliverable;
  } catch (err) {
    console.warn("⚠️ enrichDeliverable error:", err.message || err);
    return deliverable;
  }
}

// ---------------------------------------------------------------------------
// ACP client wiring
// ---------------------------------------------------------------------------

async function main() {
  const privateKey = process.env.WHITELISTED_WALLET_PRIVATE_KEY;
  const sellerEntityId = process.env.SELLER_ENTITY_ID;
  const sellerWalletAddress = process.env.SELLER_AGENT_WALLET_ADDRESS;

  if (!privateKey || !sellerEntityId || !sellerWalletAddress) {
    throw new Error(
      "Missing environment variables. Check .env: WHITELISTED_WALLET_PRIVATE_KEY, SELLER_ENTITY_ID, SELLER_AGENT_WALLET_ADDRESS"
    );
  }

  console.log("🔑 Seller Entity:", sellerEntityId);
  console.log("👛 Seller Wallet:", sellerWalletAddress);

  const acpContractClient = await AcpContractClientV2.build(
    privateKey,
    sellerEntityId,
    sellerWalletAddress,
    process.env.CUSTOM_RPC_URL || undefined,
    undefined
  );

  const acpClient = new AcpClient({
    acpContractClient,

    onNewTask: async (job, memoToSign) => {
      console.log("🟢 New job received:", job.id);
      console.log("📌 Job phase:", job.phase);
      console.log("📥 Job input full:", JSON.stringify(job.input, null, 2));
      console.log(
        "📝 Memo structuredContent:",
        memoToSign && memoToSign.structuredContent
          ? JSON.stringify(memoToSign.structuredContent, null, 2)
          : "undefined"
      );

      try {
        if (!memoToSign || memoToSign.status !== "PENDING") {
          console.log("⚪ No pending memo to act on.");
          return;
        }

        // Phase 0 -> 1: accept job, cache requirement
        if (memoToSign.nextPhase === 1) {
          const sc = memoToSign.structuredContent;
          if (sc && typeof sc === "object") {
            jobCache.set(job.id, {
              name: sc.name,
              requirement: sc.requirement || {}
            });
            console.log("💾 Cached requirement for job:", job.id);
          } else {
            console.log(
              "⚠️ No structuredContent on memo at phase 0 for job:",
              job.id
            );
          }

          console.log("🤝 Responding to job (accepting)...");
          await job.respond(true, "SAIQUE AI auto-accept");
          console.log("✅ Job accepted:", job.id);
          return;
        }

        // Phase 2 -> 3: deliver result
        if (memoToSign.nextPhase === 3) {
          console.log("📦 Preparing deliverable for job...");

          const cached = jobCache.get(job.id) || {};
          const cachedRequirement = cached.requirement || {};
          const cachedName = cached.name || null;

          let input =
            job.input && Object.keys(job.input).length
              ? job.input
              : cachedRequirement;

          console.log(
            "📥 Effective input for analysis:",
            JSON.stringify(input, null, 2)
          );

          let jobType =
            inferJobTypeFromName(cachedName) || inferJobTypeFromInput(input);
          console.log(
            "🧭 Inferred job type:",
            jobType,
            "from name:",
            cachedName
          );

          let deliverable;

          if (jobType === "smart_contract_static_pattern_analysis") {
            console.log("🔍 Running smart_contract_static_pattern_analysis");
            deliverable = analyzeSmartContractStatic(input);
          } else if (jobType === "devops_pipeline_security_review_v2") {
            console.log("🔍 Running devops_pipeline_security_review_v2");
            deliverable = analyzeDevopsPipeline(input);
          } else if (jobType === "threat_model_generator") {
            console.log("🔍 Running threat_model_generator");
            deliverable = analyzeThreatModel(input);
          } else if (jobType === "deployment_safety_review") {
            console.log("🔍 Running deployment_safety_review");
            deliverable = analyzeDeploymentSafety(input);
          } else {
            deliverable = fallbackBestEffortDeliverable(input);
          }

          // 🔁 Enrich from vuln_db + mitigation_playbook before delivering
          deliverable = await enrichDeliverable(jobType, deliverable);

          await job.deliver(deliverable);
          console.log("✅ Job delivered:", job.id);
          return;
        }

        console.log("⚪ Memo nextPhase not handled:", memoToSign.nextPhase);
      } catch (err) {
        console.error("🚨 Error while handling job:", err);
      }
    },

    onEvaluate: async (job) => {
      console.log(
        "📊 onEvaluate fired for job:",
        job.id,
        "phase:",
        job.phase
      );
      // Optional evaluator logic in future.
    }
  });

  console.log("🚀 Initializing ACP client...");
  if (typeof acpClient.init === "function") {
    await acpClient.init();
  }
  console.log(
    "🟢 ACP client initialized. Waiting for jobs from Butler / ACP..."
  );

  setInterval(() => {
    console.log("⏱ Heartbeat: provider is still running...");
  }, 60000);
}

main().catch((err) => {
  console.error("❌ ERROR:", err);
  process.exit(1);
});
