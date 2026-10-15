(function () {
  "use strict";

  const TIMELINE_STATUSES = new Set([
    "completed",
    "complete",
    "incomplete",
    "manual_review",
    "risk_detected",
    "skipped",
    "failed",
  ]);
  const SECURITY_DECISIONS = new Set(["allow", "block", "quarantine"]);
  const state = {
    scenarios: new Map(),
    results: new Map(),
    errors: new Map(),
    inFlight: new Set(),
    runButtons: new Map(),
    runAllActive: false,
  };

  const elements = {
    health: document.getElementById("health-indicator"),
    provider: document.getElementById("provider-indicator"),
    runAll: document.getElementById("run-all-button"),
    progress: document.getElementById("run-progress"),
    scenarioGrid: document.getElementById("scenario-grid"),
    globalError: document.getElementById("global-error"),
    resultSection: document.getElementById("result-section"),
    resultTitle: document.getElementById("result-title"),
    resultDecision: document.getElementById("result-decision"),
    resultContent: document.getElementById("result-content"),
    refreshEvidence: document.getElementById("refresh-evidence-button"),
    evidenceSummary: document.getElementById("evidence-summary"),
    evidenceList: document.getElementById("evidence-list"),
    scenarioCount: document.getElementById("scenario-count"),
    allowCount: document.getElementById("allow-count"),
    restrictedCount: document.getElementById("restricted-count"),
    missingCount: document.getElementById("missing-count"),
    failedCount: document.getElementById("failed-count"),
    evidenceOverview: document.getElementById("evidence-overview"),
    evidenceRecordCount: document.getElementById("evidence-record-count"),
    evidenceStatCard: document.getElementById("evidence-stat-card"),
  };

  class DashboardError extends Error {
    constructor(message, status) {
      super(message);
      this.name = "DashboardError";
      this.status = status;
    }
  }

  function isObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }

  function makeElement(tagName, className, text) {
    const node = document.createElement(tagName);
    if (className) {
      node.className = className;
    }
    if (text !== undefined && text !== null) {
      node.textContent = String(text);
    }
    return node;
  }

  function safeMessage(error, fallback) {
    if (error instanceof DashboardError) {
      return error.message;
    }
    return fallback;
  }

  async function fetchJson(path, options) {
    let response;
    try {
      response = await fetch(path, options);
    } catch (_error) {
      throw new DashboardError("The backend is unavailable. No security result was produced.");
    }

    const responseText = await response.text();
    let payload = null;
    if (responseText) {
      try {
        payload = JSON.parse(responseText);
      } catch (_error) {
        throw new DashboardError(
          `The backend returned a malformed response (HTTP ${response.status}).`,
          response.status,
        );
      }
    }

    if (!response.ok) {
      const detail = isObject(payload) && typeof payload.detail === "string"
        ? payload.detail
        : "The request failed and no security result was accepted.";
      throw new DashboardError(`HTTP ${response.status}: ${detail}`, response.status);
    }
    if (!isObject(payload)) {
      throw new DashboardError("The backend response could not be safely interpreted.");
    }
    return payload;
  }

  function requireString(value, fieldName) {
    if (typeof value !== "string" || value.length === 0) {
      throw new DashboardError(`The backend response is missing ${fieldName}.`);
    }
    return value;
  }

  function requireStringArray(value, fieldName) {
    if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
      throw new DashboardError(`The backend response has invalid ${fieldName}.`);
    }
    return value;
  }

  function validateScenarioList(payload) {
    if (!Array.isArray(payload.scenarios)) {
      throw new DashboardError("The scenario catalogue is malformed.");
    }
    payload.scenarios.forEach((scenario) => {
      if (!isObject(scenario)) {
        throw new DashboardError("The scenario catalogue contains an invalid entry.");
      }
      requireString(scenario.scenario_id, "scenario ID");
      requireString(scenario.scenario_name, "scenario name");
      requireString(scenario.description, "scenario description");
      requireString(scenario.expected_outcome, "expected outcome");
      requireString(scenario.risk_category, "risk category");
    });
    return payload.scenarios;
  }

  function validateScenarioDetail(payload) {
    if (!isObject(payload.scenario) || !Array.isArray(payload.grants)) {
      throw new DashboardError("The scenario detail response is malformed.");
    }
    requireString(payload.scenario.scenario_id, "scenario ID");
    requireStringArray(payload.scenario.intended_actions, "intended actions");
    requireStringArray(payload.scenario.grant_ids, "grant IDs");
    payload.grants.forEach((grant) => {
      if (!isObject(grant)) {
        throw new DashboardError("The scenario contains malformed grant metadata.");
      }
      requireString(grant.grant_id, "grant ID");
    });
    return payload;
  }

  function validateRunResponse(payload, expectedScenarioId) {
    if (payload.scenario_id !== expectedScenarioId || typeof payload.passed !== "boolean") {
      throw new DashboardError("The backend response could not be safely interpreted.");
    }
    if (!isObject(payload.analysis_summary) || !isObject(payload.actual_outcome)) {
      throw new DashboardError("The analysis result is incomplete.");
    }
    const analysis = payload.analysis_summary;
    [
      "granted_scopes",
      "required_scopes",
      "matched_scopes",
      "excessive_scopes",
      "missing_scopes",
      "required_capabilities",
      "granted_capabilities",
      "missing_capabilities",
    ].forEach((fieldName) => requireStringArray(analysis[fieldName], fieldName));
    if (!isObject(analysis.least_privilege_plan)) {
      throw new DashboardError("The least-privilege plan is missing.");
    }
    requireStringArray(
      analysis.least_privilege_plan.selected_scopes,
      "synthesized least-privilege scopes",
    );
    requireStringArray(analysis.least_privilege_plan.scopes_to_remove, "scopes to remove");
    requireString(analysis.recommendation, "recommendation");
    if (!Array.isArray(payload.gateway_decisions) || !Array.isArray(payload.timeline)) {
      throw new DashboardError("Runtime decision or timeline data is malformed.");
    }
    if (typeof payload.evidence_chain_valid !== "boolean") {
      throw new DashboardError("Evidence verification status is missing.");
    }
    return payload;
  }

  function setIndicator(node, label, stateClass) {
    node.replaceChildren();
    const dot = makeElement("span", "indicator-dot");
    dot.setAttribute("aria-hidden", "true");
    node.append(dot, document.createTextNode(label));
    node.className = `indicator ${stateClass}`;
  }

  function showGlobalError(message) {
    elements.globalError.textContent = message;
    elements.globalError.hidden = false;
  }

  function clearGlobalError() {
    elements.globalError.textContent = "";
    elements.globalError.hidden = true;
  }

  function formatLabel(value) {
    if (typeof value !== "string" || !value) {
      return "Unrecognized";
    }
    return value
      .split("_")
      .map((part) => part ? part[0].toUpperCase() + part.slice(1) : "")
      .join(" ");
  }

  function riskClass(category) {
    if (category === "low") {
      return "safe";
    }
    if (category === "missing_permission") {
      return "warning";
    }
    if (category === "runtime_drift") {
      return "quarantine";
    }
    if (category === "excessive_authority" || category === "composition_risk") {
      return "danger";
    }
    return "unsafe";
  }

  function resultState(result) {
    if (!result) {
      return { label: "Not executed", className: "neutral" };
    }
    const decisions = result.gateway_decisions.map((item) => (
      isObject(item) && typeof item.decision === "string" ? item.decision : "unsafe_unknown"
    ));
    if (decisions.some((decision) => !SECURITY_DECISIONS.has(decision))) {
      return { label: "Unsafe / Unknown", className: "unsafe" };
    }
    if (new Set(decisions).size > 1) {
      return { label: "Unsafe / Unknown", className: "unsafe" };
    }
    if (decisions.includes("quarantine")) {
      return { label: "Quarantined", className: "quarantine" };
    }
    if (decisions.includes("block")) {
      return { label: "Blocked", className: "danger" };
    }
    if (decisions.includes("allow")) {
      return { label: "Allowed", className: "safe" };
    }
    const pathCount = result.actual_outcome.unauthorized_path_count;
    if (Number.isInteger(pathCount) && pathCount > 0) {
      return { label: "Risk detected", className: "danger" };
    }
    if (result.analysis_summary.missing_capabilities.length > 0) {
      return { label: "Permission missing", className: "warning" };
    }
    return result.passed
      ? { label: "Completed", className: "neutral" }
      : { label: "Failed", className: "danger" };
  }

  function deterministicStrings(values) {
    return values.slice().sort((left, right) => left.localeCompare(right));
  }

  function addDefinition(list, term, description) {
    list.append(makeElement("dt", null, term), makeElement("dd", null, description));
  }

  function renderScenarioCards() {
    elements.scenarioGrid.replaceChildren();
    state.runButtons.clear();
    state.scenarios.forEach((entry, scenarioId) => {
      const summary = entry.summary;
      const detail = entry.detail;
      const card = makeElement("article", "scenario-card");
      card.setAttribute("data-scenario-id", scenarioId);

      const topline = makeElement("div", "card-topline");
      topline.append(
        makeElement("span", `risk-label ${riskClass(summary.risk_category)}`, formatLabel(summary.risk_category)),
        makeElement("span", "status-label neutral", "Not executed"),
      );
      const statusNode = topline.lastElementChild;

      card.append(topline, makeElement("h3", null, summary.scenario_name));
      card.append(makeElement("p", null, summary.description));

      const metadata = makeElement("dl", "metadata-list");
      const scenario = detail ? detail.scenario : null;
      addDefinition(
        metadata,
        "Intent",
        scenario ? deterministicStrings(scenario.intended_actions).join(", ") || "None" : "Unavailable",
      );
      addDefinition(
        metadata,
        "Grants",
        scenario ? deterministicStrings(scenario.grant_ids).join(", ") || "None" : "Unavailable",
      );
      addDefinition(metadata, "Expected", summary.expected_outcome);
      card.append(metadata);

      if (entry.detailError) {
        card.append(makeElement("p", "inline-warning", entry.detailError));
      }

      const actions = makeElement("div", "card-actions");
      const runButton = makeElement("button", "run-button", "Run Scenario");
      runButton.type = "button";
      runButton.setAttribute("aria-label", `Run ${summary.scenario_name}`);
      runButton.addEventListener("click", () => {
        runScenario(scenarioId, false).catch(() => {
          showGlobalError("An unexpected dashboard error occurred. No result was accepted.");
        });
      });
      actions.append(runButton);
      card.append(actions);
      elements.scenarioGrid.append(card);
      state.runButtons.set(scenarioId, { button: runButton, status: statusNode });
    });
    updateControls();
    refreshCardStatuses();
  }

  function refreshCardStatuses() {
    state.runButtons.forEach((controls, scenarioId) => {
      const error = state.errors.get(scenarioId);
      if (error) {
        controls.status.textContent = "Execution error";
        controls.status.className = "status-label danger";
        return;
      }
      const display = resultState(state.results.get(scenarioId));
      controls.status.textContent = display.label;
      controls.status.className = `status-label ${display.className}`;
    });
  }

  function updateControls() {
    elements.runAll.disabled = state.runAllActive || state.scenarios.size === 0;
    state.runButtons.forEach((controls, scenarioId) => {
      const running = state.inFlight.has(scenarioId);
      controls.button.disabled = state.runAllActive || running;
      controls.button.textContent = running ? "Running…" : "Run Scenario";
    });
  }

  function updateTotals() {
    let allow = 0;
    let restricted = 0;
    let missing = 0;
    state.results.forEach((result) => {
      const decisions = result.gateway_decisions
        .filter((item) => isObject(item))
        .map((item) => item.decision);
      if (decisions.includes("allow")) {
        allow += 1;
      }
      if (decisions.includes("block") || decisions.includes("quarantine")) {
        restricted += 1;
      }
      if (result.analysis_summary.missing_capabilities.length > 0) {
        missing += 1;
      }
    });
    elements.allowCount.textContent = String(allow);
    elements.restrictedCount.textContent = String(restricted);
    elements.missingCount.textContent = String(missing);
    elements.failedCount.textContent = String(state.errors.size);
  }

  function createChipList(values, variant) {
    const list = makeElement("ul", "chip-list");
    if (values.length === 0) {
      list.append(makeElement("li", "chip empty", "None"));
      return list;
    }
    deterministicStrings(values).forEach((value) => {
      list.append(makeElement("li", `chip ${variant || ""}`.trim(), value));
    });
    return list;
  }

  function createChipGroup(title, values, variant) {
    const group = makeElement("div", "chip-group");
    group.append(makeElement("h4", null, title), createChipList(values, variant));
    return group;
  }

  function createPanel(title, className) {
    const panel = makeElement("section", `panel ${className || ""}`.trim());
    panel.append(makeElement("h3", null, title));
    return panel;
  }

  function getWhyExplanation(result) {
    const decisions = result.gateway_decisions;
    if (decisions.length > 0) {
      if (decisions.some((item) => !isObject(item) || !SECURITY_DECISIONS.has(item.decision))) {
        return "The backend response could not be safely interpreted.";
      }
      if (new Set(decisions.map((item) => item.decision)).size > 1) {
        return "The backend response could not be safely interpreted.";
      }
      const explanations = decisions.map((item) => item.explanation);
      if (explanations.some((value) => typeof value !== "string" || value.length === 0)) {
        return "The backend response could not be safely interpreted.";
      }
      return `${explanations.join(" ")} ${result.analysis_summary.recommendation}`;
    }

    const composition = result.composition_summary;
    if (isObject(composition) && Array.isArray(composition.unauthorized_paths)
        && composition.unauthorized_paths.length > 0) {
      const remediation = Array.isArray(composition.remediation)
        ? composition.remediation.filter((item) => typeof item === "string")
        : [];
      if (remediation.length === 0) {
        return "The backend response could not be safely interpreted.";
      }
      return `The backend detected an unauthorized composed path. ${remediation.join(" ")}`;
    }

    if (result.analysis_summary.missing_capabilities.length > 0) {
      const explanation = result.analysis_summary.least_privilege_plan.explanation;
      if (typeof explanation !== "string" || !explanation) {
        return "The backend response could not be safely interpreted.";
      }
      return `${explanation} ${result.analysis_summary.recommendation}`;
    }

    return result.analysis_summary.recommendation ||
      "The backend response could not be safely interpreted.";
  }

  function renderScopePanel(result) {
    const analysis = result.analysis_summary;
    const plan = analysis.least_privilege_plan;
    const panel = createPanel("Scope differential", "full-width");
    const flow = makeElement("div", "authority-flow");
    flow.append(
      createChipGroup("Granted authority", analysis.granted_scopes),
      makeElement("span", "flow-arrow", "→"),
    );
    const differential = makeElement("div", "chip-group");
    differential.append(
      makeElement("h4", null, "Exposure differential"),
      createChipList(analysis.excessive_scopes, "excessive"),
    );
    flow.append(
      differential,
      makeElement("span", "flow-arrow", "→"),
      createChipGroup("Synthesized contract", plan.selected_scopes, "synthesized"),
    );
    panel.append(flow);

    const columns = makeElement("div", "chip-columns");
    columns.append(
      createChipGroup("Required scopes", analysis.required_scopes),
      createChipGroup("Matched scopes", analysis.matched_scopes, "matched"),
      createChipGroup("Excessive scopes", analysis.excessive_scopes, "excessive"),
      createChipGroup("Missing scopes", analysis.missing_scopes, "missing"),
      createChipGroup("Scopes removed", plan.scopes_to_remove, "excessive"),
      createChipGroup("Synthesized scopes", plan.selected_scopes, "synthesized"),
    );
    panel.append(columns);
    return panel;
  }

  function renderCapabilityPanel(result) {
    const analysis = result.analysis_summary;
    const panel = createPanel("Capabilities", "full-width");
    const attempted = result.gateway_decisions
      .filter((item) => isObject(item) && typeof item.attempted_capability === "string")
      .map((item) => item.attempted_capability);
    const columns = makeElement("div", "chip-columns");
    columns.append(
      createChipGroup("Required capabilities", analysis.required_capabilities),
      createChipGroup("Available capabilities", analysis.granted_capabilities),
      createChipGroup("Missing capabilities", analysis.missing_capabilities, "missing"),
      createChipGroup("Attempted capability", attempted),
    );
    panel.append(columns);
    if (analysis.missing_capabilities.length > 0 && result.contract_summary === null) {
      panel.append(makeElement(
        "p",
        "inline-warning",
        "No executable contract was created because required capability coverage is missing.",
      ));
    }
    return panel;
  }

  function renderRuntimePanel(result) {
    const panel = createPanel("Contract and runtime monitoring");
    const metadata = makeElement("dl", "metadata-list");
    const contractStatus = isObject(result.contract_summary)
      && typeof result.contract_summary.state === "string"
      ? result.contract_summary.state
      : "Not created";
    addDefinition(metadata, "Contract status", formatLabel(contractStatus));
    if (result.gateway_decisions.length === 0) {
      addDefinition(metadata, "Runtime decision", "Not executed");
      addDefinition(metadata, "Decision reason", "No runtime decision was returned by the backend.");
    } else {
      result.gateway_decisions.forEach((decision, index) => {
        if (!isObject(decision) || !SECURITY_DECISIONS.has(decision.decision)) {
          addDefinition(metadata, `Decision ${index + 1}`, "Unsafe / Unknown");
          addDefinition(metadata, "Reason", "The backend response could not be safely interpreted.");
        } else {
          addDefinition(metadata, `Decision ${index + 1}`, formatLabel(decision.decision));
          addDefinition(
            metadata,
            "Reason",
            typeof decision.reason_code === "string" ? formatLabel(decision.reason_code) : "Unrecognized",
          );
        }
      });
    }
    addDefinition(metadata, "Evidence chain", result.evidence_chain_valid ? "Valid" : "Invalid");
    panel.append(metadata);
    return panel;
  }

  function renderCompositionPanel(result) {
    const panel = createPanel("Composition paths", "full-width");
    const composition = result.composition_summary;
    const paths = isObject(composition) && Array.isArray(composition.unauthorized_paths)
      ? composition.unauthorized_paths
      : [];
    if (paths.length === 0) {
      panel.append(makeElement("p", null, "No unauthorized composition path was detected."));
      return panel;
    }

    const list = makeElement("ol", "path-list");
    paths.forEach((path, index) => {
      const item = makeElement("li", "composition-path");
      if (!isObject(path)) {
        item.append(makeElement("p", "inline-warning", "Unrecognized composition path data."));
        list.append(item);
        return;
      }
      const source = typeof path.source_capability === "string" ? path.source_capability : "Unrecognized";
      const dataType = typeof path.data_type === "string" ? path.data_type : "Unrecognized";
      const target = typeof path.target_capability === "string" ? path.target_capability : "Unrecognized";
      item.append(
        makeElement("div", "path-node", source),
        makeElement("span", "path-arrow", "→"),
        makeElement("div", "path-node", dataType),
        makeElement("span", "path-arrow", "→"),
        makeElement("div", "path-node", target),
      );
      const description = makeElement(
        "p",
        "path-description",
        `Path ${index + 1}: ${source} flows through ${dataType} to ${target}.`,
      );
      description.setAttribute("aria-label", `Unauthorized path ${index + 1}`);
      item.append(description);
      if (typeof path.remediation === "string") {
        item.append(makeElement("p", "path-description", `Remediation: ${path.remediation}`));
      }
      list.append(item);
    });
    panel.append(list);
    return panel;
  }

  function stableValueText(value) {
    if (value === null || value === undefined) {
      return "None";
    }
    if (Array.isArray(value)) {
      return value.length ? value.map((item) => String(item)).join(", ") : "None";
    }
    if (isObject(value)) {
      const ordered = {};
      Object.keys(value).sort().forEach((key) => {
        ordered[key] = value[key];
      });
      return JSON.stringify(ordered, null, 2);
    }
    return String(value);
  }

  function renderTimelinePanel(result) {
    const panel = createPanel("Execution timeline", "full-width");
    const timeline = makeElement("ol", "timeline");
    const entries = result.timeline.slice();
    let malformed = false;
    const numbers = entries.map((entry) => (
      isObject(entry) && Number.isInteger(entry.step_number) && entry.step_number > 0
        ? entry.step_number
        : null
    ));
    if (numbers.some((number) => number === null)
        || new Set(numbers).size !== numbers.length) {
      malformed = true;
    }
    const validNumbers = numbers.filter((number) => number !== null).sort((a, b) => a - b);
    if (validNumbers.some((number, index) => number !== index + 1)) {
      malformed = true;
    }
    entries.sort((left, right) => {
      const leftNumber = isObject(left) && Number.isInteger(left.step_number)
        ? left.step_number
        : Number.MAX_SAFE_INTEGER;
      const rightNumber = isObject(right) && Number.isInteger(right.step_number)
        ? right.step_number
        : Number.MAX_SAFE_INTEGER;
      return leftNumber - rightNumber;
    });

    if (malformed) {
      panel.append(makeElement(
        "p",
        "inline-warning",
        "Timeline step numbers are missing, duplicated, or malformed. Display order may be incomplete.",
      ));
    }

    entries.forEach((entry) => {
      if (!isObject(entry)) {
        timeline.append(makeElement("li", "inline-warning", "Unrecognized timeline entry."));
        return;
      }
      const item = makeElement("li", "timeline-item");
      item.append(makeElement(
        "span",
        "timeline-number",
        Number.isInteger(entry.step_number) ? entry.step_number : "?",
      ));
      const body = makeElement("div");
      const title = makeElement("div", "timeline-title");
      title.append(makeElement("h4", null, formatLabel(entry.stage)));
      const knownStatus = TIMELINE_STATUSES.has(entry.status);
      const statusText = knownStatus ? formatLabel(entry.status) : "Unrecognized";
      const statusClass = knownStatus ? timelineStatusClass(entry.status) : "unsafe";
      title.append(makeElement("span", `status-label ${statusClass}`, statusText));
      body.append(title);
      body.append(makeElement(
        "p",
        "timeline-summary",
        typeof entry.summary === "string" ? entry.summary : "The backend response could not be safely interpreted.",
      ));
      if (isObject(entry.important_values) && Object.keys(entry.important_values).length > 0) {
        body.append(makeElement("pre", "important-values", stableValueText(entry.important_values)));
      }
      if (isObject(entry.evidence_reference)) {
        const sequence = entry.evidence_reference.sequence_number;
        body.append(makeElement(
          "p",
          "timeline-summary",
          Number.isInteger(sequence) ? `Evidence sequence #${sequence}` : "Evidence reference unavailable",
        ));
      }
      item.append(body);
      timeline.append(item);
    });
    panel.append(timeline);
    return panel;
  }

  function timelineStatusClass(status) {
    if (status === "completed" || status === "complete") {
      return "neutral";
    }
    if (status === "manual_review" || status === "incomplete" || status === "skipped") {
      return "warning";
    }
    if (status === "risk_detected" || status === "failed") {
      return "danger";
    }
    return "unsafe";
  }

  function renderResult(result) {
    const entry = state.scenarios.get(result.scenario_id);
    const scenarioName = entry ? entry.summary.scenario_name : result.scenario_name;
    const display = resultState(result);
    elements.resultTitle.textContent = `${scenarioName} — analysis`;
    elements.resultDecision.textContent = display.label;
    elements.resultDecision.className = `decision-badge ${display.className}`;
    elements.resultContent.replaceChildren();

    const grid = makeElement("div", "result-grid");
    const overview = createPanel("Result overview");
    const metadata = makeElement("dl", "metadata-list");
    addDefinition(metadata, "Scenario ID", result.scenario_id);
    addDefinition(metadata, "Result", result.passed ? "Expected outcome confirmed" : "Expected outcome not confirmed");
    addDefinition(metadata, "Recommendation", result.analysis_summary.recommendation);
    const pathCount = Number.isInteger(result.actual_outcome.unauthorized_path_count)
      ? result.actual_outcome.unauthorized_path_count
      : "Unrecognized";
    addDefinition(metadata, "Unauthorized paths", pathCount);
    overview.append(metadata);

    const explanation = createPanel("Why this decision?", "explanation-panel");
    explanation.append(makeElement("p", null, getWhyExplanation(result)));

    grid.append(
      overview,
      explanation,
      renderScopePanel(result),
      renderCapabilityPanel(result),
      renderRuntimePanel(result),
      renderCompositionPanel(result),
      renderTimelinePanel(result),
    );
    elements.resultContent.append(grid);
    elements.resultSection.hidden = false;
    elements.resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  async function runScenario(scenarioId, fromRunAll) {
    if (state.inFlight.has(scenarioId)) {
      return false;
    }
    state.inFlight.add(scenarioId);
    state.errors.delete(scenarioId);
    clearGlobalError();
    updateControls();
    refreshCardStatuses();

    try {
      const payload = await fetchJson(
        `/api/v1/demo/scenarios/${encodeURIComponent(scenarioId)}/run`,
        { method: "POST", headers: { Accept: "application/json" } },
      );
      const result = validateRunResponse(payload, scenarioId);
      state.results.set(scenarioId, result);
      renderResult(result);
      return true;
    } catch (error) {
      state.results.delete(scenarioId);
      const message = safeMessage(
        error,
        "Scenario execution failed. No security result was accepted.",
      );
      state.errors.set(scenarioId, message);
      showGlobalError(`${scenarioId}: ${message}`);
      return false;
    } finally {
      state.inFlight.delete(scenarioId);
      updateControls();
      refreshCardStatuses();
      updateTotals();
      if (!fromRunAll) {
        await refreshEvidence();
      }
    }
  }

  async function runAllScenarios() {
    if (state.runAllActive || state.scenarios.size === 0) {
      return;
    }
    state.runAllActive = true;
    clearGlobalError();
    updateControls();
    const scenarioIds = Array.from(state.scenarios.keys());
    try {
      for (let index = 0; index < scenarioIds.length; index += 1) {
        const scenarioId = scenarioIds[index];
        const entry = state.scenarios.get(scenarioId);
        const name = entry ? entry.summary.scenario_name : scenarioId;
        elements.progress.textContent = `Running ${index + 1} of ${scenarioIds.length}: ${name}`;
        await runScenario(scenarioId, true);
      }
      const failureCount = state.errors.size;
      elements.progress.textContent = failureCount === 0
        ? `Completed ${scenarioIds.length} of ${scenarioIds.length} scenarios.`
        : `Completed with ${failureCount} execution error${failureCount === 1 ? "" : "s"}.`;
    } catch (_error) {
      showGlobalError("Run-all stopped unexpectedly. No incomplete request was treated as allowed.");
      elements.progress.textContent = "Run-all encountered an unsafe dashboard error.";
    } finally {
      state.runAllActive = false;
      updateControls();
      updateTotals();
      await refreshEvidence();
    }
  }

  async function loadSystemStatus() {
    try {
      const health = await fetchJson("/health", { headers: { Accept: "application/json" } });
      if (health.status === "healthy") {
        setIndicator(elements.health, "Backend: healthy", "safe");
      } else {
        setIndicator(elements.health, "Backend: unrecognized", "unsafe");
      }
    } catch (_error) {
      setIndicator(elements.health, "Backend: unavailable", "danger");
    }

    try {
      const providers = await fetchJson("/api/v1/demo/providers", {
        headers: { Accept: "application/json" },
      });
      const providerList = Array.isArray(providers.providers) ? providers.providers : [];
      const mockOnly = providerList.length > 0 && providerList.every((provider) => (
        isObject(provider) && provider.simulation_only === true
      ));
      setIndicator(
        elements.provider,
        mockOnly ? "Provider: local mock only" : "Provider: unsafe / unknown",
        mockOnly ? "safe" : "unsafe",
      );
    } catch (_error) {
      setIndicator(elements.provider, "Provider: unavailable", "danger");
    }
  }

  async function loadScenarios() {
    try {
      const catalogue = await fetchJson("/api/v1/demo/scenarios", {
        headers: { Accept: "application/json" },
      });
      const summaries = validateScenarioList(catalogue);
      state.scenarios.clear();
      for (const summary of summaries) {
        const entry = { summary, detail: null, detailError: null };
        state.scenarios.set(summary.scenario_id, entry);
        try {
          const detail = await fetchJson(
            `/api/v1/demo/scenarios/${encodeURIComponent(summary.scenario_id)}`,
            { headers: { Accept: "application/json" } },
          );
          entry.detail = validateScenarioDetail(detail);
        } catch (error) {
          entry.detailError = safeMessage(
            error,
            "Scenario details are unavailable and must not be assumed.",
          );
        }
      }
      elements.scenarioCount.textContent = String(state.scenarios.size);
      renderScenarioCards();
      elements.progress.textContent = "Ready. Scenario results are pending execution.";
    } catch (error) {
      state.scenarios.clear();
      elements.scenarioCount.textContent = "0";
      elements.scenarioGrid.replaceChildren();
      showGlobalError(safeMessage(error, "The scenario catalogue could not be loaded."));
      updateControls();
    }
  }

  function abbreviatedHash(value) {
    if (typeof value !== "string" || value.length < 16) {
      return "Unrecognized hash";
    }
    return `${value.slice(0, 10)}…${value.slice(-8)}`;
  }

  async function refreshEvidence() {
    elements.refreshEvidence.disabled = true;
    try {
      const verification = await fetchJson("/api/v1/evidence/verify", {
        headers: { Accept: "application/json" },
      });
      const recordsPayload = await fetchJson("/api/v1/evidence/records?limit=20", {
        headers: { Accept: "application/json" },
      });
      if (typeof verification.valid !== "boolean"
          || !Number.isInteger(verification.records_checked)
          || !Array.isArray(recordsPayload.records)) {
        throw new DashboardError("Evidence metadata is malformed.");
      }

      elements.evidenceOverview.textContent = verification.valid ? "Valid" : "Invalid";
      elements.evidenceRecordCount.textContent = `${verification.records_checked} records checked`;
      elements.evidenceStatCard.className = `stat-card ${verification.valid ? "safe" : "danger"}`;
      elements.evidenceSummary.textContent = typeof verification.message === "string"
        ? verification.message
        : "The backend response could not be safely interpreted.";
      elements.evidenceList.replaceChildren();
      if (recordsPayload.records.length === 0) {
        elements.evidenceList.append(makeElement("li", "evidence-item", "No evidence records yet."));
      } else {
        recordsPayload.records.forEach((record) => {
          const item = makeElement("li", "evidence-item");
          const sequence = isObject(record) && Number.isInteger(record.sequence_number)
            ? `#${record.sequence_number}`
            : "#?";
          const type = isObject(record) && typeof record.analysis_type === "string"
            ? formatLabel(record.analysis_type)
            : "Unrecognized event";
          const summary = isObject(record) && typeof record.decision_summary === "string"
            ? record.decision_summary
            : "Decision summary unavailable.";
          item.append(
            makeElement("span", "evidence-sequence", sequence),
            makeElement("span", null, `${type}: ${summary}`),
            makeElement("span", "evidence-hash", abbreviatedHash(record.record_hash)),
          );
          elements.evidenceList.append(item);
        });
      }
    } catch (error) {
      elements.evidenceOverview.textContent = "Unsafe / Unknown";
      elements.evidenceRecordCount.textContent = "Verification unavailable";
      elements.evidenceStatCard.className = "stat-card danger";
      elements.evidenceSummary.textContent = safeMessage(
        error,
        "Evidence verification failed. The chain must not be assumed valid.",
      );
      elements.evidenceList.replaceChildren();
    } finally {
      elements.refreshEvidence.disabled = false;
    }
  }

  async function initialize() {
    elements.runAll.addEventListener("click", () => {
      runAllScenarios().catch(() => {
        showGlobalError("Run-all failed unexpectedly. No result was treated as allowed.");
      });
    });
    elements.refreshEvidence.addEventListener("click", () => {
      refreshEvidence().catch(() => {
        elements.evidenceSummary.textContent = "Evidence verification failed safely.";
      });
    });
    updateTotals();
    await Promise.allSettled([
      loadSystemStatus(),
      loadScenarios(),
      refreshEvidence(),
    ]);
  }

  initialize().catch(() => {
    showGlobalError("Dashboard initialization failed. No security state should be assumed.");
    setIndicator(elements.health, "Backend: unsafe / unknown", "danger");
  });
}());
