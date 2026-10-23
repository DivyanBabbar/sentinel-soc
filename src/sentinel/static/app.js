const $ = (id) => document.getElementById(id);
const status = $("statusMessage");
const escapeHtml = (value) =>
  String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);

function setStatus(message, state = "ready") {
  status.textContent = message;
  status.dataset.state = state;
}

async function api(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(typeof data.detail === "string" ? data.detail : "The request could not be completed.");
  }
  return data;
}

async function runAction(button, pending, success, action) {
  button.disabled = true;
  setStatus(pending, "busy");
  try {
    await action();
    setStatus(success);
  } catch (error) {
    setStatus(error.message || "The action failed. Try again.", "error");
  } finally {
    button.disabled = false;
  }
}

function renderIncident(incident) {
  const severity = escapeHtml(incident.severity);
  const incidentId = escapeHtml(incident.incident_id);
  const correlatedEvents = incident.events.map((event) => `
    <div class="event">${escapeHtml(new Date(event.timestamp).toLocaleTimeString())} · ${escapeHtml(event.event_type)} · ${escapeHtml(event.source_ip || "no IP")} · ${escapeHtml(event.action || event.resource)}</div>
  `).join("");
  const findings = (incident.findings || []).map((finding) => `<p>↳ ${escapeHtml(finding)}</p>`).join("");
  const approveButton = incident.containment_status === "not_approved" && incident.recommended_action !== "review"
    ? `<button class="approve" type="button" data-action="contain/approve" data-id="${incidentId}">Approve containment</button>`
    : "";
  const executeButton = incident.containment_status === "approved"
    ? `<button class="execute" type="button" data-action="contain/execute" data-id="${incidentId}">Simulate containment</button>`
    : "";

  return `<article class="incident">
    <div class="row"><span class="pill ${severity}">${severity} · ${escapeHtml(incident.status)}</span><span class="score">${incident.risk_score} / 100</span></div>
    <h3>${escapeHtml(incident.actor)}</h3>
    <p>${escapeHtml(incident.summary)}</p>
    <div class="findings">${findings}</div>
    <details><summary>${incident.events.length} correlated events</summary>${correlatedEvents}</details>
    <div class="row"><span class="pill">${escapeHtml(incident.recommended_action)} · ${escapeHtml(incident.containment_status.replaceAll("_", " "))}</span></div>
    <div class="actions">
      ${approveButton}${executeButton}
      <button type="button" data-action="report" data-id="${incidentId}">Download report</button>
    </div>
  </article>`;
}

async function refresh() {
  const [incidents, events] = await Promise.all([api("/v1/incidents"), api("/v1/events")]);
  $("open").textContent = String(incidents.filter((incident) => incident.status === "open").length);
  $("high").textContent = String(incidents.filter((incident) => ["high", "critical"].includes(incident.severity)).length);
  $("events").textContent = String(events.length);
  $("incidents").innerHTML = incidents.length
    ? incidents.map(renderIncident).join("")
    : '<div class="empty">No incidents found. Load the synthetic incident to explore the analyst workflow.</div>';
}

$("demo").addEventListener("click", (event) => {
  runAction(
    event.currentTarget,
    "Loading synthetic password-spray and privilege-change signals…",
    "Attack simulation loaded. Review the correlated incident and timeline.",
    async () => {
      await api("/v1/demo/load", { method: "POST" });
      await api("/v1/incidents/analyze", { method: "POST" });
      await refresh();
    },
  );
});

$("analyze").addEventListener("click", (event) => {
  runAction(
    event.currentTarget,
    "Correlating recent security events…",
    "Correlation complete. Review the updated detection queue.",
    async () => {
      await api("/v1/incidents/analyze", { method: "POST" });
      await refresh();
    },
  );
});

$("refresh").addEventListener("click", (event) => {
  runAction(event.currentTarget, "Refreshing incidents and events…", "Detection queue is up to date.", refresh);
});

$("ingest").addEventListener("click", (event) => {
  runAction(
    event.currentTarget,
    "Saving and correlating the event…",
    "Event ingested. Review the updated queue.",
    async () => {
      await api("/v1/events", {
        method: "POST",
        body: JSON.stringify({
          timestamp: new Date().toISOString(),
          event_type: $("type").value,
          actor: $("actor").value.trim(),
          source_ip: $("ip").value.trim() || null,
          action: "manual analyst submission",
          outcome: "unknown",
          severity: $("severity").value,
          details: $("details").value.trim(),
        }),
      });
      await api("/v1/incidents/analyze", { method: "POST" });
      await refresh();
    },
  );
});

$("incidents").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const incidentId = encodeURIComponent(button.dataset.id);

  if (button.dataset.action === "report") {
    await runAction(button, "Preparing the incident report…", "Report downloaded with its evidence and analyst note.", async () => {
      const response = await fetch(`/v1/incidents/${incidentId}/report`);
      if (!response.ok) throw new Error("The incident report could not be downloaded.");
      const blob = await response.blob();
      const objectUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = objectUrl;
      link.download = `incident-${button.dataset.id}.md`;
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1_000);
    });
    return;
  }

  const action = button.dataset.action;
  await runAction(
    button,
    action.endsWith("approve") ? "Recording analyst approval…" : "Running simulated containment…",
    action.endsWith("approve") ? "Approval recorded. Review the action before simulation." : "Simulation complete. No account or network control was changed.",
    async () => {
      await api(`/v1/incidents/${incidentId}/${action}`, { method: "POST" });
      await refresh();
    },
  );
});

refresh().catch((error) => setStatus(error.message || "Could not load incident data.", "error"));
