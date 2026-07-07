const certTable = document.querySelector("#cert-table");
const riskList = document.querySelector("#risk-list");
const reportOutput = document.querySelector("#report-output");
const certCount = document.querySelector("#cert-count");
const riskCount = document.querySelector("#risk-count");
const criticalCount = document.querySelector("#critical-count");
const refreshButton = document.querySelector("#refresh");
const viewTitle = document.querySelector("#view-title");
const routedSections = document.querySelectorAll("[data-view]");
const routeLinks = document.querySelectorAll("[data-route]");

let latestReports = [];

async function fetchJSON(path, options) {
  const response = await fetch(path, options);
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`${response.status}: ${body}`);
  }
  return response.json();
}

function daysUntil(dateText) {
  const ms = new Date(dateText).getTime() - Date.now();
  return Math.floor(ms / 86400000);
}

function renderCertificates(certs) {
  certCount.textContent = certs.length;
  certTable.innerHTML = "";
  if (certs.length === 0) {
    certTable.innerHTML = `<tr><td colspan="4">No certificates yet. Run a scan from the CLI or POST /v1/scans.</td></tr>`;
    return;
  }
  for (const cert of certs) {
    const row = document.createElement("tr");
    const owner = cert.owner_team || "unassigned";
    row.innerHTML = `
      <td><strong>${cert.endpoint || cert.subject_common_name || cert.id}</strong><br><span>${cert.fingerprint_sha256 || ""}</span></td>
      <td>${owner}</td>
      <td>${daysUntil(cert.not_after)} days</td>
      <td><button data-cert="${cert.id}">Generate Report</button></td>
    `;
    certTable.appendChild(row);
  }
}

function renderRisks(risks) {
  riskCount.textContent = risks.length;
  criticalCount.textContent = risks.filter((risk) => risk.severity === "critical").length;
  riskList.innerHTML = "";
  if (risks.length === 0) {
    riskList.innerHTML = `<p>No open risks.</p>`;
    return;
  }
  for (const risk of risks) {
    const item = document.createElement("div");
    item.className = "risk";
    item.innerHTML = `
      <strong class="${risk.severity}">${risk.severity.toUpperCase()} · ${risk.category}</strong>
      <span>${risk.title}</span>
    `;
    riskList.appendChild(item);
  }
}

function renderReport(report) {
  latestReports = [report, ...latestReports.filter((item) => item.id !== report.id)].slice(0, 5);
  reportOutput.textContent = `# CertFlow Handoff Report

Report ID: ${report.id}
Certificate ID: ${report.certificate_id}

## Summary
${report.summary}

## Risks
${(report.risks || ["None"]).map((item) => `- ${item}`).join("\n")}

## Handoff Checklist
${(report.handoff_checklist || []).map((item) => `- ${item}`).join("\n")}

## Renewal Steps
${(report.renewal_steps || []).map((item) => `- ${item}`).join("\n")}

## Evidence
${(report.evidence_ids || []).map((item) => `- ${item}`).join("\n")}`;
}

function routeName() {
  const path = window.location.pathname;
  if (path === "/app/certificates") return "certificates";
  if (path === "/app/risks") return "risks";
  if (path === "/app/reports") return "reports";
  if (path.startsWith("/app")) return "overview";
  return "overview";
}

function applyRoute() {
  const view = routeName();
  const titles = {
    overview: "Operational Dashboard",
    certificates: "Certificate Inventory",
    risks: "Risk Queue",
    reports: "Handoff Reports",
  };
  viewTitle.textContent = titles[view];
  for (const section of routedSections) {
    const views = section.dataset.view.split(" ");
    section.hidden = !views.includes(view);
  }
  for (const link of routeLinks) {
    link.classList.toggle("active", link.dataset.route === window.location.pathname);
  }
  if (view === "reports" && latestReports.length === 0) {
    reportOutput.textContent = "Generate a report from the certificate inventory to see it here.";
  }
}

async function loadDashboard() {
  try {
    const [certs, risks] = await Promise.all([
      fetchJSON("/v1/certificates"),
      fetchJSON("/v1/risks"),
    ]);
    renderCertificates(certs);
    renderRisks(risks);
    applyRoute();
  } catch (error) {
    reportOutput.textContent = `Unable to load backend data: ${error.message}`;
  }
}

document.addEventListener("click", (event) => {
  const link = event.target.closest("a[data-route]");
  if (!link) return;
  event.preventDefault();
  history.pushState({}, "", link.href);
  applyRoute();
});

window.addEventListener("popstate", applyRoute);

certTable.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-cert]");
  if (!button) return;
  reportOutput.textContent = "Generating report...";
  try {
    const report = await fetchJSON("/v1/ai/handoff-reports", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({certificate_id: button.dataset.cert}),
    });
    renderReport(report);
    history.pushState({}, "", "/app/reports");
    await loadDashboard();
  } catch (error) {
    reportOutput.textContent = `Report generation failed: ${error.message}`;
  }
});

refreshButton.addEventListener("click", loadDashboard);
loadDashboard();
