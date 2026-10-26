async function apiGet(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
  return res.json();
}

async function apiPostJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`POST ${url} -> ${res.status}: ${detail}`);
  }
  return res.json();
}

function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

const SEVERITY_BADGE_CLASS = {
  Critical: "badge-critical",
  High: "badge-high",
  Low: "badge-low",
  Informational: "badge-info",
};

function severityBadge(label) {
  const cls = SEVERITY_BADGE_CLASS[label] || "badge-info";
  return `<span class="badge ${cls}">${escapeHtml(label)}</span>`;
}

function confidenceBadge(level) {
  return `<span class="badge bg-secondary">Confidence: ${escapeHtml(level)}</span>`;
}

function statusBadge(status) {
  const map = { New: "bg-primary", Investigating: "bg-warning text-dark", Contained: "bg-info text-dark", Closed: "bg-secondary" };
  const cls = map[status] || "bg-secondary";
  return `<span class="badge ${cls}">${escapeHtml(status)}</span>`;
}

function showToast(message, isError) {
  const container = document.getElementById("toast-container");
  if (!container) {
    if (isError) console.error(message); else console.log(message);
    return;
  }
  const el = document.createElement("div");
  el.className = `alert ${isError ? "alert-danger" : "alert-success"} py-2`;
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => el.remove(), 5000);
}
