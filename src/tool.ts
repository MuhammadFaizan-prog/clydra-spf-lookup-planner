import "./styles/base.css";
import "./styles/tool.css";
import { addInclude, analyze, normaliseDomain, spfRecords, type Analysis, type Finding, type Resolver } from "./lib/spf";
import { dohResolver, PROVIDERS, type ProviderId } from "./lib/dns";
import { memoResolver, toMarkdown } from "./lib/report";
import { SENDERS } from "./lib/senders";
import { SAMPLE_CURRENT, SAMPLE_DOMAIN, SAMPLE_PLANNED } from "./lib/sample";
import { applyWidths, budgetBar, esc, findings, meter, tree } from "./ui/render";

const $ = <T extends HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing #${id}`);
  return el as T;
};

const domainEl = $<HTMLInputElement>("domain");
const resolverEl = $<HTMLSelectElement>("resolver");
const currentEl = $<HTMLTextAreaElement>("current");
const plannedEl = $<HTMLTextAreaElement>("planned");
const statusEl = $("status");
const metersEl = $("meters");
const toastEl = $("toast");
const copyRecordBtn = $<HTMLButtonElement>("copy-record");
const copyReportBtn = $<HTMLButtonElement>("copy-report");

let provider: ProviderId = "google";
let resolver: Resolver & { clear: () => void; size: () => number; reset: () => void } = memoResolver(dohResolver(provider));
let domain: string | null = null;
let extraCurrentFindings: Finding[] = [];
let current: Analysis | null = null;
let planned: Analysis | null = null;
let view: "planned" | "current" = "planned";
let runId = 0;

/* ---------- sender chips ---------- */
$("sender-list").innerHTML = SENDERS.map((s) => `<button type="button" class="sender" data-include="${esc(s.include)}" title="include:${esc(s.include)}"><span>${esc(s.name)}</span><code>${esc(s.include)}</code></button>`).join("");
$("sender-list").addEventListener("click", (e) => {
  const b = (e.target as HTMLElement).closest<HTMLButtonElement>("button[data-include]");
  if (!b) return;
  addToPlanned(b.dataset.include ?? "");
});

$("include-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const input = $<HTMLInputElement>("include");
  const err = $("include-error");
  const raw = input.value.trim().replace(/^include:/i, "");
  const d = normaliseDomain(raw);
  if (!d) {
    err.textContent = raw ? `"${raw}" is not a valid domain name.` : "Type the domain your provider gives you, such as spf.example.net.";
    input.setAttribute("aria-invalid", "true");
    input.focus();
    return;
  }
  err.textContent = "";
  input.removeAttribute("aria-invalid");
  input.value = "";
  addToPlanned(d);
});

function addToPlanned(target: string): void {
  if (!plannedEl.value.trim()) plannedEl.value = currentEl.value.trim() || "v=spf1 ~all";
  const r = addInclude(plannedEl.value, target);
  if (!r.added) {
    flash(`include:${target} is already in the planned record.`);
    return;
  }
  plannedEl.value = r.record;
  flash(`Added include:${target} before the final term.`);
  void runAnalysis();
}

/* ---------- lookup ---------- */
$("lookup-form").addEventListener("submit", (e) => {
  e.preventDefault();
  resolver.reset(); // a deliberate new lookup always tries the network
  void lookup();
});

async function lookup(): Promise<void> {
  const err = $("domain-error");
  const d = normaliseDomain(domainEl.value);
  if (!d) {
    err.textContent = domainEl.value.trim() ? "That doesn't look like a domain. Try something like yourcompany.com." : "Enter a domain to look up.";
    domainEl.setAttribute("aria-invalid", "true");
    domainEl.focus();
    return;
  }
  err.textContent = "";
  domainEl.removeAttribute("aria-invalid");
  domainEl.value = d;
  domain = d;
  extraCurrentFindings = [];
  setStatus(`<p class="busy"><span class="spin" aria-hidden="true"></span>Reading the SPF record for <code>${esc(d)}</code> from ${esc(PROVIDERS[provider].label)}…</p>`);
  const ans = await resolver(d, "TXT");
  if (ans.status === "error") {
    setStatus(`<div class="alert err-card"><h2>Couldn't reach the resolver</h2><p>${esc(ans.error ?? "Unknown error")}. Nothing was changed. Try again, or switch to the other resolver.</p><button class="btn small" type="button" data-action="retry">Try again</button></div>`);
    return;
  }
  if (ans.status === "nxdomain") {
    setStatus(`<div class="alert err-card"><h2><code>${esc(d)}</code> does not exist</h2><p>The resolver returned NXDOMAIN. Check the spelling.</p></div>`);
    clearResults();
    return;
  }
  const recs = spfRecords(ans.records);
  if (recs.length === 0) {
    currentEl.value = "";
    $("current-src").textContent = `no SPF record at ${d}`;
    if (!plannedEl.value.trim()) plannedEl.value = "v=spf1 ~all";
    setStatus(`<div class="alert warn-card"><h2>No SPF record published for <code>${esc(d)}</code></h2><p>Receivers get "none" for this domain. Build one in the planned record: add your sending services, then publish it as a TXT record at your DNS host.</p></div>`, true);
  } else {
    currentEl.value = recs[0] ?? "";
    $("current-src").textContent = `live from ${PROVIDERS[provider].label}`;
    if (recs.length > 1) extraCurrentFindings.push({ severity: "error", code: "multiple-records", message: `${d} publishes ${recs.length} SPF records. Receivers return permerror until they are merged into one; only the first is shown.` });
    plannedEl.value = currentEl.value;
    setStatus("");
  }
  await runAnalysis();
}

/* ---------- analysis ---------- */
let timer: number | undefined;
plannedEl.addEventListener("input", () => {
  window.clearTimeout(timer);
  timer = window.setTimeout(() => void runAnalysis(), 550);
});
currentEl.addEventListener("input", () => {
  $("current-src").textContent = "edited by you";
  window.clearTimeout(timer);
  timer = window.setTimeout(() => void runAnalysis(), 550);
});

async function runAnalysis(): Promise<void> {
  const id = ++runId;
  const perr = $("planned-error");
  const plannedText = plannedEl.value.trim();
  const currentText = currentEl.value.trim();
  if (!domain) {
    const d = normaliseDomain(domainEl.value);
    if (d) domain = d;
  }
  if (!domain) {
    if (plannedText || currentText) setStatus(`<div class="alert warn-card"><h2>Add the domain first</h2><p><code>a</code> and <code>mx</code> terms are resolved against your domain, so enter it above (no need to look it up if you are pasting records).</p></div>`);
    return;
  }
  if (plannedText && !/^v=spf1(\s|$)/i.test(plannedText)) {
    perr.textContent = 'The planned record must start with "v=spf1".';
    plannedEl.setAttribute("aria-invalid", "true");
  } else {
    perr.textContent = "";
    plannedEl.removeAttribute("aria-invalid");
  }
  if (!plannedText && !currentText) {
    clearResults();
    return;
  }
  const before = resolver.size();
  const busy = window.setTimeout(() => {
    if (id === runId) metersEl.classList.add("is-busy");
  }, 150);
  try {
    const [c, p] = await Promise.all([
      currentText ? analyze(domain, resolver, { draft: currentText }) : Promise.resolve(null),
      plannedText && !perr.textContent ? analyze(domain, resolver, { draft: plannedText }) : Promise.resolve(null),
    ]);
    if (id !== runId) return; // a newer edit superseded this run
    if (c) c.findings.unshift(...extraCurrentFindings);
    current = c;
    planned = p;
    render(resolver.size() - before);
  } finally {
    window.clearTimeout(busy);
    if (id === runId) metersEl.classList.remove("is-busy");
  }
}

function render(newQueries: number): void {
  const delta = current && planned ? planned.lookups - current.lookups : null;
  const deltaHtml = delta === null ? `<div class="delta-chip neutral" aria-hidden="true">→</div>` : `<div class="delta-chip ${delta > 0 ? "up" : delta < 0 ? "down" : "neutral"}">${delta > 0 ? "+" : ""}${delta}<span>lookups</span></div>`;
  metersEl.innerHTML = meter(current, "Current") + deltaHtml + meter(planned, "Planned");

  const focus = planned ?? current;
  copyRecordBtn.disabled = !planned;
  copyReportBtn.disabled = !planned;
  if (!focus) {
    clearResults(false);
    return;
  }
  $("bar-card").hidden = false;
  $("bar").innerHTML = budgetBar(focus);
  applyWidths($("bar"));
  $("findings-card").hidden = false;
  $("findings-scope").textContent = planned ? "for the planned record" : "for the current record";
  $("findings").innerHTML = findings(focus.findings);
  $("tree-card").hidden = false;
  if (!planned) view = "current";
  renderTree();

  const dnsIssues = focus.findings.some((f) => f.code === "dns-error");
  const note = dnsIssues
    ? `<div class="alert warn-card"><h2>Some lookups failed</h2><p>Part of the tree could not be resolved, so the count may be low. <button class="link" type="button" data-action="retry-analysis">Retry</button> or switch resolver.</p></div>`
    : `<p class="meta">${esc(domain ?? "")} · ${newQueries > 0 ? `${newQueries} new DNS ${newQueries === 1 ? "query" : "queries"}` : "answers from this session's cache"} via ${esc(PROVIDERS[provider].label)}</p>`;
  if (statusEl.dataset.sticky !== "1" || dnsIssues) setStatus(note);
}

function renderTree(): void {
  const t = $("tree");
  const a = view === "planned" ? planned : current;
  $("tab-planned").setAttribute("aria-selected", String(view === "planned"));
  $("tab-current").setAttribute("aria-selected", String(view === "current"));
  $("tab-planned").tabIndex = view === "planned" ? 0 : -1;
  $("tab-current").tabIndex = view === "current" ? 0 : -1;
  t.setAttribute("aria-labelledby", view === "planned" ? "tab-planned" : "tab-current");
  t.innerHTML = a ? tree(a.root) : `<p class="meta">No ${view} record to show.</p>`;
}
for (const [id, v] of [["tab-planned", "planned"], ["tab-current", "current"]] as const) {
  $(id).addEventListener("click", () => {
    view = v;
    renderTree();
  });
  $(id).addEventListener("keydown", (e) => {
    if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
      view = view === "planned" ? "current" : "planned";
      renderTree();
      $(view === "planned" ? "tab-planned" : "tab-current").focus();
    }
  });
}

function clearResults(resetMeters = true): void {
  current = null;
  planned = null;
  if (resetMeters) metersEl.innerHTML = meter(null, "Current") + `<div class="delta-chip neutral" aria-hidden="true">→</div>` + meter(null, "Planned");
  for (const id of ["bar-card", "findings-card", "tree-card"]) $(id).hidden = true;
  copyRecordBtn.disabled = true;
  copyReportBtn.disabled = true;
}

function setStatus(html: string, sticky = false): void {
  statusEl.innerHTML = html;
  statusEl.dataset.sticky = sticky ? "1" : "";
}

statusEl.addEventListener("click", (e) => {
  const b = (e.target as HTMLElement).closest<HTMLButtonElement>("button[data-action]");
  if (!b) return;
  if (b.dataset.action === "retry" || b.dataset.action === "retry-analysis") resolver.reset();
  if (b.dataset.action === "retry") void lookup();
  if (b.dataset.action === "retry-analysis") void runAnalysis();
  if (b.dataset.action === "sample") loadSample();
});

resolverEl.addEventListener("change", () => {
  provider = resolverEl.value as ProviderId;
  resolver = memoResolver(dohResolver(provider));
  flash(`Now resolving through ${PROVIDERS[provider].label}.`);
  if (currentEl.value.trim() || plannedEl.value.trim()) void runAnalysis();
});

$("reset-planned").addEventListener("click", () => {
  plannedEl.value = currentEl.value;
  flash("Planned record reset to the current record.");
  void runAnalysis();
});

function loadSample(): void {
  domainEl.value = SAMPLE_DOMAIN;
  domain = SAMPLE_DOMAIN;
  extraCurrentFindings = [];
  currentEl.value = SAMPLE_CURRENT;
  $("current-src").textContent = "sample record (example.com)";
  plannedEl.value = SAMPLE_PLANNED;
  setStatus(`<p class="meta">Sample plan: example.com's record is a stand-in, every include is resolved live.</p>`);
  flash("Loaded the sample plan.");
  void runAnalysis();
}
$("load-sample").addEventListener("click", loadSample);

/* ---------- exports ---------- */
copyRecordBtn.addEventListener("click", () => void copy(plannedEl.value.trim(), "Planned record copied. Publish it as a single TXT record at your DNS host."));
copyReportBtn.addEventListener("click", () => {
  if (!planned || !domain) return;
  void copy(toMarkdown(domain, current, planned, plannedEl.value.trim(), PROVIDERS[provider].label), "Markdown report copied.", "spf-lookup-plan.md");
});

async function copy(text: string, ok: string, fallbackName = "spf-record.txt"): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    flash(ok);
  } catch {
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = fallbackName;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    flash(`Clipboard unavailable, so it was downloaded as ${fallbackName}.`);
  }
}

let toastTimer: number | undefined;
function flash(msg: string): void {
  toastEl.textContent = msg;
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => (toastEl.textContent = ""), 4000);
}

/* ---------- first paint ---------- */
clearResults();
setStatus(`<div class="alert intro"><h2>Start with your domain</h2><p>Look up the live record, then add or remove senders in the planned record. Both budgets update side by side.</p><button class="btn ghost small" type="button" data-action="sample">Run the sample plan</button></div>`);
window.addEventListener("hashchange", () => {
  if (location.hash === "#sample") loadSample();
});
if (location.hash === "#sample") loadSample();
