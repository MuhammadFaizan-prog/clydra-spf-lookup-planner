import "./styles/base.css";
import "./styles/landing.css";
import { analyze, type DnsAnswer } from "./lib/spf";
import { snapshotResolver } from "./lib/report";
import { SAMPLE_CURRENT, SAMPLE_DOMAIN, SAMPLE_PLANNED } from "./lib/sample";
import snapshot from "./lib/snapshot.json";
import { applyWidths, budgetBar, findings, meter, tree } from "./ui/render";

// The sample is computed by the real analyser, against DNS answers captured on 2026-10-16.
async function main(): Promise<void> {
  const r = snapshotResolver(snapshot.answers as Record<string, DnsAnswer>);
  const [cur, plan] = await Promise.all([analyze(SAMPLE_DOMAIN, r, { draft: SAMPLE_CURRENT }), analyze(SAMPLE_DOMAIN, r, { draft: SAMPLE_PLANNED })]);
  const meters = document.getElementById("sample-meters");
  if (meters) meters.innerHTML = meter(cur, "Current record") + `<div class="delta" aria-hidden="true">+${plan.lookups - cur.lookups}</div>` + meter(plan, "With Salesforce added");
  const bar = document.getElementById("sample-bar");
  if (bar) {
    bar.innerHTML = budgetBar(plan);
    applyWidths(bar);
  }
  const f = document.getElementById("sample-findings");
  if (f) f.innerHTML = findings(plan.findings);
  const t = document.getElementById("sample-tree");
  if (t) t.innerHTML = tree(plan.root);
}
void main();
