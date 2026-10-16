import { LOOKUP_LIMIT, budgetState, type Analysis, type Finding, type RecordNode, type TermNode } from "../lib/spf";
import { contributions, subtreeCost } from "../lib/report";

export function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);
}

const STATE_LABEL = { ok: "Within budget", tight: "Close to the limit", over: "Over the limit" } as const;

export function meter(a: Analysis | null, label: string, opts: { compact?: boolean } = {}): string {
  if (!a) return `<div class="meter empty"><p class="m-label">${esc(label)}</p><p class="m-num"><b>–</b><span>/ ${LOOKUP_LIMIT}</span></p><p class="m-state">Not analysed yet</p></div>`;
  const st = budgetState(a.lookups);
  const cells = Array.from({ length: Math.max(LOOKUP_LIMIT, a.lookups) }, (_, i) => `<i class="${i < a.lookups ? (i >= LOOKUP_LIMIT ? "over" : "used") : ""}"></i>`).join("");
  const extra = a.permerror && st !== "over" ? `<p class="m-warn">Has errors that cause permerror</p>` : "";
  return `<div class="meter ${st}${opts.compact ? " compact" : ""}" role="group" aria-label="${esc(`${label}: ${a.lookups} of ${LOOKUP_LIMIT} DNS lookups, ${STATE_LABEL[st]}`)}">
    <p class="m-label">${esc(label)}</p>
    <p class="m-num"><b>${a.lookups}</b><span>/ ${LOOKUP_LIMIT} lookups</span></p>
    <div class="m-cells" aria-hidden="true">${cells}<em class="m-limit"></em></div>
    <p class="m-state">${STATE_LABEL[st]} · ${a.voids} void${a.voids === 1 ? "" : "s"} of 2</p>${extra}
  </div>`;
}

const PALETTE = ["c1", "c2", "c3", "c4", "c5", "c6"];

export function budgetBar(a: Analysis): string {
  const items = contributions(a);
  const total = Math.max(LOOKUP_LIMIT, a.lookups);
  if (!items.length) return `<p class="bar-empty">This record makes no DNS lookups.</p>`;
  let at = 0;
  const segs = items
    .map((c, i) => {
      const cls = PALETTE[i % PALETTE.length];
      const start = at;
      at += c.cost;
      const crosses = at > LOOKUP_LIMIT;
      return `<span class="seg ${cls}${crosses ? " crosses" : ""}" data-w="${(c.cost / total) * 100}" title="${esc(`${c.raw}: ${c.cost} lookup${c.cost === 1 ? "" : "s"} (#${start + 1}${c.cost > 1 ? `–${at}` : ""})`)}"></span>`;
    })
    .join("");
  const legend = items
    .map((c, i) => `<li><i class="sw ${PALETTE[i % PALETTE.length]}"></i><code>${esc(c.label)}</code><b>${c.cost}</b></li>`)
    .join("");
  return `<div class="bar" aria-hidden="true">${segs}<em class="bar-limit" data-left="${(LOOKUP_LIMIT / total) * 100}"><span>limit 10</span></em></div>
  <ol class="legend" aria-label="Lookups per term">${legend}</ol>`;
}

/** Inline styles are blocked by the CSP, so widths are applied through the CSSOM after insertion. */
export function applyWidths(root: HTMLElement): void {
  root.querySelectorAll<HTMLElement>("[data-w]").forEach((el) => (el.style.width = `${el.dataset.w}%`));
  root.querySelectorAll<HTMLElement>("[data-left]").forEach((el) => (el.style.left = `${el.dataset.left}%`));
}

function mechLabel(t: TermNode): string {
  if (t.mechanism === "include") return "include";
  if (t.mechanism === "redirect") return "redirect";
  return t.mechanism;
}

function termRow(t: TermNode): string {
  const sub = subtreeCost(t);
  const cost = t.cost ? `<span class="cost" title="Counts toward the limit">+1</span>` : `<span class="cost zero" title="No DNS lookup">0</span>`;
  const cum = t.cost ? `<span class="cum" title="Running total">#${t.cumulative}</span>` : `<span class="cum"></span>`;
  const subtotal = t.child && sub > t.cost ? `<span class="sub">${sub} total</span>` : "";
  const notes = t.notes.length ? `<span class="notes">${t.notes.map(esc).join(" ")}</span>` : "";
  const limit = t.overLimit ? `<span class="limit-flag">Limit reached: receivers stop here</span>` : "";
  return `<span class="t-main">${cum}${cost}<code class="raw">${esc(t.raw)}</code><span class="mech">${esc(mechLabel(t))}</span>${subtotal}</span>${limit}${notes}`;
}

export function tree(node: RecordNode, depth = 0): string {
  if (!node.record) return `<p class="node-error">${esc(node.error ?? "No record")}</p>`;
  // Group runs of ip4/ip6 terms into one collapsible row: they cost nothing and would bury the lookups.
  const groups: (TermNode | TermNode[])[] = [];
  for (const t of node.terms) {
    const isIp = t.mechanism === "ip4" || t.mechanism === "ip6";
    const last = groups[groups.length - 1];
    if (isIp && Array.isArray(last)) last.push(t);
    else groups.push(isIp ? [t] : t);
  }
  const items = groups
    .map((t) => {
      if (Array.isArray(t)) {
        if (t.length === 1 && t[0]) return `<li class="term sev-ok"><div class="leaf">${termRow(t[0])}</div></li>`;
        const list = t.map((x) => `<li><code>${esc(x.raw)}</code></li>`).join("");
        return `<li class="term sev-ok ips"><details><summary><span class="t-main"><span class="cum"></span><span class="cost zero">0</span><span class="raw">${t.length} address ranges</span><span class="mech">ip4/ip6</span></span></summary><ul class="ip-list">${list}</ul></details></li>`;
      }
      const cls = `term sev-${t.severity}${t.overLimit ? " is-over" : ""}${t.ignored ? " is-ignored" : ""}${t.void ? " is-void" : ""}`;
      if (t.child) {
        const childRec = t.child.record ? `<p class="child-rec"><code>${esc(t.child.record)}</code></p>` : "";
        return `<li class="${cls}"><details ${depth < 1 ? "open" : ""}><summary>${termRow(t)}</summary><div class="child">${childRec}${tree(t.child, depth + 1)}</div></details></li>`;
      }
      return `<li class="${cls}"><div class="leaf">${termRow(t)}</div></li>`;
    })
    .join("");
  return `<ul class="tree depth-${depth}">${items}</ul>`;
}

export function findings(list: Finding[]): string {
  if (!list.length) return `<p class="no-findings">No problems found beyond the lookup count.</p>`;
  const order = { error: 0, warn: 1, info: 2 } as const;
  return `<ul class="findings">${[...list]
    .sort((a, b) => order[a.severity] - order[b.severity])
    .map((f) => `<li class="f-${f.severity}"><span class="f-sev">${f.severity === "error" ? "Breaks SPF" : f.severity === "warn" ? "Check" : "Note"}</span><span>${esc(f.message)}</span></li>`)
    .join("")}</ul>`;
}
