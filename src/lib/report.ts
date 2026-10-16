import { LOOKUP_LIMIT, budgetState, type Analysis, type DnsAnswer, type Resolver, type TermNode } from "./spf";

export function subtreeCost(t: TermNode): number {
  let n = t.cost;
  if (t.child) for (const c of t.child.terms) n += subtreeCost(c);
  return n;
}

export interface Contribution {
  raw: string;
  label: string;
  cost: number;
}

/** Lookup cost of each top-level term of the root record, in record order (zero-cost terms omitted). */
export function contributions(a: Analysis): Contribution[] {
  return a.root.terms
    .filter((t) => !t.ignored)
    .map((t) => ({ raw: t.raw, label: t.target ?? t.mechanism, cost: subtreeCost(t) }))
    .filter((c) => c.cost > 0);
}

/** Memoising wrapper so re-analysing a draft does not repeat DNS queries. */
/** After a network failure or timeout, further queries fail fast for a short window instead of each waiting for its own timeout. */
export function memoResolver(inner: Resolver, failFastMs = 8000, now: () => number = Date.now): Resolver & { clear: () => void; size: () => number; reset: () => void } {
  const cache = new Map<string, Promise<DnsAnswer>>();
  let lastNetFail = -Infinity;
  const r = ((name, type) => {
    const k = `${type} ${name}`;
    let p = cache.get(k);
    if (!p) {
      if (now() - lastNetFail < failFastMs) return Promise.resolve({ status: "error", records: [], error: "skipped because the resolver was unreachable a moment ago" } as DnsAnswer);
      p = inner(name, type).then((a) => {
        if (a.status === "error") {
          cache.delete(k); // allow a retry after a failure
          if (/timed out|network/.test(a.error ?? "")) lastNetFail = now();
        }
        return a;
      });
      cache.set(k, p);
    }
    return p;
  }) as Resolver & { clear: () => void; size: () => number; reset: () => void };
  r.clear = () => cache.clear();
  r.size = () => cache.size;
  r.reset = () => {
    lastNetFail = -Infinity; // an explicit retry should try the network again
  };
  return r;
}

export function snapshotResolver(answers: Record<string, DnsAnswer>): Resolver {
  return async (name, type) => answers[`${type} ${name}`] ?? { status: "nxdomain", records: [] };
}

const STATE_WORD = { ok: "within budget", tight: "close to the limit", over: "over the limit (permerror)" } as const;

export function toMarkdown(domain: string, current: Analysis | null, planned: Analysis, plannedRecord: string, resolverLabel: string): string {
  const L: string[] = [];
  L.push(`## SPF lookup plan for ${domain}`);
  L.push("");
  if (current) L.push(`- Current record: **${current.lookups} of ${LOOKUP_LIMIT}** DNS lookups, ${STATE_WORD[budgetState(current.lookups)]}${current.permerror && budgetState(current.lookups) !== "over" ? ", with errors" : ""}`);
  L.push(`- Planned record: **${planned.lookups} of ${LOOKUP_LIMIT}** DNS lookups, ${STATE_WORD[budgetState(planned.lookups)]}${planned.permerror && budgetState(planned.lookups) !== "over" ? ", with errors" : ""}`);
  L.push(`- Void lookups (planned): ${planned.voids} of 2 allowed`);
  L.push("");
  L.push("### Planned record");
  L.push("");
  L.push("```");
  L.push(plannedRecord);
  L.push("```");
  L.push("");
  L.push("### Where the lookups go (planned)");
  L.push("");
  L.push("| Term | Lookups |");
  L.push("|---|---|");
  for (const c of contributions(planned)) L.push(`| \`${c.raw}\` | ${c.cost} |`);
  L.push("");
  if (planned.findings.length) {
    L.push("### Findings (planned)");
    L.push("");
    for (const f of planned.findings) L.push(`- ${f.severity === "error" ? "Error" : f.severity === "warn" ? "Warning" : "Note"}: ${f.message}`);
    L.push("");
  }
  L.push(`Resolved through ${resolverLabel}. Counts follow RFC 7208 section 4.6.4; provider records change, so re-check before publishing.`);
  return L.join("\n") + "\n";
}
