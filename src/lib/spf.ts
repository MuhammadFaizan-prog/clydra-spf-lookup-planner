// Static SPF lookup-budget analysis following RFC 7208.
// It does not evaluate a specific sender IP; it walks the record tree and counts the
// DNS-querying terms a receiver must process, in evaluation order:
// - include, a, mx, ptr, exists and the redirect modifier each count 1 toward the limit of 10 (section 4.6.4)
// - void lookups (NXDOMAIN or no answer) SHOULD be limited to 2 (section 4.6.4)
// - an included domain without an SPF record makes include return permerror (section 5.2)
// - more than one SPF record at a name is a permerror (section 4.5)
// - redirect is ignored when the record contains an "all" mechanism (section 6.1)

export type RRType = "TXT" | "A" | "AAAA" | "MX";

export interface DnsAnswer {
  status: "ok" | "nxdomain" | "nodata" | "error";
  records: string[];
  error?: string;
}

export type Resolver = (name: string, type: RRType) => Promise<DnsAnswer>;

export const LOOKUP_LIMIT = 10;
export const VOID_LIMIT = 2;
const MAX_QUERIES = 60; // hard stop so a hostile or looping record cannot run away

export type Mechanism = "include" | "a" | "mx" | "ptr" | "exists" | "ip4" | "ip6" | "all" | "redirect" | "exp" | "modifier" | "unknown";

export interface TermNode {
  raw: string;
  qualifier: "+" | "-" | "~" | "?";
  mechanism: Mechanism;
  target: string | null;
  cost: number; // 0 or 1
  cumulative: number; // lookups counted once this term has been processed
  overLimit: boolean; // this term pushed the count past the limit
  void: boolean;
  child: RecordNode | null;
  notes: string[];
  severity: "ok" | "info" | "warn" | "error";
  ignored: boolean; // e.g. redirect alongside all
}

export interface RecordNode {
  domain: string;
  source: "dns" | "draft";
  record: string | null;
  terms: TermNode[];
  error: string | null;
  depth: number;
}

export interface Finding {
  severity: "error" | "warn" | "info";
  code: string;
  message: string;
  domain?: string;
}

export interface Analysis {
  root: RecordNode;
  lookups: number;
  voids: number;
  queries: number;
  permerror: boolean;
  findings: Finding[];
  includes: string[]; // every include/redirect target in evaluation order
  ip4: number;
  ip6: number;
  stoppedEarly: boolean;
}

const DNS_TERMS: Mechanism[] = ["include", "a", "mx", "ptr", "exists", "redirect"];

export function normaliseDomain(input: string): string | null {
  let d = input.trim().toLowerCase();
  d = d.replace(/^[a-z]+:\/\//, "").replace(/\/.*$/, "").replace(/\.$/, "");
  if (d.startsWith("@")) d = d.slice(1);
  if (d.includes("@")) d = d.split("@").pop() ?? "";
  if (!/^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/.test(d)) return null;
  return d;
}

/** Pick SPF records out of a TXT answer. Cloudflare returns quoted, split strings; Google returns plain text. */
export function spfRecords(txt: string[]): string[] {
  return txt
    .map((t) => {
      const s = t.trim();
      if (!s.startsWith('"')) return s;
      const parts = [...s.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => (m[1] ?? "").replace(/\\(.)/g, "$1"));
      return parts.join("");
    })
    .filter((s) => /^v=spf1(\s|$)/i.test(s));
}

export function parseTerm(raw: string): { qualifier: TermNode["qualifier"]; mechanism: Mechanism; target: string | null } {
  let t = raw;
  let qualifier: TermNode["qualifier"] = "+";
  const q = t[0];
  if (q === "+" || q === "-" || q === "~" || q === "?") {
    qualifier = q;
    t = t.slice(1);
  }
  const lower = t.toLowerCase();
  const mod = /^(redirect|exp)=(.*)$/i.exec(t);
  if (mod) return { qualifier, mechanism: (mod[1] ?? "").toLowerCase() as Mechanism, target: mod[2] ?? "" };
  if (/^[a-z][a-z0-9_.-]*=/i.test(t)) return { qualifier, mechanism: "modifier", target: t };
  const m = /^(include|a|mx|ptr|exists|ip4|ip6|all)(?::([^/]*))?(\/.*)?$/i.exec(t);
  if (!m) return { qualifier, mechanism: "unknown", target: lower };
  const mech = (m[1] ?? "").toLowerCase() as Mechanism;
  const target = m[2] !== undefined ? m[2] : null;
  return { qualifier, mechanism: mech, target: mech === "ip4" || mech === "ip6" ? (m[2] ?? "") + (m[3] ?? "") : target };
}

function hasMacro(s: string): boolean {
  return /%\{/.test(s);
}

export interface AnalyzeOptions {
  draft?: string | null; // record text to use for the root instead of DNS
}

export async function analyze(domain: string, resolver: Resolver, opts: AnalyzeOptions = {}): Promise<Analysis> {
  const findings: Finding[] = [];
  const includes: string[] = [];
  const cache = new Map<string, Promise<DnsAnswer>>();
  let queries = 0;
  let lookups = 0;
  let voids = 0;
  let ip4 = 0;
  let ip6 = 0;
  let permerror = false;
  let stoppedEarly = false;
  const seenTargets = new Map<string, number>();

  const q = (name: string, type: RRType): Promise<DnsAnswer> => {
    const key = `${type} ${name}`;
    const hit = cache.get(key);
    if (hit) return hit;
    queries++;
    const p = resolver(name, type).catch((e: unknown) => ({ status: "error" as const, records: [], error: e instanceof Error ? e.message : String(e) }));
    cache.set(key, p);
    return p;
  };

  const perm = (code: string, message: string, d?: string) => {
    permerror = true;
    findings.push({ severity: "error", code, message, domain: d });
  };

  async function loadRecord(name: string, source: "dns" | "draft", depth: number, draft?: string): Promise<RecordNode> {
    const node: RecordNode = { domain: name, source, record: null, terms: [], error: null, depth };
    if (source === "draft") {
      const recs = spfRecords([draft ?? ""]);
      if (!recs.length) {
        node.error = 'The draft must start with "v=spf1".';
        return node;
      }
      node.record = recs[0] ?? null;
    } else {
      const ans = await q(name, "TXT");
      if (ans.status === "error") {
        node.error = `DNS lookup failed: ${ans.error ?? "unknown error"}. Result is incomplete (a receiver would return temperror).`;
        return node;
      }
      const recs = spfRecords(ans.records);
      if (recs.length === 0) {
        node.error = ans.status === "nxdomain" ? "Domain does not exist (NXDOMAIN)." : "No SPF record published here.";
        return node;
      }
      if (recs.length > 1) {
        perm("multiple-records", `${name} publishes ${recs.length} SPF records. Receivers must return permerror; merge them into one.`, name);
      }
      node.record = recs[0] ?? null;
    }
    return node;
  }

  async function walk(node: RecordNode, path: string[]): Promise<void> {
    if (!node.record) return;
    const rawTerms = node.record.split(/\s+/).slice(1).filter(Boolean);
    if (node.record.length > 450) {
      findings.push({ severity: "warn", code: "long-record", message: `${node.domain}: record is ${node.record.length} characters. Long TXT answers can exceed 512-byte UDP responses and need TCP fallback.`, domain: node.domain });
    }
    const parsed = rawTerms.map((raw) => ({ raw, ...parseTerm(raw) }));
    const hasAll = parsed.some((p) => p.mechanism === "all");
    // Mechanisms in order, then redirect last (modifiers are evaluated after mechanisms).
    const ordered = [...parsed.filter((p) => p.mechanism !== "redirect"), ...parsed.filter((p) => p.mechanism === "redirect")];
    if (parsed.filter((p) => p.mechanism === "redirect").length > 1) perm("double-redirect", `${node.domain}: more than one redirect modifier.`, node.domain);

    for (const p of ordered) {
      const term: TermNode = { raw: p.raw, qualifier: p.qualifier, mechanism: p.mechanism, target: p.target, cost: 0, cumulative: lookups, overLimit: false, void: false, child: null, notes: [], severity: "ok", ignored: false };
      node.terms.push(term);

      if (p.mechanism === "unknown") {
        term.severity = "error";
        term.notes.push("Unrecognised term. Receivers return permerror on unknown mechanisms.");
        perm("unknown-term", `${node.domain}: unrecognised term "${p.raw}".`, node.domain);
        continue;
      }
      if (p.mechanism === "ip4" || p.mechanism === "ip6") {
        if (p.mechanism === "ip4") ip4++;
        else ip6++;
        continue;
      }
      if (p.mechanism === "all") {
        if (node.depth === 0) {
          if (p.qualifier === "+") {
            term.severity = "error";
            term.notes.push("+all authorises every server on the internet to send as this domain.");
            findings.push({ severity: "error", code: "plus-all", message: `${node.domain} ends in +all, which lets anyone pass SPF.`, domain: node.domain });
          } else if (p.qualifier === "?") {
            term.severity = "warn";
            term.notes.push("?all is neutral: mail from unlisted servers is neither passed nor failed.");
          }
        }
        continue;
      }
      if (p.mechanism === "modifier") {
        term.notes.push("Unknown modifier: receivers ignore it.");
        continue;
      }
      if (p.mechanism === "exp") {
        term.notes.push("exp is fetched only after a fail and does not count toward the limit.");
        continue;
      }
      if (p.mechanism === "redirect" && hasAll) {
        term.ignored = true;
        term.severity = "warn";
        term.notes.push('Ignored: a record with an "all" mechanism never follows redirect.');
        findings.push({ severity: "warn", code: "redirect-ignored", message: `${node.domain}: redirect is ignored because the record also has "all".`, domain: node.domain });
        continue;
      }

      // DNS-querying terms
      if (!DNS_TERMS.includes(p.mechanism)) continue;
      term.cost = 1;
      lookups++;
      term.cumulative = lookups;
      if (lookups === LOOKUP_LIMIT + 1) {
        term.overLimit = true;
        term.severity = "error";
        term.notes.push(`This is lookup ${lookups}. Receivers stop here and return permerror.`);
        perm("over-limit", `The record needs more than ${LOOKUP_LIMIT} DNS lookups. Receivers return permerror at the term "${p.raw}" in ${node.domain}.`, node.domain);
      }
      if (queries >= MAX_QUERIES) {
        stoppedEarly = true;
        term.notes.push("Not expanded: analysis stopped after too many DNS queries.");
        continue;
      }

      const target = p.target && p.target.length ? p.target.toLowerCase().replace(/\.$/, "") : node.domain;
      if (p.mechanism === "ptr") {
        term.severity = term.severity === "error" ? "error" : "warn";
        term.notes.push("ptr is deprecated by RFC 7208 (slow, unreliable). Some receivers ignore it. Replace it with ip4/ip6 or include.");
        findings.push({ severity: "warn", code: "ptr", message: `${node.domain} uses ptr, which RFC 7208 says SHOULD NOT be used.`, domain: node.domain });
        continue;
      }
      if (hasMacro(target)) {
        term.notes.push("Contains a macro that depends on the sender, so it cannot be resolved ahead of time. Counted as one lookup.");
        if (p.mechanism === "include" || p.mechanism === "redirect") includes.push(target);
        continue;
      }

      if (p.mechanism === "include" || p.mechanism === "redirect") {
        includes.push(target);
        seenTargets.set(target, (seenTargets.get(target) ?? 0) + 1);
        if (path.includes(target)) {
          term.severity = "error";
          term.notes.push("Loop: this domain is already being evaluated higher up the tree.");
          perm("loop", `${target} includes itself through ${path.join(" → ")}.`, target);
          continue;
        }
        const child = await loadRecord(target, "dns", node.depth + 1);
        term.child = child;
        if (!child.record) {
          const nx = child.error?.startsWith("Domain does not exist") || child.error?.startsWith("No SPF record");
          if (nx) {
            term.void = true;
            voids++;
            term.severity = "error";
            term.notes.push(`${p.mechanism === "include" ? "include" : "redirect"} target has no SPF record. Receivers return permerror for this term.`);
            perm("include-none", `${target} (${p.mechanism}d from ${node.domain}) has no SPF record.`, target);
          } else {
            term.severity = "warn";
            term.notes.push(child.error ?? "Lookup failed.");
            findings.push({ severity: "warn", code: "dns-error", message: `${target}: ${child.error ?? "lookup failed"}`, domain: target });
          }
          continue;
        }
        await walk(child, [...path, target]);
        continue;
      }

      if (p.mechanism === "a" || p.mechanism === "exists") {
        const a = await q(target, "A");
        const aaaa = p.mechanism === "a" ? await q(target, "AAAA") : { status: "nodata" as const, records: [] };
        if (a.status === "error") {
          term.severity = "warn";
          term.notes.push(`Lookup failed: ${a.error ?? ""}`);
        } else if (a.records.length === 0 && aaaa.records.length === 0) {
          term.void = true;
          voids++;
          if (p.mechanism === "a") {
            term.severity = "warn";
            term.notes.push(`${target} has no A or AAAA records: a void lookup that never matches.`);
          } else term.notes.push("No A record right now, which is normal for exists; it still counts as a void lookup.");
        } else {
          term.notes.push(`${a.records.length + aaaa.records.length} address record${a.records.length + aaaa.records.length === 1 ? "" : "s"}.`);
        }
        continue;
      }

      if (p.mechanism === "mx") {
        const mx = await q(target, "MX");
        if (mx.status === "error") {
          term.severity = "warn";
          term.notes.push(`Lookup failed: ${mx.error ?? ""}`);
          continue;
        }
        if (mx.records.length === 0) {
          term.void = true;
          voids++;
          term.severity = "warn";
          term.notes.push(`${target} has no MX records: a void lookup that never matches.`);
          continue;
        }
        if (mx.records.length > 10) {
          term.severity = "error";
          perm("mx-over-10", `${target} has ${mx.records.length} MX records; the mx mechanism allows at most 10.`, target);
        }
        term.notes.push(`${mx.records.length} MX host${mx.records.length === 1 ? "" : "s"}; each host's addresses are looked up too (not counted toward the 10 by common implementations, limited to 10 hosts).`);
      }
    }

    if (node.depth === 0 && !hasAll && !parsed.some((p) => p.mechanism === "redirect")) {
      findings.push({ severity: "warn", code: "no-all", message: `${node.domain} has no "all" or redirect, so unlisted senders get a neutral result. End with ~all or -all.`, domain: node.domain });
    }
  }

  const root = await loadRecord(domain, opts.draft != null ? "draft" : "dns", 0, opts.draft ?? undefined);
  if (root.error) findings.push({ severity: "error", code: "root", message: `${domain}: ${root.error}`, domain });
  await walk(root, [domain]);

  if (voids > VOID_LIMIT) perm("void-limit", `${voids} void lookups. Receivers that apply the recommended limit of ${VOID_LIMIT} return permerror.`);
  for (const [t, n] of seenTargets) {
    if (n > 1) findings.push({ severity: "warn", code: "duplicate", message: `${t} is included ${n} times in the tree. Each copy costs lookups again; keep one.`, domain: t });
  }
  if (stoppedEarly) findings.push({ severity: "warn", code: "stopped", message: `Stopped after ${MAX_QUERIES} DNS queries. Part of the tree was not expanded.` });

  return { root, lookups, voids, queries, permerror, findings, includes, ip4, ip6, stoppedEarly };
}

/** Insert an include before the final all/redirect term, unless it is already present. */
export function addInclude(record: string, target: string): { record: string; added: boolean } {
  const terms = record.trim().split(/\s+/).filter(Boolean);
  if (!terms.length || !/^v=spf1$/i.test(terms[0] ?? "")) terms.unshift("v=spf1");
  const want = `include:${target.toLowerCase()}`;
  if (terms.some((t) => t.toLowerCase().replace(/^\+/, "") === want)) return { record: terms.join(" "), added: false };
  const idx = terms.findIndex((t) => /^[+\-~?]?all$/i.test(t) || /^redirect=/i.test(t));
  if (idx === -1) terms.push(want);
  else terms.splice(idx, 0, want);
  return { record: terms.join(" "), added: true };
}

export function budgetState(lookups: number): "ok" | "tight" | "over" {
  if (lookups > LOOKUP_LIMIT) return "over";
  if (lookups >= 8) return "tight";
  return "ok";
}
