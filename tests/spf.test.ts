import { describe, expect, it } from "vitest";
import { addInclude, analyze, budgetState, normaliseDomain, parseTerm, spfRecords, type DnsAnswer, type Resolver } from "../src/lib/spf";
import { dohResolver } from "../src/lib/dns";

type Zone = Record<string, Partial<Record<"TXT" | "A" | "AAAA" | "MX", string[] | "NX" | "ERR">>>;

function fake(zone: Zone): Resolver & { calls: string[] } {
  const calls: string[] = [];
  const r = (async (name: string, type: "TXT" | "A" | "AAAA" | "MX"): Promise<DnsAnswer> => {
    calls.push(`${type} ${name}`);
    const z = zone[name];
    if (!z) return { status: "nxdomain", records: [] };
    const v = z[type];
    if (v === "NX") return { status: "nxdomain", records: [] };
    if (v === "ERR") return { status: "error", records: [], error: "timed out after 6s" };
    if (!v || v.length === 0) return { status: "nodata", records: [] };
    return { status: "ok", records: v };
  }) as Resolver & { calls: string[] };
  r.calls = calls;
  return r;
}

const ten = (n: number): Zone => {
  const z: Zone = {};
  for (let i = 0; i < n; i++) z[`s${i}.test`] = { TXT: ["v=spf1 ip4:192.0.2.0/24 -all"] };
  return z;
};

describe("parsing helpers", () => {
  it("normalises domains and email addresses", () => {
    expect(normaliseDomain("https://Example.COM/path")).toBe("example.com");
    expect(normaliseDomain("billing@shop.example.org")).toBe("shop.example.org");
    expect(normaliseDomain("not a domain")).toBeNull();
    expect(normaliseDomain("localhost")).toBeNull();
  });
  it("joins quoted, split TXT strings and keeps only SPF records", () => {
    expect(spfRecords(['"v=spf1 ip4:192.0.2.1 " "include:a.test -all"', "google-site-verification=x"])).toEqual(["v=spf1 ip4:192.0.2.1 include:a.test -all"]);
    expect(spfRecords(["v=spf10 nope", "v=spf1"])).toEqual(["v=spf1"]);
  });
  it("parses qualifiers, mechanisms and modifiers", () => {
    expect(parseTerm("~all")).toEqual({ qualifier: "~", mechanism: "all", target: null });
    expect(parseTerm("include:_spf.google.com").target).toBe("_spf.google.com");
    expect(parseTerm("ip4:192.0.2.0/24").target).toBe("192.0.2.0/24");
    expect(parseTerm("a/24").mechanism).toBe("a");
    expect(parseTerm("redirect=_spf.x.test").mechanism).toBe("redirect");
    expect(parseTerm("foo=bar").mechanism).toBe("modifier");
    expect(parseTerm("inclde:x.test").mechanism).toBe("unknown");
  });
  it("adds an include before the all term and never twice", () => {
    expect(addInclude("v=spf1 include:a.test ~all", "b.test")).toEqual({ record: "v=spf1 include:a.test include:b.test ~all", added: true });
    expect(addInclude("v=spf1 include:b.test ~all", "B.test").added).toBe(false);
    expect(addInclude("v=spf1 redirect=x.test", "b.test").record).toBe("v=spf1 include:b.test redirect=x.test");
    expect(addInclude("", "b.test").record).toBe("v=spf1 include:b.test");
  });
  it("budget states", () => {
    expect(budgetState(7)).toBe("ok");
    expect(budgetState(8)).toBe("tight");
    expect(budgetState(10)).toBe("tight");
    expect(budgetState(11)).toBe("over");
  });
});

describe("lookup counting (RFC 7208 4.6.4)", () => {
  it("counts nested includes depth-first and ignores ip4/ip6/all", async () => {
    const r = fake({
      "shop.test": { TXT: ["v=spf1 ip4:192.0.2.1 include:mail.test include:crm.test mx -all"], MX: ["10 mx1.shop.test."] },
      "mail.test": { TXT: ["v=spf1 include:eu.mail.test include:us.mail.test -all"] },
      "eu.mail.test": { TXT: ["v=spf1 ip4:198.51.100.0/24 -all"] },
      "us.mail.test": { TXT: ["v=spf1 ip6:2001:db8::/32 -all"] },
      "crm.test": { TXT: ["v=spf1 a:send.crm.test -all"] },
      "send.crm.test": { A: ["203.0.113.5"] },
    });
    const a = await analyze("shop.test", r);
    expect(a.lookups).toBe(6); // mail, eu, us, crm, a:, mx
    expect(a.permerror).toBe(false);
    expect(a.ip4).toBe(2);
    expect(a.ip6).toBe(1);
    const mail = a.root.terms.find((t) => t.target === "mail.test");
    expect(mail?.child?.terms.map((t) => t.cumulative)).toEqual([2, 3, 3]);
  });

  it("flags the exact term that crosses 10", async () => {
    const z = ten(11);
    z["big.test"] = { TXT: ["v=spf1 " + Array.from({ length: 11 }, (_, i) => `include:s${i}.test`).join(" ") + " -all"] };
    const a = await analyze("big.test", fake(z));
    expect(a.lookups).toBe(11);
    expect(a.permerror).toBe(true);
    const over = a.root.terms.find((t) => t.overLimit);
    expect(over?.raw).toBe("include:s10.test");
    expect(a.findings.some((f) => f.code === "over-limit")).toBe(true);
  });

  it("exactly 10 is still valid", async () => {
    const z = ten(10);
    z["ten.test"] = { TXT: ["v=spf1 " + Array.from({ length: 10 }, (_, i) => `include:s${i}.test`).join(" ") + " -all"] };
    const a = await analyze("ten.test", fake(z));
    expect(a.lookups).toBe(10);
    expect(a.permerror).toBe(false);
  });

  it("include of a domain without SPF is a permerror and a void lookup", async () => {
    const a = await analyze("x.test", fake({ "x.test": { TXT: ["v=spf1 include:gone.test ~all"] } }));
    expect(a.permerror).toBe(true);
    expect(a.voids).toBe(1);
    expect(a.findings.some((f) => f.code === "include-none")).toBe(true);
  });

  it("more than two void lookups is a permerror", async () => {
    const a = await analyze("v.test", fake({ "v.test": { TXT: ["v=spf1 a:n1.v.test a:n2.v.test a:n3.v.test -all"] }, "n1.v.test": {}, "n2.v.test": {}, "n3.v.test": {} }));
    expect(a.voids).toBe(3);
    expect(a.findings.some((f) => f.code === "void-limit")).toBe(true);
  });

  it("detects multiple SPF records, loops, duplicates, +all, ptr and missing all", async () => {
    const r = fake({
      "m.test": { TXT: ["v=spf1 -all", "v=spf1 ~all"] },
      "loop.test": { TXT: ["v=spf1 include:loop2.test -all"] },
      "loop2.test": { TXT: ["v=spf1 include:loop.test -all"] },
      "dup.test": { TXT: ["v=spf1 include:p.test include:q.test ptr +all"] },
      "p.test": { TXT: ["v=spf1 include:q.test -all"] },
      "q.test": { TXT: ["v=spf1 ip4:192.0.2.0/24 -all"] },
      "noall.test": { TXT: ["v=spf1 ip4:192.0.2.1"] },
    });
    expect((await analyze("m.test", r)).findings.some((f) => f.code === "multiple-records")).toBe(true);
    expect((await analyze("loop.test", r)).findings.some((f) => f.code === "loop")).toBe(true);
    const d = await analyze("dup.test", r);
    const codes = d.findings.map((f) => f.code);
    expect(codes).toContain("duplicate");
    expect(codes).toContain("plus-all");
    expect(codes).toContain("ptr");
    expect(d.lookups).toBe(4); // p, q (inside p), q, ptr
    expect((await analyze("noall.test", r)).findings.some((f) => f.code === "no-all")).toBe(true);
  });

  it("redirect counts, is evaluated last, and is ignored next to all", async () => {
    const r = fake({
      "r.test": { TXT: ["v=spf1 redirect=_spf.r.test include:a.test"] },
      "_spf.r.test": { TXT: ["v=spf1 ip4:192.0.2.0/24 -all"] },
      "a.test": { TXT: ["v=spf1 -all"] },
      "ra.test": { TXT: ["v=spf1 redirect=_spf.r.test -all"] },
    });
    const a = await analyze("r.test", r);
    expect(a.root.terms.map((t) => t.mechanism)).toEqual(["include", "redirect"]);
    expect(a.lookups).toBe(2);
    const b = await analyze("ra.test", r);
    expect(b.lookups).toBe(0);
    expect(b.root.terms.find((t) => t.mechanism === "redirect")?.ignored).toBe(true);
  });

  it("macros count one lookup but are not expanded", async () => {
    const a = await analyze("s.test", fake({ "s.test": { TXT: ["v=spf1 exists:%{i}._spf.mta.s.test -all"] } }));
    expect(a.lookups).toBe(1);
    expect(a.root.terms[0]?.notes.join(" ")).toContain("macro");
  });

  it("DNS failures are reported as incomplete, not as a void lookup", async () => {
    const a = await analyze("e.test", fake({ "e.test": { TXT: ["v=spf1 include:slow.test -all"] }, "slow.test": { TXT: "ERR" } }));
    expect(a.voids).toBe(0);
    expect(a.findings.some((f) => f.code === "dns-error")).toBe(true);
  });

  it("drafts replace the root record but includes still resolve", async () => {
    const r = fake({ "q.test": { TXT: ["v=spf1 include:q2.test -all"] }, "q2.test": { TXT: ["v=spf1 -all"] } });
    const a = await analyze("planned.test", r, { draft: "v=spf1 include:q.test ~all" });
    expect(a.root.source).toBe("draft");
    expect(a.lookups).toBe(2);
    expect(r.calls).not.toContain("TXT planned.test");
    const bad = await analyze("planned.test", r, { draft: "include:q.test" });
    expect(bad.root.error).toContain("v=spf1");
  });

  it("caches repeated queries", async () => {
    const r = fake({ "c.test": { TXT: ["v=spf1 include:x.test include:x.test -all"] }, "x.test": { TXT: ["v=spf1 -all"] } });
    await analyze("c.test", r);
    expect(r.calls.filter((c) => c === "TXT x.test")).toHaveLength(1);
  });
});

describe("DoH resolver", () => {
  const mk = (body: unknown, ok = true, status = 200) =>
    (async () => ({ ok, status, json: async () => body }) as unknown as Response) as unknown as typeof fetch;
  it("maps NOERROR, NXDOMAIN, SERVFAIL and HTTP errors", async () => {
    expect(await dohResolver("google", 1000, mk({ Status: 0, Answer: [{ name: "a", type: 16, data: "v=spf1 -all" }, { name: "a", type: 5, data: "cname." }] }))("a", "TXT")).toEqual({ status: "ok", records: ["v=spf1 -all"] });
    expect((await dohResolver("google", 1000, mk({ Status: 3 }))("a", "TXT")).status).toBe("nxdomain");
    expect((await dohResolver("google", 1000, mk({ Status: 0 }))("a", "TXT")).status).toBe("nodata");
    expect((await dohResolver("google", 1000, mk({ Status: 2 }))("a", "TXT")).status).toBe("error");
    expect(await dohResolver("cloudflare", 1000, mk({}, false, 503))("a", "TXT")).toMatchObject({ status: "error", error: "HTTP 503 from Cloudflare 1.1.1.1" });
  });
  it("times out", async () => {
    const hang = ((_u: string, init?: RequestInit) =>
      new Promise((_res, rej) => init?.signal?.addEventListener("abort", () => rej(new DOMException("aborted", "AbortError"))))) as unknown as typeof fetch;
    const r = await dohResolver("google", 30, hang)("a", "TXT");
    expect(r.error).toContain("timed out");
  });
});
