import { describe, expect, it } from "vitest";
import { analyze, type DnsAnswer } from "../src/lib/spf";
import { contributions, memoResolver, snapshotResolver, toMarkdown } from "../src/lib/report";
import snapshot from "../src/lib/snapshot.json";
import { SAMPLE_CURRENT, SAMPLE_DOMAIN, SAMPLE_PLANNED } from "../src/lib/sample";

const answers = snapshot.answers as Record<string, DnsAnswer>;

describe("sample scenario from real DNS answers captured 2026-10-16", () => {
  it("current uses 9 lookups; adding Salesforce makes it 11 and a permerror", async () => {
    const r = snapshotResolver(answers);
    const cur = await analyze(SAMPLE_DOMAIN, r, { draft: SAMPLE_CURRENT });
    const plan = await analyze(SAMPLE_DOMAIN, r, { draft: SAMPLE_PLANNED });
    expect(cur.lookups).toBe(9);
    expect(cur.permerror).toBe(false);
    expect(plan.lookups).toBe(11);
    expect(plan.permerror).toBe(true);
    const c = contributions(plan);
    expect(c.find((x) => x.label === "mailgun.org")?.cost).toBe(5);
    expect(c.reduce((s, x) => s + x.cost, 0)).toBe(11);
    const md = toMarkdown(SAMPLE_DOMAIN, cur, plan, SAMPLE_PLANNED, "Google Public DNS");
    expect(md).toContain("Planned record: **11 of 10**");
    expect(md).toContain("| `include:mailgun.org` | 5 |");
  });

  it("memo resolver queries each name once and retries after errors", async () => {
    let n = 0;
    let fail = true;
    const inner = async (): Promise<DnsAnswer> => {
      n++;
      if (fail) {
        fail = false;
        return { status: "error", records: [], error: "x" };
      }
      return { status: "ok", records: ["v=spf1 -all"] };
    };
    const m = memoResolver(inner);
    expect((await m("a.test", "TXT")).status).toBe("error");
    expect((await m("a.test", "TXT")).status).toBe("ok");
    await m("a.test", "TXT");
    expect(n).toBe(2);
  });

  it("fails fast for a while after a network error", async () => {
    let t = 0;
    let n = 0;
    const m = memoResolver(async () => {
      n++;
      return { status: "error", records: [], error: "network error (offline or blocked)" };
    }, 8000, () => t);
    await m("a.test", "TXT");
    expect((await m("b.test", "TXT")).error).toContain("skipped");
    expect(n).toBe(1);
    m.reset();
    await m("b.test", "TXT");
    expect(n).toBe(2);
    t = 20000;
    await m("c.test", "TXT");
    expect(n).toBe(3);
  });
});
