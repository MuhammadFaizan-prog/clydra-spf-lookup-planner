// Captures real DNS answers for the landing-page sample so the preview is reproducible offline.
// Run: node --experimental-strip-types scripts/snapshot.ts > src/lib/snapshot.json
import { analyze, type DnsAnswer, type RRType } from "../src/lib/spf.ts";
import { dohResolver } from "../src/lib/dns.ts";
import { SAMPLE_CURRENT, SAMPLE_PLANNED, SAMPLE_DOMAIN } from "../src/lib/sample.ts";

const live = dohResolver("google");
const answers: Record<string, DnsAnswer> = {};
const rec = async (n: string, t: RRType) => {
  const a = await live(n, t);
  answers[`${t} ${n}`] = a;
  return a;
};
const cur = await analyze(SAMPLE_DOMAIN, rec, { draft: SAMPLE_CURRENT });
const plan = await analyze(SAMPLE_DOMAIN, rec, { draft: SAMPLE_PLANNED });
console.error("current", cur.lookups, "planned", plan.lookups, plan.permerror, plan.findings.map((f) => f.code));
// eslint-disable-next-line no-console -- CLI output
console.log(JSON.stringify({ capturedAt: "2026-10-16", resolver: "dns.google", answers }, null, 1));
