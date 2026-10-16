# Structure

```
index.html               Landing page (sample instrument computed from captured DNS answers)
tool.html                Planner workspace
public/clydara-logo.png  Approved Clydara mark
src/landing.ts           Renders the sample with the real analyser + snapshot resolver
src/tool.ts              Workspace state, lookup, planned edits, states, exports
src/lib/spf.ts           SPF term parser, RFC 7208 static analyser, findings, addInclude, budget states
src/lib/dns.ts           DNS-over-HTTPS client (Google, Cloudflare) with timeouts
src/lib/report.ts        Subtree costs, memo/fail-fast resolver, snapshot resolver, Markdown report
src/lib/senders.ts       Common sending-service includes
src/lib/sample.ts        Sample plan (example.com adds Salesforce)
src/lib/snapshot.json    Real DNS answers captured 2026-10-16 for the landing sample
src/ui/render.ts         Meter, budget bar, tree and findings renderers
src/styles/*.css         base (tokens, meter, bar, tree), landing, tool
scripts/snapshot.ts      Refreshes snapshot.json from live DoH
tests/spf.test.ts        Parser, counting, permerror cases, DoH client
tests/report.test.ts     Sample scenario from captured answers, resolver caching/fail-fast
vite.config.ts           Multi-page build, production CSP, vitest config
PRD, Techspec, Appflow, Schema, ImplementationPlan, Tracker, Rules, Security, Structure, design-research, README, LICENSE, .env.example
```
