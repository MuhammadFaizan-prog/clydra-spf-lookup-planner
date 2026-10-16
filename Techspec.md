# Techspec

- Stack: TypeScript 6, Vite 8 multi-page (`index.html`, `tool.html`), no runtime dependencies; Vitest 5; ESLint 10.
- Modules: `src/lib/spf.ts` (term parser, recursive static analyser, findings, `addInclude`), `dns.ts` (DoH JSON client for dns.google and cloudflare-dns.com, 6 s timeout via AbortController, TXT quoting handled), `report.ts` (subtree costs, memoising + fail-fast resolver, snapshot resolver, Markdown), `senders.ts`, `sample.ts`, `snapshot.json` (real DNS answers captured 2026-10-16 by `scripts/snapshot.ts`, used only for the landing preview); UI in `src/ui/render.ts`, `src/landing.ts`, `src/tool.ts`.
- Counting rules: include/a/mx/ptr/exists/redirect +1 each across the whole tree in evaluation order (mechanisms, then redirect); redirect ignored when `all` present; void = NXDOMAIN/no data (>2 permerror); include target without SPF = permerror; >1 SPF record = permerror; mx counted once and >10 MX hosts flagged; macros counted, not expanded; loop detection; cap of 60 DNS queries per analysis.
- External API contract: `GET https://dns.google/resolve?name=&type=` or `GET https://cloudflare-dns.com/dns-query?name=&type=` with `accept: application/dns-json`; Status 0 = NOERROR, 3 = NXDOMAIN, others = error. No keys, free public services; failures shown as incomplete (temperror-like), never as void.
- Retries: explicit Retry button / new lookup reset the fail-fast window; failed answers are not cached.
- CSP (production): `connect-src https://dns.google https://cloudflare-dns.com` only.
- Supabase: dedicated project `clydra_spf_lookup_planner` NOT created and not used (browser-only, stores nothing).
- Deployment: static `dist/`; not deployed. Cost $0 beyond static hosting; DoH resolvers are free public services (their availability is a dependency).
