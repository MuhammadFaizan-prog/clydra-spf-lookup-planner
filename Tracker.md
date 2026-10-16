# Tracker

Status (2026-10-16): **Built and verified locally. Local commit only: private GitHub repo BLOCKED** (Hark GitHub app gets 403 on repo_create). Not deployed.

## Verification evidence (fresh, 2026-10-16)
- lint pass, typecheck pass, `npm test` 21/21 pass (2 files), build pass, `npm audit` 0 vulnerabilities.
- Browser (local production build, Chromium 155, live DoH): `../verify/verify_spf.py` 40/40 pass: landing sample 9 -> 11 with marked lookup #11, links/anchors, empty/invalid domain, email normalised, live google.com = 1/10, add SendGrid 1 -> 3, add Mailgun 3 -> 8, duplicate refused, invalid include, over-limit meter + finding + marked tree term, planned without v=spf1, Cloudflare resolver, no-SPF domain (neverssl.com), NXDOMAIN, resolver unreachable + working retry (bug found and fixed: retry was suppressed by fail-fast window), tree tabs + arrows, copy record + Markdown, visible keyboard focus, no horizontal scroll at 390/768, no console errors except the deliberately aborted request, only dns.google + cloudflare-dns.com contacted.
- Secrets: none in source, dist or history.
- Video: `../videos/clydra-spf-lookup-planner.mp4` (89 s, local build, live DNS).
- NOT TESTED: Safari/Firefox; very large real-world trees beyond the 60-query cap.

## Decisions
- Static budget analysis, not per-IP check_host. mx counted once (common implementations). Supabase project not created (no stored data).

## Next
1. Owner creates empty private repo `clydra-spf-lookup-planner` and grants the Hark GitHub app access; then push.
2. Owner review; deploy only on explicit approval (then verify DoH from the deployed origin's CSP).
