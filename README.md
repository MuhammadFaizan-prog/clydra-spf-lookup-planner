# Clydara SPF Lookup Planner

Plan an SPF change before you publish it. Look up a domain's live record, add or remove sending services in a planned record, and compare both against SPF's limit of 10 DNS lookups (RFC 7208 section 4.6.4): the cost of each include, the numbered evaluation order, the term where receivers would stop, void lookups, duplicates, loops, `ptr` and `+all`. Copy the planned record or a Markdown report.

- Landing page: `/` · Workspace: `/tool.html` (`/tool.html#sample` runs a sample plan)
- Browser-only. Domain names are resolved through Google Public DNS or Cloudflare DNS-over-HTTPS (user's choice); nothing else leaves the browser.

## Develop
```bash
npm install
npm run dev
npm test
npm run lint && npm run typecheck
npm run build && npm run preview
# refresh the landing sample's captured DNS answers:
node --experimental-strip-types scripts/snapshot.ts > src/lib/snapshot.json
```

## Limits
Counts the lookup budget; does not evaluate a specific sending IP. Macro terms are counted but not expanded. Provider records change; confirm include values in each provider's guide.

Built by [Clydara](https://www.clydralab.com/). Private source; see LICENSE.
