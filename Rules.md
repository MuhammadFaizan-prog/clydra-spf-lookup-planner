# Rules

- No runtime dependencies; analysis logic stays pure in `src/lib` with tests citing RFC 7208 sections.
- Never treat a DNS failure as a void lookup or a pass; show it as incomplete.
- Status always uses words plus colour (Within budget / Close to the limit / Over the limit).
- No inline styles/scripts (CSP); widths via CSSOM.
- Network only to the two DoH resolvers; no analytics.
- Sender catalog values must resolve live and carry the "confirm with provider" caveat.
- Brand: tool name -> `/`; "Built by Clydara" -> https://www.clydralab.com/. No founder names, CRM mentions or invented claims.
- Never commit `dist/` or `node_modules/`.
