# Security

- Trust boundary: browser only; third parties = Google Public DNS / Cloudflare DoH (domain names only).
- Secrets: none; `.env.example` intentionally empty. No secrets in source, bundle or history (checked).
- CSP: `default-src 'self'; img-src 'self' data:; style-src 'self'; object-src 'none'; base-uri 'self'; form-action 'none'; connect-src https://dns.google https://cloudflare-dns.com`.
- XSS: DNS answers are untrusted; every record/term is HTML-escaped before rendering. No eval.
- Abuse/DoS: 60-query cap per analysis, loop detection, 6 s timeouts, fail-fast after network errors, memo cache to avoid repeat queries; debounced re-analysis.
- Privacy: domain names go to the chosen resolver (stated in UI); nothing else leaves the browser.
- Dependencies: dev-only; `npm audit` in Tracker.
