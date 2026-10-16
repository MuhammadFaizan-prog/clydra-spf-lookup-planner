# PRD: Clydara SPF Lookup Planner

## User and job
Whoever manages a domain's email DNS (IT admins, developers, agencies, marketing ops) and has to add, remove or audit an email sending service without breaking SPF.

## Problem and evidence (researched 2026-10-16)
- RFC 7208 section 4.6.4 limits SPF evaluation to 10 DNS-querying terms (include, a, mx, ptr, exists, redirect) and SHOULD limit void lookups to 2; exceeding either is a permerror ([RFC 7208](https://www.rfc-editor.org/rfc/rfc7208.html)).
- Vendors document it as a common failure: Cloudflare's DMARC docs ([DNS lookup limit](https://developers.cloudflare.com/dmarc-management/dns-lookup-limits)), Adobe Marketo KB ([Common SPF errors](https://experienceleague.adobe.com/en/docs/experience-cloud-kcs/kbarticles/ka-28228)), Infoblox ([too many included lookups](https://support.infoblox.com/s/article/SPF-record-throws-error)), Broadcom ([SPF=permerror](https://knowledge.broadcom.com/external/article/282174/spfpermerror.html)), Server Fault ([void lookup limit exceeded](https://serverfault.com/questions/666282/permerror-spf-permanent-error-void-lookup-limit-of-2-exceeded)).
- Implementations disagree on counting details (e.g. mx handling in [stalwartlabs/mail-auth#35](https://github.com/stalwartlabs/mail-auth/issues/35); Internet.nl once counted only include/redirect, [NLnetLabs/Internet.nl#286](https://github.com/NLnetLabs/Internet.nl/issues/286)).
- The pain arrives when a new service is added: provider includes nest (live DNS on 2026-10-16: `include:mailgun.org` costs 5 lookups; `include:_spf.salesforce.com` costs 2).

## Alternatives
| Tool | Does well | Gap |
|---|---|---|
| dmarcian SPF Surveyor | Clear "N/10" headline, expandable include tree | Checks the published record; no draft/what-if comparison. REA capture: lookup runs server-side (domain sent to dmarcian), page loads CookieYes, Weglot, Typekit, NitroPack third parties |
| MXToolbox SPF | Fast lookup, problem list | Published record only; heavy ads/upsell |
| EasyDMARC / PowerDMARC checkers | Validation + flattening upsell | Published record only; push paid flattening |
| Cloudflare DMARC Management | Warns at edit time | Only for domains on Cloudflare with the product enabled |

## Original value
A **what-if planner**: current vs planned side by side, one-click common senders, the cost of each top-level include (subtree), the numbered evaluation order with the exact term that crosses 10, void/duplicate/loop/ptr/+all findings, and a Markdown report. Runs in the browser; only DNS queries leave it, sent to the resolver the user picks.

## Scope
In: domain lookup via DoH (Google or Cloudflare), current + planned records, sender catalog (14), custom include, findings, tree, budget bar, copy record/report, landing page, mobile, failure handling.
Out: testing a specific sending IP (check_host simulation), automatic flattening, monitoring, accounts, storage.

## Stories and acceptance criteria
1. Look up a domain and see the live budget. AC: `google.com` loads `v=spf1 include:_spf.google.com ~all` = 1/10 (browser check).
2. Add a sender and see the planned cost. AC: adding SendGrid then Mailgun raises 1 -> 3 -> 8 (live), include inserted before `~all`.
3. See where it breaks. AC: sample plan (9 -> 11) marks lookup #11 (`exists:%{i}._spf.mta.salesforce.com`) and a "Breaks SPF" finding.
4. Errors are explained. AC: invalid/empty domain, NXDOMAIN, no SPF published, draft without `v=spf1`, resolver unreachable (with working retry).
5. Export. AC: planned record and Markdown report copied to clipboard.
6. Mobile. AC: no page-level horizontal scroll at 390/768/1440.

## Success measures (only after an approved deployment)
Lookups run, plans with an added sender, report copies, return visits, clicks to clydralab.com. None measured; not deployed.
