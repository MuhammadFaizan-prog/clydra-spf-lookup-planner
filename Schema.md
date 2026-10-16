# Schema

**No user data is stored.** No database, cookies, localStorage or server.
In-memory: `Analysis {root, lookups, voids, queries, permerror, findings, includes, ip4, ip6}`, `RecordNode {domain, source, record, terms, error, depth}`, `TermNode {raw, qualifier, mechanism, target, cost, cumulative, overLimit, void, child, notes, severity, ignored}`, `Finding {severity, code, message}`. A per-tab DNS answer cache lives only in memory.
Validation: domains normalised (URL/email accepted) and checked against a hostname pattern; includes validated the same way; planned record must start with `v=spf1`.
Data leaving the browser: queried domain names, to the selected DoH resolver only.
Retention: closing the tab discards everything. Supabase `clydra_spf_lookup_planner` not created.
