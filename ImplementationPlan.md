# Implementation plan

1. SPF term parser + static analyser + findings with RFC 7208 tests (done).
2. DoH client with timeouts; memo + fail-fast resolver (done).
3. Snapshot of real DNS answers for the landing sample (done; refresh with `node --experimental-strip-types scripts/snapshot.ts > src/lib/snapshot.json`).
4. Landing page, workspace, states, mobile (done).
5. Production CSP, build, browser verification `verify/verify_spf.py` against live DoH (done, 40/40).
6. Review video (done) -> owner review gate.
7. Deployment only after explicit approval (section 15); then re-verify live DoH from the deployed origin.
Recovery: private repo history + `../clydra-spf-lookup-planner.bundle`.
