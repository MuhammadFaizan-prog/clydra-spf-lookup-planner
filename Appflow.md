# Appflow

1. Landing `/`: nav (Read the result, How it works, FAQ, Open the planner, Built by Clydara) -> hero -> sample instrument (meters 9 -> 11, budget bar, findings, tree; computed from captured answers) -> reading the result -> how it works + lookup definition -> use cases table -> privacy & limits -> FAQ -> closing CTA.
2. "Open the planner" -> `/tool.html` (intro state). "Run the sample plan" -> `/tool.html#sample` (live resolution).
3. Workspace: left = domain + resolver, current record, planned record (sender chips, custom include, copy buttons); right = status line, two meters with delta, budget bar, findings, evaluation tree with Planned/Current tabs.
States: intro; invalid/empty domain; resolving (spinner); live record loaded; no SPF published (start one); NXDOMAIN; resolver unreachable (retry/switch); partial DNS failures (warning, retry); planned invalid (`v=spf1` required); within budget / close (8-10) / over (>10); copy feedback; clipboard fallback to download.
Responsive: <=920 px single column; meters 2-up with delta below on phones; tree indents compactly.
Keyboard: forms submit with Enter; sender chips are buttons; tree uses native details/summary; tabs switch with arrows; skip link.
