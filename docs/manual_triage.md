# Nightly Triage Playbook

## When a Link Is Cancelled

- Treat `cancelled` Leak guard runs as superseded by a newer SHA, not as proof of a defect.
- Inspect the **latest** same-workflow run for the current head, then a prior
  completed run if needed.
- Compare the run logs against `docs/leak_guard_concurrency.md`.
- Other workflows can also read `cancelled` **with zero jobs** when a still-queued
  run is replaced (pending-supersede): confirmed via the run API where `jobs == []`
  and no step ever started. That is queue bookkeeping, not a mid-run interruption
  or a data defect — look at the workflow's newest run before triaging further.

## Before Blaming CI

1. Confirm the commit message matches `<type>(<scope>): <subject> [R<n>]`.
2. Run targeted suites:
   - `pcb.tests_pipeline.test_checks_bundle`
   - `pcb.tests_pipeline.test_commit_data.TestLoopCommitFormat`
3. Verify private PCB bundle is checked out only when `BUNDLE_PAT` exists.

## Current Blocking Pattern

- Local full `git sync` is very slow in this workspace, so public changes use
  atomic single-file API commits plus state tracking instead of broad local checkouts.

## When the Health Badge Turns Red

The stats chain runs the pool watchdog every ~2h and turns
`data/output/badge.json` red on any alert. Checks are **fail-open**: each has a
minimum-sample floor, so short/empty rounds stay silent. Two exit-side alerts to
know about:

- **`exit-geo-multi stale`** — `data/quality/exit_geo_multi.json` (the
  per-exit-IP multi-source consensus behind the `←CC` and `⇋` markers) is older
  than 12h / has too few entries. Its producing step is **not** covered by the
  exit-family commit gate, so the artifact can silently freeze while
  `exit_family.json` keeps refreshing. Inspect the geo step of the latest
  `Exit family check` run.
- **`exit-geo multi-source degraded`** — the number of independent families that
  actually voted this round (`summary.families_active`, target 10) fell below the
  collapse floor (8), i.e. the "compare multiple sources" consensus is running on
  too few sources. Read `summary.providers` for per-endpoint `ok` counts and
  prune/rotate the failing endpoint. Note `families_configured` is a static
  constant and cannot show this; only `families_active` reflects runtime health.
  The optional local DB being absent (⇒ 9) is deliberately above the alert floor.
- **`entry-audit stale`** — `data/quality/entry_audit.json` (the entry-country
  label audit behind `chart_entry_audit.svg`) is older than 12h / has too few
  entries. Its producing step (`Audit entry CC labels`) runs with `always()` and
  is **not** referenced by the quality-check commit gate, so a crashed audit
  leaves the artified chart title marked 【数据停摆】 while the badge stays green —
  this alert makes it proactive. Inspect that step of the latest
  `Quality check` run.
- **`source-quality stale`** — `data/quality/source_quality.json` (per-source
  attribution quality) is older than 12h. Its producing step (`Source quality
  analysis`) is likewise **not** in the stats-chain commit gate, so it can freeze
  while the chain keeps committing. Inspect that step of the latest
  `Stats and charts` run.
- **`CN per-ISP supply collapsed` / `CN carrier dispatch wasted`** — the CN chain's
  per-operator latency readings (`china.json` → each reachable entry's `isp_ms`)
  are produced by a small subset of the dispatch sources. `isp_ms_sources`
  records per-source `{ran, made}`; the watchdog alerts when the overall output
  rate drops below 10% (measured baseline 25.6% — ran 15918 / made 4080) or when
  ≥90% of dispatches go to zero-yield sources (baseline 68.6% — 38 sources that
  ran but produced no `isp_ms`). Both mean the operator dimension is silently
  disappearing from the lists. Inspect the `China check` run's stderr lines
  `isp_ms coverage:` / `carrier breakdown:` / the R466
  `zero-yield sources` warning, then `data/quality/china.json.isp_ms_sources`.
- **`CN list ms-rewrite degraded` / `CN list junk ms`** — the CN list
  (`data/valid/all_cn.txt`) lost its mainland latency figures on a large share of
  lines (no `ms` token) or gained lines whose `ms` is below the exit region's
  physical RTT floor. Both facts are computed by the CN chain's landing
  self-check and published as `china.json.meta.list_health`
  (`{count, no_ms, junk_ms}`); the watchdog alerts when `no_ms/count > 10%`
  (measured baseline 289/18220 ≈ 1.6% — reachable keys with no credible mainland
  reading) or `junk_ms > 100` (baseline 0, since the write side drops
  sub-`CN_ICMP_NOISE_MS` readings and applies the per-country floor). A missing
  `list_health` block (older artifact) is treated as healthy. Inspect the
  `China check` run's stderr line
  `all_cn.txt: … health: count=… no_ms=… junk_ms(<=2ms)=…`.

- **`exit labeling collapse` / `multi-region(⇋) labeling divergence` /
  `multi-exit(⇄) labeling divergence`** — the published list's exit markers are
  drifting from the observed evidence. `data/output/stats.json`
  (`collect_exit_coverage`) records two user-flagged quantities: the share of
  lines with **no** exit observation (`exit_untagged_ratio`, baseline 0.0 — the
  watchdog alerts above 5%) and the "same-universe" reconciliation between the
  expected multi-exit/multi-region counts (`exit_multi_*_published`, from
  `all.json`'s `real_exit.multi_*`) and the markers actually written to `all.txt`
  (`exit_marked_multi_exit` = `⇄` lines, `exit_marked_multi_region` = `⇋` lines).
  A gap beyond the self-healing window (`max(3, 25%)`) means the evidence exists
  but the marker did not land — the "some multi-exit nodes are unlabeled"
  symptom. These two counters are only comparable when `export_json` runs
  **before** `generate_stats` in `stats.yml` (order fixed in R700); beforehand
  the `*_published` values were always one round behind the markers. Inspect the
  `Stats and charts` run and `data/output/stats.json`.

Full check list: `pcb/docs/scripts.md` (health_alert).

