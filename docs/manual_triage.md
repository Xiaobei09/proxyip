# Nightly Triage Playbook

## When a Link Is Cancelled

- Treat `cancelled` Leak guard runs as superseded by a newer SHA, not as proof of a defect.
- Inspect the **latest** same-workflow run for the current head, then a prior
  completed run if needed.
- Compare the run logs against `docs/leak_guard_concurrency.md`.

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

Full check list: `pcb/docs/scripts.md` (health_alert).

