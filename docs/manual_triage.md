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
