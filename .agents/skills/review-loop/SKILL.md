---
name: review-loop
description: Use when the user says "review-loop" to review, fix, and push selected PRs until a subagent review finds no issues.
---

# Review loop

## Select PRs

Use the user's requested authors, counts, PR numbers/URLs, branches, or dates. Default to open PRs in this repository, with no date limit; “last” means newest by creation time. Ask if the selection is missing or unclear.

Examples: `review-loop last pr of someuser440`, `review-loop last three open prs`.

## Run

1. Resolve the selection with `gh` and announce the PRs. Create a separate worktree at each PR's head and a fresh primary OpenCode Build session in that worktree. Explicitly allow delegation: set session `permissions` to `[{"action":"subagent","resource":"*","effect":"allow"}]` through `opencode api`. Pass these instructions and PR metadata to each worker.
2. Independent PRs may run concurrently; PRs sharing a head branch must run sequentially. Each worker follows `AGENTS.md` and applicable skills, then repeats:
   - **Review:** launch a fresh, read-only reviewer subagent over the full PR diff against its target branch. Consider security, correctness, good practices, code smells, readability, performance, and UI/UX. Require actionable findings with severity, file/line, and evidence.
   - **Wait:** do not edit, commit, or push until every reviewer finishes and returns its final report. An interrupted or incomplete review is blocked, not clean.
   - **Stop if clean:** no new findings and no unresolved previous findings on the latest head/base snapshot.
   - **Fix and push:** address supported findings, run `pnpm typecheck`, `pnpm lint`, and `pnpm test` plus relevant checks, then commit and push to the existing PR head branch. Start another fresh review.
3. Recheck the remote head/base before pushing or declaring clean; refresh and re-review if they changed. Report permission, verification, or progress blockers honestly. Never force-push, merge, or overwrite user changes.
4. Wait for all PR sessions to finish before reporting results.

## Final summary

For each PR, briefly report:

- PR link and what it does in one or two sentences.
- Source branch → target branch.
- Current whole-PR lines added/deleted and files changed, refreshed with `gh pr view`; mention key files when useful.
- Clean/blocked status, review rounds, fixes pushed, and verification results.
