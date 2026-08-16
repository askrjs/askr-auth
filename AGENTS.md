# AGENTS.md

Operational guide for `@askrjs/auth`, which owns domain-neutral authentication
contracts while applications retain identity storage and policy ownership.

## Askr North Star

Keep every authentication flow narratable from supplied artifact through
validation to an explicit result. Enforce invariants where invalid state enters,
with errors that identify the failed contract and corrective action. Give each
new primitive distinguishable failure modes and tests for them. Preserve the
documented boundaries between authentication mechanics and application-owned
users, storage, replay prevention, and policy. Prefer explicit issuers,
algorithms, stores, and callback state over inference. Add surface area only for
a demonstrated application need.

Run `npm run check` before declaring a change ready. Exercise real signed
artifacts and failure paths when the affected contract depends on them.

## Optimization Gate

A benchmark number is only half of an optimization's success criterion. The
change must also preserve a causal path that a human or agent can narrate in one
sentence.

Every benchmark-driven change must include:

1. the one-sentence causal description of the optimized path;
2. the exact fallback trigger and proof that optimized and fallback paths have
   identical observable behavior and error surfaces;
3. an explicit legibility-cost statement, including `none` when no new path or
   concept is introduced; and
4. evidence that a measured bottleneck in a real application justifies the
   optimization now.

Prefer making the existing single path faster. New caches, inference,
memoization, shortcuts, fast paths, or scheduler states require an explicit
legibility decision; a speedup alone does not justify them.
