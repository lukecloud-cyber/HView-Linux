# Project instructions

Read `TRACKER.md` before starting work.
Read `PLAN.md` for requirements and acceptance checks.
Treat `TRACKER.md` as the current implementation record.
Update the tracker after each implementation change, verification result, blocker, or scope change.
Before stopping work, record incomplete changes and the exact next action.
Mark work complete only after the required checks and Astra review pass.

Use `gpt-6-astra` with reasoning effort `high` for planning and review.
Use `gpt-5.6-sol` with reasoning effort `xhigh` for all application code, tests, and build scripts.
Delegate coding work to that model.
Use Intel disassembly syntax by default.
Provide AT&T syntax only through explicit configuration.
Keep the rewrite in Rust on `rust-rewrite`.
Use the previous C source on `main` only as a behavior reference.
