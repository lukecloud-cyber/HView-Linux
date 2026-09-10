# Project instructions

Follow the ASD-STE100 instructions in `/home/sweet_cicero/AGENTS.md` for all English text.

Read `TRACKER.md` before starting work.
Read `PLAN.md` for requirements and acceptance checks.
Treat `TRACKER.md` as the current implementation record.
Update the tracker after each implementation change, verification result, blocker, or scope change.
Before stopping work, record incomplete changes and the exact next action.
Mark work complete only after the required checks and Astra review pass.

Use `gpt-6-astra` with reasoning effort `xhigh` for all planning and review.
Use `gpt-5.6-sol` subagents with reasoning effort `xhigh` for all other work.
Delegate documentation, application code, tests, build scripts, and check runs to those subagents.

For each changed source file, add educational block comments to every logical section.
Explain the section purpose, inputs, data flow, state changes, decisions, and connection to the next section.
Write the comments for a reader who does not know the source.
Keep each comment accurate when the related code changes.
Do not retrofit source files that the current task does not change.

Make a feature-for-feature Linux reproduction of `/home/sweet_cicero/Projects/HView-windows`.
Treat the sibling repository as a read-only source unless the user explicitly authorizes changes.
Use the sibling source behavior as the parity reference.
Document each intentional Linux deviation.

Use Intel disassembly syntax by default.
Provide AT&T syntax only through explicit configuration.
Keep the rewrite in Rust on `rust-rewrite`.
Use the previous C source on `main` only as a behavior reference.
