# F3 Draft Pass Approval Canary

This documentation-only change verifies that a passing review in `draft` mode
waits for an exact-context approval label. The approval must be consumed once,
reported to Discord, and stopped by `ATOMIC_SERVER_GATES_UNAVAILABLE` without
merging the pull request.
