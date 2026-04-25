---
name: Always ask before committing
description: User wants to approve commits before they are made — do not commit autonomously
type: feedback
---

Always ask the user before running `git commit`. Do not commit changes without explicit approval, even when the task seems self-contained.

**Why:** User preference — they want visibility and control over what lands in git history.

**How to apply:** After making code changes, show a summary of what changed and ask "OK to commit?" before running git commit. This applies to all commits including fixes, refactors, and follow-up changes.
