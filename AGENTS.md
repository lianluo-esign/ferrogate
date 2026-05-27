# Ferrogate Project Instructions

## Commit Requirements

- Every commit must reference the GitHub issue it implements or fixes.
- Put the issue reference in the commit subject when practical, for example `(#18)`, and include a closing or related issue body line or trailer such as `Fixes #18`, `Refs #18`, or `Related: #18`.
- Commit messages must be detailed enough to preserve the decision context: explain why the change exists, what constraints shaped the approach, what alternatives were rejected when relevant, and what was tested.
- Follow the Lore Commit Protocol structure for non-trivial commits, including useful trailers such as `Constraint:`, `Rejected:`, `Confidence:`, `Scope-risk:`, `Directive:`, `Tested:`, and `Not-tested:`.
- Do not use vague commit messages like `fix`, `update`, or `misc`; if the change cannot be tied to an issue, identify or create the appropriate issue before committing.
