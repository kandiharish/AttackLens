# Vendored Sigma rules

- Source: https://github.com/SigmaHQ/sigma
- Commit: 05d1031f537e830b76da53bae2400c5814c89165 (committed 2026-10-21T08:49:44+05:45)
- Vendored: 2026-10-31, unmodified copies of the folders below
- Folders: `rules/` (3161 .yml), `rules-emerging-threats/` (474), `rules-threat-hunting/` (141), `rules-compliance/` (3)
  = 3779 rule files. Not vendored: `deprecated/`, `unsupported/`, `rules-placeholder/`, `regression_data/`, `tests/`.
- Licence: Detection Rule License (DRL) 1.1 — full text in `LICENSE.Detection.Rules.md`
  (from https://github.com/SigmaHQ/Detection-Rule-License); the repository licence notice is `LICENSE.md`.
- Attribution (DRL 1.1): when AttackLens shows or shares a Sigma-based detection, the rule's author(s) and its
  reference/link must be retained. Each rule file keeps its `author`, `id` and `references`; alerts carry the
  rule id `sigma_<first 8 hex of the Sigma id>` and the coverage report (`work/sigma_coverage.json`) maps them to titles.

Update: re-clone at a new commit, replace these folders, update this file. The compiled cache
(`data/cache/sigma/`) is keyed on file contents, so it rebuilds automatically.
