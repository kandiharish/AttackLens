---
name: eval
description: Run the AttackLens pipeline on a data set with ground truth and print the accuracy scorecard. Use only when asked to evaluate a data set.
argument-hint: [set name under data/raw, e.g. g1 or dev]
disable-model-invocation: true
---
Evaluate data set `$0` (folder `data/raw/$0`).

1. Find ground truth: `data/raw/$0/ground_truth/attacks.json` (synthetic) or the organisers' file for `dev`.
   If none exists, stop and say so; do not invent one.
2. If `data/parquet/$0` exists and the raw folder is unchanged, re-run from Stage 2:
   `.venv/Scripts/python -m attacklens.run --set $0 --from-stage 2 --ground-truth <file>`;
   otherwise run the full pipeline: `.venv/Scripts/python -m attacklens.run --raw data/raw/$0 --out data/out/$0 --ground-truth <file>`.
3. Print from `data/out/$0/eval_scorecard.json`: detection %, labels %, rebuilt %, FA strict %, FA lenient %,
   singleton recall, and the PRD tier (Good/Great/below) for each; then per-attack lines for anything not rebuilt.
4. Print from `run_metrics.json`: total wall time and peak RSS; from `ingest_accounting.json`: drops per source.
5. List unmatched incidents (id, risk, top 3 episodes) so they can be reviewed. Do not change any code or config.
