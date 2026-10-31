---
name: gen-data
description: Generate a synthetic AttackLens test data set of a given size with planted attack scenarios and ground truth, using tools/gen_dataset.py around reports/edr_log_generator.py. Use only when asked to generate data.
argument-hint: [size, e.g. 50M, 1G, 10G, 30G, 50G] [optional alert ratio]
disable-model-invocation: true
---
Generate data set of size `$0` per docs/TESTING.md §3.

1. Validate `$0` matches a number followed by K, M or G. Otherwise stop and ask.
2. If `tools/gen_dataset.py` does not exist, stop: it must be built first by the test-engineer (TESTING.md §8.3).
3. Pre-flight disk: required free space ≈ size × 1.9 + 20 GB (TESTING.md §6.1). Show `df -h /c`. Stop if short and
   list which `data/raw/*` folders could be deleted (do not delete without being asked).
4. Run in the background:
   `.venv/Scripts/python tools/gen_dataset.py --size $0 --out data/raw/g$0 --seed 42 --workers 6 --scenarios all --force --alert-ratio <R>`
   where `<R>` is `$1` if given, else `0.0005`
   (use 1 worker for sizes below 100M).
5. When it finishes, print `manifest.json` essentials: bytes, events, MB/s, scenarios, noise alert count, and check:
   bytes ≥ target, no line contains `"threat"` or `"labels"` (sample 1 000 lines per part), timestamps monotonic per part.
