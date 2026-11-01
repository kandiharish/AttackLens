#!/usr/bin/env bash
# QA track qa_contracts: run the real pipeline on the small sets only (never n10/n30/n50).
# data/tmp/qa_config is re-made from config/ on every invocation (so it never drifts from the product config); only
# pipeline.yaml runtime knobs are patched (memory_limit / threads / temp_directory) for a shared machine.
# Rules, thresholds, sources, linking are byte-identical to config/.
# Env: QA_MEM (default 1GB), QA_THREADS (default 2).
set -u
cd /c/cyberforge
PY=C:/cyberforge/.venv/Scripts/python
CFG=data/tmp/qa_config
MEM=${QA_MEM:-1GB}
THR=${QA_THREADS:-2}

refresh_cfg() {
  rm -rf "$CFG" && mkdir -p "$CFG" data/tmp/qa_spill
  for f in config/*; do [ -f "$f" ] && cp "$f" "$CFG/"; done   # config/sigma is referenced by repo-relative path
  "$PY" - "$CFG/pipeline.yaml" "$MEM" "$THR" <<'EOF'
import re, sys
p, mem, thr = sys.argv[1:4]
t = open(p, encoding="utf-8").read()
t, n1 = re.subn(r'(?m)^memory_limit:.*$', f'memory_limit: "{mem}"   # QA contended', t)
t, n2 = re.subn(r'(?m)^threads:.*$', f'threads: {thr}   # QA contended', t)
t, n3 = re.subn(r'(?m)^temp_directory:.*$', 'temp_directory: "data/tmp/qa_spill"', t)
assert (n1, n2, n3) == (1, 1, 1), (n1, n2, n3)
open(p, "w", encoding="utf-8").write(t)
EOF
  for f in "$CFG"/*; do
    b=$(basename "$f"); [ "$b" = pipeline.yaml ] && continue
    cmp -s "$f" "config/$b" || { echo "config copy differs: $b"; exit 2; }
  done
  echo "=== qa_config refreshed (memory_limit=$MEM threads=$THR)"
}

run() {  # set gt
  local set=$1 gt=${2:-}
  local args=(-m attacklens.run --raw data/raw/$set --out data/out/qa_$set --parquet data/parquet/qa_$set --config $CFG)
  [ -n "$gt" ] && args+=(--ground-truth "$gt")
  rm -rf data/out/qa_$set data/parquet/qa_$set
  echo "=== $set start $(date -u +%FT%TZ)"
  powershell -NoProfile -Command "\$o=Get-CimInstance Win32_OperatingSystem; 'free_mb=' + [int](\$o.FreePhysicalMemory/1024) + ' cpu_pct=' + (Get-CimInstance Win32_Processor).LoadPercentage"
  "$PY" "${args[@]}" > data/tmp/qa_run_$set.log 2>&1
  echo "=== $set rc=$? end $(date -u +%FT%TZ)"
}

refresh_cfg
for s in "$@"; do
  case $s in
    f1) run f1 data/raw/f1/ground_truth/attacks.json ;;
    g50m) run g50m data/raw/g50m/ground_truth/attacks.json ;;
    demo) run demo data/raw/demo/ground_truth/attacks.json ;;
    smoke_mixed) run smoke_mixed ;;  # its attacks.json is a bare [] -> harness AttributeError (QA-C1); run without GT
    *) run "$s" ;;
  esac
done
