#!/usr/bin/env bash
# Run external Windows sets DIRECTLY (no jobq) from the frozen snapshot, one at a time, in the order given.
# Before each run waits (30 s polls) until psutil available RAM >= 600 MB.
#   bash tools/ext/win_run_direct.sh name1 name2 ...
set -u
SNAP=/c/cyberforge/data/snap/ext_win
PY=C:/cyberforge/.venv/Scripts/python.exe
for NAME in "$@"; do
  RAW=C:/cyberforge/data/raw/ext_win_$NAME
  LOGD=/c/cyberforge/data/raw/ext_win_$NAME/.logs; mkdir -p $LOGD
  until $PY -I -c "import psutil,sys; sys.exit(0 if psutil.virtual_memory().available >= 600*2**20 else 1)"; do
    echo "$(date -u +%T) $NAME waiting for RAM"; sleep 30; done
  LOGF=$LOGD/run_$(date +%Y%m%dT%H%M%S).log
  free=$($PY -I -c "import psutil; print(round(psutil.virtual_memory().available/2**20))")
  start=$(date +%s)
  ( cd $SNAP/backend && PYTHONPATH=$SNAP/backend $PY -m attacklens.run --raw $RAW --out C:/cyberforge/data/out/ext_win_$NAME \
      --parquet C:/cyberforge/data/parquet/ext_win_$NAME --ground-truth $RAW/ground_truth/attacks.json ) > $LOGF 2>&1
  rc=$?
  echo "$NAME rc=$rc wall_s=$(( $(date +%s) - start )) free_mb_at_start=$free log=$LOGF" | tee -a $LOGF
done
