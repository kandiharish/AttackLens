#!/usr/bin/env bash
# Run one external Windows set through jobq from the frozen snapshot (data/snap/ext_win).
#   bash tools/ext/win_run.sh <name>      (raw = data/raw/ext_win_<name>, GT override with env GT=...)
set -u
NAME=$1
SNAP=/c/cyberforge/data/snap/ext_win
PY=C:/cyberforge/.venv/Scripts/python.exe
RAW=C:/cyberforge/data/raw/ext_win_$NAME
OUT=C:/cyberforge/data/out/ext_win_$NAME
PQ=C:/cyberforge/data/parquet/ext_win_$NAME
GT=${GT:-$RAW/ground_truth/attacks.json}
LOGD=/c/cyberforge/data/raw/ext_win_$NAME/.logs; mkdir -p $LOGD
LOGF=$LOGD/run_$(date +%Y%m%dT%H%M%S).log
cd $SNAP/backend || exit 2
export PYTHONPATH=$SNAP/backend
start=$(date +%s)
$PY /c/cyberforge/tools/sched/jobq.py run --name extwin_$NAME --prio 4 --ram-gb 4 --est-min 10 --threads 4 -- \
  $PY -m attacklens.run --raw $RAW --out $OUT --parquet $PQ --ground-truth $GT > $LOGF 2>&1
rc=$?
echo "$NAME rc=$rc wall_incl_queue_s=$(( $(date +%s) - start )) log=$LOGF" | tee -a $LOGF
