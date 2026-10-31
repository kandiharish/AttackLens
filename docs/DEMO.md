# AttackLens — 5-minute live demo script

Audience: judges and SOC analysts. Read every number from the screen. Do not quote numbers from memory.

## Before going on stage (not counted in the 5 minutes)

- [ ] Pipeline already run: `data/out/<set>/` has `incidents_index.json`, `run_metrics.json`, `eval_scorecard.json`.
- [ ] API running: `ATTACKLENS_OUT=data/out/<set> python -m uvicorn attacklens.api:app --port 8000`.
- [ ] UI running: `cd frontend && npm run dev`, browser open on http://localhost:5173, zoom 125 %.
- [ ] A second terminal ready with the run command (for the "run" beat, use the 1 GB set so it finishes in the slot).
- [ ] Mock UI tab ready: `VITE_USE_MOCK=true npm run dev` on port 5174 (fallback).
- [ ] Network off is fine. Nothing needs it.

## Script

| Time | Say | Do on screen |
|---|---|---|
| 0:00–0:30 | Problem. "Each step of a break-in is one log line, millions of lines apart. Tools alert one by one. An analyst needs hours to link them." | Slide or terminal. Show the data folder size. |
| 0:30–1:15 | Run. "AttackLens streams the raw logs through DuckDB in bounded memory and writes Parquet." | Run `python -m attacklens.run --raw data/raw/g1 --out data/out/g1 --ground-truth data/raw/g1/ground_truth/attacks.json`. Point at the stage lines. If it is too slow, switch to the finished output. |
| 1:15–1:45 | Incident list. "Thousands of alerts became a few incidents, worst on top." | Open the UI list. Point at risk and the "N alerts to 1 incident" count (B-1, B-3). |
| 1:45–2:15 | Open the S1 incident. "One planted attack: password guessing, then foothold, then data copied out." | Click the top S1 incident. Show the header, entry point, kill-chain bar. Point at a dashed gap if shown. |
| 2:15–3:00 | Path, graph, timeline. "Each step has an ATT&CK technique and a stage. Edges say why two steps were linked: same user, host, IP, time." | Scroll the ordered steps, open one evidence line. Hover an edge to show why-linked. Show the graph, compromised hosts highlighted. |
| 3:00–3:30 | Reach next. "This is where the attacker can go from here, with the evidence." | Open the reach-next list. Read one row: host, hops, via user. |
| 3:30–3:55 | Narrative. "Plain-English report. The model only sees placeholders, never raw log text." | Show the narrative and its `template` / `llm` badge. |
| 3:55–4:30 | Scorecard. "These numbers come from the metric files of this run, compared with planted ground truth." | Read the banner: detection, labels, attacks rebuilt, false alarms, time, peak RSS. Say each value as shown. |
| 4:30–5:00 | Live mode and close. "New log lines update the path in seconds." | If live mode works: append a prepared line to `data/raw/live/`, show the path update. Then: "Add a rule by editing `config/rules.yaml`, no code." Show the file. |

## Fallback plan

| If this fails | Do this |
|---|---|
| Pipeline run too slow or crashes | Say "pre-computed run", open the finished `data/out/<set>` through the UI. Show `run_metrics.json` for time. |
| API does not start | Run the mock UI (`VITE_USE_MOCK=true`). Say it is the recorded incident JSON. Do not read scorecard numbers in mock mode. |
| UI does not load | Use `curl http://localhost:8000/api/incidents` and `.../path` in the terminal. Show the JSON. |
| Graph does not render | Use the ordered step list; it carries the same path. |
| Narrative shows `template` | This is the offline default. Say so. It is not a failure. |
| Live mode not working or not built | Skip the live beat. Say "live mode is in `live.py`, status at `/api/live/status`". Do not claim it works. |
| Scorecard missing | Say "no ground truth in this run". Do not state accuracy. |
| Laptop is slow | Use the 1 GB set. Never start a 10 GB run on stage. |

## Likely judge questions

| Question | Answer, with source |
|---|---|
| Does it scale to 50 GB? | Quote the table in README §5.3 or `reports/stress/*.md`. If a tier is "not measured yet", say that. |
| How accurate? | Read the banner. Same numbers as `eval_scorecard.json`. |
| Is the linking causal? | No. It is evidence-linked: shared entities inside time windows. |
| Does the model see our logs? | No. Placeholders and enums only. Without a key it uses the template. |
| How do I add a detection? | Edit `config/rules.yaml` (README §6). |
