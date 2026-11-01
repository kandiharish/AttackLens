# AttackLens — 5-minute live demo script

Audience: judges and SOC analysts. Read every number from the screen. Do not quote numbers from memory.

## Which data to open

1. If a FortiGate incident exists (run on the synthetic FortiGate set or a real tier), open it first.
   Say which kind it is. A real-tier incident has no ground truth: say "found", never "accuracy".
2. Otherwise open the S1 incident from `data/out/g1x`.

Say the honest-IOC point once: "In g1x the attacker IPs are not in our threat-intel list. The attack is found from
behaviour (failed-login burst, new admin logon, Office spawning PowerShell, large upload), not from a known-bad IP."
Why: `data/out/g1` used a set where IOC hits could help; g1x removes that help.

## Before going on stage (not counted in the 5 minutes)

- [ ] Pipeline already run: `data/out/<set>/` has `incidents_index.json`, `run_metrics.json`, `eval_scorecard.json`.
- [ ] API running from the repo root: `ATTACKLENS_OUT=data/out/g1x python -m uvicorn attacklens.api:app --port 8000`.
- [ ] UI running: `cd frontend && npm run dev`, browser open on http://localhost:5173, zoom 125 %.
- [ ] A second terminal ready with the run command (use the 1 GB set so it finishes in the slot).
- [ ] Mock UI tab ready: `VITE_USE_MOCK=true npm run dev` on another port (fallback).
- [ ] Live mode ready if built: `python -m attacklens.live --watch data/raw/live --out data/out/live --reset`, plus a prepared
      log line to append.
- [ ] Network off is fine. Nothing needs it.

### SIEM beat setup (optional)

- [ ] Terminal A: `python tools/mock_siem.py --data data/raw/g1 --port 9200` (loopback only, no auth).
- [ ] `config/integrations.yaml`: `connectors.elastic.enabled: true`, and `api_key_env`, `user_env`, `password_env` set
      to `null`. Revert after the demo (everything else stays disabled).
- [ ] Rehearse once: check `pulled` is above 0 in the pull log and in `data/spool/connector_status.json`. If it is 0,
      widen `--since`. Alert-mode runs have no scorecard. Do not read accuracy for this incident.
- [ ] Start the API on the SIEM output: `ATTACKLENS_OUT=data/out/siem1 python -m uvicorn attacklens.api:app --port 8000`
      (restart it on `data/out/g1x` afterwards, or use `POST /api/reload` after changing the output directory).
- [ ] Optional status check: `curl http://localhost:8000/api/integrations/status`.

## Script

| Time | Say | Do on screen |
|---|---|---|
| 0:00–0:30 | Problem. "Each step of a break-in is one log line, millions of lines apart. Tools alert one by one. An analyst needs hours to link them." | Slide or terminal. Show the data folder size. |
| 0:30–1:15 | Run. "AttackLens streams the raw logs through DuckDB in bounded memory and writes Parquet." | Run `python -m attacklens.run --raw data/raw/g1x --out data/out/g1x --ground-truth data/raw/g1x/ground_truth/attacks.json`. Point at the stage lines. If too slow, switch to the finished output. |
| 1:15–1:45 | Incident list. "Thousands of alerts became a few incidents, worst on top." | Open the UI list. Point at risk and the "N alerts to 1 incident" count (B-1, B-3). |
| 1:45–2:15 | Open the incident (FortiGate if available, else S1). "Password guessing, then a foothold, then data copied out." Say the honest-IOC point here. | Click the top incident. Show header, entry point, kill-chain bar. Point at a dashed gap if shown. |
| 2:15–3:00 | Path, graph, timeline. "Each step has an ATT&CK technique and a stage. Edges say why two steps were linked: same user, host, IP, time." | Scroll the ordered steps, open one evidence line. Hover an edge to show why-linked. Show the graph, compromised hosts highlighted. |
| 3:00–3:30 | Reach next. "This is where the attacker can go from here, with the evidence." | Open the reach-next list. Read one row: host, hops, via user. |
| 3:30–3:55 | Narrative. "Plain-English report. The model only sees placeholders, never raw log text." | Show the narrative and its `template` / `llm` badge. |
| 3:55–4:30 | Scorecard. "These numbers come from the metric files of this run, compared with planted ground truth." | Read the banner: detection, labels, attacks rebuilt, false alarms, time, peak RSS. Say each value as shown. For a real tier, show only time, memory, accounting and incidents found. |
| Optional beat (SIEM; take ~30 s from the narrative beat) | "Your SIEM fired N separate alerts (read N from the pull log). AttackLens shows one incident." | Mock SIEM already running (see "SIEM beat setup"). Run `python -m attacklens.connect --source elastic --mode alerts --since 7d --once`, point at `pulled / written / skipped / failed` in the log. Run `python -m attacklens.run --raw data/raw/g1 --out data/out/siem1 --siem-alerts`, open the incident. Read the real alert count from the screen. Then `curl http://localhost:8000/api/incidents/<id>/pivots` and read one SPL / KQL / Lucene query. Say "mock SIEM, not a real one". |
| 4:30–5:00 | Live mode and close. "New log lines update the path in seconds." | If live mode works: append the prepared line to a file in `data/raw/live/`, show the path update. Then: "Add a rule by editing `config/rules.yaml`, no code." Show the file. |

## Fallback plan

| If this fails | Do this |
|---|---|
| Pipeline run too slow or crashes | Say "pre-computed run", open the finished `data/out/<set>` through the UI. Show `run_metrics.json` for time. |
| API does not start | Run the mock UI (`VITE_USE_MOCK=true`). Say it is the recorded incident JSON. Do not read scorecard numbers in mock mode. |
| UI does not load | Use `curl http://localhost:8000/api/incidents` and `.../path` in the terminal. Show the JSON. |
| Graph does not render | Use the ordered step list; it carries the same path. |
| Narrative shows `template` | This is the offline default. Say so. It is not a failure. |
| Live mode not working | Skip the live beat. Say "live mode is `attacklens.live`, status at `/api/live/status`". Do not claim it works. |
| Scorecard missing | Say "no ground truth in this run". Do not state accuracy. |
| Laptop is slow | Use the 1 GB set. Never start a 10 GB run on stage. |
| SIEM beat fails (mock down, `pulled: 0`, pull error) | Skip it. Say "it works on top of your SIEM; connectors are tested against a local mock only". Show `data/spool/connector_status.json` if asked. Do not claim a real SIEM was tested. |
| Docker asked about | Say it is being verified. Show the native run. |

## Likely judge questions

| Question | Answer, with source |
|---|---|
| Does it scale to 50 GB? | Quote README section 7.3 or `reports/stress/*.md`. Rows marked "TBD (run pending)" are not measured. Do not estimate. |
| How accurate? | Read the banner. Same numbers as `eval_scorecard.json`. Accuracy is on synthetic data with 5 planted attacks. Real FortiGate tiers have no ground truth, so no accuracy score. |
| Is a 100 % score believable? | Small set (5 attacks, 21 steps), synthetic. We show per-attack detail and the g1x set without IOC help. We do not claim the same on real data. |
| Is this a SIEM replacement? | No. It sits on top. The SIEM stores logs and runs detections. AttackLens correlates and pushes incidents back. |
| Is the integration tested on a real SIEM? | Only against the local mock, unless a real test is recorded. Say so. |
| Is the linking causal? | No. It is evidence-linked: shared entities inside time windows. |
| Does the model see our logs? | No. Placeholders and enums only. Without a key it uses the template. |
| How do I add a detection? | Edit `config/rules.yaml` (README section 8). |
| Why not follow the spec's tactic order exactly? | Real attack order breaks the literal rule. See README section 5. |
