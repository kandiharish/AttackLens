# AttackLens benchmark report

Written 2026-10-31. Our numbers are measured. Other tools' numbers are claims they published.
The two are never mixed in one cell. No tool is ranked where the conditions differ.

## 1. What we measured, and on what

**Rule:** every AttackLens number below is copied from a named file. Cells marked `(c)` are computed by us from
two copied numbers; the formula is given.

| Source file | Holds |
|---|---|
| `data/out/<set>/run_metrics.json` | wall time, peak RSS, rows/s, rows in/ok, bytes in, stage stats, Sigma stats |
| `data/out/<set>/ingest_accounting.json` | rows in / ok / dropped per source, drop reasons |
| `data/out/<set>/eval_scorecard.json` | accuracy (only when a ground truth exists) |
| `reports/stress/real_tiers.md`, `g10.md`, `g30.md` | machine, commit, contention, API latency, file problems |

**Hardware** (`reports/stress/g10.md`, `real_tiers.md`): Intel Core i5-13420H, 8 cores / 12 threads,
16,045 MB RAM (15.7 GiB), Windows 11, DuckDB 2.0.0, `memory_limit 5GB`. One laptop. Other agents' jobs ran on it
during every run (CPU load and free RAM at start are in the reports). Wall times include that contention.

**Code state:**

| Sets | Code | Source |
|---|---|---|
| g10, g30 | git HEAD 6fbfe3c plus uncommitted work, frozen copy `C:\alf`, no `config/sigma` | `reports/stress/g10.md`, `g30.md` |
| rt50, rt10, rt30 | git HEAD 6fbfe3c plus 117 uncommitted files, frozen copy `C:\alf2`, Sigma on | `reports/stress/real_tiers.md` |
| g1x, f1, demo | commit not recorded (`run_metrics.json` has no commit field) | `data/out/<set>/run_metrics.json` |

**Sets:**

| Set | What it is | Ground truth |
|---|---|---|
| g1x, g10, g30 | synthetic EDR/ECS JSON from the provided generator, 1 / 10 / 30 GB targets, planted attacks S1-S5 | yes |
| f1 | synthetic FortiGate key=value set, planted attacks F1-F3 | yes |
| demo | small synthetic set (`bytes_in` 210,033,604) | yes |
| rt50 (`50g.txt`) | organiser FortiGate text. True size 45,474,446 bytes, **not 50 GB** | no |
| rt10 (`firex-10G.log`) | organiser FortiGate text, 6,543,120,032 bytes | no |
| rt30 (`firex-30G.log`) | organiser FortiGate text, 19,621,285,387 bytes | no |

Organiser logs are confidential. This file holds counts, timings, byte offsets, rule ids and ATT&CK ids only.

**Limits of every number here:**
- One run per set. No median of 3. Run-to-run spread is not measured under controlled conditions.
- Example of spread: g10 total wall was 234.91 s at commit 81e47ab (`data/out/g10_81e47ab/run_metrics.json`) and
  258.526 s now, with contention in the second run (`reports/stress/g10.md`).

## 2. Throughput, wall time, memory

MB = 10^6 bytes, GB = 10^9 bytes. `MB/s (c)` = `bytes_in / total_wall_s / 10^6`.
`GB/h (c)` = `bytes_in / total_wall_s * 3600 / 10^9`. Rows/s is copied from `run_metrics.json` (`rows_per_s`).
All cells in a row come from `data/out/<set>/run_metrics.json`.

| Set | bytes_in | total_wall_s | MB/s (c) | GB/h (c) | rows/s | peak RSS MB | stage at peak | RSS under 5 GB |
|---|---|---|---|---|---|---|---|---|
| rt50 | 45,474,446 | 60.398 | 0.75 | 2.7 | 1,422.8 | 206.8 | ingest | yes |
| rt10 | 6,543,120,032 | 336.702 | 19.4 | 70.0 | 66,685.1 | 2,758.4 | ingest | yes |
| rt30 | 19,621,285,387 | 222.439 | 88.2 | 317.6 | 36,589.3 | 2,444.6 | ingest | yes |
| g10 | 10,737,733,035 | 258.526 | 41.5 | 149.5 | 50,471.3 | 2,552.9 | ingest | yes |
| g30 | 32,212,574,455 | 595.544 | 54.1 | 194.7 | 65,726.0 | 3,133.0 | detect | yes |
| g1x | 1,074,061,398 | 28.561 | 37.6 | 135.4 | 45,706.1 | 2,506.8 | not read | yes |
| f1 | 1,073,818,839 | 60.532 | 17.7 | 63.9 | 33,636.8 | 1,902.4 | not read | yes |
| demo | 210,033,604 | 64.283 | 3.27 | 11.8 | 3,970.6 | 1,467.7 | not read | yes |

Stage at peak: rt50, rt10, rt30 from `real_tiers.md` (and `run_metrics.json` `stages`); g10 and g30 from `g10.md`, `g30.md`.
"Under 5 GB" compares process peak RSS with the DuckDB cap. RSS is the whole process; the cap is DuckDB's own limit.
Both are below 5,000 MB in every row.

**Read rt10 and rt30 with their file problems (section 6).** The raw MB/s above counts corrupt bytes.

| Set | Valid bytes (offset of first corrupt data) | MB/s on valid bytes (c) | GB/h on valid bytes (c) | Valid rows per second (c) |
|---|---|---|---|---|
| rt10 | 4,815,675,121 (`real_tiers.md`) | 14.3 | 51.5 | 27,102 (`rows_ok` 9,125,382 / 336.702) |
| rt30 | 4,294,967,296 (`real_tiers.md`) | 19.3 | 69.5 | 36,589 (`rows_ok` 8,138,878 / 222.439) |

- rt10's `rows_per_s` 66,685.1 counts 13,327,641 dropped lines. Valid rows per second is 27,102.
- rt30's 88.2 MB/s counts a 15.3 GB NUL tail that is one line.

**Stage split** (`real_tiers.md`, from `run_metrics.json` `stages`):

| Stage wall s | rt50 | rt10 | rt30 |
|---|---|---|---|
| ingest | 7.214 | 172.75 | 117.445 |
| detect | 50.874 | 140.674 | 93.879 |
| total | 60.398 | 336.702 | 222.439 |

On rt50, Sigma rule loading from cache took 43.68 s (`sigma_wall_s` 46.245). The same cache loaded in 2.507 s on rt10
and 22.636 s on rt30. The cause is not measured. `real_tiers.md` lists contention and a cold file cache as possible
causes (estimate, not verified).

**API latency** (HTTP to a local uvicorn, 1 warm-up excluded, all HTTP 200):

| Set | Request | p50 ms | p95 ms | max ms | Source |
|---|---|---|---|---|---|
| g10 | 200 x `/path` over 5 incidents | 3.68 | 26.94 | 29.53 | `reports/stress/g10.md` |
| g30 | 200 x `/path` over 5 incidents | 15.65 | 17.01 | 25.40 | `reports/stress/g30.md` |
| rt10 | 200 x `/path` | 15.25 | 16.98 | 27.48 | `reports/stress/real_tiers.md` |
| rt10 | 20 x incident detail | 3.22 | 27.48 | 27.83 | `reports/stress/real_tiers.md` |
| rt10 | 20 x incident list | 3.22 | 21.62 | 27.78 | `reports/stress/real_tiers.md` |

PRD target: open one incident's path in under 500 ms (great).

## 3. Detection

### 3.1 Sets with ground truth

Source: `data/out/<set>/eval_scorecard.json`. Scores are percent.

| Measure | g1x | g10 | g30 | f1 | demo |
|---|---|---|---|---|---|
| `detection_pct` | 100.0 | 100.0 | 95.24 | **23.08** | 100.0 |
| `labels_pct` | 100.0 | 100.0 | 95.0 | 100.0 | 100.0 |
| `rebuilt_pct` | 100.0 | 100.0 | **80.0** | **0.0** | 100.0 |
| `false_alarms_strict_pct` | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `step_precision_pct` | 80.77 | not in scorecard | not in scorecard | 100.0 | 72.41 |
| `singleton_recall_pct` | 100.0 | 100.0 | 100.0 | null | 100.0 |

Counts behind them (`counts`):

| Count | g1x | g10 | g30 | f1 | demo |
|---|---|---|---|---|---|
| attacks / rebuilt | 5 / 5 | 5 / 5 | 5 / 4 | 3 / 0 | 5 / 5 |
| GT steps / matched | 21 / 21 | 21 / 21 | 21 / 20 | 13 / 3 | 21 / 21 |
| labels correct | 21 | 21 | 19 | 3 | 21 |
| predicted steps | 26 | 33 | 30 | 3 | 29 |
| incidents / unmatched | 5 / 0 | 5 / 0 | 5 / 0 | 1 / 0 | 5 / 0 |
| noise detected / detectable | 494 / 494 | 5,107 / 5,107 | 15,372 / 15,372 | 0 / 0 | 108 / 108 |

PRD targets (good / great): detection > 70 / > 90, labels > 60 / > 85, rebuilt half / all, false alarms < 30 / < 10.

- **g1x, g10, demo:** all four targets met at "great".
- **g30:** detection and labels meet "great". Rebuilt 80.0 does not (`targets.rebuilt_pct.great` is false).
  `reports/stress/g30.md` verdict is FAIL on scale invariance (g10 100 / 100 / 100 vs g30 95.24 / 95.0 / 80.0).
  Its suspected causes (not confirmed): component peeling drops the S1 brute-force step off its chain under denser
  noise; a noise alert counts as lateral-movement context and blocks a relabel on S5.
- **f1:** detection 23.08 and rebuilt 0.0 miss the PRD "good" bar. 3 of 13 planted steps matched. All 3 matched steps
  have the right label. Attacks F2 and F3 matched 0 steps. The same `run_metrics.json` shows 1,241 episodes kept and
  35,369 spilled. A link between the spill and the misses is not established here.
- **step precision below 100** (g1x 26 predicted vs 21 matched; demo 29 vs 21): extra steps in the incidents.
  What the extra steps are is not analysed here.
- 5 attacks and 21 steps is a small sample. A score of 100 on it does not show the same score on real data.
- The g1x, g10, g30, f1 and demo `run_metrics.json` files have no Sigma keys. These accuracy numbers are for the
  built-in rules only.

### 3.2 Sigma on versus off, same small synthetic set (52,739,548 bytes)

Sources: `data/out/g50m_nosigma/` and `data/out/g50m_sigma/` (`eval_scorecard.json`, `run_metrics.json`).
Commit not recorded.

| | Sigma off | Sigma on |
|---|---|---|
| `detection_pct` | 100.0 | 100.0 |
| `labels_pct` | 100.0 | 95.24 |
| `rebuilt_pct` | 100.0 | 100.0 |
| `false_alarms_strict_pct` | 0.0 | **28.57** |
| incidents / unmatched | 5 / 0 | 7 / 2 |
| `total_wall_s` | 16.995 | 31.09 |
| `peak_rss_mb` | 231.2 | 255.0 |

Sigma on added two incidents that match no planted attack on this set. The reason is not analysed here.
The g1x, g10, g30 and demo scores above were not measured with Sigma on.

### 3.3 Organiser logs: no ground truth

No `eval_scorecard.json` exists for rt50, rt10, rt30. **No accuracy number is claimed.** Incidents found are
"found", not scored. Source: `data/out/<set>/run_metrics.json`, `reports/stress/real_tiers.md`.

| | rt50 | rt10 | rt30 |
|---|---|---|---|
| rows in / ok / dropped | 85,937 / 85,936 / 1 | 22,453,023 / 9,125,382 / 13,327,641 | 8,138,881 / 8,138,878 / 3 |
| incidents | 0 | 1 | 0 |
| raw alert rows / sum of `raw_alert_count` | 2,395 / 3,773 | 59,534 / 1,476,419 | 23,773 / 1,980,442 |
| episodes kept / spilled / total | 2,382 / 0 / 2,382 | 426 / 54,159 / 54,585 | 14,390 / 0 / 14,390 |
| link edges | 1,447 | 1,273 | 51,138 |
| Sigma rules: total / compiled / running | 3,779 / 1,707 / 1,691 | same | same |
| Sigma rules applicable / fired | 112 / 1 | 143 / 1 | 112 / 1 |
| Sigma alerts after cap / dropped by cap | 37 / 0 | 1,000 / 2,906 | 1,000 / 2,568 |

- Only one Sigma rule fired, on every tier: `sigma_fa0c05b6` (T1204, SigmaHQ "Antivirus - Hacktool Signature").
- Of 3,779 Sigma rules, 1,090 are skipped for an unmapped log source and 711 for an unmapped field.
  Only 112-143 apply to FortiGate data.
- The one rt10 incident: risk 36, tactics Reconnaissance, Initial Access, Credential Access, Lateral Movement,
  techniques T1021, T1110, T1189, T1190, T1210, T1590, 10 backbone steps plus 7 in one branch, 35 episodes.
  Three backbone steps have confidence 3-10 and need human review.
- Before this run (`real_tiers.md`, section "Before", commit c76e212) rt10 produced 13 incidents. The drop to 1 is
  attributed there to the episode spill keeping 426 of 54,585 episodes (cap 25,000). That is an open issue.
- rt30 has 1 distinct alert timestamp, so every component is suppressed. This is a limit of the file.

## 4. Comparison with published claims

How to read this table:
- Left side: what the vendor or author published. Right side: our closest measured number.
- `comparable?` says yes, partly or no, with the reason. No row declares a winner.
- Derived values in the claim column are our arithmetic on their numbers, marked `(c)`.
- Every claim row was checked on its page by the research step unless marked unverified.

| Tool | Their claim | Conditions | Our closest measured number | Comparable? |
|---|---|---|---|---|
| Zircolite 4.6.0 | 13.3 GB EVTX in 30.2 s median (range 30.0-30.3); 440 MB/s (c), 1,585 GB/h (c); peak 9,158 MiB; 4,527 rules; 1,720,383 events after filter | Apple M1 Max, 10 cores, 64 GB, macOS, SSD, median of 3 after 1 warm-up. Author benchmarks own tool | g30: 32.2 GB in 595.544 s, 54.1 MB/s (c), 65,726.0 rows/s, peak RSS 3,133.0 MB | **No.** EVTX binary vs JSON/text. Warm cache, 64 GB host. Their peak RAM exceeds our 5 GB cap. Single-event Sigma matching only, no linking or path |
| Hayabusa 4.2.0 | 13.3 GB EVTX in 500.3 s median (498.2-503.2); 26.6 MB/s (c), 95.7 GB/h (c); peak 1,390 MiB; 4,674 rules | Same Zircolite benchmark and machine. Measured by a competing author | g10: 41.5 MB/s (c), 149.5 GB/h (c), peak RSS 2,552.9 MB | **No.** Different machine, format and output volume (703,920 detections incl. informational) |
| Chainsaw 2.17.1 | 13.3 GB EVTX in 183.0 s median (181.2-185.0); 72.7 MB/s (c), 261.6 GB/h (c); peak 1,176 MiB; 3,630 rules | Same Zircolite benchmark and machine. Vendor publishes no numbers | g10: 41.5 MB/s (c); g30: 54.1 MB/s (c) | **No.** Same reasons. Per-event Sigma matching only |
| Hayabusa (PR #894, 2023) | 6.1 GB EVTX in 10:42.195 (642.195 s); 9.5 MB/s (c), 34.2 GB/h (c); 7,501 events/s (c); peak 4.4 GiB; 4,817,181 events | Windows 10, 8 cores, 16 GB, SSD, laptop. Vendor PR, old version | rt10: 6.5 GB in 336.702 s, 19.4 MB/s (c) raw or 14.3 MB/s on valid bytes (c); peak RSS 2,758.4 MB | **Partly.** Closest size (6.1 vs 6.5 GB) and hardware class (8 cores, 16 GB, Windows). Still EVTX binary vs FortiGate text with a 26.4 % corrupt tail; 2023 build; rule matching only |
| Zircolite / Hayabusa / Chainsaw, small Sysmon set | 478 MB, 452,554 events: Zircolite 7.7 s / 1,200 MiB; Hayabusa 23.3 s / 749 MiB; Chainsaw 48.3 s / 378 MiB | M1 Max, 64 GB, median of 3 after warm-up. Page says startup and rule loading dominate | demo: 210 MB in 64.283 s, peak RSS 1,467.7 MB; rt50: 45 MB in 60.398 s, peak RSS 206.8 MB | **No.** Our small sets are slower per MB than our large sets. rt50 spends 43.68 s of 60.398 s loading Sigma rules. Demo cause not measured |
| Zircolite / Hayabusa / Chainsaw, alert counts | Page: "Detection totals therefore do not measure detection quality" | Each tool uses its own rules | Accuracy is reported as detection, labels, rebuilt, false alarms against ground truth (section 3.1) | **n/a.** We do not compare alert counts |
| FortiAnalyzer VM 8.0.0 | 10,000 logs/s sustained at 8 cores + 16 GB; 3,000-5,000 at 4 cores + 16 GB; 20,000 at 16 cores + 32 GB. Collector rate = analytic x 1.5 | Vendor minimum VM sizing table. Sustained 48 h with SQL storage and reporting | rt30: 36,589.3 rows/s; rt10: 27,102 valid rows/s (c); f1: 33,636.8 rows/s | **Partly. Closest on log family (FortiGate) and hardware class.** Theirs is sustained streaming with storage; ours is one batch detection pass. Not a head-to-head |
| FortiAnalyzer FAZ-300G / FAZ-810G | FAZ-300G: 100 GB/day (4.2 GB/h (c)), 2,000 analytic / 3,000 collector logs/s. FAZ-810G: 200 GB/day, 4,000 / 6,000 logs/s | Datasheet FAZ-DAT-R88-20260715. Sustained 48 h without degradation | Same as the row above | **Partly.** Same log family. Different unit (sustained rate vs batch pass) and hardware |
| Splunk Enterprise | Up to 300 GB/day per indexer with search load; 12.5 GB/h (c), 3.47 MB/s (c) | Minimum reference indexer: 12 physical cores (24 vCPU) + 12 GB RAM. Guideline | Batch: 14.3-88.2 MB/s across rt10, rt30, g10, g30, g1x (section 2) | **No.** Continuous indexing on a server vs batch detection. Indexing is not detection. Their minimum has more cores than our 8 |
| Splunk Enterprise Security | 300 GB/day on 3 indexers with 20 detections; 100 GB/day per indexer (c) = 4.2 GB/h (c) | Each indexer 16 cores + 32 GB. Cluster | Same as above | **No.** Cluster, continuous load, 20 detections |
| Splunk ES (Hurricane Labs, independent) | 75-100 GB/day per indexer for ES | Consultancy rule of thumb, 2018 byline (page metadata conflicts) | Same as above | **No.** Old guidance, continuous server workload |
| Splunk Security Content | 2,207 detections, 367 analytic stories (page fetched 2026-10-31) | All data sources | 41 built-in rule ids (keys of `detect.alerts_per_rule` in `data/out/g1x/run_metrics.json`); Sigma 1,691 running, 112-143 applicable to FortiGate, 1 fired (rt tiers) | **No.** Library breadth vs one dataset. Compare ATT&CK tactic coverage, not counts |
| Elastic Security | 1,100+ prebuilt rules, 760+ SIEM (2023 blog) | Multi-source library | Same as above | **No.** Library size, dated |
| Elasticsearch (Rally `http_logs`) | Mean 175,950 docs/s, median 166,383 | 3 nodes, 48 vCPU, GCP e2-standard-16, indexing only. Vendor says it is not a reference point | Max rows/s: 66,685.1 (rt10, counts dropped lines) | **No.** Indexing only, 3-node cluster, JSON HTTP logs. Vendor disclaims use as a reference |
| Wazuh | Default agent send rate 500 EPS, queue 5,000 events | Per-agent throttle, not server capacity | Not applicable | **No.** Throttle, not throughput |
| Wazuh 4.12.0 | 54,547 events in 320 s (170 EPS (c)); analysisd 245.29 % CPU | 5 cores of i7-10750H, 20 GB, Ubuntu 24.04. Observed load, not a maximum | Not applicable | **No.** Observed load on a streaming SIEM, not its limit |
| Wazuh quickstart | 1-25 agents: 4 vCPU / 8 GiB; 26-100 agents: 8 vCPU / 8 GiB | Sized by agent count | Not applicable | **No.** Sized by agents, not GB or EPS |
| Velociraptor | t2.large (2 cores, 8 GB) for up to 10k endpoints; CPU 160-180 % in a hunt | Endpoint collection platform | Not applicable | **No.** No log-scan throughput published |
| Microsoft Sentinel (NRT rules) | Run every 1 minute, 2-minute built-in delay, max 50 NRT rules; scheduled rules default 5-minute look-back | Cloud SIEM, Learn doc updated 2026-06-28 | Live mode latency: **not measured yet** | **No** until live latency is measured. Latency, not batch throughput |
| Azure Monitor Logs (Sentinel store) | Average ingestion latency under 10 s; agent upload adds 30 s to 2 min | Cloud streaming ingest | Live mode latency: **not measured yet** | **No.** Cloud ingest latency |
| Google SecOps | Single-event rules: under 5 min after arrival. Multi-event rules, window up to 48 h: hourly (every 10 min for windows under 1 h) | Docs updated 2026-10-28 | Live mode latency: **not measured yet** | **No** until measured. Shows multi-event detection in a cloud SIEM runs on a schedule |
| Google SecOps (burst limits) | 3-10 MBps (100 TB/yr tier) up to 0.96-2.86 GBps (30 PB tier), enforced per 5 minutes | Contracted quota. Table cells were misaligned in extraction, so tier edges are partly unverified | Not applicable | **No.** Licence quota, not measured speed |
| SigmaHQ | More than 3,000 rules | Repo README | 3,779 rule files loaded in our run (`sigma_rules_total`) | **Yes** for rule count (same rule set family). Mostly Windows/EDR rules; 112-143 apply to FortiGate |
| sigma-cli / pySigma | No performance figures. Converts rules only | README | Not applicable | **No.** Does not scan logs |

**Claims excluded or unverified** (the research step could not confirm them on the page):
- Hayabusa README "up to 5x faster": not found on the README. Not used. The README only says "multi-threaded".
- Chainsaw README: "Lightning fast", no figures. Not used as a number.
- Splunk mid-range tier "16 cores / 12 GB" from a search summary was wrong. The page says 24 cores + 64 GB.
- Wazuh "158 % CPU" from a search summary was wrong. The page says 245.29 %.
- Microsoft "20 s to 3 min" ingestion latency from older docs: seen only in search snippets, not on the current page.
- Google SecOps larger burst tiers and a "20 MBps to 2.6 GBps" snippet: not verified.
- FortiAnalyzer larger models (FAZ-1000G and up): rows misaligned in PDF extraction. Not used.
- Wazuh: no official maximum server EPS found.

**Sources**

| Tool | URL |
|---|---|
| Zircolite, Hayabusa, Chainsaw benchmark | https://github.com/wagga40/Zircolite/blob/master/docs/Benchmark.md |
| Hayabusa PR #894 | https://github.com/Yamato-Security/hayabusa/pull/894 |
| Hayabusa README | https://github.com/Yamato-Security/hayabusa |
| Chainsaw README | https://github.com/WithSecureLabs/chainsaw |
| Splunk indexer capacity | https://help.splunk.com/en/splunk-enterprise/get-started/deployment-capacity-manual/10.2/performance-reference/summary-of-performance-recommendations |
| Splunk reference hardware | https://help.splunk.com/en/splunk-enterprise/get-started/deployment-capacity-manual/10.0/performance-reference/reference-hardware |
| Splunk ES performance | https://help.splunk.com/en/splunk-enterprise-security-8/install/8.3/planning/performance-reference-for-splunk-enterprise-security |
| Hurricane Labs | https://www.hurricanelabs.com/blog/splunking-responsibly-part-1-considerations-for-managing-limited-system-resources |
| Splunk Security Content | https://research.splunk.com/ |
| Elasticsearch Rally | https://www.elastic.co/blog/how-to-interpret-ingest-only-tracks-rally-elasticsearch |
| Elastic prebuilt rules | https://www.elastic.co/blog/security-teams-prebuilt-protections |
| Sentinel NRT rules | https://learn.microsoft.com/en-us/azure/sentinel/near-real-time-rules |
| Sentinel ingestion delay | https://learn.microsoft.com/azure/sentinel/ingestion-delay |
| Azure Monitor ingestion time | https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-ingestion-time |
| Google SecOps rule frequency | https://docs.cloud.google.com/chronicle/docs/detection/rule-execution-frequency |
| Google SecOps burst limits | https://docs.cloud.google.com/chronicle/docs/ingestion/burst-limits |
| FortiAnalyzer VM sizing | https://docs.fortinet.com/document/fortianalyzer-private-cloud/8.0.0/openstack-administration-guide/583600 |
| FortiAnalyzer datasheet | https://www.fortinet.com/content/dam/fortinet/assets/data-sheets/fortianalyzer.pdf |
| Wazuh anti-flooding | https://documentation.wazuh.com/current/user-manual/agent/agent-management/antiflooding.html |
| Wazuh resource test | https://wazuh.com/?p=27340 |
| Wazuh quickstart | https://documentation.wazuh.com/current/quickstart.html |
| Velociraptor sizing | https://docs.velociraptor.app/docs/deployment/resources/ |
| SigmaHQ | https://github.com/SigmaHQ/sigma |
| sigma-cli | https://github.com/SigmaHQ/sigma-cli |

**What a fair head-to-head needs**

| Needed | Why | Status |
|---|---|---|
| Same input file for every tool | Format and size change the work | not measured yet. We have no EVTX ingest measured; they do not read FortiGate text as measured here |
| Same machine, nothing else running | Our runs shared the laptop | not measured yet |
| Same rule set (a named SigmaHQ commit) | Rule count changes the time | not measured yet |
| Median of 3 passes after 1 warm-up, as the Zircolite page does | Removes cold-cache and startup noise | not measured yet |
| Whole-process-tree RSS sampled at a fixed interval | Same memory definition | not measured yet. Their page samples every 20 ms. Our sampling method is not stated in the files read |
| Ground truth for accuracy, not alert counts | The Zircolite page says counts do not measure quality | We have it on synthetic sets only |

## 5. Benchmarks we set

Targets come from the published claims and the PRD. Status is from our measured files.
"Met" means the measured number clears the target. It does not mean the claim and our run are comparable.

| # | Target | Derived from | Our number | Status |
|---|---|---|---|---|
| B1 | Total wall under 1 h at 10 GB and 30 GB tiers | PRD "great" | g10 258.526 s; g30 595.544 s; rt10 336.702 s; rt30 222.439 s | **met** |
| B2 | Total wall under 1 h at 50 GB | PRD "great" | no 50 GB set has been run (`50g.txt` is 45,474,446 bytes) | **not measured yet** |
| B3 | Peak RSS under 8 GB | PRD "great" | max 3,133.0 MB (g30) | **met** |
| B4 | Peak RSS under 5 GB (our DuckDB cap) and under Zircolite's 9,158 MiB | Zircolite page, own design | max 3,133.0 MB | **met** |
| B5 | Peak RSS at or under 4.4 GiB on a 16 GB laptop | Hayabusa PR #894 | rt10 2,758.4 MB | **met** |
| B6 | At least 34.2 GB/h on an 8-core 16 GB laptop | Hayabusa PR #894 (c) | g10 149.5; g30 194.7; rt10 70.0 raw, 51.5 on valid bytes | **met** |
| B7 | At least 10,000 rows/s on an 8-core 16 GB machine, inputs of 1 GB and up | FortiAnalyzer VM sizing | f1 33,636.8; rt10 27,102 valid; g1x 45,706.1; g10 50,471.3; g30 65,726.0; rt30 36,589.3 | **met** for 1 GB and up |
| B8 | At least 10,000 rows/s on inputs under 100 MB | FortiAnalyzer VM sizing | rt50 1,422.8; demo 3,970.6 (demo is 210 MB) | **not met.** Fixed costs dominate. rt50: Sigma load 43.68 s of 60.398 s |
| B9 | Batch rate of at least 3.47 MB/s (Splunk 300 GB/day) | Splunk indexer guideline (c) | min 14.3 MB/s (rt10, valid bytes) among 1 GB+ sets | **met for batch.** Sustained live ingest: **not measured yet** |
| B10 | Open one incident's path in under 500 ms | PRD "great" | p95 26.94 ms (g10), 17.01 ms (g30), 16.98 ms (rt10) | **met** |
| B11 | Detection above 90, labels above 85, rebuilt all, false alarms below 10 | PRD "great" | g1x, g10, demo met. g30 rebuilt 80.0. f1 detection 23.08, rebuilt 0.0 | **partly met** |
| B12 | Accuracy on organiser logs | PRD | no ground truth | **not measured yet** |
| B13 | Accuracy unchanged from 10 GB to 30 GB (within 1 point) | `reports/stress/g30.md` check | 100 / 100 / 100 vs 95.24 / 95.0 / 80.0 | **not met** |
| B14 | Live mode: new log line updates the path within seconds | PRD B-5; Sentinel NRT about 1 min plus 2 min delay; Google SecOps single-event under 5 min | no latency measured in the files read | **not measured yet** |
| B15 | Sigma on with strict false alarms still under 10 | PRD "great" | g50m_sigma 28.57 (52.7 MB set) | **not met** on that set |
| B16 | Head-to-head with one other tool on the same file and machine | section 4 | none run | **not measured yet** |

## 6. Limitations and data quality of the organiser files

Source for all lines: `reports/stress/real_tiers.md` (offset-only scans, no content read out).

**rt10, `firex-10G.log` (6,543,120,032 bytes)**
- First non-UTF-8 line starts at byte 4,815,675,121 (73.6 % into the file). The binary tail is 1,727,444,911 bytes (26.4 %).
- First NUL byte at 4,815,675,445. An earlier report said 4,815,675,419, a 26-byte difference between two scans.
- 13,327,641 of 22,453,023 lines dropped (59.36 %): `decode_error` 13,187,868 and `unparseable_line` 139,773.
- `decode_error` is not counted line by line. It is `rows_in - rows_written` after the `line_too_long` count.
  It is logged with a reason, so no drop above 0.1 % is unexplained. It is a residual, not an observation.
- An independent scan found 9,125,382 valid key=value lines, equal to `rows_ok`. No valid line was lost.
- Time spread: 5,277,139 lines (57.83 %) share one `eventtime` second. 599,505 distinct seconds in total.
  Only the first part of the file has real time spread.
- Episodes: 54,585 found, cap 25,000, only 426 kept and 54,159 spilled. In spill mode Stage 2.5 keeps only episodes
  near a seed (277 seeds). This is an open issue (owner: backend-builder).

**rt30, `firex-30G.log` (19,621,285,387 bytes)**
- NUL padding runs from byte 4,294,967,296 (2^32) to the end: 15,326,318,091 bytes (78.1 %).
  Real content is the first 4 GiB.
- A second NUL run of 61,941 bytes sits inside a line.
- The 15.3 GB tail has no line break. It is booked as 1 `line_too_long`. The earlier run booked it as `decode_error`.
- All 8,138,878 valid lines share 1 `eventtime` second. A time-ordered path cannot be built.
  Result: 0 incidents, 1,389 components all suppressed (1,205 low confidence, 184 fewer than 2 tactics).
  This is a limit of the data. It is not claimed as a code bug.
- Valid lines found by scan equal `rows_ok`: 8,138,878.

**rt50, `50g.txt` (45,474,446 bytes)**
- The file is 43.4 MiB, not 50 GB. No 50 GB tier has been measured.
- 1 dropped line (the first line is a URL, not key=value). 85,936 valid lines, 5,454 distinct `eventtime` seconds.
- 0 incidents; 1,276 components all suppressed.

**Run conditions**
- Free RAM at tier start (rt50, rt10, rt30): 3,086, 2,534, 4,251 MB. Free RAM was below the 5 GB cap on all three.
- CPU load at start: 49, 28, 31 %. Fast-suite pytest runs and dev servers ran on the same machine.
- DuckDB spill directory: 0 bytes at peak on all three tiers (sampled every 5 s). g10 and g30: not recorded.
- The `C:\alf2` snapshot fast suite: 560 passed, 2 skipped, 3 xfailed, 2 failed, 91 errors.
  Every failure is a missing file outside `backend/` (`frontend/` and `tools/` were not in the snapshot).
  The `C:\alf` snapshot (g10, g30): 728 passed, 2 skipped, 3 xfailed, 6 failed, 38 errors, all from one missing
  frontend mock file.
- Earlier overwritten runs: `data/out/t10` and `data/out/t30` were overwritten by a later run and no longer match
  the "before" figures in `real_tiers.md`.

**Open issues that affect these numbers** (`real_tiers.md`)
- Sigma rule `sigma_fa0c05b6` hits its 1,000-alert cap: 74 % of its matches discarded on rt10, 72 % on rt30.
  The overflow is counted in `sigma_alerts_capped_by_rule`, not lost silently.
- Sigma cache load time varies 2.507 s to 43.68 s on the same file. Cause not measured.
- Only 1 of 1,691 running Sigma rules fires on the organiser data.
