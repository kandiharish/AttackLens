# Live vendor tests: AttackLens connectors and sinks against real software in Docker

Status (2026-11-01 04:30 IST): **harness written and verified offline; NO container was started, NO image pulled.**
The orchestrator held all containers while the 30G / 50G benchmarks and other sessions' pipeline jobs ran. Gate before
EACH container start (now built into `livectl.py gate`): no python process running `attacklens.run` /
`attacklens.live`, and >= 6 GB free RAM (`AL_LIVE_MIN_FREE_GB`). While a vendor runs, a watchdog runs
`docker compose down -v` if free RAM drops below 2 GB (`AL_LIVE_WATCHDOG_GB`) and records `stopped_low_ram`.
Gate checked every 2–3 min from 01:55 to 03:47 IST: never open. Free RAM peaked at 2.9 GB (mostly 0.4–2.7 GB), and
`attacklens.run` processes (n30 benchmark, then other sessions' QA CLI tests) were running most of the time.
Every vendor row below is therefore **not run**. Fill this file from the run (see "Run").

Until a row says "pass" here, the earlier DEVELOPMENT.md §8b statement still holds: the connectors are verified
against the local mock SIEM only.

## Run (one command per vendor, one vendor at a time)
```
# 0. preconditions (prints the reason when not ready: Docker, free RAM / disk, another vendor up)
.venv/Scripts/python tools/live/livectl.py gate splunk
# 1. each command: gate -> pull if missing -> compose up -> setup + seed -> checks -> docker compose down -v
.venv/Scripts/python -m pytest backend/tests/live -m live -k splunk  -v
.venv/Scripts/python -m pytest backend/tests/live -m live -k elastic -v
.venv/Scripts/python -m pytest backend/tests/live -m live -k syslog  -v
.venv/Scripts/python -m pip install -e "backend[cloud]"     # boto3, only for the S3 check
.venv/Scripts/python -m pytest backend/tests/live -m live -k s3      -v
# 2. results table (last run per vendor / check) to paste below
.venv/Scripts/python tools/live/report.py
# 3. remove the images pulled for this
.venv/Scripts/python tools/live/livectl.py clean
```
- `AL_LIVE_KEEP=1` keeps the container after the run (debugging); then `livectl.py down <vendor>`.
- `AL_LIVE_FORCE=1` skips the free-RAM check only.
- The fast suite never starts a container: `live` tests are deselected unless `-m` names `live` (or `RUN_LIVE=1`),
  see `backend/tests/conftest.py`.

## Rules the harness enforces
| Rule | How |
|---|---|
| Loopback only | every `ports:` entry is `127.0.0.1:<free port>:<container port>`; checked by `test_live_harness.py` |
| Throwaway secrets | Splunk / Elastic passwords from `secrets.token_urlsafe`, passed as env vars to `docker compose`, held in memory only; tokens / API keys created at run time; checked that no secret value reaches spool, state, status, logs |
| Memory limits | Splunk `mem_limit: 3g`; Elasticsearch `-Xms1g -Xmx1g`, `mem_limit: 2g`; rsyslog 256m; LocalStack 1g |
| One vendor at a time | one compose project per test module; `gate` refuses while another `al-live-*` project runs; `down -v` in the fixture's `finally` |
| Seed and count independently | `tools/live/*_seed.py` + `vhttp.py` (stdlib), never the product's `httpc` / connectors |
| Generated files | certs, rsyslog.conf, results under `data/live/` (git-ignored) |

## Targets, steps, checks
Image tag + digest, pulled vs seeded counts and timings come from `data/live/results/*.jsonl` (`tools/live/report.py`).

### 1. Splunk (`splunk/splunk:latest`, General Terms accepted for local testing by the user) — NOT RUN
Steps (fixture `test_live_splunk.py::splunk`): throwaway CA + server cert (SAN 127.0.0.1) mounted as app
`attacklens_tls` (splunkd 8089 and HEC 8088 serve it) -> REST: indexes `attacklens`, `attacklens_sink`; token auth
on; JWT auth token for `admin`; HEC on; HEC tokens `al_live_noack` (useACK=0) and `al_live_ack` (useACK=1) -> 499 ECS
events via HEC with explicit `time` (now-50 min .. now-8 min, 5 s apart; seq 250 has seq 249's exact ms; every 100th
carries `threat` / `labels_extra`) -> wait until Splunk counts 499.
| Check | Test | Result | Pulled / seeded | Time |
|---|---|---|---|---|
| splunkd serves the test CA's cert | `test_splunk_served_cert_is_the_test_ca` | not run | | |
| PUT settings + secret -> POST test ok -> POST start -> spool -> stop; 499 + 1 late-indexed event (dated 5 min before the checkpoint, indexed after the first pull); every seq exactly once; pulled = written + skipped + failed, failed 0; labels stripped; no secret in outputs | `test_splunk_api_pull_equals_seed_incl_tie_and_late_event` | not run | | |
| spool -> Stage 0-1: rows in = rows ok = spool rows | `test_splunk_spool_ingests_without_loss` | not run | | |
| bad token -> `auth_failed`, "Splunk rejected the credentials (HTTP 401): check the key, token or secret." | `test_splunk_bad_token_gives_actionable_401` | not run | | |
| self-signed TLS: verify on, no CA -> `tls_error` "not trusted ... CA file"; with ca_file -> ok; verify off -> ok | `test_splunk_self_signed_tls[*]` | not run | | |
| HEC sink via API (PUT + test + enable) -> `publish_all` -> 3 incidents searchable, ack off and ack on | `test_splunk_hec_sink_delivers[ack_off\|ack_on]` | not run | | |
| HEC sink, verify on + ca_file (config key) | `test_splunk_hec_sink_verifies_with_ca_file` | not run | | |

### 2. Elasticsearch 8.x (`docker.elastic.co/elasticsearch/elasticsearch:8.19.5`, override `ES_IMAGE`) — NOT RUN
Steps: single node, security on (auto-config), HTTPS, basic licence, heap 1g -> copy `http_ca.crt` out of the
container -> API keys `al_live_reader` (read on `logs-attacklens-*`) and `al_live_writer` (create_doc + auto_configure
on `logs-attacklens.incidents-*`; index + auto_configure on `attacklens-incidents-live*`) = the catalogs' documented
minimum -> 1234 ECS docs into data stream `logs-attacklens-default` with bulk `create` (seq 400..649 share one
@timestamp: with page_size 100 the PIT paging crosses two page boundaries inside the tie).
| Check | Test | Result | Pulled / seeded | Time |
|---|---|---|---|---|
| API pull with ca_file = http_ca.crt; PIT used (node stats `point_in_time_total` up, `point_in_time_current` back to 0, no "PIT unavailable" log); >= 13 page queries; every seq exactly once; accounted; labels stripped | `test_elastic_api_pull_pit_paging_equals_seed` | not run | | |
| verify on without CA -> `tls_error` | `test_elastic_tls_verify_without_ca_fails_actionably` | not run | | |
| bad API key -> `auth_failed` HTTP 401 | `test_elastic_bad_api_key_gives_actionable_401` | not run | | |
| elastic_bulk -> data stream `logs-attacklens.incidents-default`: POST test ok with the minimal key, 3 sent, data stream exists, 3 docs; re-send counts as delivered, still 3 docs | `test_elastic_bulk_sink_writes_to_data_stream` | not run (expected FAIL at POST test: see bug 1) | | |
| elastic_bulk -> plain index: index op overwrites an updated incident | `test_elastic_bulk_sink_plain_index_upsert` | not run | | |
| ES serves the auto-generated CA | `test_elastic_peer_cert_is_autogenerated_ca` | not run | | |

### 3. Syslog (`rsyslog/syslog_appliance_alpine:latest`) — NOT RUN
Steps: AttackLens listener (`connectors.syslog`, events mode) on 127.0.0.1:<P> UDP + TCP, started first -> rsyslog
relay (imtcp in on a loopback port) forwards to `host.docker.internal:<P>` by program name: `al_udp` UDP,
`al_tcp` TCP `TCP_Framing="traditional"`, `al_octet` TCP `TCP_Framing="octet-counted"` (RFC 6587) -> 300 lines per
transport.
| Check | Test | Result | Sent / received / written | Time |
|---|---|---|---|---|
| UDP | `test_rsyslog_forwarding_counts[udp]` | not run | | |
| TCP newline framing | `test_rsyslog_forwarding_counts[tcp]` | not run | | |
| TCP octet counting | `test_rsyslog_forwarding_counts[octet]` | not run | | |
Risk to check on the first run: Docker Desktop must deliver `host.docker.internal` UDP to a listener bound to the
host's 127.0.0.1. If UDP shows 0 received and TCP passes, it is the Docker network path, not the connector
(`AL_LIVE_SYSLOG_BIND` lets you try another bind address on a trusted machine).

### 4. AWS CloudTrail S3 mode (`localstack/localstack:4.4`, S3 only) — NOT RUN
Steps: bucket `al-live-cloudtrail`; `AWSLogs/123456789012/CloudTrail/us-east-1/<y>/<m>/<d>/`: three `.json.gz` +
one plain `.json` (45 records) and one `CloudTrail-Digest` file (no Records). Test config `ingest_lag: 0s` (the
default 5 min lag would hold freshly written objects back one cycle). Needs boto3 (`backend[cloud]`, not installed
in the venv on 2026-11-01).
| Check | Test | Result | Pulled / seeded | Time |
|---|---|---|---|---|
| connector, dated prefix and `AWSLogs/` root (digest yields 0 rows, no error): 45 = 45, unique eventIDs | `test_s3_mode_connector_pulls_every_record[*]` | not run | | |
| UI `endpoint_url` reaches the S3 client, then API test / start / spool / stop | `test_s3_mode_endpoint_url_from_the_ui_reaches_s3` | not run (expected FAIL: bug 2) | | |

## Bugs found while building the harness (failing tests written, fixes belong to backend-builder)
1. **Sink connection test ignored `ca_file`** — FIXED during this session (by the owner, in parallel).
   At 02:16 IST `connect.py` `_probe_sink` passed only `verify_tls` for splunk_hec / elastic_bulk, while the sinks
   send with `ca_file`: a sink that delivers over a private CA was reported "certificate not trusted".
   Regression tests: `backend/tests/live/test_live_offline_tls.py::test_sink_connection_test_honours_ca_file[splunk_hec|elastic_bulk]`
   (failed at 02:16, pass at 04:25), control `..._without_ca_is_untrusted` passes. Remaining gap: neither sink's
   catalog has a `ca_file` field, so from the UI a private-CA sink still needs verification off.
2. **S3 mode ignores the UI `endpoint_url`** — `backend/attacklens/connectors/aws_cloudtrail.py:138` uses
   `endpoint_url` for the `cloudtrail` client only; S3 reads `s3_endpoint_url`, which is not in the catalog. From the
   Integrations page an S3 VPC endpoint / LocalStack / MinIO cannot be set. Failing test (needs LocalStack + boto3):
   `test_live_aws_s3.py::test_s3_mode_endpoint_url_from_the_ui_reaches_s3` (asserts before any network call).
3. To confirm on the first Splunk run: the HEC sink's connection test (`connect.py` `_probe_sink`) posts an empty body
   without `X-Splunk-Request-Channel`; with indexer acknowledgement on, Splunk may answer 400 "Data channel is
   missing" (code 10) instead of "No data", which the probe treats as a failure. Covered by
   `test_splunk_hec_sink_delivers[ack_on]`. The sink itself sends the channel header but never polls
   `/services/collector/ack`, so with ack on a "sent" incident is not confirmed as indexed.

## Not testable locally
| Target | Why |
|---|---|
| Microsoft Sentinel / Azure Monitor (Log Analytics query API, Entra ID sign-in) | no local emulator; needs an Azure tenant + workspace |
| GCP Cloud Logging (entries.list, service-account JWT) | no local emulator for the Logging API |
| AWS CloudTrail LookupEvents | not in LocalStack community; needs a real AWS account |
Those connectors stay verified against `tools/mock_siem.py` only (`backend/tests/test_e2e_integrations.py`).
