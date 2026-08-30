# Swift

Filter the garbage. Keep what works.

Swift collects public proxy configs, tests them, and keeps the ones that actually work.

There are already plenty of subscriptions with tens of thousands of entries. Swift is for
people who would rather import a small list and have a reasonable chance that its entries can
actually carry traffic.

## Subscriptions

### Main

The normal list. It contains at most 200 configs.

`https://sub.femboypig.ru/main.txt`

There is no minimum. If 21 configs meet the verification criteria, the file contains exactly 21.

### White

Configs intended for the Russian whitelist/restricted-network case. Swift starts with configs
associated with whitelisting and checks independent community evidence: the resolved endpoint IP
(against published CIDR ranges) and the TLS SNI visible to the operator.

`https://sub.femboypig.ru/white.txt`

White no longer relies only on cloud testing or TCP/TLS reachability before publication. Every
candidate must pass the same sustained actual-traffic verification from the Russian network probe.
This list is also capped at 200. A config passing the normal test does not make it eligible for White.

### All

Every unique candidate from the current run that passed both proxy test rounds and the throughput
floor in cloud testing.

`https://sub.femboypig.ru/all.txt`

## Telegram proxies

Swift also maintains MTProto proxy lists for Telegram:

- `https://sub.femboypig.ru/Telegram/all.txt` contains every proxy that passed the current
  Telegram check at least twice out of three attempts.
- `https://sub.femboypig.ru/Telegram/stable.txt` is capped at 50 and requires three successful
  workflow runs before a new proxy can enter it.
- `https://sub.femboypig.ru/Telegram/fastest.txt` contains up to 20 currently working proxies,
  ordered by median Telegram RTT with penalties for a bad tail and jitter.

The checker doesn't stop at DNS or an open TCP port. It opens the MTProxy transport, sends an
unauthenticated `req_pq_multi` request, and accepts the proxy only after Telegram returns a valid
`resPQ` with the same nonce. Raw 16-byte, `dd` secure, and `ee` FakeTLS secrets are supported.
Unknown extended secret formats are reported as unsupported instead of being counted as dead.

MTProto history is kept separately in `data/telegram-history.json`. Stable proxies survive two
transient failed runs and are removed on the third. A sudden collapse keeps the previous files
for two valid confirmation runs; broken source downloads, an incomplete run, or a failed direct
Telegram control check do not wipe them.

`Telegram/status.json` contains current counts, source results, failure reasons, and the proxies
selected for the optional channel message. Set `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, and
`TELEGRAM_MESSAGE_ID` as GitHub Actions secrets to edit one existing message after each run. If
any value is missing, this step is skipped. Swift never creates a new message on its own.

## Karing and Happ

The universal files are plain URI lists. Karing documents standard subscription formats and the
protocols Swift emits. Happ documents standard URL subscriptions containing URI lines, but its
public protocol list does not include TUIC.

For Happ, use these versions. They omit TUIC and include Happ's profile metadata:

`https://sub.femboypig.ru/happ/main.txt`

`https://sub.femboypig.ru/happ/white.txt`

Keeping `#profile-title`, `#profile-update-interval`, and `#profile-web-page-url` out of the
universal files avoids depending on how other clients treat Happ-specific lines.

Compatibility was checked against the current [Karing documentation](https://github.com/KaringX/karing/blob/main/README.md),
[Karing FAQ](https://github.com/KaringX/karing-docu/blob/main/docs/faq.md),
[Happ subscription documentation](https://github.com/HappDev/happ_su/blob/main/faq/adding-configuration-subscription.md),
and [Happ profile metadata documentation](https://github.com/HappDev/happ_su/blob/main/dev-docs/app-management.md).

Swift currently parses and tests:

- VLESS, including Reality
- VMess
- Trojan
- Shadowsocks without external plugins
- Hysteria2
- Hysteria v1
- TUIC

The stock sing-box core does not support every Xray transport. Swift rejects configs it cannot
represent faithfully, including XHTTP, mKCP, and TCP header obfuscation. A parsed-but-changed
config is worse than an honest rejection.

## What the test does

The pipeline runs on a scheduled cadence (every 30 minutes):

1. **Fetch & Normalize**: Fetch each source independently, extract supported URIs, validate parameters,
   and calculate canonical fingerprints.
2. **Deduplication**: Merge duplicates while preserving source provenance metadata. Source reputation
   does not grant scoring bonuses; every candidate is evaluated strictly on measured performance.
3. **White Evidence Check**: For White, compare the resolved endpoint IP against community CIDR whitelists
   and verify operator-visible TLS SNI.
4. **Candidate Selection**: Pick a bounded candidate budget (up to 800 for Main, 250 for White). Active
   and strong veteran configs come first; unmeasured and older configs receive a rotating discovery quota.
   Being untested in a given run simply means waiting in the queue, not that the node is dead.
5. **DNS & Security Filtering**: Resolve endpoints and reject private, link-local, loopback, and cloud metadata IPs.
6. **Cloud Traffic Testing**: Execute real traffic tests on GitHub Actions runners. Each config runs inside an
   isolated sing-box core with a temporary local SOCKS inbound, performing multi-target HTTPS probes and payload
   download testing.
7. **History & Scoring**: Record latency, jitter, throughput, and availability into compact historical observation
   windows. A newly discovered config requires at least two consecutive successful observations before promotion.
8. **Shortlisting & Diversity**: Select the top-ranked candidates (up to 200 for Main and 200 for White) applying
   soft diversity caps across endpoints, /24 IPv4 (or /48 IPv6) subnets, and ASNs.
9. **Russian Sustained Live Verification**: Top Main and White candidates are verified directly from inside
   Russia via a dedicated self-hosted Mac mini runner bound to the physical network interface (`wlan0`).
   Each unique candidate is evaluated through a sustained traffic engine:
   - At least 2 of 3 independent neutral HTTPS reachability probes must succeed;
   - Two independent sequential rounds of 256 KiB real payload downloads;
   - Both download rounds must complete successfully;
   - Minimum throughput quality floor: $\min(R1, R2) \ge 64\text{ KiB/s}$;
   - Continuous stall detection (`--speed-limit 16384 --speed-time 3`).
   A simple TCP handshake or short burst is not enough; proxies that stall or degrade under sustained transfer are rejected.
10. **Main + White Deduplication on Mac**: If a config belongs to both Main and White, the verification runner
    tests it exactly once by fingerprint and applies the resulting pass/fail state to both subscription outputs.
11. **Service Diagnostics**: Passing nodes undergo lightweight reachability checks against Yandex, VK, Ozon,
    and the Telegram Bot API (`telegram_api`, testing HTTPS reachability to `api.telegram.org`, distinct from MTProto).
    These checks are diagnostic metrics recorded in `stats.json` and are not hard blockers for generic Main publishing.
12. **Synchronous Publishing**: Filter and write both plain and Happ outputs consistently, update `stats.json`,
    and deploy subscriptions to GitHub Pages.

## GeoIP and RU Classification

Country labels in subscriptions (`🇫🇮 FI · 001`, `🇷🇺 RU · 001`) are determined strictly by the actual resolved
endpoint GeoIP observed during traffic tests.

Swift does not infer Russian egress from `.ru` hostnames, source names, or upstream remarks. An entry labeled
as `RU Hysteria2` strictly denotes a confirmed endpoint with GeoIP == `RU`.

## Scoring and history

History is a compact JSON file with the last 16 observations per config and per list. Main and
White do not share health observations.

The Main score is 0–100:

- 34% weighted historical availability
- 21% the last three runs
- 14% median latency
- 8% p95 latency
- 8% jitter
- 10% small-download throughput
- 5% time since the last successful observation

The most recent history has more weight. Latency has a broad curve rather than a race to the
smallest number. A steady 65 ms config should beat one that sometimes answers in 25 ms but times
out or stalls regularly.

White uses a separate score: 50% historical availability, 30% recent health, 10% throughput,
and 10% freshness. GitHub latency is deliberately absent. A restricted-network config can be
slow or inconsistent from an Actions runner and still be useful from the network it was built
for.

An active config gets one failed-run grace period if its history is strong. Two consecutive failed
observations make it dead.

## Failure handling and Outage Protection

Swift does not publish before the complete run has been assessed. It retains last-known-good (LKG)
subscriptions when:

- every source fails;
- both the primary whitelist CIDR feed and its fallback fail validation or download;
- the direct target preflight cannot reach at least two targets;
- most sing-box processes fail to start;
- the verification runner experiences an infrastructure-level failure (e.g. mass core timeouts or local network outage).

If an infrastructure failure occurs during Mac verification, the runner logs a warning and preserves
the previous valid subscriptions rather than zeroing out outputs. Individual proxy failures (e.g. stalled
or blocked nodes) under a healthy checker are dropped normally.

*Note on runner availability*: If the self-hosted runner machine is completely offline at the GitHub Actions
workflow level, the workflow job does not proceed to deployment, preserving the previously deployed GitHub Pages site.

## Sources

The default config fetches candidates from multiple community repositories:

- [Akres/VPN](https://gitverse.ru/Akres/VPN), using its bounded gRPC feed for Main and `bwl` feed for White;
- [vpnsvpns/Prihs](https://github.com/vpnsvpns/Prihs) as an hourly GitHub-hosted fallback for the same Akres feeds;
- [RKPchannel/RKP_bypass_configs](https://github.com/RKPchannel/RKP_bypass_configs), using its normal and whitelist feeds;
- [zieng2/wl](https://github.com/zieng2/wl), using its hourly `vless_universal.txt` feed for White;
- [igareck/vpn-configs-for-russia](https://github.com/igareck/vpn-configs-for-russia), using its mobile and full CIDR lists for White, and its international/black feeds for Main;
- [0xRadikal/configs-collector](https://github.com/0xRadikal/configs-collector), using verified configs for Main;
- [VovaplusEXP/Secure-configs](https://github.com/VovaplusEXP/Secure-configs), using secure VLESS feeds for Main;
- [FLEXIY0/matryoshka](https://github.com/FLEXIY0/matryoshka), using whitelist configs for Main and White;
- [AirLinkVPN](https://github.com/AirLinkVPN1/AirLinkVPN),
  [bywarm/rser](https://gitverse.ru/bywarm/rser),
  [AetrisVPN](https://github.com/flaafix/AetrisVPN-white-list-lite),
  [Kizyak](https://github.com/Maskkost93/kizyak-vpn-4.0), and
  [PypsCFG](https://github.com/heops6767/PypsCFG) as additional discovery feeds;
- [whoahaow/rjsxrd](https://github.com/whoahaow/rjsxrd), using its bypass feeds;
- [mifa.world](https://mifa.world/), fetched independently.

Whitelist endpoint evidence is verified against:
- [hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist) (primary CIDR and domain lists);
- [artembsk mirror](https://github.com/artembsk/russia-mobile-internet-whitelist) (fallback CIDR and domain lists);
- [escapingworm/russia-whitelist](https://github.com/escapingworm/russia-whitelist) (secondary CIDR evidence).

Adding a plain/Base64 URI source is one `[[sources]]` entry in `config.toml`. A failed upstream
does not stop the other sources.

## Observability and Stats

Every run emits structured telemetry in `stats.json`:

- **Production counts**: Final verified node counts for `main`, `white`, and `all`.
- **Mac verification**: Detailed candidate counts, passes, and failure breakdown (`HTTPS_FAILED`, `STALLED`, `TOO_SLOW`, `DOWNLOAD_R1_FAILED`, `DOWNLOAD_R2_FAILED`).
- **Discovery queue**: Number of `total_never_tested` configs, `tested_first_time_this_run`, queue drain velocity, and estimated hours to clear.
- **Service diagnostics**: Reachability status for Yandex, VK, Ozon, and Telegram Bot API.
- **Protocol metrics**: Coverage and verification states for Hysteria 2 and other key protocols.

## Running it

Python 3.12 or newer, `curl`, and sing-box 1.13.x are required. Install the small pinned Python
dependency set before running either pipeline:

```console
python -m pip install .
PYTHONPATH=src python -m unittest discover -s tests -v
SWIFT_SING_BOX=/path/to/sing-box PYTHONPATH=src python -m swiftproxy.main
PYTHONPATH=src python -m swiftproxy.main --check-output
PYTHONPATH=src python -m swiftproxy.ru_verify --concurrency 6
PYTHONPATH=src python -m swiftproxy.telegram_main
PYTHONPATH=src python -m swiftproxy.telegram_main --check-output
```

Tuning lives in `config.toml`. Candidate counts, concurrency, timeouts, probes, history window,
quality thresholds, and list caps are there. Protocol details and parser behavior are code, not
configuration knobs.

## Limitations

These are free public proxies run by unknown people. Treat them as untrusted. Use end-to-end
encryption for anything important.

Primary latency and throughput are measured from GitHub Actions runners, with secondary sustained
traffic verification conducted from a dedicated self-hosted Mac mini runner located inside Russia.
While this eliminates servers completely blocked by TSPU or throttled by DPI, regional routing,
carrier-specific filtering, and dynamic carrier whitelists can still vary across mobile operators.
Passing Swift tests means a proxy was observed working under sustained traffic during verification,
not a permanent or security guarantee.

White evidence relies on published community CIDRs and SNIs, which can evolve over time as carrier
restrictions change.

## License

MIT. See `LICENSE`.
