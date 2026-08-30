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

There is no minimum. If 74 configs meet the threshold, the file contains 74.

### White

Configs intended for the Russian whitelist/restricted-network case. Swift starts with configs
that an upstream puts in that category and checks two independent pieces of community evidence:
the resolved endpoint IP and the TLS SNI visible to the operator. Candidates matching both are
preferred, followed by IP-only matches and then SNI-only matches. Every candidate still has to
carry real proxy traffic twice and pass the Russian sustained actual-traffic verification;
an upstream `white` label is not enough on its own.

`https://sub.femboypig.ru/white.txt`

This is also capped at 200. A config passing the normal test does not make it eligible for White.

### All

Every unique candidate from the current run that passed both proxy test rounds and the small
download floor. This can be larger than the recommended lists.

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

The three normal files are plain URI lists. Karing documents V2Ray/Sub subscriptions and the
protocols Swift emits. Happ documents standard URL subscriptions containing URI lines, but its
current public protocol list does not include TUIC.

For Happ, use these versions. They omit TUIC and include Happ's profile metadata:

`https://sub.femboypig.ru/happ/main.txt`

`https://sub.femboypig.ru/happ/white.txt`

Keeping `#profile-title`, `#profile-update-interval`, and `#profile-web-page-url` out of the
universal files avoids depending on how other clients treat Happ-specific lines.

Compatibility was checked against the current [Karing documentation](https://github.com/KaringX/karing/blob/main/README.md),
[Karing FAQ](https://github.com/KaringX/karing-docu/blob/main/docs/faq.md),
[Happ subscription documentation](https://github.com/HappDev/happ_su/blob/main/faq/adding-configuration-subscription.md),
and [Happ profile metadata documentation](https://github.com/HappDev/happ_su/blob/main/dev-docs/app-management.md).
Actual import on every Karing/Happ platform still needs testing on real devices.

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

The Actions job runs this pipeline every 30 minutes:

1. Fetch each source independently.
2. Extract supported URIs, validate them, and calculate canonical fingerprints.
3. Merge duplicates while keeping source provenance.
4. For White, resolve every endpoint address and compare both the IP and visible TLS SNI with the
   current community lists. Prefer combined IP+SNI evidence, then IP-only, then SNI-only.
5. Pick a bounded candidate set (up to 1000 for Main, 250 for White). Active and previously good configs
   come first; new and older configs get a rotating discovery sample.
6. Resolve endpoints and reject local, private, link-local, reserved, and metadata addresses.
7. Use a cheap TCP connection only as a prefilter for TCP protocols. UDP protocols skip it.
8. Serialize the config exactly as it will be published and parse it again.
9. Start an isolated sing-box process with a local SOCKS inbound.
10. Make five HTTPS requests through that SOCKS proxy, rotating across several targets, then
    download 256 KiB.
11. Perform a secondary live verification stage directly inside Russia via a dedicated self-hosted
    runner with physical interface binding (e.g. `wlan0`) to test actual sustained traffic through
    Russian ISP filters for both Main and White candidates (>=2/3 neutral HTTPS probes, 2x256 KiB downloads,
    min throughput >= 64 KiB/s, stall detection). If a config belongs to both lists, it is tested once.
12. Update history, score, select, and publish only configs that passed all verification rounds.

Twenty configs are tested concurrently in Cloud. Each process has its own temporary JSON file and local
port. Commands use argument arrays, not a shell, and process groups are terminated in `finally`
blocks. Upstream remarks and credentials are never written to logs.

Country data comes from Cloudflare's trace response during testing. Country labels reflect the actual
resolved endpoint GeoIP, never `.ru` hostnames or upstream remarks.

Names are intentionally plain: `🇫🇮 FI · 001` in Main and `🇫🇮 FI · W001` in White. All uses an
`A` prefix. Swift doesn't put Actions latency in the name; that number says little about latency
from another ISP.

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

A new config can become active in one run only after two independent core sessions. Each session
must pass at least four of five requests and its lane's download floor: 128 KiB/s for Main and
48 KiB/s for White. An active config gets one failed-run grace period if its history is strong.
Two consecutive failed observations make it dead. This is deliberately small and boring; the
states are just values in JSON.

Selection first applies soft caps per exact endpoint, /24 IPv4 or /48 IPv6 subnet, and ASN. If
those caps would leave space unused, the best deferred configs fill it. Scores are sorted in
one-point buckets, with the previous order used inside a bucket to avoid pointless reshuffling.

## Failure handling

Swift does not publish before the complete run has been assessed. It keeps the old subscription
files when:

- every source fails;
- both the primary whitelist CIDR feed and its fallback fail validation or download;
- the direct target preflight cannot reach at least two targets;
- most sing-box processes fail to start;
- the global test deadline leaves too many jobs unfinished;
- the Russian verification runner detects an infrastructure failure or network outage;
- Main or White suddenly collapses compared with the last published counts.

The failed run writes `data/run-diagnostics.json`, preserves the previous subscriptions and
history, commits the diagnostic, and marks the Actions run failed. This makes the outage visible
without replacing a useful list with an empty one.

## Sources

The default config uses:

- [Akres/VPN](https://gitverse.ru/Akres/VPN), using its bounded gRPC feed for Main and `bwl` feed
  for White;
- [vpnsvpns/Prihs](https://github.com/vpnsvpns/Prihs) as an hourly GitHub-hosted fallback for the
  same Akres feeds. Prihs does not test configs itself, so duplicate provenance from these two URLs
  is treated as one source;
- [RKPchannel/RKP_bypass_configs](https://github.com/RKPchannel/RKP_bypass_configs), using its
  independently maintained and core-tested normal and whitelist feeds;
- [zieng2/wl](https://github.com/zieng2/wl), using its hourly `vless_universal.txt` feed for White;
- [igareck/vpn-configs-for-russia](https://github.com/igareck/vpn-configs-for-russia), using its
  mobile and full CIDR lists for White, and its international feeds for Main;
- [0xRadikal/configs-collector](https://github.com/0xRadikal/configs-collector), using verified
  configs for Main;
- [VovaplusEXP/Secure-configs](https://github.com/VovaplusEXP/Secure-configs), using secure VLESS feeds for Main;
- [FLEXIY0/matryoshka](https://github.com/FLEXIY0/matryoshka), using whitelist configs for Main and White;
- [AirLinkVPN](https://github.com/AirLinkVPN1/AirLinkVPN),
  [bywarm/rser](https://gitverse.ru/bywarm/rser),
  [AetrisVPN](https://github.com/flaafix/AetrisVPN-white-list-lite),
  [Kizyak](https://github.com/Maskkost93/kizyak-vpn-4.0), and
  [PypsCFG](https://github.com/heops6767/PypsCFG) as additional White discovery feeds;
- [whoahaow/rjsxrd](https://github.com/whoahaow/rjsxrd), using its Xray-tested bypass output for
  White. Swift still applies its own CIDR and traffic checks instead of trusting the upstream tag;
- [mifa.world](https://mifa.world/), fetched independently as requested. Its anonymous homepage
  currently exposes no config URIs, so Swift reports it as empty instead of scraping an
  undocumented authenticated endpoint.

The Telegram pipeline starts with the current feeds from
[SoliSpirit/mtproto](https://github.com/SoliSpirit/mtproto),
[Argh94/Proxy-List](https://github.com/Argh94/Proxy-List),
[shablin/mtproto-proxy](https://github.com/shablin/mtproto-proxy), and
[klondike0x/mtp4tg-proxies](https://github.com/klondike0x/mtp4tg-proxies). They overlap heavily;
Swift normalizes and deduplicates them before testing and keeps their provenance as metadata.

White endpoint evidence comes from
[hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist).
Its CIDR file is built from addresses observed as reachable during restrictions across different
operators and regions. The actively maintained
[artembsk mirror](https://github.com/artembsk/russia-mobile-internet-whitelist) and
[escapingworm/russia-whitelist](https://github.com/escapingworm/russia-whitelist) are fetched as
fallbacks. Swift uses the CIDR feed rather than treating each entry in `ipwhitelist.txt` as an
exact `/32`: that file intentionally contains one sampled address per `/24`.

Adding a plain/Base64 URI source is one `[[sources]]` entry in `config.toml`. A failed upstream
does not stop the other sources. Source reputation does not give scoring bonuses.

## Running it

Python 3.12 or newer, `curl`, and sing-box 1.13.x are required. Install the small pinned Python
dependency set before running either pipeline.

```console
python -m pip install .
PYTHONPATH=src python -m unittest discover -s tests -v
SWIFT_SING_BOX=/path/to/sing-box PYTHONPATH=src python -m swiftproxy.main
PYTHONPATH=src python -m swiftproxy.main --check-output
PYTHONPATH=src python -m swiftproxy.ru_verify --concurrency 6
PYTHONPATH=src python -m swiftproxy.telegram_main
PYTHONPATH=src python -m swiftproxy.telegram_main --check-output
```

The normal place to run the full network job is GitHub Actions. The workflow downloads the pinned
sing-box release, verifies its published SHA-256 checksum, caches the binary, tests, performs
output sanity checks, commits only when tracked data changed, and deploys the subscriptions to
GitHub Pages.

Tuning lives in `config.toml`. Candidate counts, concurrency, timeouts, probes, history window,
quality thresholds, and list caps are there. Protocol details and parser behavior are code, not
configuration knobs.

## Limitations

These are free public proxies run by unknown people. Treat them as untrusted. Use end-to-end
encryption for anything important.

Primary latency and throughput are measured from a GitHub-hosted runner, with secondary sustained
traffic verification conducted from a dedicated self-hosted Mac mini runner located inside Russia.
While this eliminates servers completely blocked at the Russian gateway level, local mobile ISP filters,
regional DPI throttles, and dynamic carrier whitelists can still differ across operators. Swift selects
what can be verified; it does not promise globally bulletproof bypass under every local carrier restriction.
The same applies to MTProto RTT in `Telegram/fastest.txt`.

The White job is independent, but a GitHub runner cannot reproduce a Russian carrier's restricted
or whitelist mode. Public lists combine observations from different operators, regions, towers,
and dates. Some operators check only SNI, some check IP and SNI together, and a total shutdown may
pass almost nothing. In Swift, White means the endpoint currently matches a published whitelist
CIDR or uses an allowed visible SNI, and the config carried ordinary proxy traffic through
sing-box and passed Russian live sustained verification. None of these checks proves that a config works
during a shutdown for your SIM. That requires a probe from the affected carrier and region.

An address or SNI missing from the community lists is not necessarily blocked; the data is
incomplete. Swift still excludes candidates with neither kind of evidence instead of filling White
with ordinary proxies carrying a speculative upstream label.

## License

MIT. See `LICENSE`.
