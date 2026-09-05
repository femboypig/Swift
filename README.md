# Swift

Filter the garbage. Keep what works.

Swift collects public proxy configs, tests them, and keeps the ones that actually work.

There are already plenty of subscriptions with tens of thousands of entries. Swift is for
people who would rather import a small list and have a reasonable chance that its entries can
actually carry traffic.

## Subscriptions

### Main

The normal list. It contains at most 80 configs.

`https://sub.femboypig.ru/main.txt`

80 is strictly a maximum output cap, not a fixed target. Final Main is formed ONLY from configs that successfully pass the Russian sustained actual-traffic verification on the Mac runner. If 12 pass, the file contains 12. If 130 pass, the best 80 are selected with diverse ASN/subnet limits. A Mac verification failure has a 0% chance of publication regardless of historical score.

### White

Configs intended for the Russian whitelist/restricted-network case. Publication requires the IP
actually selected by RU resolution to be present in a current community CIDR feed. TLS SNI and
upstream White labels are retained as telemetry, but aren't enough on their own. Every candidate
still has to carry real proxy traffic and pass the same Russian sustained verifier. This is stronger
evidence, not proof that a config will work during a real whitelist-only shutdown.

`https://sub.femboypig.ru/white.txt`

This is also capped at 200. A config passing the normal test does not make it eligible for White.

### All

Every unique candidate that passed the complete current RU verification, before Main and White
ranking caps. This can be larger than the recommended lists.

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

The Actions workflow is scheduled every four hours and runs this pipeline:

1. Fetch each source independently.
2. Extract supported URIs, validate them, and calculate canonical fingerprints.
3. Merge duplicates while keeping source provenance.
4. Write an immutable generation manifest and exact canonical candidate artifact. GitHub does no
   DNS, TCP, HTTPS, or throughput proxy testing.
5. On the self-hosted RU runner, run direct-path and sing-box preflight controls.
6. Resolve every hostname in the RU environment. Reject unsafe answers and preserve the original
   hostname for fingerprint, TLS SNI, and transport Host semantics.
7. Record a protocol-aware endpoint sanity result. It is telemetry only and is skipped for UDP
   protocols.
8. Start sing-box and require acceptable HTTP responses from two distinct neutral HTTPS targets.
   Repeat that rule in a fresh core session for stability.
9. Complete two 256 KiB downloads. Both must avoid stalls and sustain at least 64 KiB/s.
10. Near publication, recheck every provisional PASS through a fresh sing-box session and two
    distinct HTTPS targets. This keeps an early result from sitting stale for most of a long run.
11. Account for every expected fingerprint. Missing, duplicate, unknown, cancelled, or deferred
    work makes the generation incomplete.
12. Build proposed Main, White, All, and Happ files on the RU runner. A GitHub job independently
    checks the generation identity, accounting, RU PASS population, caps, and syntax before one
    complete generation is committed.

Resolution, initial HTTPS, stability, sustained downloads, and diagnostics have separate bounded
concurrency. Downloads default to one at a time with a 128 KiB/s verifier budget. If direct control
latency shows clear local congestion, a quality-sensitive result is deferred instead of becoming a
false `TOO_SLOW`. An unresolved defer prevents publication.

Country data is collected through a proxy only after it has passed the authoritative checks. It is
RU-run telemetry, not GitHub latency or an upstream hostname guess.

Names are intentionally plain: `🇫🇮 FI · 001` in Main and `🇫🇮 FI · W001` in White. All uses an
`A` prefix. Swift doesn't put Actions latency in the name; that number says little about latency
from another ISP.

## Scoring and history

RU history is kept separately in `data/ru-history.json`. Legacy GitHub observations are not treated
as RU observations. The last 16 results retain availability, recent availability, consecutive
success/failure counts, RU latency, throughput, last success, and confidence.

History changes deterministic test order and final ranking. It never decides whether a current
candidate receives the RU test. Previous RU passes run first, then unseen configs, recent failures,
and repeated failures. Every tier still runs. A new config can enter the output after one strong
current RU PASS; it does not need old Cloud history.

Selection first applies soft caps per exact endpoint, /24 IPv4 or /48 IPv6 subnet, and ASN. If
those caps would leave space unused, the best deferred configs fill it. Scores are sorted in
one-point buckets, with the previous order used inside a bucket to avoid pointless reshuffling.

## Failure handling

Swift does not publish before every expected fingerprint has one terminal result. It keeps the old
subscription files when:

- every source fails;
- RU direct-path or core preflight/postflight fails;
- mass process/resource startup failures indicate a broken verifier environment;
- the RU deadline leaves even one candidate unaccounted;
- local congestion leaves a deferred candidate unresolved;
- the result artifact has a wrong generation, wrong HEAD, count mismatch, duplicate, or unknown
  fingerprint.

The failed run uploads bounded telemetry and marks the workflow failed. It does not commit partial
subscriptions or history, so the repository remains the last-known-good generation.

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
- [EtoNeYa](https://etoneya.su/whitelist), using its actively maintained whitelist feed;
- [HardVPN](https://github.com/ksenkovsolo/HardVPN-bypass-WhiteLists-), using only its small
  post-check `good_keys` feed;
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
[escapingworm/russia-whitelist](https://github.com/escapingworm/russia-whitelist) are merged when
their feeds pass validation. Swift uses CIDR feeds rather than treating each entry in
`ipwhitelist.txt` as an
exact `/32`: that file intentionally contains one sampled address per `/24`.

Adding a plain/Base64 URI source is one `[[sources]]` entry in `config.toml`. A failed upstream
does not stop the other sources. Source reputation does not give scoring bonuses.

## Running it

Python 3.12 or newer, `curl`, and sing-box 1.13.x are required. Install the small pinned Python
dependency set before running either pipeline.

```console
python -m pip install .
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m swiftproxy.main --check-output
PYTHONPATH=src python -m swiftproxy.generation
SWIFT_BIND_INTERFACE=wlan0 SWIFT_SING_BOX=/path/to/sing-box \
  PYTHONPATH=src python -m swiftproxy.ru_golden
PYTHONPATH=src python -m swiftproxy.publication --check-only
PYTHONPATH=src python -m swiftproxy.telegram_main
PYTHONPATH=src python -m swiftproxy.telegram_main --check-output
```

`swiftproxy.main` without `--check-output` is the retired Cloud verifier and now requires the
explicit `--legacy-cloud` flag. It is not part of production. The normal workflow collects on
GitHub, verifies through the pinned sing-box build on the RU runner, validates the completed
artifact back on GitHub, commits only complete changed data, and deploys it to Pages.

Tuning lives in `config.toml`. Candidate counts, concurrency, timeouts, probes, history window,
quality thresholds, and list caps are there. Protocol details and parser behavior are code, not
configuration knobs.

## Limitations

These are free public proxies run by unknown people. Treat them as untrusted. Use end-to-end
encryption for anything important.

Proxy latency, stability, and throughput are measured only from a dedicated self-hosted Mac mini
runner on a Russian network. Local mobile ISP filters, regional DPI throttles, and dynamic carrier
whitelists can still differ across operators. Swift selects what can be verified from that RU path;
it does not promise bypass under every carrier restriction.
The same applies to MTProto RTT in `Telegram/fastest.txt`.

The White lane is independent, but the RU runner is not placed in a forced carrier whitelist mode.
Public lists combine observations from different operators, regions, towers,
and dates. Some operators check only SNI, some check IP and SNI together, and a total shutdown may
pass almost nothing. In Swift, White means the RU-selected endpoint currently matches a published
whitelist CIDR, and the config carried ordinary proxy traffic through sing-box and passed Russian
live sustained verification. None of these checks proves that a config works
during a shutdown for your SIM. That requires a probe from the affected carrier and region.

An address missing from the community lists is not necessarily blocked; the data is incomplete.
SNI matches and explicit upstream White labels remain telemetry, but they no longer make a config
publishable in White and are not proof of whitelist-mode connectivity.

## License

MIT. See `LICENSE`.
