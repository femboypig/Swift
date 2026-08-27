# Swift

Filter the garbage. Keep what works.

Swift collects public proxy configs, tests them, and keeps the ones that actually work.

There are already plenty of subscriptions with tens of thousands of entries. Swift is for
people who would rather import a small list and have a reasonable chance that its entries can
actually carry traffic.

## Subscriptions

### Main

The normal list. It contains at most 200 configs.

`https://raw.githubusercontent.com/femboypig/swift/main/sub/main.txt`

There is no minimum. If 74 configs meet the threshold, the file contains 74.

### White

Configs intended for the Russian whitelist/restricted-network case. They come only from sources
that explicitly put them in that category, then go through a separate test and history track.

`https://raw.githubusercontent.com/femboypig/swift/main/sub/white.txt`

This is also capped at 200. A config passing the normal test does not make it eligible for White.

### All

Every unique candidate from the current run that passed real proxy requests and the small
download floor. This can be larger than the recommended lists.

`https://raw.githubusercontent.com/femboypig/swift/main/sub/all.txt`

## Karing and Happ

The three normal files are plain URI lists. Karing documents V2Ray/Sub subscriptions and the
protocols Swift emits. Happ documents standard URL subscriptions containing URI lines, but its
current public protocol list does not include TUIC.

For Happ, use these versions. They omit TUIC and include Happ's profile metadata:

`https://raw.githubusercontent.com/femboypig/swift/main/sub/happ/main.txt`

`https://raw.githubusercontent.com/femboypig/swift/main/sub/happ/white.txt`

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
- TUIC

The stock sing-box core does not support every Xray transport. Swift rejects configs it cannot
represent faithfully, including XHTTP, mKCP, and TCP header obfuscation. A parsed-but-changed
config is worse than an honest rejection.

## What the test does

The Actions job runs this pipeline every 30 minutes:

1. Fetch each source independently.
2. Extract supported URIs, validate them, and calculate canonical fingerprints.
3. Merge duplicates while keeping source provenance.
4. Pick a bounded candidate set. Active and previously good configs come first; new and older
   configs get a rotating discovery sample.
5. Resolve endpoints and reject local, private, link-local, reserved, and metadata addresses.
6. Use a cheap TCP connection only as a prefilter for TCP protocols. UDP protocols skip it.
7. Start one isolated sing-box process with a local SOCKS inbound.
8. Make five HTTPS requests through that SOCKS proxy, rotating across several targets.
9. Download 256 KiB through survivors and record the actual transfer rate.
10. Update history, score, select, and publish.

Twenty configs are tested concurrently. Each process has its own temporary JSON file and local
port. Commands use argument arrays, not a shell, and process groups are terminated in `finally`
blocks. Upstream remarks and credentials are never written to logs.

The optional country/ASN data comes from Cloudflare's small speed-test metadata response through
the proxy. If that request fails, the config can still pass. Geo enrichment is not a hard
dependency.

## Scoring and history

History is a compact JSON file with the last 16 observations per config and per list. Main and
White do not share health observations.

The score is 0–100:

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

A new config can become active in one run by passing at least four of five proxy requests and the
download floor. An active config gets one failed-run grace period if its history is strong. Two
consecutive failed observations make it dead. This is deliberately small and boring; the states
are just values in JSON.

Selection first applies soft caps per exact endpoint, /24 IPv4 or /48 IPv6 subnet, and ASN. If
those caps would leave space unused, the best deferred configs fill it. Scores are sorted in
one-point buckets, with the previous order used inside a bucket to avoid pointless reshuffling.

## Failure handling

Swift does not publish before the complete run has been assessed. It keeps the old subscription
files when:

- every source fails;
- the direct target preflight cannot reach at least two targets;
- most sing-box processes fail to start;
- the global test deadline leaves too many jobs unfinished;
- Main or White suddenly collapses compared with the last published counts.

The failed run writes `data/run-diagnostics.json`, preserves the previous subscriptions and
history, commits the diagnostic, and marks the Actions run failed. This makes the outage visible
without replacing a useful list with an empty one.

## Sources

The default config uses:

- [igareck/vpn-configs-for-russia](https://github.com/igareck/vpn-configs-for-russia), with its
  normal and whitelist files kept in separate lanes;
- [mifa.world](https://mifa.world/), fetched independently as requested. Its anonymous homepage
  currently exposes no config URIs, so Swift reports it as empty instead of scraping an
  undocumented authenticated endpoint;
- [0xRadikal/Free-v2ray-Configs](https://github.com/0xRadikal/Free-v2ray-Configs), using the
  measured `verified` tier;
- [morpheusadam/v2ray-config](https://github.com/morpheusadam/v2ray-config), using the bounded
  `best` bundle.

Adding a plain/Base64 URI source is one `[[sources]]` entry in `config.toml`. A failed upstream
does not stop the other sources.

## Running it

Python 3.12 or newer, `curl`, and sing-box 1.13.x are required. There are no Python runtime
dependencies.

```console
PYTHONPATH=src python -m unittest discover -s tests -v
SWIFT_SING_BOX=/path/to/sing-box PYTHONPATH=src python -m swiftproxy.main
PYTHONPATH=src python -m swiftproxy.main --check-output
```

The normal place to run the full network job is GitHub Actions. The workflow downloads the pinned
sing-box release, verifies its published SHA-256 checksum, caches the binary, tests, performs
output sanity checks, and commits only when tracked data changed.

Tuning lives in `config.toml`. Candidate counts, concurrency, timeouts, probes, history window,
quality thresholds, and list caps are there. Protocol details and parser behavior are code, not
configuration knobs.

## Limitations

These are free public proxies run by unknown people. Treat them as untrusted. Use end-to-end
encryption for anything important.

Latency is measured from a GitHub-hosted runner. It is not the latency from your home ISP or a
Russian mobile network. A server measured at 55 ms in Actions can be slow or unreachable for you.
Swift ranks what the runner can measure; it does not promise the globally fastest servers.

The White job is independent, but a GitHub runner cannot reproduce a carrier's restricted or
whitelist mode. Upstream whitelist classification is preserved and then checked for actual proxy
traffic. Final reachability from the affected network still has to be confirmed by users on that
network.

## License

MIT. See `LICENSE`.
