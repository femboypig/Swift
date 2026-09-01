# RU verification pipeline

Swift's production health result is measured from the self-hosted Russian runner. The GitHub job only collects and canonicalizes candidates. It does not resolve endpoints or try proxy traffic.

Each collected generation has an immutable ID and an exact fingerprint set. The RU runner accounts for every fingerprint once. A generation with a missing, duplicate, unknown, cancelled, or deferred result cannot be published.

The verifier runs these stages:

1. Resolve the original endpoint on the RU runner. Unsafe answers are rejected. The selected address is test telemetry and does not change the canonical fingerprint or TLS hostname.
2. Record a protocol-aware endpoint sanity result. Raw TCP is telemetry only; it is skipped for UDP protocols and never overrides the actual core test.
3. Start sing-box and reach two distinct HTTPS targets with acceptable HTTP status (200–399). Two successes or two failures end the three-target stage early.
4. Start a fresh core session and repeat the two-distinct-target rule. This is the stability confirmation.
5. With a separate download limit, complete two 256 KiB transfers. Each must sustain at least 64 KiB/s and must not stall.
6. Run bounded service diagnostics after the authoritative result. They do not gate Main or White.

Resolution, endpoint telemetry, initial HTTPS, stability, downloads, and diagnostics have independent concurrency limits. Sustained downloads default to one at a time with a 128 KiB/s verifier budget. Direct control latency is checked before quality-sensitive downloads. If the local connection is congested, the candidate is deferred and retried; an unresolved deferred result makes the whole generation incomplete instead of producing `TOO_SLOW`.

`data/ru-history.json` contains only observations tagged with the RU vantage point. History determines deterministic scheduling and ranking, never whether a current candidate receives a test. A new candidate can be published after one complete strong RU PASS.

`sub/all.txt` is the complete current RU PASS population before Main/White ranking caps. White additionally requires White lane membership and CIDR, SNI, or upstream-label evidence. That evidence is not proof that a proxy works during an actual whitelist-only shutdown.

The self-hosted job creates a proposed publication artifact. A GitHub-hosted job verifies the generation identity, exhaustive accounting, output populations, caps, and subscription syntax before committing it. The repository's existing files are the last-known-good generation until that commit succeeds.
