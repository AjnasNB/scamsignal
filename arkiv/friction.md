# Arkiv integration friction

Environment: Windows, Node.js 24.15.0, React/TypeScript browser client, `@arkiv-network/sdk` **0.8.1**, Tiramisu chain **7738577**. Integration date: **11 October 2026**.

## Typed indexes need to be explicit

APK hashes and package digests use `bytes32`; schema/version/expiry use `u64`; creator filters use `addr`. Querying these as untyped JSON strings or numbers does not express the same typed index. Our code imports constructors from `@arkiv-network/sdk/attr`, and exact queries and real transaction keys are in [schema.md](schema.md) and [evidence.json](evidence.json).

Reproduce: run `npm run arkiv:verify`; inspect `live_query` in its output file. Then compare a hash query constructed with `bytes32` to one constructed with `str`. Suggested documentation improvement: a compact cookbook showing mixed typed user attributes and `$creator`/`$expiresAt` filters together.

## Creator and owner have distinct security meanings

Applications must verify protocol creator metadata rather than accepting an `issuer` field in their own payload. A mutable entity can retain its original creator after transfer while a later owner changes it. Our reader therefore accepts only readonly payloads and binds index values to strict payload fields. It does not require owner equality for readonly records because transfer cannot change their payload.

Reproduce: `npm test` exercises a trusted creator's mutable entity with an untrusted owner and rejects it. Suggested improvement: include this transferred-mutable-record threat in provenance examples, alongside the difference between creator and owner.

## Expiry is a live-query condition

`getBlockTiming()` returns a block number, Unix timestamp in seconds, and duration in seconds. We filter `$expiresAt` and derive an approximate display time from the current timing. Event notifications are useful for writes, but the application still needs periodic refresh to remove expired records. Expiry is not a promise of historical deletion.

Reproduce: [protocol-verification.json](protocol-verification.json), when present, records the separate synthetic short-life fixture and actual live-query expiration result. Main review records remain long-lived; the expiry demonstration never shortens their lives. Suggested improvement: show an explicit clock-driven refresh pattern beside WebSocket examples.

## Reviewer setup requires a funded testnet wallet

Anonymous public reads worked without an access key. Writes required a dedicated reviewer wallet, free Tiramisu testnet GLM, and the correct chain ID. The Arkiv Hub faucet required its CAP proof-of-work/browser check and then returned an asynchronous accepted claim. We verified the delivered balance before creating any entities. No paid token purchase was required.

Suggested improvement: document the faucet's asynchronous claim states and expected funding sequence alongside the first entity-write example. This report includes no CAPTCHA/session cookies, access credentials or private wallet material.

## Direct reading is intentionally independent

The scanner runs on a free Azure F1 host; the frontend and independent viewer run on Cloudflare static hosting. The browser queries Arkiv directly. A scanner outage cannot be treated as a missing warning, and a failed Arkiv lookup cannot be treated as a clean result. Our integration contains explicit unavailable and unknown states and bounded pagination.

Reproduce: the browser fault tests in `tests/web` deliberately fail the scan/API or record connection. Actual five-upload hosted measurements are in `scanner/live-evaluation.json`; these are distinct from mocked UI tests. Actual Arkiv read-back is in `arkiv/verification.json`.
