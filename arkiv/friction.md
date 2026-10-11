# Arkiv integration friction

Measured on 11 October 2026: Windows, Node.js 24.15.0, React/TypeScript, `@arkiv-network/sdk` **0.8.1**, viem **2.57.4**, Tiramisu chain **7738577**. Production reads use Wrangler **4.149.0** and Workers compatibility date **2026-10-11**. Credentials, wallet secrets, browser sessions, and private uploads are excluded.

## TypeScript SDK and typed query indexes

**Expected:** artifact hashes, package digests, creator policy, and lifetimes could be combined in one typed query. **Observed:** constructors must be explicit: `bytes32` for hashes, `u64` for schema/version/expiry, and `addr` for protocol creator. Untyped JSON-looking strings and numbers are not equivalent. Our reader consumes pagination and checks strict payload/index agreement.

**Reproduce:** `npm ci` then `npm run arkiv:verify`. Inspect `live_query` in [verification.json](verification.json), and the constructors in [schema.md](schema.md) and [client source](../packages/arkiv-client/src/index.ts). The fresh read-back at block 440003 accepted all 19 published records and twelve artifact identities. **Improvement:** a mixed-type cookbook combining user attributes with `$creator` and `$expiresAt` would reduce first-query mistakes.

## Creator, ownership, and readonly payloads

**Expected:** a trusted creator filter would establish who authored accepted data. **Observed:** creator and current owner are different properties. A mutable transferred entity can retain a trusted creator while its later owner changes the payload. We require readonly records, protocol creator metadata, exact artifact binding, and strict attribute/payload consistency. A publisher name in JSON proves nothing.

**Reproduce:** `npm test` checks forged authorship, mutable transferred records, wrong typed attributes, incomplete signer sets, and same-author correction ordering. [protocol-verification.json](protocol-verification.json) separately records a real unapproved-wallet fixture rejected by policy. **Improvement:** put the transferred-mutable-record threat beside creator/owner examples. The client trusts its RPC provider for protocol metadata; it does not independently verify a state proof.

## WebSocket events and clock-driven expiry

**Expected:** events would keep the viewer current without excess HTTP traffic. **Observed:** shared-chain events include other applications' activity. Refreshing on every event consumed quota unnecessarily. Expiry also needs clock-driven reads; it is not treated as an entity-write event. `getBlockTiming()` provides block number, Unix seconds, and duration for approximate expiry display.

**Resolution:** filter events to approved creator/owner addresses or accepted entity keys; throttle relevant refreshes to a 15-second cooldown; poll every 60 seconds. Filter `$expiresAt > currentBlock` on every live query. An outage remains unavailable, not clear of warnings.

**Reproduce:** `npm test` includes unrelated-event and transport cases; `npm run test:e2e` exercises bursts, expiry, and stalled-query recovery with controlled fixtures. Actual short-life expiry and retraction transactions are in [protocol-verification.json](protocol-verification.json). Main records cover judging; experiments use separate synthetic records. **Improvement:** document relevant-event filtering, cooldown, and periodic expiry together.

## Direct JSON-RPC, anonymous quota, and access keys

**Expected:** anonymous reads would support a small public demo, and an 18-second request timeout would bound loading. **Observed:** live queries eventually returned HTTP 429 with `ANON_COST_LIMITED`. viem honored a long `Retry-After` between automatic attempts, leaving the UI loading for minutes despite the per-request timeout. This was an actual browser failure.

**Resolution:** HTTP `retryCount: 0`, an 18-second request timeout, a 30-second viewer deadline, explicit unavailable state, and a restricted same-origin Cloudflare gateway with a server-only Hub access key. It accepts only timing and scoped query methods; it bounds namespace, creators, payload sizes, time, pagination, and rate. Public viewers never receive the credential. Independent clients can use their own Arkiv provider. Browser traffic remains independent of the APK scan API.

**Reproduce:** `npm test` asserts that a 429 with a long `Retry-After` fails promptly and that unscoped/write requests are rejected. `npm run arkiv:verify` reads the live public gateway by default. For local keyed reads, store your own key in ignored `.dev.vars`, then run `npx wrangler dev --local --port 8787`; see [worker README](../worker/README.md). Keep keys out of URLs and `VITE_*` variables. **Improvement:** include the anonymous-quota-to-key path, `X-API-KEY` header, fail-fast retry, and bounded viewer in the first-entity cookbook.

## Hub and free Faucet setup

**Expected:** a testnet reviewer could obtain free write gas before publishing. **Observed:** the Hub faucet required its browser CAPTCHA/proof check and returned an asynchronous accepted claim. We checked delivery before publishing. The approved reviewer received free Tiramisu GLM; the separate unapproved test wallet received a small test-only transfer. No paid token purchase was required.

**Reproduce:** connect your own test wallet to [Arkiv Hub](https://hub.arkiv.network), choose Tiramisu, request the free faucet, and verify balance before creating an entity. Supply a private wallet file outside the checkout to operator scripts. Actual receipts are in [evidence.json](evidence.json). **Improvement:** document accepted/pending/funded states and chain ID next to the first write example.

## Hub access-key onboarding

**Expected:** the logged-in account could create a free read-quota key. **Observed:** it initially had no Tiramisu key. Creation required a separate authorized CAPTCHA. The Copy button silently failed while Chrome was in the background; a foreground user copy completed transfer. The key stays outside the checkout and in a Cloudflare secret.

**Reproduce:** generate a Tiramisu key in your own Hub account, verify foreground copying, and configure the server-side `X-API-KEY` header. **Improvement:** show explicit copy-success/failure instead of silently swallowing clipboard errors; distinguish wallet funding from API quota.

## Docs and Block Explorer

**Expected:** SDK docs and transaction links would make judging reproducible. **Observed:** these surfaces worked; no distinct explorer failure was observed. Docs clarified typed attributes, readonly flags, timing, and events. Every published transaction has an explorer link in [evidence.json](evidence.json); protocol experiments have separate receipts.

**Reproduce:** follow `tx_url`; compare entity key, creator wallet, expiry block, and readonly properties with `npm run arkiv:verify`. **Improvement:** link a complete creator-filtered, expiring application example to source and receipts, including quota/retry behavior.

## Validation boundaries

[scanner/live-evaluation.json](../scanner/live-evaluation.json) records twelve real uploads, exact hash agreement, signatures, private-job authorization, deletion, and CORS. [verification.json](verification.json) records fresh Arkiv reads and optional direct entity audits. Controlled browser fixtures do not substitute for either live measurement. Five historical malware specimens span three documented campaigns and establish no detection-accuracy or current India-threat claim.

Surfaces used: SDK, direct JSON-RPC, WebSocket events, Docs, Hub, Faucet, Access keys, Block Explorer. No Arkiv Data Explorer, Arkiv MCP, Arkiv skills, or Arkiv plugin was used. Devfolio's separate MCP connection is not an Arkiv surface.
