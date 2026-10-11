# ScamSignal Arkiv schema

Network: **Tiramisu**, chain ID **7738577**. Tested SDK: **@arkiv-network/sdk 0.8.1**.

Approved creator: `0xd153C0cC313884DA0065615BB411Dfb8b873fE54`.
This is the project's evaluation reviewer, not an APK publisher or government authority.
The public browser policy is `/data/trust-policy.json`; it is also committed in `apps/web/public/data/trust-policy.json`.

Five passports and two training-app advisories were published on 11 October 2026.
Actual entity keys, transaction hashes, creator address, expiration blocks, and the verified query are in [evidence.json](evidence.json).
Actual per-APK read-back results are in [verification.json](verification.json).

## Entity attributes

| Attribute | Arkiv type | Purpose |
|---|---|---|
| `app_id` | `str` | Namespace, always `scamsignal-v1` |
| `schema_version` | `u64` | Strict schema version, currently 1 |
| `kind` | `str` | `passport`, `advisory`, or `correction` |
| `apk_sha256` | `bytes32` | Exact uploaded-file identity |
| `package_digest` | `bytes32` | SHA-256 of Android package name; enables release comparison |
| `version_code` | `u64` | Android version code, when present |
| `signer_sha256` | `bytes32` | First signing certificate fingerprint; complete signer set in payload |
| `severity` | `str` | Advisory scope: `info`, `review`, or `high` |
| `target_key` | `key` | Correction target entity |

Each JSON payload contains the same namespace, schema, kind, artifact hash and package name, plus display name, version code, complete signing fingerprint set, review timestamp, title, summary, bounded evidence strings, severity, classification, and HTTPS source reference. A correction also contains `target_key` and `action: "retract"`. Unknown payload fields are rejected.

Classifications are `open_source_release`, `insecure_training_app`, and `synthetic_demo`. None means safe, authentic publisher, confirmed malware, or confirmed scam. The frontend labels identity matches separately from analysis findings and warnings.

## Exact production queries

The block number is read from `arkiv_getBlockTiming`, then inserted as a typed `u64`. Creator addresses come from the published policy. At the initial read-back, the base query was:

```text
app_id = str('scamsignal-v1') AND schema_version = u64(1) AND $expiresAt > u64(438783) AND $creator = addr(0xd153C0cC313884DA0065615BB411Dfb8b873fE54)
```

For an uploaded APK, append an OR of its exact hash and package digest:

```ts
client.select().where(
  eq('app_id', str('scamsignal-v1')),
  eq('schema_version', u64(1)),
  gt('$expiresAt', u64(currentBlock)),
  eq('$creator', addr(approvedReviewer)),
  or(
    eq('apk_sha256', bytes32(apkHash)),
    eq('package_digest', bytes32(packageHash)),
  ),
).limit(100).fetch()
```

For the independent viewer, append `eq('apk_sha256', bytes32(apkHash))`. Full fields are selected, and every page is consumed up to a defensive ten-page limit. An incomplete query fails closed with an unavailable state. No local database or bundled result is substituted for Arkiv records.

## Provenance and decisions

The client accepts **protocol `$creator`**, never a publisher label inside JSON. It requires a live entity, a configured creator, `creationFlags.readonly === true`, strict payload validation, and agreement between indexed attributes and payload fields. This prevents an owner from changing a transferred mutable entity while retaining its trusted original creator. Ownership alone does not establish authorship.

An exact passport match requires the same APK SHA-256, package name, successful APK signature verification, and complete certificate fingerprint set. A new APK signed by an existing reference signer is still an unknown release. A different certificate triggers a signer mismatch. Signature verification unavailable or invalid remains incomplete; an RPC failure remains unavailable.

An advisory applies only to its exact artifact and package. A live correction suppresses its target only when the protocol creator, artifact, package and creation ordering agree. Publishing verifies the target's creator and artifact and gives the correction a lifetime covering the target. If operators extend a target, they must also preserve its correction; expired corrections cannot be recovered from a live-only query. There is no automatic assumption that expired warnings indicate safety.

## Lifetime, events and custody

Default passports last 30 days; advisories last 14 days. These evaluation records cover the published judging window. Payloads are readonly and permissionless extension is disabled. Expiration, deletion, transfer, and ownership extension are separate protocol operations; readonly is not permanent undeletability. Historical copies may remain after live expiry.

The browser watches entity events over the public WebSocket and re-queries verified records. Periodic HTTP refresh handles expiry, which is not treated as an entity event. Socket failure falls back to bounded refresh and does not manufacture a warning or safety claim.

Raw APKs, scan-session tokens, filenames, certificate subjects, contacts, email, device/user identifiers and private keys never go to Arkiv. Stored hashes identify public software artifacts and certificate bytes; they are not hashes of people's private information. New private uploads are not automatically published. Approved reviewers explicitly curate technical public evidence.

## Reproduce the read-back

```sh
npm ci
npm run arkiv:verify
```

This reads the five reports and policy from the checkout, performs fresh Arkiv queries, and writes `arkiv/verification.json`. Reviewer publication requires an explicitly supplied private wallet file outside the repository; no private key is included in source or browser bundles.
