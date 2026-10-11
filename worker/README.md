# Restricted Arkiv read gateway

`/api/arkiv-rpc` is the site's same-origin JSON-RPC endpoint. `ARKIV_API_KEY` is a Cloudflare secret sent upstream in `X-API-KEY`; it is never a browser configuration value. Operator SDK clients can still use Arkiv's external RPC directly.

Only `arkiv_getBlockTiming` and `arkiv_query` are accepted. Queries use a finite typed predicate grammar and a server-controlled outer `AND` restriction for `scamsignal-v1`, schema 1, and the published reviewer creator wallets. Required protocol metadata is checked again in responses. Expired entities are removed against a fresh upstream head on every page, while the guarded query remains stable for SDK cursors. Payload publisher names never establish creator identity.

The gateway accepts one JSON-RPC request, a declared page limit of 1–100, an 8 KiB request body, and at most 2 MiB of upstream JSON. Unsupported methods, writes, batches, notifications, arbitrary query syntax, unknown projections, unbounded limits, and cross-origin browser posts are rejected. A shared 14-second upstream deadline includes timing, querying, and response reading. Upstream errors and headers are not exposed. Failure diagnostics contain only a static stage/category and numeric upstream HTTP status; exception messages, request bodies, wallet keys, queries, API secrets, and visitor IPs are not logged. Upstream redirects are returned manually and rejected, preventing the server key from reaching another host.

The anonymous public-read resource has a conservative 60-request/minute rate binding per Cloudflare location. Cloudflare describes these counters as permissive and eventually consistent; they are not a global quota or precise billing cap. Static files use the `ASSETS` binding, and only this endpoint runs the Worker ahead of the static router.

Local checks:

```sh
npx wrangler types worker/worker-configuration.d.ts --env-interface Env
npx tsc --project worker/tsconfig.json
npx vitest run worker
npx wrangler deploy --dry-run --outdir .local/gateway-bundle
```

`index.ts` exports only the Worker handler; the finite query parser and testable gateway live in `gateway.ts`. Local `wrangler dev --local` verification also checks that static HTML is served, forbidden transaction calls return 403, batches return 400, and a missing secret returns a JSON-RPC 503 rather than an SPA page. Initial authenticated local workerd verification read a real block timing and seven scoped records; the subsequent expanded public read-back verified all 19. The 44 unit checks include bounded responses, timeouts, preserved fetch receiver, redirect rejection, stable pagination, and diagnostic redaction. Public `npm run arkiv:verify` needs no deployment credentials; running your own keyed gateway requires your own private Arkiv key, and deployment requires Cloudflare authorization.

Configuration follows the current [Worker-first static asset routing](https://developers.cloudflare.com/workers/static-assets/routing/worker-script/), [rate-limit binding](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/), [secret binding](https://developers.cloudflare.com/workers/configuration/secrets/), and [Workers best practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/) documentation. Generated binding types should be refreshed after configuration changes.
