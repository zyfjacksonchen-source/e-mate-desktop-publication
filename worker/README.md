# Cloudflare plugin large-object bridge

This module is a publication helper for the connected Codex Cloudflare plugin.
It is not part of either composite action and is never deployed by GitHub,
Wrangler, a repository secret, or a local release command.

It closes one existing handoff seam: signed macOS mode contains exactly the
final DMG, blockmap, signed receipt, and verification receipt; unsigned macOS
contains the exact formal-CI DMG, blockmap, and two CI receipts; Windows
contains the exact formal-CI installer and two CI receipts. These explicit
contracts are closed ZIP `Stored` entry sets,
and the control-plane object PUT is too small for the macOS DMG.
The Worker range-checks the bounded central directory against the plan's exact
entry names/byte counts, streams the full archive once, verifies both the GitHub
artifact archive SHA-256 and the embedded installer byte count/SHA-256, completes
multipart only at a random one-time temp key, reads the temp back in full,
promotes the installer with create-only `If-None-Match: *`, then reads the
immutable final object back in full. A final collision succeeds only when bytes
and metadata are identical. Successful final readback deletes only that exact
random temp key; a failure response returns `temp_key` for exact plugin cleanup.

## Cloudflare plugin-only invocation

For each installer object independently, the connected plugin must:

1. Revalidate the exact three-file handoff and select one installer entry from
   `immutable_objects`. Use its exact GitHub artifact id, run, attempt, name,
   archive digest, exact archive entries, artifact path, final key, bytes,
   SHA-256 and metadata.
2. Ask GitHub for that exact artifact's archive download redirect and retain
   only the final short-lived signed `productionresultssaN.blob.core.windows.net/actions-results/...`
   URL. Do not pass a repository token to the Worker.
3. Deploy a uniquely named, short-lived module Worker from `index.mjs` using
   `deployment-contract.json`. Bind `RELEASES` only to
   `emate-desktop-downloads`, set `nodejs_compat`, and provide these exact
   per-object variables from the reviewed plan and redirect:

   - `EXPECTED_BUCKET`, `EXPECTED_KEY`, `EXPECTED_ARTIFACT_PATH`
   - `EXPECTED_BYTES`, `EXPECTED_SHA256`, `EXPECTED_GITHUB_ARTIFACT_DIGEST`, `EXPECTED_GITHUB_ARTIFACT_BYTES`
   - `EXPECTED_ARCHIVE_ENTRIES` as the exact plan array JSON
   - `EXPECTED_PUBLICATION_METADATA` as the exact installer `publication_metadata` JSON
   - `EXPECTED_PLAN_SHA256`, `EXPECTED_CONTENT_TYPE`, `EXPECTED_CACHE_CONTROL`
   - `EXPECTED_SOURCE_ORIGIN`, `EXPECTED_SOURCE_PATH`, `EXPIRES_AT`
   - one freshly generated 32-byte base64url secret `AUTH_TOKEN`

4. Before `EXPIRES_AT`, call only `POST /v1/ingest` with the bearer secret and:

   ```json
   {
     "schema_version": 1,
     "plan_sha256": "<64 lowercase hex>",
     "source_url": "<exact short-lived signed GitHub artifact URL>"
   }
   ```

5. Require HTTP 200 and the exact key/bytes/SHA-256 response. Independently
   perform the publication plan's public full-byte/SHA-256 readback through the
   Cloudflare plugin. Then delete the Worker and revoke its secret. A claim is
   consumed even on failure; retry requires a new Worker and random secret.

The Worker has no list, arbitrary-delete, pointer, overwrite-current, CORS,
health, or generic upload route. Its sole delete call is hard-bound to the local
random `tempKey` after successful final readback; it never deletes a final or
claim key. On failure the connected plugin may clean only the returned exact
`temp_key`. Pointer CAS and public release activation remain later Cloudflare
plugin operations after every immutable object has passed independent public
readback.
