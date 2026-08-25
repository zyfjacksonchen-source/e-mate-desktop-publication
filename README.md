# e-Mate Desktop protected publication action

This repository is the external production owner for the first signed e-Mate
Desktop feed. It does not build, test, relabel, or discover release bytes. It
self-downloads exact GitHub Actions artifacts, validates all identities before
the first R2 write, adds only the domain-separated Ed25519 signature, and
publishes in one fixed order.

The action is deliberately pinned to:

- caller repository `zyfjacksonchen-source/e-Mate`;
- release `2.0.13`;
- public origin `https://pub-ada3f610c0234a76838f4e19fe2bb25e.r2.dev`;
- legacy `desktop/latest.json` at 948 bytes / SHA-256
  `e6d5e045364bdac97ea7fef41b1e28a20af06c9f4ffdd85d2c136e982d12a7dc`;
- action repository `zyfjacksonchen-source/e-mate-desktop-publication`, invoked
  only as an exact 40-character commit, never a tag or branch.

A future release or repository move requires a reviewed action commit. There is
no generic release switch.

## Required caller state

The caller must first use `actions/setup-node` with Node 24, then invoke this
action from `workflow_dispatch` on `refs/heads/main`. GitHub must report
`GITHUB_REF_PROTECTED=true`; the branch-protection API must independently show
strict required check `CI admission` and enforcement for administrators.

The action accepts these non-secret inputs:

| Input | Contract |
| --- | --- |
| `source-sha` | Current protected `main`, exact successful CI/build/performance/admission source |
| `main-ci-run-id` | Successful `.github/workflows/ci.yml` push run with `CI admission` |
| `admission-artifact-id` | `e-mate-desktop-admission-<sha>` from a completed successful `desktop-admission.yml` run |
| `expected-signed-current` | `absent`, or exact `<bytes>:<sha256>` for an idempotent same-candidate replay |
| `signing-key-id` | Existing key in the admitted Base `profile_signing_keys` and signed performance admission |

The R2 bucket is not caller-selectable: the action pins
`emate-desktop-downloads`, matching the fixed public origin.

The admission artifact is downloaded by ID through GitHub, not accepted from a
caller path. Its file set is exactly:

```text
base-contract.json
desktop-release-unsigned.json
```

`desktop-release-unsigned.json` must be the deterministic 11-field output of
the e-Mate admission producer. Its two GitHub provenance rows point to:

1. `e-mate-desktop-release-<sha>`, produced by the successful build workflow and
   containing exactly the performance-pending candidate plus the formal DMG and
   Setup.exe; and
2. `e-mate-performance-admission-<sha>`, produced by the successful performance
   workflow and containing one `performance-admission.json` plus its evidence.

The action downloads both by artifact ID, matches the GitHub API digest, run,
attempt, workflow, branch, source commit and required successful jobs, then
hashes the extracted installer files again. `mac-smoke` anywhere in an input
archive is a hard failure.

The performance admission is deterministic JSON with these exact fields:

```json
{
  "schema_version": 1,
  "document_type": "emate.performance-admission",
  "status": "passed",
  "performance_run_id": "...",
  "source_commit": "<40 lowercase hex>",
  "base_contract_id": "e-mate-desktop-profile-v7-dsh-...",
  "profile_component_aggregate_sha256": "<64 lowercase hex>",
  "desktop_artifacts": {
    "darwin": { "bytes": 1, "sha256": "<64 lowercase hex>" },
    "win32": { "bytes": 1, "sha256": "<64 lowercase hex>" }
  },
  "evidence_sha256": "<64 lowercase hex>",
  "verifier": {},
  "signature": {
    "algorithm": "ed25519",
    "key_id": "<Base trust key id>",
    "value": "<canonical base64>"
  }
}
```

Its signature context is `e-mate-performance-admission-v1\0`. The raw file
SHA-256, key ID, verifier, installer identities, Profile aggregate, source and
Base must all equal the unsigned Desktop manifest. The release signature uses
the separate context `e-mate-desktop-release-manifest-v1\0` and covers the
canonical 11-field body. The production private key must derive exactly the
SPKI public key already present in the admitted Base contract.

## Secret boundary

Composite actions do not declare secret inputs. The protected environment must
provide these variables directly on the `uses` step:

```yaml
env:
  EMATE_GITHUB_PROVENANCE_TOKEN: ${{ secrets.EMATE_GITHUB_PROVENANCE_TOKEN }}
  EMATE_DESKTOP_SIGNING_PRIVATE_KEY_PEM: ${{ secrets.EMATE_PROFILE_SIGNING_KEY }}
  EMATE_R2_ACCOUNT_ID: ${{ secrets.R2_ACCOUNT_ID }}
  EMATE_R2_ACCESS_KEY_ID: ${{ secrets.R2_ACCESS_KEY_ID }}
  EMATE_R2_SECRET_ACCESS_KEY: ${{ secrets.R2_SECRET_ACCESS_KEY }}
```

The provenance token needs only repository Actions/Contents read plus
Administration read for the branch-protection check. R2 credentials must be
scoped to the one pinned bucket. The action never prints these values, places
them in command arguments, writes them to the receipt, or forwards them to
GitHub artifacts. The signing key is used only in memory. Native child processes
receive an allow-listed environment, so the signer and R2 secrets are not
inherited by `gh` or `unzip`. GitHub artifacts are fetched with `gh` through
`GH_TOKEN`; R2 uses Node 24 `fetch` plus a local SigV4 implementation.

## Threat boundary

The action trusts only GitHub's API/TLS identity, a protected-main source and
successful required jobs, the admitted Base trust root, the protected signing
key, bucket-scoped R2 credentials, and exact caller-supplied run/artifact/current
pointer identities. Caller paths, checkout files, tags, branch-named action
references, artifact prose, provider claims, existing mutable objects and public
HTTP status alone are not authorities.

It does not build or repair candidates, rerun performance checks, choose a Base,
rotate keys, migrate legacy clients, publish Profile desired state, update a
website, or roll back an activated release. Losing GitHub administration-read,
artifact digest support, public full-byte readback, conditional R2 writes or an
exact Base key is a hard stop, not a fallback.

## Fixed write protocol

All GitHub, manifest, Base, signing-key, performance, installer, legacy
tombstone, manual-key and expected-pointer checks complete before the first
write. Authenticated R2 and public reads must agree.

1. Create missing immutable DMG and Setup.exe keys with `If-None-Match: *`.
   Existing keys are accepted only when bytes, SHA-256, content type and cache
   policy are identical.
2. Create `desktop/manual/v2.0.13/latest.json` with `If-None-Match: *`. An
   identical existing object is an idempotent resume; different bytes fail.
3. Read the installers and manual manifest through the public origin and verify
   full byte counts and SHA-256. Re-read the frozen legacy tombstone and the
   expected signed pointer.
4. Activate `desktop/signed/latest.json` with an S3 conditional PUT and
   `Cache-Control: no-store`.
5. Read the active pointer and legacy tombstone again. Emit a non-secret CAS
   receipt.

There is no write operation for `desktop/latest.json`. Any mismatch or partial
failure stops before pointer activation. A retry resumes the same immutable
objects; it never manufactures new bytes or a new sequence.

## Minimal e-Mate workflow wiring

The e-Mate repository still needs one protected admission workflow that runs
after the exact build and performance runs. It should download those artifacts,
run the existing `desktop-release-manifest.ts admit` producer, and upload only
`desktop-release-unsigned.json` plus the exact `base-contract.json` as
`e-mate-desktop-admission-${GITHUB_SHA}`. It must expose a single successful job
named `Desktop release admission`.

The blocked `r2` job in `desktop-release.yml` should remain blocked until that
admission run has completed. A separate protected-environment publish job then:

1. sets up Node 24;
2. invokes this repository at an exact reviewed commit;
3. supplies the five protected secret variables above and the five non-secret
   admission inputs; and
4. uploads only the returned non-secret receipt for audit.

Do not copy this action into the product repository, expose the private key to
the checkout, or replace the exact artifact IDs with paths downloaded by an
operator.

## Local verification

```sh
node --test
```

Tests use generated Ed25519 keys and in-memory GitHub/R2/public adapters. They
perform no network call and no real object write.
