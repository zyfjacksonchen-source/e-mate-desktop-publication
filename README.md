# e-Mate Desktop protected publication action

This repository is the external production owner for the first signed e-Mate
Desktop feed. It does not build, test, relabel, or discover release bytes. It
self-downloads exact GitHub Actions artifacts, validates all identities before
the first R2 write, adds only the domain-separated Ed25519 signature, and
publishes in one fixed order.

The action is deliberately pinned to:

- caller repository `zyfjacksonchen-source/e-Mate-2.0.11`;
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
The currently verified production environment is `r2-publish`; it admits only
protected branches. The private `zyfjacksonchen-source/e-Mate` repository is
not a publication authority and is rejected even if it contains identical
source bytes.

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
hashes the extracted installer files again. The repository's one native
same-source Windows/macOS retry path remains valid: the final candidate run must
contain the successful reuse-admission, macOS and manifest jobs, while the exact
original Windows run must contain successful Profile and Windows jobs and retain
its original run ID in the artifact record. No other cross-run relabelling is
accepted. `mac-smoke` anywhere in an input archive is a hard failure.

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

## Protected performance admission action

The independent action entrypoint is
`zyfjacksonchen-source/e-mate-desktop-publication/performance@<40-character-commit>`.
It verifies and signs evidence only; it has no R2 client or publication step.
In addition to `source-sha`, `main-ci-run-id` and `signing-key-id`, it accepts
only the exact GitHub artifact IDs `desktop-artifact-id` and
`evidence-artifact-id`. It never accepts a caller path or caller-reported
artifact digest.

The downloaded `e-mate-desktop-release-<sha>` artifact must contain exactly:

```text
base-contract.json
desktop-candidate.json
profile-component-aggregate.json
e-Mate-2.0.13-mac-universal.dmg
e-Mate-2.0.13-win-x64-Setup.exe
```

The Base bytes must also equal the file read independently from protected-main
GitHub Contents. Both installer hashes and byte counts must equal the candidate;
the generated Profile aggregate must have the existing target schema. The
action accepts the repository's single same-source native retry contract, but
validates both the final run and the exact original Windows run.

The downloaded `e-mate-performance-evidence-<sha>` artifact must contain the
root `e-mate-performance-evidence.json`, the exact protected-main
`scripts/performance-parity.mjs`, and exactly the unique relative evidence files
named by the three native run receipts. The action compares the verifier bytes
with GitHub Contents, runs that verifier under Node 24 with a secret-free child
environment, and accepts only `production-real-provider` evidence whose gate is
`passed`, whose production artifacts were verified, and whose Base, target
Profile generation, composition and installed package bytes match the build
artifact.

The returned action-owned directory is uploaded as
`e-mate-performance-admission-<sha>`. Its exact file set is root
`performance-admission.json`, root `e-mate-performance-evidence.json`, and the
evidence files referenced by the run receipts—nothing else. The verifier is the
following exact eight-field object inside the signed 11-field admission:

```json
{
  "contract": "ttft-v2",
  "source": "scripts/performance-parity.mjs",
  "source_commit": "<40 lowercase hex>",
  "source_sha256": "<64 lowercase hex>",
  "harness_commit": "<40 lowercase hex>",
  "evidence_filename": "e-mate-performance-evidence.json",
  "decision_sha256": "<64 lowercase hex>",
  "gate_status": "passed"
}
```

`decision_sha256` is the SHA-256 of the verifier's deterministic pretty-JSON
decision plus its final newline. The top-level `evidence_sha256` binds the exact
root evidence bytes. Fixture, `mac-smoke`, extra-file, failed-gate and missing
supporting-evidence artifacts fail closed.

## Secret boundary

Composite actions do not declare secret inputs. The protected environment must
provide these variables directly on the `uses` step:

```yaml
env:
  EMATE_GITHUB_PROVENANCE_TOKEN: ${{ secrets.EMATE_GITHUB_PROVENANCE_TOKEN }}
  EMATE_DESKTOP_SIGNING_PRIVATE_KEY_PEM: ${{ secrets.EMATE_PROFILE_SIGNING_PRIVATE_KEY }}
  EMATE_R2_ACCOUNT_ID: ${{ secrets.ECOREX_R2_ACCOUNT_ID }}
  EMATE_R2_ACCESS_KEY_ID: ${{ secrets.ECOREX_R2_ACCESS_KEY_ID }}
  EMATE_R2_SECRET_ACCESS_KEY: ${{ secrets.ECOREX_R2_SECRET_ACCESS_KEY }}
```

The `/performance` entrypoint receives only
`EMATE_GITHUB_PROVENANCE_TOKEN` and
`EMATE_DESKTOP_SIGNING_PRIVATE_KEY_PEM`; it neither requires nor reads the R2
variables.

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

The root publication entrypoint does not build or repair candidates, rerun performance checks, choose a Base,
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

Read-only production-authority audit at public `main`
`5fb9d595749ee9de4f8019ae4decce02ad3af541` on 2026-08-25:

| Contract | Current public repository state |
| --- | --- |
| `.github/workflows/ci.yml` / `CI admission` | Present and the exact strict required check |
| `.github/workflows/desktop-release.yml` | Present; existing build/reuse/macOS/Windows/manifest job names match this action |
| `e-mate-desktop-release-<sha>` | Present, but currently contains old `latest.json`, not the required `desktop-candidate.json` rich candidate |
| `.github/workflows/desktop-performance.yml` / `Performance admission` | Missing |
| `e-mate-performance-admission-<sha>` | Missing |
| `.github/workflows/desktop-admission.yml` / `Desktop release admission` | Missing |
| `e-mate-desktop-admission-<sha>` | Missing |
| `zyfjacksonchen-source/e-mate-desktop-publication` | Missing; this local commit has not been pushed |
| `r2-publish` Environment | Present, protected-branches-only; signing key ID/private-key bindings exist |

The existing Desktop publisher still writes `desktop/latest.json`. It is a
2.0.12 publisher, not a compatible partial implementation of this action.

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

The current public production repository does not yet contain
`desktop-performance.yml` or `desktop-admission.yml`. Its current
`desktop-release.yml` still emits the old `latest.json` candidate and its
production job writes the legacy `desktop/latest.json`; that job must remain
disabled for 2.0.13. The repository must first land the reviewed rich-candidate
producer, frozen legacy tombstone, signed performance owner and admission
workflows. The current `r2-publish` environment already contains the Profile
signing key ID/private-key bindings, but no GitHub administration-read
provenance-token binding was present at the time of this audit. Existing R2
credential values were not inspected; they must be verified as actual
bucket-scoped S3 credentials because this action intentionally does not carry
the legacy bearer-token conversion fallback.

## Local verification

```sh
node --test
```

Tests use generated Ed25519 keys and in-memory GitHub/R2/public adapters. They
perform no network call and no real object write.
