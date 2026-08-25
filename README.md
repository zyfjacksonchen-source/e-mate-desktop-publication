# e-Mate Desktop protected publication action

The supported entrypoint in this repository is the protected performance
admission action. It verifies exact GitHub evidence and adds only a
domain-separated Ed25519 signature; it does not publish.

The root action still contains a direct S3/R2 publication path. It is not an
authorized production implementation: the connected Codex Cloudflare plugin is
the sole production R2 writer. The root publication path must be removed before
this repository can be treated as a production publication owner.

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

## Blocked legacy root consumer contract

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
   containing exactly the performance-pending candidate, formal DMG and
   Setup.exe; and
2. `e-mate-performance-admission-<sha>-attempt-1`, produced by the
   successful performance workflow and containing one
   `performance-admission.json` plus its evidence.

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
the exact GitHub identities `desktop-artifact-id`, `profile-release-run-id`,
`profile-artifact-id`, and `evidence-artifact-id`. It never accepts a caller
path or caller-reported artifact digest.

The downloaded `e-mate-desktop-release-<sha>` artifact must contain exactly:

```text
desktop-candidate.json
e-Mate-2.0.13-mac-universal.dmg
e-Mate-2.0.13-win-x64-Setup.exe
```

The Base is read independently from protected-main GitHub Contents. Both
installer hashes and byte counts must equal the candidate. The action accepts
the repository's single same-source native retry contract, but validates both
the final run and the exact original Windows run.

The Profile artifact must be the exact
`e-mate-profile-native-cloudflare-publication-<sha>` artifact from a completed,
successful `.github/workflows/profile-release.yml` run whose job `Prepare signed
native Cloudflare publication bundle` succeeded.

The downloaded `e-mate-performance-evidence-<sha>-attempt-1` artifact must
contain the root `e-mate-performance-evidence.json`, the exact protected-main
`scripts/performance-parity.mjs`, `profile-component-aggregate.json`, and
exactly the unique relative evidence files named by the three native run
receipts. The aggregate is the four-field output independently recomputed by
protected-main `scripts/desktop-admission.mjs`; the signer requires its exact
closed schema and recomputes its domain-separated `aggregate_sha256`. The action
compares the verifier bytes with GitHub Contents, runs that verifier under Node
24 with a secret-free child environment, and accepts only
`production-real-provider` evidence whose gate is `passed`, whose production
artifacts were verified, and whose Base, target Profile generation, composition
and installed package bytes match the build artifact.

The evidence artifact must belong to the action's own `GITHUB_RUN_ID` and
`GITHUB_RUN_ATTEMPT`, and both must identify attempt 1. While the signer job is
executing, that workflow run must still be `in_progress`, but its `TTFT
evidence` job must already be completed and successful. A completed prior run,
a different run, or an artifact named for an older attempt is rejected. Every
admitted CI, Desktop, Profile, performance and admission run must also be
attempt 1; a failed run requires a new dispatch and run ID, not GitHub rerun.
The publication consumer later requires this run to be completed successfully
with its `Performance admission` job successful.

The returned action-owned directory is uploaded as
`e-mate-performance-admission-<sha>-attempt-1`. Its exact file set is
root `performance-admission.json`, root `e-mate-performance-evidence.json`, and
the evidence files referenced by the run receipts—nothing else. The verifier is
the following exact eight-field object inside the signed 11-field admission:

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
```

The `/performance` entrypoint neither requires nor reads `EMATE_R2_*`. The
provenance token needs only repository Actions/Contents read plus Administration
read for the branch-protection check. The action never prints either secret,
places it in command arguments, writes it to the output artifact, or forwards
it to the verifier child. The signing key is used only in memory.

## Threat boundary

The performance action trusts only GitHub's API/TLS identity, protected-main
source, exact attempt-1 successful jobs and artifacts, the Base trust root, and
the protected signing key. Caller paths, checkout files, tags, branch-named
action references, artifact prose, provider claims and public HTTP status are
not authorities.

## Blocked legacy root entrypoint

`action.yml` and `src/main.mjs` still contain a direct S3/R2 writer. This is a
release blocker, not a supported fallback or publishable implementation. It
must be deleted; production uploads, readback and activation belong exclusively
to the connected Codex Cloudflare plugin.

## Minimal e-Mate workflow wiring

Read-only production-authority audit at public `main`
`5fb9d595749ee9de4f8019ae4decce02ad3af541` on 2026-08-25:

| Contract | Current public repository state |
| --- | --- |
| `.github/workflows/ci.yml` / `CI admission` | Present and the exact strict required check |
| `.github/workflows/desktop-release.yml` | Present; existing build/reuse/macOS/Windows/manifest job names match this action |
| `e-mate-desktop-release-<sha>` | Present, but currently contains old `latest.json`, not the required `desktop-candidate.json` rich candidate |
| `.github/workflows/desktop-performance.yml` / `Performance admission` | Missing |
| `e-mate-performance-admission-<sha>-attempt-1` | Missing |
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

The blocked `r2` job in `desktop-release.yml` must remain blocked. After every
admission gate succeeds, the connected Codex Cloudflare plugin is the sole
production upload, readback and activation authority.

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
provenance-token binding was present at the time of this audit. No R2 credential
is required or accepted by the supported performance action.

## Local verification

```sh
node --test
```

Tests use generated Ed25519 keys and in-memory GitHub/R2/public adapters. They
perform no network call and no real object write.
