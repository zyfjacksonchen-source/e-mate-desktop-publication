# e-Mate Desktop protected admission actions

This repository has two exact-commit composite actions:

- `/performance` verifies real installed TTFT evidence and signs the performance admission.
- `/` verifies the final protected-main admission, signs the Desktop manifest, and emits a byte-bound publication plan for the connected Codex Cloudflare plugin.

Neither action can read or write production Cloudflare R2 state. The root action
never claims that an object is online or that a pointer changed. Its successful
status is only `ready-for-cloudflare-plugin`.

## Fixed authority

Both actions are deliberately pinned to:

- caller repository `zyfjacksonchen-source/e-Mate-2.0.11`;
- release `2.0.13`;
- protected branch `main` with strict required check `CI admission`, administrator enforcement, linear history, and no force-push or deletion;
- public origin `https://pub-ada3f610c0234a76838f4e19fe2bb25e.r2.dev`;
- bucket `emate-desktop-downloads`;
- action repository `zyfjacksonchen-source/e-mate-desktop-publication`, invoked only by an exact 40-character commit.

A future release or repository move requires a reviewed action commit. There is
no generic release switch.

## Root Desktop handoff action

The caller must use Node 24 and invoke the action from an attempt-1
`workflow_dispatch` run on protected `refs/heads/main`.

Inputs:

| Input | Contract |
| --- | --- |
| `source-sha` | Current protected `main`, shared by every admitted run and artifact |
| `main-ci-run-id` | Successful attempt-1 `.github/workflows/ci.yml` push run with `CI admission` |
| `admission-artifact-id` | Exact attempt-1 `e-mate-desktop-admission-<sha>` artifact |
| `macos-artifact-id` | Exact single-file `e-mate-desktop-macos-<sha>` staging artifact from the admitted Desktop run |
| `windows-artifact-id` | Exact single-file `e-mate-desktop-windows-<sha>` staging artifact from the manifest's Windows build run |
| `expected-signed-current` | Literal `absent`, or exact `<bytes>:<sha256>` for the plugin to recheck before activation |
| `signing-key-id` | Existing key in the admitted Base `profile_signing_keys` and signed performance admission |

The protected admission artifact must contain exactly:

```text
base-contract.json
desktop-release-unsigned.json
```

The unsigned manifest binds the final three-file Desktop artifact and the signed
performance artifact. The action verifies their GitHub API ID, name, archive
digest, run, attempt, workflow, branch, source commit, required jobs, exact file
set, installer byte count, and installer SHA-256. `mac-smoke`, extra files,
path traversal, old attempts, or a different protected-main source fail closed.

The macOS and Windows staging artifacts each contain exactly one installer as a
ZIP `Stored` entry (upload compression level 0). They are independently
downloaded and compared with the same installer in the final three-file
candidate. The plan binds each staging source with:

```text
github_artifact_id
github_artifact_digest
github_run_id
github_run_attempt = 1
github_artifact_name
artifact_path
bytes
sha256
content_type
cache_control
```

This single-file, compression-level-0 staging shape lets the connected
Cloudflare plugin use an action-time range-stream Worker for installers larger
than the direct object API limit. This repository does not deploy that Worker,
obtain a GitHub download redirect, or upload any bytes.

### Three-file output

The action-owned output directory contains exactly:

```text
desktop-release-signed.json
cloudflare-publication-plan.json
cloudflare-plugin-handoff.json
```

`desktop-release-signed.json` is the admitted 11-field manifest plus one
domain-separated Ed25519 signature. Its signing context is
`e-mate-desktop-release-manifest-v1\0`, and the private key must derive exactly
the public key already present in the admitted Base.

`cloudflare-publication-plan.json` has a closed schema. It records:

- status `ready-for-cloudflare-plugin` and authority `codex-cloudflare-plugin`;
- exact repository, source, bucket, public origin, CI/admission/candidate/performance/staging artifact IDs;
- signed-manifest identity, bytes, SHA-256, Base, schedule protocol, and key ID;
- `desktop/latest.json` only as an `expected-unchanged` tombstone with mutation forbidden;
- macOS installer, Windows installer, and manual signed manifest as immutable objects;
- `desktop/signed/latest.json` as the only active pointer, with exact expected current, `no-store`, and `execution_order: last`.

The manual immutable manifest and active pointer reference the same
`desktop-release-signed.json` bytes and SHA-256.

`cloudflare-plugin-handoff.json` binds the manifest and plan hashes to the exact
action commit and GitHub provenance. It explicitly records that no production
write, public readback, or pointer change occurred.

The caller should upload this directory unchanged as
`e-mate-desktop-cloudflare-handoff-<sha>`. The connected Codex Cloudflare plugin
is the sole production writer. It must independently check the plan, expected
tombstone, expected active pointer, immutable-object collisions, uploaded bytes,
metadata, and public readback before changing the active pointer last.

## Protected performance admission action

The independent entrypoint is:

```text
zyfjacksonchen-source/e-mate-desktop-publication/performance@<40-character-commit>
```

It accepts exact IDs for the protected-main CI run, final three-file Desktop
artifact, Profile release run/artifact, current-run evidence artifact, and Base
signing key. It accepts no caller filesystem path.

The downloaded performance evidence artifact must contain root
`e-mate-performance-evidence.json`, exact protected-main
`scripts/performance-parity.mjs`, `profile-component-aggregate.json`, and exactly
the unique evidence files referenced by the native run receipts. The signer:

- recomputes the four-field Profile aggregate and its domain-separated digest;
- compares installer, Base, Profile generation, composition, installed package, and source identities;
- runs the protected verifier under Node 24 with a secret-free child environment;
- accepts only `production-real-provider`, `passed`, production-artifact-verified evidence;
- requires the current performance run and every upstream run to be attempt 1.

The current performance workflow may be `in_progress` only while its already
successful `TTFT evidence` job is being signed. A completed prior run, another
run, fixture evidence, `mac-smoke`, an extra file, or an old attempt is rejected.
The output is `e-mate-performance-admission-<sha>-attempt-1`.

Its signature context is `e-mate-performance-admission-v1\0`. The performance
action behavior is independent of the root publication-plan handoff.

## Secret boundary

Composite actions do not declare secret inputs. The protected environment
provides only:

```yaml
env:
  EMATE_GITHUB_PROVENANCE_TOKEN: ${{ secrets.EMATE_GITHUB_PROVENANCE_TOKEN }}
  EMATE_DESKTOP_SIGNING_PRIVATE_KEY_PEM: ${{ secrets.EMATE_PROFILE_SIGNING_PRIVATE_KEY }}
```

The provenance token needs only repository Actions/Contents read plus
Administration read for branch protection. The signing key stays in memory.
Neither secret is printed, placed in command arguments, written into output, or
forwarded to the performance verifier.

## Local verification

```sh
node --test
```

Tests use generated Ed25519 keys and in-memory GitHub adapters. They perform no
production network call or object write.
