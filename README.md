# e-Mate Desktop protected admission actions

This repository has two exact-commit composite actions:

- `/` verifies the final protected-main release admission, signs the Desktop manifest, and emits a byte-bound publication plan for the connected Codex Cloudflare plugin.
- `/performance` remains an optional diagnostic action for four installed TTFT v2 evidence leaves. Its output is not a release prerequisite and is not consumed by `/`.

Neither action can read or write production Cloudflare R2 state. The root action
never claims that an object is online or that a pointer changed. Its successful
status is only `ready-for-cloudflare-plugin`.

## Fixed authority

Both actions are deliberately pinned to:

- caller repository `zyfjacksonchen-source/e-Mate-2.0.11`;
- release `2.0.14`;
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
| `macos-artifact-id` | Exact closed `e-mate-desktop-macos-<sha>` staging artifact from the admitted CI run |
| `windows-artifact-id` | Exact closed `e-mate-desktop-windows-<sha>` staging artifact from the admitted CI run |
| `expected-signed-current` | Literal `absent`, or exact `<bytes>:<sha256>` for the plugin to recheck before activation |
| `expected-legacy-current` | Exact approved `desktop/latest.json` predecessor `<bytes>:<sha256>` for the final bridge CAS; only the frozen final 2.0.13 signed manifest identity is accepted |
| `signing-key-id` | Existing key in the admitted Base `profile_signing_keys` |

The protected admission artifact must contain exactly:

```text
base-contract.json
desktop-release-unsigned.json
```

The unsigned manifest binds the final three-file Desktop artifact. The action verifies its GitHub API ID, name, archive
digest, run, attempt, workflow, branch, source commit, required jobs, exact file
set, installer byte count, and installer SHA-256. `mac-smoke`, extra files,
path traversal, old attempts, or a different protected-main source fail closed.

The macOS and Windows staging artifacts each contain the installer, runtime
verification receipt, artifact receipt, and optional blockmap as ZIP `Stored`
entries (upload compression level 0). They are independently downloaded and
compared with the same installer in the final three-file candidate. The plan
binds each staging source with:

```text
github_artifact_id
github_artifact_digest
github_run_id
github_run_attempt = 1
github_artifact_name
github_archive_entries = exact ordered names and byte counts
artifact_path
bytes
sha256
content_type
cache_control
```

This closed, compression-level-0 staging shape lets the connected
Cloudflare plugin use the reviewed short-lived range-stream Worker under
`worker/` for installers larger than the direct object API limit. Neither
composite action deploys that Worker, obtains a GitHub download redirect, or
uploads any bytes; deployment and invocation remain an explicit connected
Cloudflare plugin operation.

### Three-file output

The action-owned output directory contains exactly:

```text
desktop-release-signed.json
cloudflare-publication-plan.json
cloudflare-plugin-handoff.json
```

`desktop-release-signed.json` is the admitted 10-field schema-v2 manifest plus one
domain-separated Ed25519 signature. Its signing context is
`e-mate-desktop-release-manifest-v2\0`, and the private key must derive exactly
the public key already present in the admitted Base.

`cloudflare-publication-plan.json` has a closed schema. It records:

- status `ready-for-cloudflare-plugin` and authority `codex-cloudflare-plugin`;
- exact repository, source, bucket, public origin, CI/admission/candidate/staging artifact IDs;
- signed-manifest identity, bytes, SHA-256, Base, schedule protocol, and key ID;
- macOS installer, Windows installer, and manual signed manifest as immutable objects;
- `desktop/signed/latest.json` as the Base v7 active pointer, with exact expected current and `no-store`;
- `desktop/latest.json` as the one corrective bootstrap pointer, CAS-bound to the exact frozen final 2.0.13 manifest and changed last to the same 2.0.14 signed manifest bytes.

The manual immutable manifest and both active pointers reference the same
`desktop-release-signed.json` bytes and SHA-256. The signed bytes are also
bounded by the 2.0.12 reader's 16 KiB limit. Old clients ignore fields they do
not understand but still require the fixed R2 origin, immutable release path,
byte count, SHA-256, installer format, codesign, native updater transaction and
rollback; after this transition Base v7 reads only the signed pointer.

`cloudflare-plugin-handoff.json` binds the manifest and plan hashes to the exact
action commit and GitHub provenance. It explicitly records that no production
write, public readback, or pointer change occurred.

The caller should upload this directory unchanged as
`e-mate-desktop-cloudflare-handoff-<sha>`. The connected Codex Cloudflare plugin
is the sole production writer. It must independently check the plan, expected
predecessor, both expected active pointers, immutable-object collisions, uploaded
bytes, metadata, and public readback before changing the signed pointer and then
the legacy bootstrap pointer last.

## Protected performance admission action

The independent entrypoint is:

```text
zyfjacksonchen-source/e-mate-desktop-publication/performance@<40-character-commit>
```

It accepts exact IDs for the protected-main CI run, final three-file Desktop
artifact, Profile release run/artifact, four named current-run evidence
artifacts, and Base signing key. It accepts no caller filesystem path. The
ordered roster is fixed to:

1. `ecorex-chat` / `e-mate-enterprise` / `gpt-5.6-luna` / `max`
2. `ecorex-gpt-5.6-sol` / `e-mate-enterprise` / `gpt-5.6-sol` / `medium`
3. `ecorex-deepseek-v4-pro` / `e-mate-enterprise-deepseek` / `deepseek-v4-flash` / `max`
4. `ecorex-doubao-seed-2.0-pro` / `e-mate-enterprise-doubao` / `doubao-seed-2-0-pro-260215` / `medium`

Each downloaded evidence artifact is named
`e-mate-performance-evidence-<leaf-id>-<sha>-attempt-1`, where the ordered leaf
IDs are `luna`, `sol`, `deepseek`, and `doubao`, and must contain root
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
Missing, repeated, reordered, extra, or failed leaves are rejected. The output
is `e-mate-performance-admission-<sha>-attempt-1`, containing root
`performance-admission.json` plus four closed `children/01-luna/` through
`children/04-doubao/` trees.
Each child keeps the existing `e-mate-performance-admission-v1\0` signature and
TTFT v2 verifier contract. The outer document type is
`emate.performance-aggregate-admission`; its
`e-mate-performance-aggregate-admission-v1\0` signature binds the frozen
roster and every child run identity, verifier, evidence SHA, and admission SHA.
Desktop publication verifies the outer signature and all four leaf signatures
before signing, while the Desktop manifest `performance` object remains the
same four fields: `performance_run_id`, `admission_sha256`,
`signature_key_id`, and `verifier`.

The performance action behavior is independent of the root publication-plan
handoff. One reviewed 40-character action commit therefore owns both aggregate
admission and the corresponding Desktop publication verification.

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
