import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash, generateKeyPairSync, verify } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { describe, it } from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  CLOUDFLARE_HANDOFF_FILENAME,
  DESKTOP_RELEASE_ARTIFACT_FILES,
  EXPECTED_ACTION_REPOSITORY,
  EXPECTED_REPOSITORY,
  LEGACY_PREDECESSOR,
  PUBLICATION_PLAN_FILENAME,
  PUBLIC_ORIGIN,
  RELEASE_SIGNATURE_CONTEXT,
  SIGNED_MANIFEST_FILENAME,
  bufferSource,
  canonicalJson,
  parseExpectedCurrent,
  prepareDesktopPublication,
} from '../src/publisher.mjs'
import { parseStoredArchiveEntries, validateArchiveEntries } from '../src/main.mjs'

const SOURCE = 'a'.repeat(40)
const BASE_ID = `e-mate-desktop-profile-v7-dsh-${SOURCE.slice(0, 12)}`
const KEY_ID = 'e0a81164526dcbcd'
const MACOS_CI_ARCHIVE_SHA256 = 'a'.repeat(64)
const MACOS_CI_ARCHIVE_BYTES = 1206
const DEVELOPER_TEAM_ID = 'ABCDE12345'

describe('external Desktop Cloudflare plugin handoff owner', () => {
  it('initializes the GitHub client before running the executable entrypoint', () => {
    const result = spawnSync(process.execPath, [fileURLToPath(new URL('../src/main.mjs', import.meta.url))], {
      encoding: 'utf8',
      env: { PATH: process.env.PATH ?? '' },
    })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /required publication binding GITHUB_REPOSITORY is missing/u)
    assert.doesNotMatch(result.stderr, /before initialization/u)
  })

  it('verifies protected evidence, signs once, and emits only a closed three-file handoff', async () => {
    const fixture = releaseFixture()
    const result = await fixture.prepare()
    assert.equal(result.artifactName, `e-mate-desktop-cloudflare-handoff-${SOURCE}`)
    assert.deepEqual([...result.files.keys()], [
      SIGNED_MANIFEST_FILENAME,
      PUBLICATION_PLAN_FILENAME,
      CLOUDFLARE_HANDOFF_FILENAME,
    ])

    const signedBytes = await result.files.get(SIGNED_MANIFEST_FILENAME).read()
    const signed = JSON.parse(signedBytes)
    const { signature, ...unsigned } = signed
    assert.equal(signature.key_id, KEY_ID)
    assert.deepEqual(Object.keys(signature), ['algorithm', 'key_id', 'value'])
    assert.equal(unsigned.schema_version, 2)
    assert.deepEqual(Object.keys(unsigned), [
      'schema_version', 'document_type', 'release_status', 'version', 'source_commit',
      'base_contract_id', 'schedule_protocol_floor', 'profile_component_aggregate',
      'github_artifact_provenance', 'artifacts',
    ])
    assert.deepEqual(Object.keys(signed), [...Object.keys(unsigned), 'signature'])
    assert.equal('publication_metadata' in signed, false)
    assert.equal(verify(
      null,
      Buffer.concat([RELEASE_SIGNATURE_CONTEXT, Buffer.from(canonicalJson(unsigned), 'utf8')]),
      fixture.keyPair.publicKey,
      Buffer.from(signature.value, 'base64'),
    ), true)
    for (const incompatible of [
      { ...unsigned, schema_version: 4 },
      { ...unsigned, publication_metadata: { mode: 'unsigned' } },
    ]) {
      assert.equal(verify(
        null,
        Buffer.concat([RELEASE_SIGNATURE_CONTEXT, Buffer.from(canonicalJson(incompatible), 'utf8')]),
        fixture.keyPair.publicKey,
        Buffer.from(signature.value, 'base64'),
      ), false)
    }
    assert.equal(verify(
      null,
      Buffer.concat([
        Buffer.from('e-mate-desktop-release-manifest-v4\0', 'utf8'),
        Buffer.from(canonicalJson(unsigned), 'utf8'),
      ]),
      fixture.keyPair.publicKey,
      Buffer.from(signature.value, 'base64'),
    ), false)

    const planBytes = await result.files.get(PUBLICATION_PLAN_FILENAME).read()
    const plan = JSON.parse(planBytes)
    assert.equal(plan.schema_version, 4)
    assert.deepEqual(Object.keys(plan), [
      'schema_version', 'document_type', 'status', 'publication_authority', 'repository',
      'source_commit', 'bucket', 'public_origin', 'github', 'publication_metadata', 'signed_manifest',
      'immutable_objects', 'active_pointer', 'legacy_bootstrap_pointer',
    ])
    assert.equal(plan.status, 'ready-for-cloudflare-plugin')
    assert.equal(plan.publication_authority, 'codex-cloudflare-plugin')
    assert.deepEqual(plan.github, {
      main_ci_run_id: '100',
      macos_publication_mode: 'signed',
      macos_signer_run_id: '105',
      admission_artifact_id: '201',
      desktop_artifact_id: '202',
      macos_signed_artifact_id: '208',
      windows_staging_artifact_id: '207',
    })
    assert.deepEqual(plan.publication_metadata, {
      description: 'e-Mate 2.0.15 publishes a Developer ID signed and notarized macOS installer and an unsigned Windows installer.',
      platforms: {
        darwin: { mode: 'signed', signed: true, notarized: true, description: 'Developer ID signed and notarized.' },
        win32: { mode: 'unsigned', signed: false, notarized: false, description: 'Unsigned and not notarized.' },
      },
    })
    assert.equal(plan.active_pointer.execution_order, 'before-legacy-bootstrap')
    assert.equal(plan.active_pointer.expected_current, 'absent')
    assert.equal(plan.active_pointer.cache_control, 'no-store')
    assert.deepEqual(plan.legacy_bootstrap_pointer, {
      execution_order: 'last',
      key: LEGACY_PREDECESSOR.key,
      url: `${PUBLIC_ORIGIN}/${LEGACY_PREDECESSOR.key}`,
      expected_current: `${LEGACY_PREDECESSOR.bytes}:${LEGACY_PREDECESSOR.sha256}`,
      artifact_path: SIGNED_MANIFEST_FILENAME,
      bytes: signedBytes.byteLength,
      sha256: sha256(signedBytes),
      content_type: 'application/json',
      cache_control: 'no-store',
    })

    const [mac, win, manual] = plan.immutable_objects
    assert.deepEqual([mac.github_artifact_id, win.github_artifact_id], ['208', '207'])
    assert.deepEqual([mac.github_run_id, win.github_run_id], ['105', '100'])
    assert.deepEqual([mac.github_run_attempt, win.github_run_attempt], [1, 1])
    assert.deepEqual([mac.github_artifact_name, win.github_artifact_name], [
      `e-mate-desktop-macos-signed-${SOURCE}`,
      `e-mate-desktop-windows-${SOURCE}`,
    ])
    assert.deepEqual([mac.artifact_path, win.artifact_path], DESKTOP_RELEASE_ARTIFACT_FILES.slice(1))
    assert.ok([mac, win].every(item => /^sha256:[0-9a-f]{64}$/u.test(item.github_artifact_digest)))
    assert.deepEqual([mac.github_artifact_bytes, win.github_artifact_bytes], [1208, 1207])
    assert.deepEqual(mac.github_archive_entries.map(item => item.name), [
      'desktop-macos-signed-receipt.json',
      'desktop-macos-signed-verification.json',
      'e-Mate-2.0.15-mac-universal.dmg',
      'e-Mate-2.0.15-mac-universal.dmg.blockmap',
    ])
    assert.deepEqual(win.github_archive_entries.map(item => item.name), [
      'desktop-artifact-receipt.json',
      'desktop-runtime-verification.json',
      'e-Mate-2.0.15-win-x64-Setup.exe',
    ])
    assert.equal(manual.artifact_path, SIGNED_MANIFEST_FILENAME)
    for (const field of ['bytes', 'sha256', 'content_type']) {
      assert.equal(manual[field], plan.active_pointer[field])
      assert.equal(manual[field], plan.legacy_bootstrap_pointer[field])
    }
    assert.equal(manual.sha256, sha256(signedBytes))

    const handoff = JSON.parse(await result.files.get(CLOUDFLARE_HANDOFF_FILENAME).read())
    assert.equal(handoff.schema_version, 4)
    assert.deepEqual(Object.keys(handoff), [
      'schema_version', 'document_type', 'status', 'publication_authority', 'repository',
      'source_commit', 'action', 'github', 'publication_metadata', 'files', 'production_state',
    ])
    assert.equal(handoff.status, 'ready-for-cloudflare-plugin')
    assert.deepEqual(handoff.production_state, {
      r2_write_performed: false,
      public_readback_performed: false,
      active_pointer_changed: false,
      legacy_pointer_changed: false,
    })
    assert.equal(handoff.files.signed_manifest.sha256, sha256(signedBytes))
    assert.equal(handoff.files.publication_plan.sha256, sha256(planBytes))
    const forbiddenStatus = new RegExp(`"status":"(?:publi${'shed'}|already-publi${'shed'})"`, 'u')
    assert.doesNotMatch(JSON.stringify({ plan, handoff }), forbiddenStatus)
  })

  it('publishes exact formal-CI unsigned macOS bytes with explicit unsigned security state', async () => {
    const fixture = releaseFixture({ macosPublicationMode: 'unsigned' })
    const result = await fixture.prepare()
    const manifest = JSON.parse(await result.files.get(SIGNED_MANIFEST_FILENAME).read())
    const plan = JSON.parse(await result.files.get(PUBLICATION_PLAN_FILENAME).read())
    assert.equal(manifest.schema_version, 2)
    assert.equal('publication_metadata' in manifest, false)
    assert.deepEqual(plan.github, {
      main_ci_run_id: '100',
      macos_publication_mode: 'unsigned',
      admission_artifact_id: '201',
      desktop_artifact_id: '202',
      macos_unsigned_artifact_id: '206',
      windows_staging_artifact_id: '207',
    })
    assert.deepEqual(plan.publication_metadata, {
      description: 'e-Mate 2.0.15 publishes unsigned macOS and Windows installers; macOS is not notarized.',
      platforms: {
        darwin: { mode: 'unsigned', signed: false, notarized: false, description: 'Unsigned and not notarized.' },
        win32: { mode: 'unsigned', signed: false, notarized: false, description: 'Unsigned and not notarized.' },
      },
    })
    const [mac, win] = plan.immutable_objects
    assert.deepEqual([mac.github_artifact_id, win.github_artifact_id], ['206', '207'])
    assert.deepEqual([mac.github_run_id, win.github_run_id], ['100', '100'])
    assert.deepEqual([mac.github_artifact_bytes, win.github_artifact_bytes], [MACOS_CI_ARCHIVE_BYTES, 1207])
    assert.deepEqual([mac.github_artifact_name, win.github_artifact_name], [
      `e-mate-desktop-macos-${SOURCE}`,
      `e-mate-desktop-windows-${SOURCE}`,
    ])
    assert.deepEqual(mac.github_archive_entries.map(item => item.name), [
      'desktop-artifact-receipt.json',
      'desktop-runtime-verification.json',
      'e-Mate-2.0.15-mac-universal.dmg',
      'e-Mate-2.0.15-mac-universal.dmg.blockmap',
    ])
    assert.deepEqual([mac.publication_metadata, win.publication_metadata], [
      plan.publication_metadata.platforms.darwin,
      plan.publication_metadata.platforms.win32,
    ])
    assert.equal(JSON.stringify(plan).includes('Developer ID'), false)
    assert.equal(JSON.stringify(plan).includes('Accepted'), false)
  })

  it('fails closed on macOS publication mode confusion and unsigned provenance drift', async t => {
    const cases = [
      ['unknown mode', fixture => { fixture.config.macosPublicationMode = 'automatic' }],
      ['unsigned mode without unsigned artifact', fixture => { fixture.config.macosUnsignedArtifactId = undefined }],
      ['signed mode without signed artifact', fixture => { fixture.config.macosSignedArtifactId = undefined }],
      ['unsigned mode with signer run', fixture => { fixture.config.macosSignerRunId = '105' }],
      ['unsigned mode with signed artifact', fixture => { fixture.config.macosSignedArtifactId = '208' }],
      ['signed mode with unsigned artifact', fixture => { fixture.config.macosUnsignedArtifactId = '206' }],
      ['unsigned candidate owned by signer', fixture => {
        for (const [id, name] of [['201', 'desktop-release-unsigned.json'], ['202', 'desktop-candidate.json']]) {
          mutateJson(fixture, id, name, value => { value.artifacts.darwin.build_run_id = '105' })
        }
      }],
      ['unsigned mode with signed Desktop release job', fixture => {
        fixture.github.jobs.set('102', [job('Bind exact signed macOS and protected-main CI Windows bytes')])
      }],
      ['unsigned mode with signed artifact id', fixture => { fixture.config.macosUnsignedArtifactId = '208' }],
      ['unsigned artifact ID drift', fixture => { fixture.github.artifacts.get('206').metadata.id = '999' }],
      ['unsigned artifact name drift', fixture => { fixture.github.artifacts.get('206').metadata.name = 'other' }],
      ['unsigned artifact from wrong run', fixture => { fixture.github.artifacts.get('206').metadata.runId = '101' }],
      ['unsigned artifact source drift', fixture => { fixture.github.artifacts.get('206').metadata.sourceCommit = 'b'.repeat(40) }],
      ['unsigned artifact API digest drift', fixture => {
        fixture.github.artifacts.get('206').metadata.digest = `sha256:${'e'.repeat(64)}`
      }],
      ['unsigned artifact API archive bytes drift', fixture => { fixture.github.artifacts.get('206').metadata.bytes += 1 }],
      ['unsigned artifact archive digest drift', fixture => { fixture.github.artifacts.get('206').bundle.archiveSha256 = 'f'.repeat(64) }],
      ['unsigned artifact bytes drift', fixture => {
        fixture.github.replaceFile('206', 'e-Mate-2.0.15-mac-universal.dmg', Buffer.from('other'))
      }],
      ['unsigned artifact archive bytes drift', fixture => { fixture.github.artifacts.get('206').bundle.archiveBytes += 1 }],
      ['unsigned artifact missing blockmap', fixture => {
        fixture.github.artifacts.get('206').bundle.files.delete('e-Mate-2.0.15-mac-universal.dmg.blockmap')
      }],
      ['unsigned artifact extra file', fixture => {
        fixture.github.artifacts.get('206').bundle.files.set('extra.bin', testSource('extra'))
      }],
      ['unsigned artifact traversal file', fixture => {
        fixture.github.artifacts.get('206').bundle.files.set('../escape', testSource('extra'))
      }],
      ['unsigned runtime Harness drift', fixture => {
        mutateJson(fixture, '206', 'desktop-runtime-verification.json', value => { value.harness_commit = 'b'.repeat(40) })
      }],
      ['unsigned runtime adds signing claim', fixture => {
        mutateJson(fixture, '206', 'desktop-runtime-verification.json', value => { value.installer.signed = true })
      }],
    ]
    for (const [name, mutate] of cases) {
      await t.test(name, async () => {
        const fixture = releaseFixture({ macosPublicationMode: name.startsWith('signed') ? 'signed' : 'unsigned' })
        mutate(fixture)
        await assert.rejects(fixture.prepare())
      })
    }
  })

  it('keeps the expected active pointer identity as data for the plugin, without reading it', async () => {
    const fixture = releaseFixture()
    fixture.config.expectedSignedCurrent = { bytes: 123, sha256: 'f'.repeat(64) }
    const result = await fixture.prepare()
    const plan = JSON.parse(await result.files.get(PUBLICATION_PLAN_FILENAME).read())
    assert.equal(plan.active_pointer.expected_current, `123:${'f'.repeat(64)}`)
    assert.equal(parseExpectedCurrent('absent'), null)
    assert.deepEqual(parseExpectedCurrent(`123:${'f'.repeat(64)}`), fixture.config.expectedSignedCurrent)
    assert.throws(() => parseExpectedCurrent('latest'), /expected signed current/u)

    assert.deepEqual(fixture.config.expectedLegacyCurrent, {
      bytes: LEGACY_PREDECESSOR.bytes,
      sha256: LEGACY_PREDECESSOR.sha256,
    })

    fixture.config.expectedLegacyCurrent = { bytes: LEGACY_PREDECESSOR.bytes, sha256: 'e'.repeat(64) }
    await assert.rejects(fixture.prepare(), /exact approved predecessor/u)
  })

  it('binds the mandatory signed blockmap without turning it or the unsigned CI input into an immutable object', async () => {
    const fixture = releaseFixture()
    const result = await fixture.prepare()
    const plan = JSON.parse(await result.files.get(PUBLICATION_PLAN_FILENAME).read())
    assert.equal(plan.immutable_objects[0].artifact_path, 'e-Mate-2.0.15-mac-universal.dmg')
    assert.equal(plan.immutable_objects.some(item => item.artifact_path.endsWith('.blockmap')), false)
    assert.equal(plan.immutable_objects.some(item => item.github_artifact_id === '206'), false)
    assert.deepEqual(plan.immutable_objects[0].github_archive_entries.map(item => item.name), [
      'desktop-macos-signed-receipt.json',
      'desktop-macos-signed-verification.json',
      'e-Mate-2.0.15-mac-universal.dmg',
      'e-Mate-2.0.15-mac-universal.dmg.blockmap',
    ])
  })

  it('fails closed on authority, provenance, closed-schema, staging, or trust drift', async t => {
    const cases = [
      ['unexpected repository', fixture => { fixture.config.repository = 'zyfjacksonchen-source/e-Mate' }],
      ['unprotected main', fixture => { fixture.config.refProtected = false }],
      ['private repository', fixture => { fixture.github.repository.visibility = 'private' }],
      ['ordinary push cannot impersonate formal RC', fixture => { fixture.github.runs.get('100').event = 'push' }],
      ['failed CI', fixture => { fixture.github.jobs.get('100')[0].conclusion = 'failure' }],
      ['rerun CI', fixture => { fixture.github.runs.get('100').runAttempt = 2 }],
      ['2.0.14 manifest', fixture => {
        mutateJson(fixture, '201', 'desktop-release-unsigned.json', value => { value.version = '2.0.14' })
      }],
      ['darwin bound to formal CI instead of signer', fixture => {
        for (const [id, name] of [['201', 'desktop-release-unsigned.json'], ['202', 'desktop-candidate.json']]) {
          mutateJson(fixture, id, name, value => { value.artifacts.darwin.build_run_id = '100' })
        }
      }],
      ['wrong signer workflow path', fixture => {
        fixture.github.runs.get('105').path = '.github/workflows/ci.yml'
      }],
      ['rerun signer', fixture => { fixture.github.runs.get('105').runAttempt = 2 }],
      ['failed signer job', fixture => { fixture.github.jobs.get('105')[0].conclusion = 'failure' }],
      ['duplicate signer job', fixture => { fixture.github.jobs.get('105').push(job('Sign and notarize exact accepted macOS bytes')) }],
      ['signed artifact from wrong run', fixture => { fixture.github.artifacts.get('208').metadata.runId = '100' }],
      ['unsigned macOS artifact cannot replace signed output', fixture => { fixture.config.macosSignedArtifactId = '206' }],
      ['signed artifact ID drift', fixture => { fixture.github.artifacts.get('208').metadata.id = '999' }],
      ['signed artifact name drift', fixture => { fixture.github.artifacts.get('208').metadata.name = 'other' }],
      ['signed artifact source drift', fixture => { fixture.github.artifacts.get('208').metadata.sourceCommit = 'b'.repeat(40) }],
      ['signed artifact API digest drift', fixture => { fixture.github.artifacts.get('208').metadata.digest = `sha256:${'f'.repeat(64)}` }],
      ['signed artifact archive digest drift', fixture => { fixture.github.artifacts.get('208').bundle.archiveSha256 = 'f'.repeat(64) }],
      ['extra signed artifact file', fixture => {
        fixture.github.artifacts.get('208').bundle.files.set('extra.bin', testSource('extra'))
      }],
      ['missing signed blockmap', fixture => {
        fixture.github.artifacts.get('208').bundle.files.delete('e-Mate-2.0.15-mac-universal.dmg.blockmap')
      }],
      ['unsafe signed artifact path', fixture => {
        fixture.github.artifacts.get('208').bundle.files.set('../escape', testSource('extra'))
      }],
      ['compressed signed artifact entry', fixture => {
        fixture.github.artifacts.get('208').bundle.stored.delete('e-Mate-2.0.15-mac-universal.dmg')
      }],
      ['signed receipt source drift', fixture => {
        mutateJson(fixture, '208', 'desktop-macos-signed-receipt.json', value => { value.source_commit = 'b'.repeat(40) })
      }],
      ['signed receipt input artifact digest drift', fixture => {
        mutateJson(fixture, '208', 'desktop-macos-signed-receipt.json', value => { value.input.artifact_api_digest = `sha256:${'f'.repeat(64)}` })
      }],
      ['Developer ID team drift', fixture => {
        mutateJson(fixture, '208', 'desktop-macos-signed-receipt.json', value => { value.developer_id.team_id = 'ZZZZZ99999' })
      }],
      ['notary rejection', fixture => {
        mutateJson(fixture, '208', 'desktop-macos-signed-receipt.json', value => { value.notarization.status = 'Invalid' })
      }],
      ['signed output equals unsigned input', fixture => {
        mutateJson(fixture, '208', 'desktop-macos-signed-receipt.json', value => { value.output.dmg.sha256 = value.input.dmg.sha256 })
      }],
      ['signed verification check drift', fixture => {
        mutateJson(fixture, '208', 'desktop-macos-signed-verification.json', value => { value.checks.stapler_dmg = 'invalid' })
      }],
      ['unsigned input artifact archive digest drift', fixture => { fixture.github.artifacts.get('206').bundle.archiveSha256 = 'f'.repeat(64) }],
      ['rerun admission', fixture => { fixture.github.runs.get('101').runAttempt = 2 }],
      ['rerun Desktop build', fixture => { fixture.github.runs.get('102').runAttempt = 2 }],
      ['old Desktop release job name', fixture => {
        fixture.github.jobs.set('102', [job('Bind exact protected-main CI artifacts to the release manifest')])
      }],
      ['extra admission file', fixture => {
        fixture.github.artifacts.get('201').bundle.files.set('extra.json', testSource('{}'))
      }],
      ['extra final candidate file', fixture => {
        fixture.github.artifacts.get('202').bundle.files.set('extra.bin', testSource('extra'))
      }],
      ['extra staging file', fixture => {
        fixture.github.artifacts.get('207').bundle.files.set('extra.bin', testSource('extra'))
      }],
      ['missing staging receipt', fixture => {
        fixture.github.artifacts.get('207').bundle.files.delete('desktop-artifact-receipt.json')
      }],
      ['staging receipt digest drift', fixture => {
        const receipt = JSON.parse(fixture.github.file('207', 'desktop-artifact-receipt.json').buffer)
        receipt.files[0].sha256 = 'f'.repeat(64)
        fixture.github.replaceFile('207', 'desktop-artifact-receipt.json', pretty(receipt))
      }],
      ['runtime verification run drift', fixture => {
        const runtime = JSON.parse(fixture.github.file('207', 'desktop-runtime-verification.json').buffer)
        runtime.ci_run_id = '99'
        fixture.github.replaceFile('207', 'desktop-runtime-verification.json', pretty(runtime))
      }],
      ['mac-smoke staging file', fixture => {
        fixture.github.artifacts.get('207').bundle.files.set('mac-smoke.dmg', testSource('smoke'))
      }],
      ['staging artifact run drift', fixture => {
        fixture.github.artifacts.get('207').metadata.runId = '101'
      }],
      ['compressed staging entry', fixture => {
        fixture.github.artifacts.get('207').bundle.stored.delete('e-Mate-2.0.15-win-x64-Setup.exe')
      }],
      ['compressed staging receipt', fixture => {
        fixture.github.artifacts.get('207').bundle.stored.delete('desktop-artifact-receipt.json')
      }],
      ['final installer bytes drift', fixture => {
        fixture.github.replaceFile('202', 'e-Mate-2.0.15-win-x64-Setup.exe', Buffer.from('other'))
      }],
      ['Base trust-key drift', fixture => {
        const base = JSON.parse(fixture.github.file('201', 'base-contract.json').buffer)
        base.profile_signing_keys[0].public_key_spki_der_base64 = Buffer.alloc(44).toString('base64')
        fixture.github.replaceFile('201', 'base-contract.json', pretty(base))
      }],
      ['unsigned manifest extra field', fixture => {
        const manifest = JSON.parse(fixture.github.file('201', 'desktop-release-unsigned.json').buffer)
        manifest.channel = 'stable'
        fixture.github.replaceFile('201', 'desktop-release-unsigned.json', pretty(manifest))
      }],
    ]
    for (const [name, mutate] of cases) {
      await t.test(name, async () => {
        const fixture = releaseFixture()
        mutate(fixture)
        await assert.rejects(fixture.prepare())
      })
    }
  })

  it('has no R2 credential, object client, network write, or publication claim in the root action', async () => {
    const sources = await Promise.all([
      readFile(new URL('../action.yml', import.meta.url), 'utf8'),
      readFile(new URL('../src/main.mjs', import.meta.url), 'utf8'),
      readFile(new URL('../src/publisher.mjs', import.meta.url), 'utf8'),
    ])
    assert.match(sources[0], /^  macos-signer-run-id:/mu)
    assert.match(sources[0], /^  macos-signed-artifact-id:/mu)
    assert.match(sources[0], /^  macos-publication-mode:/mu)
    assert.match(sources[0], /^  macos-unsigned-artifact-id:/mu)
    assert.match(sources[1], /EMATE_MACOS_SIGNER_RUN_ID/u)
    assert.match(sources[1], /EMATE_MACOS_SIGNED_ARTIFACT_ID/u)
    assert.match(sources[1], /EMATE_MACOS_PUBLICATION_MODE/u)
    assert.match(sources[1], /EMATE_MACOS_UNSIGNED_ARTIFACT_ID/u)
    assert.doesNotMatch(`${sources[0]}\n${sources[1]}`, /EMATE_MACOS_STAGING_ARTIFACT_ID/u)
    const text = sources.join('\n')
    const forbidden = new RegExp([
      `EMATE_${'R2_'}`, `${'R2'}${'Store'}`, `HttpObject${'Reader'}`, `cloudflare${'storage'}`,
      `AWS4-${'HMAC'}`, `secret${'AccessKey'}`, `access${'KeyId'}`, `putCreate${'Only'}`, `put${'Cas'}`,
    ].join('|'), 'u')
    assert.doesNotMatch(text, forbidden)
    assert.doesNotMatch(text, /method:\s*['"](?:PUT|HEAD)['"]/u)
    const publicationClaim = new RegExp(`status:\\s*['"](?:publi${'shed'}|already-publi${'shed'})['"]`, 'u')
    assert.doesNotMatch(text, publicationClaim)
    assert.match(text, /ready-for-cloudflare-plugin/u)
    assert.match(text, /codex-cloudflare-plugin/u)
  })

  it('rejects archive paths that could escape or be reinterpreted by unzip', () => {
    assert.doesNotThrow(() => validateArchiveEntries(['base-contract.json', 'evidence/receipt.json']))
    for (const path of ['../escape', '/absolute', 'wild*card', '-option', 'link/../../secret', 'line\nbreak']) {
      assert.throws(() => validateArchiveEntries([path]), /artifact path/u)
    }
  })

  it('accepts only a ZIP stored entry for the range-stream installer source', () => {
    const listing = [
      '      19  Stored       19   0% 08-25-2026 00:00 00000000  e-Mate-2.0.15-mac-universal.dmg',
      '      20  Defl:N       18  10% 08-25-2026 00:00 00000000  e-Mate-2.0.15-win-x64-Setup.exe',
    ].join('\n')
    assert.deepEqual([...parseStoredArchiveEntries(listing, DESKTOP_RELEASE_ARTIFACT_FILES.slice(1))], [
      'e-Mate-2.0.15-mac-universal.dmg',
    ])
  })
})

function releaseFixture(options = {}) {
  const macosPublicationMode = options.macosPublicationMode ?? 'signed'
  const keyPair = generateKeyPairSync('ed25519')
  const privateKeyPem = keyPair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
  const publicKey = keyPair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
  const unsignedMac = Buffer.from('exact-unsigned-mac-installer')
  const mac = Buffer.from('exact-signed-mac-installer')
  const blockmap = Buffer.from('exact-signed-blockmap')
  const win = Buffer.from('exact-windows-installer')
  const aggregate = {
    aggregate_sha256: 'e296a56501500b1383041407beeb3421feedf1729f90ff210fb5cc8a7bc63ada',
    inventory_sha256: '2'.repeat(64),
    staged_profile_tree_sha256: '3'.repeat(64),
    targets: ['darwin-arm64', 'darwin-x64', 'win32-x64'].map(target => ({
      target,
      profile_generation: '4'.repeat(64),
      component_aggregate_sha256: '5'.repeat(64),
    })),
  }
  const publishedMac = macosPublicationMode === 'signed' ? mac : unsignedMac
  const artifacts = {
    darwin: manifestArtifact('darwin', publishedMac, macosPublicationMode === 'signed' ? '105' : '100'),
    win32: manifestArtifact('win32', win, '100'),
  }
  const candidateBundleSha = '7'.repeat(64)
  const provenance = {
    schema_version: 1,
    document_type: 'emate.github-artifact-provenance',
    source_commit: SOURCE,
    artifacts: [
      {
        role: 'desktop_candidate',
        name: `e-mate-desktop-release-${SOURCE}`,
        artifact_id: '202',
        digest: `sha256:${candidateBundleSha}`,
        run_id: '102',
        run_attempt: 1,
      },
    ],
  }
  const manifest = {
    schema_version: 2,
    document_type: 'emate.desktop-release-manifest',
    release_status: 'admitted',
    version: '2.0.15',
    source_commit: SOURCE,
    base_contract_id: BASE_ID,
    schedule_protocol_floor: 1,
    profile_component_aggregate: aggregate,
    github_artifact_provenance: provenance,
    artifacts,
  }
  const candidate = {
    schema_version: 2,
    document_type: 'emate.desktop-artifact-candidate',
    release_status: 'admission-pending',
    version: '2.0.15',
    source_commit: SOURCE,
    schedule_protocol_floor: 1,
    artifacts,
  }
  const base = {
    schema_version: 1,
    id: BASE_ID,
    desktop_api: 1,
    profile_format: 1,
    desktop_reference: {
      repository: 'anywhere-labs/deepseek-harness-desktop',
      commit: 'b'.repeat(40),
      harness_repository: 'deepseek-ai/deepseek-harness',
      harness_commit: 'c'.repeat(40),
      harness_version: '0.1.0-rc.7',
    },
    schedule_protocol_floor: 1,
    harness_version: '0.1.0-rc.7',
    harness_commit: SOURCE,
    runtime_imports: {
      '@deepseek-ai/dsh-client-runtime': '0.1.0-rc.7',
      react: '18.3.1',
    },
    profile_signing_keys: [{
      id: KEY_ID,
      algorithm: 'ed25519',
      public_key_spki_der_base64: publicKey,
    }],
  }
  const macosCiFiles = stagingFiles('darwin', unsignedMac, Buffer.from('exact-unsigned-blockmap'))
  const github = new FakeGithub({
    source: SOURCE,
    artifacts: [
      artifact('201', `e-mate-desktop-admission-${SOURCE}`, '101', '9'.repeat(64), {
        'base-contract.json': pretty(base),
        'desktop-release-unsigned.json': pretty(manifest),
      }),
      artifact('202', `e-mate-desktop-release-${SOURCE}`, '102', candidateBundleSha, {
        'desktop-candidate.json': pretty(candidate),
        'e-Mate-2.0.15-mac-universal.dmg': publishedMac,
        'e-Mate-2.0.15-win-x64-Setup.exe': win,
      }),
      artifact('206', `e-mate-desktop-macos-${SOURCE}`, '100', MACOS_CI_ARCHIVE_SHA256, macosCiFiles, MACOS_CI_ARCHIVE_BYTES),
      artifact('207', `e-mate-desktop-windows-${SOURCE}`, '100', 'b'.repeat(64), stagingFiles('win32', win)),
      artifact('208', `e-mate-desktop-macos-signed-${SOURCE}`, '105', 'c'.repeat(64), signedMacFiles({
        inputFiles: macosCiFiles,
        inputDmg: unsignedMac,
        outputDmg: mac,
        outputBlockmap: blockmap,
      })),
    ],
  })
  if (macosPublicationMode === 'unsigned') {
    github.jobs.set('102', [job('Bind exact protected-main CI unsigned desktop bytes')])
  }
  const config = {
    repository: EXPECTED_REPOSITORY,
    actionRepository: EXPECTED_ACTION_REPOSITORY,
    actionRef: 'b'.repeat(40),
    eventName: 'workflow_dispatch',
    ref: 'refs/heads/main',
    refProtected: true,
    githubSha: SOURCE,
    sourceCommit: SOURCE,
    mainCiRunId: '100',
    macosPublicationMode,
    macosSignerRunId: macosPublicationMode === 'signed' ? '105' : undefined,
    admissionArtifactId: '201',
    macosSignedArtifactId: macosPublicationMode === 'signed' ? '208' : undefined,
    macosUnsignedArtifactId: macosPublicationMode === 'unsigned' ? '206' : undefined,
    windowsArtifactId: '207',
    expectedSignedCurrent: null,
    expectedLegacyCurrent: { bytes: LEGACY_PREDECESSOR.bytes, sha256: LEGACY_PREDECESSOR.sha256 },
    signingKeyId: KEY_ID,
    privateKeyPem,
  }
  return {
    keyPair,
    github,
    config,
    prepare: () => prepareDesktopPublication(config, { github }),
  }
}

class FakeGithub {
  constructor({ source, artifacts }) {
    this.source = source
    this.repository = {
      fullName: EXPECTED_REPOSITORY,
      visibility: 'public',
      defaultBranch: 'main',
      archived: false,
      disabled: false,
    }
    this.runs = new Map([
      ['100', run('100', '.github/workflows/ci.yml', 'workflow_dispatch')],
      ['101', run('101', '.github/workflows/desktop-admission.yml', 'workflow_dispatch')],
      ['102', run('102', '.github/workflows/desktop-release.yml', 'workflow_dispatch')],
      ['105', run('105', '.github/workflows/desktop-macos-signing.yml', 'workflow_dispatch')],
    ])
    this.jobs = new Map([
      ['100', [
        job('CI admission'),
        job('Windows x64 / unsigned desktop installer'),
        job('macOS universal / unsigned desktop disk image'),
      ]],
      ['101', [job('Desktop release admission')]],
      ['102', [job('Bind exact signed macOS and protected-main CI Windows bytes')]],
      ['105', [job('Sign and notarize exact accepted macOS bytes')]],
    ])
    this.artifacts = new Map(artifacts.map(item => [item.metadata.id, item]))
  }

  async getRepository() { return structuredClone(this.repository) }
  async getBranchHead() { return this.source }
  async getRun(id) { return structuredClone(this.runs.get(String(id))) }
  async getRunJobs(id) { return structuredClone(this.jobs.get(String(id))) }
  async getArtifact(id) { return structuredClone(this.artifacts.get(String(id)).metadata) }
  async downloadArtifact(id) { return this.artifacts.get(String(id)).bundle }
  file(id, name) { return this.artifacts.get(String(id)).bundle.files.get(name) }
  replaceFile(id, name, bytes) {
    this.artifacts.get(String(id)).bundle.files.set(name, testSource(bytes))
  }
}

function run(id, path, event) {
  return {
    id,
    status: 'completed',
    conclusion: 'success',
    headSha: SOURCE,
    headBranch: 'main',
    event,
    path,
    runAttempt: 1,
  }
}

function job(name) {
  return { name, status: 'completed', conclusion: 'success' }
}

function artifact(id, name, runId, archiveSha256, files, bytes = Number(id) + 1000) {
  const stored = new Set(Object.keys(files))
  return {
    metadata: {
      id,
      name,
      runId,
      digest: `sha256:${archiveSha256}`,
      expired: false,
      sourceCommit: SOURCE,
      bytes,
    },
    bundle: {
      archiveSha256,
      archiveBytes: bytes,
      files: new Map(Object.entries(files).map(([path, bytes]) => [path, testSource(bytes)])),
      stored,
      storedEntries: async () => new Set(stored),
    },
  }
}

function testSource(bytes) {
  const buffer = Buffer.from(bytes)
  return { ...bufferSource(buffer), buffer }
}

function stagingFiles(platform, installer, blockmap) {
  const installerName = platform === 'darwin'
    ? 'e-Mate-2.0.15-mac-universal.dmg'
    : 'e-Mate-2.0.15-win-x64-Setup.exe'
  const runtime = pretty({
    schema_version: 1,
    document_type: 'emate.desktop-runtime-verification',
    platform,
    source_commit: SOURCE,
    ci_run_id: '100',
    base_contract_id: BASE_ID,
    harness_commit: SOURCE,
    installer: {
      name: installerName,
      bytes: installer.byteLength,
      sha256: sha256(installer),
      format: platform === 'darwin' ? 'udif' : 'pe',
    },
  })
  const payloads = {
    [installerName]: installer,
    'desktop-runtime-verification.json': runtime,
    ...(blockmap === undefined ? {} : { [`${installerName}.blockmap`]: blockmap }),
  }
  const files = Object.entries(payloads).map(([name, bytes]) => ({
    name,
    bytes: bytes.byteLength,
    sha256: sha256(bytes),
  })).sort((left, right) => left.name.localeCompare(right.name))
  return {
    ...payloads,
    'desktop-artifact-receipt.json': pretty({
      schema_version: 1,
      document_type: 'emate.desktop-ci-artifact',
      platform,
      source_commit: SOURCE,
      ci_run_id: '100',
      base_contract_id: BASE_ID,
      files,
    }),
  }
}

function signedMacFiles({ inputFiles, inputDmg, outputDmg, outputBlockmap }) {
  const dmgName = 'e-Mate-2.0.15-mac-universal.dmg'
  const blockmapName = `${dmgName}.blockmap`
  const input = fileIdentity(dmgName, inputDmg)
  const output = fileIdentity(dmgName, outputDmg)
  return {
    [dmgName]: outputDmg,
    [blockmapName]: outputBlockmap,
    'desktop-macos-signed-receipt.json': pretty({
      schema_version: 1,
      document_type: 'emate.desktop-macos-signed-release',
      source_commit: SOURCE,
      ci_run_id: '100',
      base_contract_id: BASE_ID,
      harness_commit: SOURCE,
      input: {
        artifact_id: '206',
        artifact_name: `e-mate-desktop-macos-${SOURCE}`,
        artifact_api_digest: `sha256:${MACOS_CI_ARCHIVE_SHA256}`,
        artifact_archive_bytes: MACOS_CI_ARCHIVE_BYTES,
        desktop_artifact_receipt: fileIdentity('desktop-artifact-receipt.json', inputFiles['desktop-artifact-receipt.json']),
        runtime_verification_receipt: fileIdentity('desktop-runtime-verification.json', inputFiles['desktop-runtime-verification.json']),
        dmg: input,
        signing: 'adhoc',
      },
      output: {
        dmg: output,
        blockmap: fileIdentity(blockmapName, outputBlockmap),
        signing: 'developer-id',
        notarized: true,
      },
      developer_id: {
        identity: `Developer ID Application: e-Mate (${DEVELOPER_TEAM_ID})`,
        team_id: DEVELOPER_TEAM_ID,
        credential_source: 'p12',
      },
      notarization: {
        credential_source: 'api-key',
        submission_id: '123e4567-e89b-12d3-a456-426614174000',
        status: 'Accepted',
      },
    }),
    'desktop-macos-signed-verification.json': pretty({
      schema_version: 1,
      document_type: 'emate.desktop-macos-signed-verification',
      source_commit: SOURCE,
      ci_run_id: '100',
      input_dmg_sha256: input.sha256,
      output_dmg_sha256: output.sha256,
      checks: {
        codesign_app: 'passed',
        codesign_dmg: 'passed',
        gatekeeper_app: 'accepted',
        gatekeeper_dmg: 'accepted',
        stapler_dmg: 'valid',
        verify_mac_release: 'passed',
      },
    }),
  }
}

function fileIdentity(name, bytes) {
  return { name, bytes: bytes.byteLength, sha256: sha256(bytes) }
}

function mutateJson(fixture, artifactId, name, mutate) {
  const value = JSON.parse(fixture.github.file(artifactId, name).buffer)
  mutate(value)
  fixture.github.replaceFile(artifactId, name, pretty(value))
}

function manifestArtifact(platform, bytes, buildRunId) {
  const filename = platform === 'darwin'
    ? 'e-Mate-2.0.15-mac-universal.dmg'
    : 'e-Mate-2.0.15-win-x64-Setup.exe'
  return {
    url: `${PUBLIC_ORIGIN}/desktop/releases/v2.0.15/${SOURCE}/${filename}`,
    bytes: bytes.byteLength,
    sha256: sha256(bytes),
    build_source_commit: SOURCE,
    build_run_id: buildRunId,
  }
}

function pretty(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`)
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}
