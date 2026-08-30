import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, verify } from 'node:crypto'
import { mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, it } from 'node:test'
import {
  CLOUDFLARE_HANDOFF_FILENAME,
  EXPECTED_ACTION_REPOSITORY,
  EXPECTED_REPOSITORY,
  PUBLICATION_PLAN_FILENAME,
  PUBLIC_ORIGIN,
  RELEASE_SIGNATURE_CONTEXT,
  SIGNED_MANIFEST_FILENAME,
  admitLocalDesktopCandidate,
  bufferSource,
  canonicalJson,
  prepareLocalSchema2DesktopPublication,
} from '../src/publisher.mjs'

const SOURCE = 'a'.repeat(40)
const CURRENT_SOURCE = 'b'.repeat(40)
const RUN_ID = `20260831T031500Z-${SOURCE.slice(0, 12)}-abcdef`
const POINTER_IDENTITY = Object.freeze({ bytes: 2961, sha256: '8'.repeat(64), etag: '6'.repeat(32) })

describe('local exact-candidate admission seam', () => {
  it('binds only the exact request, installer paths and bytes, and three-file handoff request', async () => {
    const fixture = await localFixture()
    try {
      const admitted = await admitLocalDesktopCandidate(fixture.config)
      assert.equal(admitted.status, 'awaiting-manifest-input-and-client-compatible-provenance')
      assert.deepEqual(admitted.request, {
        path: fixture.requestPath,
        sha256: fixture.config.requestSha256,
        run_id: RUN_ID,
        version: '2.0.16',
        source_commit: SOURCE,
        transaction_mode: 'new-version',
        current_public_pointers: fixture.request.transaction_plan.current_public_pointers,
      })
      assert.deepEqual(admitted.artifacts, {
        darwin: { path: fixture.macPath, bytes: fixture.mac.byteLength, sha256: sha256(fixture.mac) },
        win32: { path: fixture.winPath, bytes: fixture.win.byteLength, sha256: sha256(fixture.win) },
      })
      assert.deepEqual(admitted.handoff_files, [
        SIGNED_MANIFEST_FILENAME, PUBLICATION_PLAN_FILENAME, CLOUDFLARE_HANDOFF_FILENAME,
      ])
      assert.deepEqual(Object.keys(admitted), ['status', 'request', 'artifacts', 'handoff_files'])
      assert.equal(JSON.stringify(admitted).includes('base'), false)
      assert.equal(JSON.stringify(admitted).includes('profile'), false)
      assert.equal(JSON.stringify(admitted).includes('signing'), false)
      assert.equal('privateKeyPem' in admitted, false)
      assert.equal('github' in admitted, false)
    } finally {
      await fixture.dispose()
    }
  })

  it('admits the explicitly named same-version exception without weakening current identities', async () => {
    const fixture = await localFixture({ sameVersion: true })
    try {
      const admitted = await admitLocalDesktopCandidate(fixture.config)
      assert.equal(admitted.request.version, '2.0.15')
      assert.equal(admitted.request.transaction_mode, 'same-version-2.0.15-exception')
      assert.deepEqual(admitted.request.current_public_pointers, fixture.request.transaction_plan.current_public_pointers)
    } finally {
      await fixture.dispose()
    }
  })

  it('fails closed on request, path, byte, provenance, context, and file-set drift', async t => {
    const cases = [
      ['request SHA drift', async fixture => { fixture.config.requestSha256 = 'f'.repeat(64) }],
      ['request path drift', async fixture => {
        const other = join(fixture.runRoot, 'publication', 'other.json')
        await writeFile(other, await readFile(fixture.requestPath))
        fixture.config.requestPath = other
      }],
      ['installer byte drift', async fixture => { await writeFile(fixture.macPath, 'changed') }],
      ['installer name drift', async fixture => {
        fixture.request.immutable_objects[0].artifact_path = 'artifacts/macos/wrong.dmg'
        await fixture.writeRequest()
      }],
      ['source drift', async fixture => {
        fixture.request.source_commit = 'c'.repeat(40)
        await fixture.writeRequest()
      }],
      ['run id source drift', async fixture => {
        fixture.request.run_id = `20260831T031500Z-${'c'.repeat(12)}-abcdef`
        fixture.request.transaction_plan.run_id = fixture.request.run_id
        await fixture.writeRequest()
      }],
      ['path escape', async fixture => {
        fixture.request.immutable_objects[0].artifact_path = '../outside.dmg'
        await fixture.writeRequest()
      }],
      ['symlink installer', async fixture => {
        const outside = join(fixture.root, 'outside.dmg')
        await writeFile(outside, fixture.mac)
        await rm(fixture.macPath)
        await symlink(outside, fixture.macPath)
      }],
      ['extra immutable file', async fixture => {
        fixture.request.immutable_objects.push({
          ...fixture.request.immutable_objects[0],
          artifact_path: `artifacts/macos/e-Mate-2.0.16-mac-universal.dmg.sig`,
          key: `desktop/releases/v2.0.16/${SOURCE}/e-Mate-2.0.16-mac-universal.dmg.sig`,
        })
        await fixture.writeRequest()
      }],
      ['GitHub metadata mixed into local mode', async fixture => {
        fixture.request.github = { main_ci_run_id: '100' }
        await fixture.writeRequest()
      }],
      ['signature context drift', async fixture => {
        fixture.request.manifest_admission_and_signing.signed_manifest.signing_context = 'e-mate-desktop-release-manifest-v3\0'
        await fixture.writeRequest()
      }],
      ['recovery contract drift', async fixture => {
        fixture.request.publication_and_activation.recovery.foreign_state = 'overwrite'
        await fixture.writeRequest()
      }],
      ['extra handoff file', async fixture => {
        fixture.request.manifest_admission_and_signing.handoff.exact_files.push('extra.json')
        await fixture.writeRequest()
      }],
    ]
    for (const [name, mutate] of cases) {
      await t.test(name, async () => {
        const fixture = await localFixture()
        try {
          await mutate(fixture)
          await assert.rejects(admitLocalDesktopCandidate(fixture.config))
        } finally {
          await fixture.dispose()
        }
      })
    }
  })
})

async function localFixture({ sameVersion = false } = {}) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'e-mate-local-candidate-')))
  const runRoot = join(root, 'run')
  const publicationRoot = join(runRoot, 'publication')
  const macRoot = join(runRoot, 'artifacts', 'macos')
  const winRoot = join(runRoot, 'artifacts', 'windows')
  await Promise.all([
    mkdir(publicationRoot, { recursive: true }),
    mkdir(macRoot, { recursive: true }),
    mkdir(winRoot, { recursive: true }),
  ])

  const mac = Buffer.from('exact local mac installer')
  const blockmap = Buffer.from('exact local mac blockmap')
  const win = Buffer.from('exact local windows installer')
  const version = sameVersion ? '2.0.15' : '2.0.16'
  const macName = `e-Mate-${version}-mac-universal.dmg`
  const blockmapName = `${macName}.blockmap`
  const winName = `e-Mate-${version}-win-x64-Setup.exe`
  const macPath = join(macRoot, macName)
  const blockmapPath = join(macRoot, blockmapName)
  const winPath = join(winRoot, winName)
  await Promise.all([
    writeFile(macPath, mac),
    writeFile(blockmapPath, blockmap),
    writeFile(winPath, win),
  ])

  const currentPublicPointers = {
    signed: { key: 'desktop/signed/latest.json', identity: { ...POINTER_IDENTITY } },
    legacy: { key: 'desktop/latest.json', identity: { ...POINTER_IDENTITY } },
    manual: { key: 'desktop/manual/v2.0.15/latest.json', identity: { ...POINTER_IDENTITY } },
  }
  const target = {
    artifact_path: SIGNED_MANIFEST_FILENAME,
    bytes: 'from-manifest-admission.signed_manifest.bytes',
    sha256: 'from-manifest-admission.signed_manifest.sha256',
    etag: 'from-conditional-write-result.etag',
  }
  const pointer = name => ({
    key: currentPublicPointers[name].key,
    expected_current: { ...currentPublicPointers[name].identity },
    target: { ...target },
    compare_and_swap: 'required',
    authenticated_readback: 'required',
    public_full_byte_readback: 'required',
  })
  const immutable = (platform, name, bytes) => ({
    platform,
    artifact_path: `artifacts/${platform}/${name}`,
    key: `desktop/releases/v${version}/${SOURCE}/${name}`,
    bytes: bytes.byteLength,
    sha256: sha256(bytes),
    write: 'create-only',
  })
  const request = {
    schema_version: 1,
    document_type: 'emate.local-cloudflare-owner-request',
    operation: 'publish',
    mode: 'apply',
    status: 'ready-for-existing-owner',
    authority: 'existing-desktop-manifest-admission-signing-owner+codex-cloudflare-plugin',
    distribution_origin: PUBLIC_ORIGIN,
    run_id: RUN_ID,
    version,
    source_commit: SOURCE,
    transaction_plan: {
      schema_version: 1,
      mode: sameVersion ? 'same-version-2.0.15-exception' : 'new-version',
      distribution_origin: PUBLIC_ORIGIN,
      run_id: RUN_ID,
      product_version: version,
      source_commit: SOURCE,
      current_public_version: '2.0.15',
      current_public_source_commit: CURRENT_SOURCE,
      current_public_pointers: currentPublicPointers,
      manual_manifest: {
        key: `desktop/manual/v${version}/latest.json`,
        write: sameVersion ? 'compare-and-swap' : 'create-only',
        rollback: sameVersion ? 'restore-by-cas' : 'retain',
      },
      activation_order: ['manual', 'signed', 'legacy'],
      rollback_order: sameVersion ? ['legacy', 'signed', 'manual'] : ['legacy', 'signed'],
      manual_reinstall_required_for_existing_2_0_15: sameVersion,
    },
    rebuild: false,
    macos_publication_mode: 'unsigned',
    installer_security: {
      darwin: { code_signed: false, notarized: false },
      win32: { code_signed: false, notarized: false },
    },
    immutable_objects: [
      immutable('macos', macName, mac),
      immutable('macos', blockmapName, blockmap),
      immutable('windows', winName, win),
    ],
    manifest_admission_and_signing: {
      owner: `zyfjacksonchen-source/e-mate-desktop-publication@${'c'.repeat(40)}`,
      signed_manifest: {
        artifact_path: SIGNED_MANIFEST_FILENAME,
        schema_version: 2,
        document_type: 'emate.desktop-release-manifest',
        release_status: 'admitted',
        signing_context: 'e-mate-desktop-release-manifest-v2\0',
        signature: { algorithm: 'ed25519', key_source: 'existing-base-profile_signing_keys' },
        max_bytes: 16 * 1024,
      },
      handoff: {
        status: 'ready-for-cloudflare-plugin',
        exact_files: [SIGNED_MANIFEST_FILENAME, PUBLICATION_PLAN_FILENAME, CLOUDFLARE_HANDOFF_FILENAME],
      },
    },
    publication_and_activation: {
      current_public_pointer_readback: 'required-before-any-write',
      manual_manifest: {
        key: `desktop/manual/v${version}/latest.json`,
        write: sameVersion ? 'compare-and-swap' : 'create-only',
        rollback: sameVersion ? 'restore-by-cas' : 'retain',
        expected_current: sameVersion ? { ...POINTER_IDENTITY } : 'must-not-exist',
        target,
        authenticated_readback: 'required',
        public_full_byte_readback: 'required',
      },
      pointers: {
        ...(sameVersion ? { manual: pointer('manual') } : {}),
        signed: pointer('signed'),
        legacy: pointer('legacy'),
      },
      activation_order: ['manual', 'signed', 'legacy'],
      recovery: {
        accepted_current_states: ['exact-before', 'exact-after'],
        already_exact: 'idempotent',
        stale_etag: 'fail-closed',
        foreign_state: 'fail-closed',
        partial_activation: 'resume-ordered-prefix',
        crash_recovery: 'resume-same-request',
      },
      order: [
        'current-public-three-pointer-readbacks', 'existing-owner-admission-and-ed25519-manifest-signing',
        'immutable-create-only', 'authenticated-readback', 'public-readback',
        sameVersion ? 'manual-pointer-cas-and-readbacks' : 'manual-manifest-create-only-and-readbacks',
        'signed-pointer-cas-and-readbacks',
        'legacy-pointer-cas-and-readbacks',
      ],
    },
    delete_objects: [],
  }
  const requestPath = join(publicationRoot, 'cloudflare-owner-request.json')
  const config = {
    runRoot,
    requestPath,
    requestSha256: '',
    artifacts: { darwin: macPath, win32: winPath },
  }
  const writeRequest = async () => {
    const bytes = pretty(request)
    await writeFile(requestPath, bytes)
    config.requestSha256 = sha256(bytes)
  }
  await writeRequest()
  return {
    root, runRoot, requestPath, macPath, winPath, mac, win, request, config, writeRequest,
    dispose: () => rm(root, { recursive: true, force: true }),
  }
}

function pretty(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`)
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

describe('local schema-2 compatibility signer', () => {
  it('signs the exact R2 identities with real carrier provenance and a verified Profile projection', async () => {
    const fixture = await schema2Fixture()
    try {
      const result = await fixture.prepare()
      assert.deepEqual([...result.files.keys()], [
        SIGNED_MANIFEST_FILENAME, PUBLICATION_PLAN_FILENAME, CLOUDFLARE_HANDOFF_FILENAME,
      ])
      const signedBytes = await result.files.get(SIGNED_MANIFEST_FILENAME).read()
      const signed = JSON.parse(signedBytes)
      const { signature, ...unsigned } = signed
      assert.deepEqual(Object.keys(unsigned), [
        'schema_version', 'document_type', 'release_status', 'version', 'source_commit',
        'base_contract_id', 'schedule_protocol_floor', 'profile_component_aggregate',
        'github_artifact_provenance', 'artifacts',
      ])
      assert.deepEqual(Object.keys(signed.profile_component_aggregate), [
        'aggregate_sha256', 'inventory_sha256', 'staged_profile_tree_sha256', 'targets',
      ])
      assert.equal(signed.artifacts.darwin.build_run_id, fixture.carrierRunId)
      assert.equal(signed.artifacts.win32.build_run_id, fixture.carrierRunId)
      assert.equal(signed.artifacts.darwin.url, fixture.compatibility.installers.darwin.url)
      assert.equal(signed.artifacts.win32.url, fixture.compatibility.installers.win32.url)
      assert.equal(JSON.stringify(signed).includes('github.com'), false)
      assert.equal(verify(
        null,
        Buffer.concat([RELEASE_SIGNATURE_CONTEXT, Buffer.from(canonicalJson(unsigned), 'utf8')]),
        fixture.keyPair.publicKey,
        Buffer.from(signature.value, 'base64'),
      ), true)

      const plan = JSON.parse(await result.files.get(PUBLICATION_PLAN_FILENAME).read())
      assert.deepEqual(Object.keys(plan), [
        'schema_version', 'document_type', 'status', 'owner', 'repository', 'source_commit',
        'run_id', 'version', 'data_plane', 'inputs', 'compatibility_attestation',
        'github_verification', 'profile_signing', 'signed_manifest', 'next_owner', 'forbidden_actions',
      ])
      assert.equal(plan.status, 'ready-for-main-local-flow-activation')
      assert.equal(plan.owner, `${EXPECTED_ACTION_REPOSITORY}@${fixture.actionRef}`)
      assert.equal(plan.data_plane.origin, PUBLIC_ORIGIN)
      assert.equal(plan.data_plane.github_role, 'compatibility-attestation-carrier-only')
      assert.equal(plan.data_plane.github_built_or_tested_installer_bytes, false)
      assert.equal(plan.github_verification.workflow.job.unique, true)
      assert.equal(plan.github_verification.artifact.archive.compression_level_0, true)
      assert.equal(plan.profile_signing.verification.manifest_signature, 'passed')
      assert.deepEqual(Object.keys(plan.profile_signing.protected_source_files), [
        'base_contract', 'component_inventory',
      ])
      assert.ok(Object.values(plan.profile_signing.protected_source_files)
        .every(file => file.verification === 'passed'))

      const handoff = JSON.parse(await result.files.get(CLOUDFLARE_HANDOFF_FILENAME).read())
      assert.deepEqual(Object.keys(handoff), [
        'schema_version', 'document_type', 'status', 'owner', 'repository', 'source_commit',
        'run_id', 'version', 'data_plane', 'inputs', 'compatibility_attestation',
        'github_verification', 'profile_signing', 'files', 'production_state', 'next_owner',
      ])
      assert.equal(handoff.document_type, 'emate.local-schema2-signer-receipt')
      assert.equal(handoff.status, 'passed')
      assert.deepEqual(handoff.compatibility_attestation, result.compatibilityAttestation)
      assert.deepEqual(handoff.production_state, {
        r2_write_performed: false,
        public_readback_performed: false,
        active_pointer_changed: false,
        legacy_pointer_changed: false,
      })
      assert.equal(handoff.files.signed_manifest.sha256, sha256(signedBytes))
      assert.equal(handoff.files.publication_plan.sha256, result.planSha256)
      assert.equal(JSON.stringify(handoff).includes('PRIVATE KEY'), false)
    } finally {
      await fixture.dispose()
    }
  })

  it('fails closed on immutable, carrier, Profile, Base and signer drift', async t => {
    const cases = [
      ['equal-length immutable identity tamper', async fixture => {
        fixture.immutable.immutable_objects[0].sha256 = 'e'.repeat(64)
        await fixture.writeImmutable()
      }],
      ['equal-length immutable receipt tamper', async fixture => {
        fixture.receipt.immutable_objects[0].authenticated_readback.sha256 = 'e'.repeat(64)
        await fixture.writeReceipt()
      }],
      ['compatibility extra field', async fixture => {
        fixture.compatibility.unexpected = false
        await fixture.writeCompatibility()
      }],
      ['compatibility control-plane lie', async fixture => {
        fixture.compatibility.control_plane = 'github-metadata-only-compatibility-carrier'
        await fixture.writeCompatibility()
      }],
      ['compatibility exact-file order drift', async fixture => {
        fixture.compatibility.workflow.exact_files.reverse()
        await fixture.writeCompatibility()
      }],
      ['protected main head drift', async fixture => { fixture.github.source = 'd'.repeat(40) }],
      ['carrier workflow failure', async fixture => {
        fixture.github.runs.get(fixture.carrierRunId).conclusion = 'failure'
      }],
      ['carrier attempt drift', async fixture => { fixture.github.runs.get(fixture.carrierRunId).runAttempt = 2 }],
      ['carrier job is not unique', async fixture => {
        fixture.github.jobs.get(fixture.carrierRunId).push({ ...fixture.github.jobs.get(fixture.carrierRunId)[0] })
      }],
      ['artifact expired', async fixture => { fixture.github.artifact.metadata.expired = true }],
      ['artifact source drift', async fixture => { fixture.github.artifact.metadata.sourceCommit = 'd'.repeat(40) }],
      ['API and archive digest drift', async fixture => { fixture.github.artifact.bundle.archiveSha256 = 'e'.repeat(64) }],
      ['carrier has an extra file', async fixture => {
        fixture.github.artifact.bundle.files.set('extra.txt', bufferSource(Buffer.from('extra')))
        fixture.github.artifact.bundle.stored.add('extra.txt')
      }],
      ['carrier entry is compressed', async fixture => {
        fixture.github.artifact.bundle.stored.delete('desktop-candidate.json')
      }],
      ['candidate run owner drift', async fixture => {
        fixture.candidate.artifacts.darwin.build_run_id = String(Number(fixture.carrierRunId) + 1)
        fixture.github.replaceCandidate(fixture.candidate)
      }],
      ['candidate R2 identity drift', async fixture => {
        fixture.candidate.artifacts.win32.sha256 = 'e'.repeat(64)
        fixture.github.replaceCandidate(fixture.candidate)
      }],
      ['Profile aggregate digest drift', async fixture => {
        fixture.profile.targets[0].component_aggregate_sha256 = 'e'.repeat(64)
        await fixture.writeProfile()
      }],
      ['Profile aggregate extra field', async fixture => {
        fixture.profile.unexpected = false
        await fixture.writeProfile()
      }],
      ['Base bytes drift', async fixture => {
        fixture.base.desktop_api = 2
        await writeFile(fixture.basePath, pretty(fixture.base))
      }],
      ['protected source Base equal-length drift', async fixture => {
        const path = 'desktop/e-mate-desktop/base-contract.json'
        fixture.github.sourceFiles.set(path, Buffer.from(
          fixture.github.sourceFiles.get(path).toString('utf8').replace('"desktop_api": 1', '"desktop_api": 2'),
        ))
      }],
      ['protected source inventory equal-length drift', async fixture => {
        const path = 'packages/dsh/profile/component-inventory.json'
        fixture.github.sourceFiles.set(path, Buffer.from(
          fixture.github.sourceFiles.get(path).toString('utf8').replace('"components"', '"componentz"'),
        ))
      }],
      ['untrusted private key', async fixture => {
        fixture.config.privateKeyPem = generateKeyPairSync('ed25519').privateKey.export({ format: 'pem', type: 'pkcs8' })
      }],
    ]
    for (const [name, mutate] of cases) {
      await t.test(name, async () => {
        const fixture = await schema2Fixture()
        try {
          await mutate(fixture)
          await assert.rejects(fixture.prepare())
        } finally {
          await fixture.dispose()
        }
      })
    }
  })
})

async function schema2Fixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'e-mate-schema2-signer-')))
  const runRoot = join(root, 'run')
  const publicationRoot = join(runRoot, 'publication')
  const profileRoot = join(runRoot, 'manifest-inputs', 'platforms', 'macos')
  const signingRoot = join(runRoot, 'profile-signing')
  await Promise.all([
    mkdir(publicationRoot, { recursive: true }),
    mkdir(profileRoot, { recursive: true }),
    mkdir(signingRoot, { recursive: true }),
  ])
  const keyPair = generateKeyPairSync('ed25519')
  const actionRef = 'c'.repeat(40)
  const signingKeyId = 'release-2026'
  const carrierRunId = '900'
  const carrierArtifactId = '901'
  const baseId = `e-mate-desktop-profile-v14-dsh-${SOURCE.slice(0, 12)}`
  const base = {
    schema_version: 1,
    id: baseId,
    desktop_api: 1,
    profile_format: 1,
    desktop_reference: {
      repository: EXPECTED_REPOSITORY,
      commit: SOURCE,
      harness_repository: 'deepseek-ai/DeepSeek-Harness',
      harness_commit: SOURCE,
      harness_version: '1.0.0',
    },
    schedule_protocol_floor: 1,
    harness_version: '1.0.0',
    harness_commit: SOURCE,
    runtime_imports: { '@deepseek-ai/runtime': '1.0.0' },
    profile_signing_keys: [{
      id: signingKeyId,
      algorithm: 'ed25519',
      public_key_spki_der_base64: keyPair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    }],
  }
  const basePath = join(profileRoot, 'base-contract.json')
  const inventoryPath = join(profileRoot, 'component-inventory.json')
  const profileReceiptPath = join(profileRoot, 'profile-build-receipt.json')
  const inventory = { schema_version: 1, components: [] }
  const inventoryBytes = pretty(inventory)
  const stagedProfileTreeSha256 = '4'.repeat(64)
  await Promise.all([writeFile(basePath, pretty(base)), writeFile(inventoryPath, inventoryBytes)])
  const baseDescriptor = { path: 'base-contract.json', ...fileIdentityFromBytes(pretty(base)) }
  const inventoryDescriptor = { path: 'component-inventory.json', ...fileIdentityFromBytes(inventoryBytes) }
  const profileReceipt = {
    schema_version: 1,
    document_type: 'emate.desktop-profile-build-receipt',
    source_commit: SOURCE,
    base_contract_id: baseId,
    inventory_sha256: inventoryDescriptor.sha256,
    staged_profile_tree_sha256: stagedProfileTreeSha256,
    file_count: 1,
    total_bytes: 1,
  }
  await writeFile(profileReceiptPath, pretty(profileReceipt))
  const profileReceiptDescriptor = {
    path: 'profile-build-receipt.json', ...fileIdentityFromBytes(pretty(profileReceipt)),
  }
  const ledgerBase = {
    ...baseDescriptor,
    id: baseId,
    schedule_protocol_floor: 1,
    harness_commit: SOURCE,
    trusted_signing_key_ids: [signingKeyId],
  }
  const platformReceipt = {
    schema_version: 1,
    document_type: 'emate.local-manifest-platform-inputs',
    platform: 'macos',
    version: '2.0.15',
    source_commit: SOURCE,
    source_status: 'committed-clean',
    targets: ['darwin-arm64', 'darwin-x64'],
    toolchain: {},
    base_contract: ledgerBase,
    component_inventory: inventoryDescriptor,
    profile_build_receipt: profileReceiptDescriptor,
    profile_artifact: { root: 'profile-artifact', file_count: 1, total_bytes: 1, sha256: stagedProfileTreeSha256 },
    unsigned_component_payloads: [],
    profile_signing: 'awaiting-existing-owner',
    tree: { file_count: 1, total_bytes: 1, sha256: '5'.repeat(64) },
  }
  const platformReceiptPath = join(profileRoot, 'platform-inputs.json')
  await writeFile(platformReceiptPath, pretty(platformReceipt))
  const platformDescriptor = { path: 'platform-inputs.json', ...fileIdentityFromBytes(pretty(platformReceipt)) }

  const mac = Buffer.from('canonical R2 mac installer')
  const win = Buffer.from('canonical R2 windows installer')
  const immutableObject = (platform, name, bytes) => {
    const key = `desktop/releases/v2.0.15/${SOURCE}/${name}`
    return {
      platform,
      artifact_path: `artifacts/${platform}/${name}`,
      key,
      bytes: bytes.byteLength,
      sha256: sha256(bytes),
      write: 'create-only',
      url: `${PUBLIC_ORIGIN}/${key}`,
    }
  }
  const immutable = {
    schema_version: 1,
    document_type: 'emate.local-cloudflare-owner-request',
    operation: 'publish-installers-immutable',
    mode: 'apply',
    status: 'ready-for-existing-owner',
    authority: 'codex-cloudflare-plugin',
    distribution_origin: PUBLIC_ORIGIN,
    release_scope: 'full-installers-immutable-only',
    run_id: RUN_ID,
    version: '2.0.15',
    source_commit: SOURCE,
    transaction_mode: 'same-version-2.0.15-exception',
    manual_reinstall_required_for_existing_2_0_15: true,
    rebuild: false,
    macos_publication_mode: 'unsigned',
    installer_security: {
      darwin: { code_signed: false, notarized: false },
      win32: { code_signed: false, notarized: false },
    },
    immutable_objects: [
      immutableObject('macos', 'e-Mate-2.0.15-mac-universal.dmg', mac),
      immutableObject('windows', 'e-Mate-2.0.15-win-x64-Setup.exe', win),
    ],
    completion: {
      order: ['immutable-create-only-or-already-exact', 'authenticated-full-byte-readback', 'public-full-byte-readback'],
      terminal_state: 'immutable-installers-verified',
      next_request: 'schema-2-compatibility-attestation',
    },
    delete_objects: [],
  }
  const immutablePath = join(publicationRoot, 'immutable-owner-request.json')
  await writeFile(immutablePath, pretty(immutable))
  const immutableDescriptor = { path: 'publication/immutable-owner-request.json', ...fileIdentityFromBytes(pretty(immutable)) }

  const ledger = {
    schema_version: 1,
    document_type: 'emate.local-manifest-input-ledger',
    run_id: RUN_ID,
    version: '2.0.15',
    source_commit: SOURCE,
    source_status: 'committed-clean',
    distribution_origin: PUBLIC_ORIGIN,
    profile_signing: 'awaiting-existing-owner',
    client_compatible_provenance: 'open-existing-owner',
    targets: ['darwin-arm64', 'darwin-x64', 'win32-x64'],
    base_contract: ledgerBase,
    component_inventory: inventoryDescriptor,
    platform_receipts: { macos: platformDescriptor, windows: platformDescriptor },
    artifact_receipts: { macos: {}, windows: {} },
    local_candidate_provenance: {},
    files: [],
  }
  const ledgerPath = join(runRoot, 'manifest-inputs', 'manifest-inputs.json')
  await writeFile(ledgerPath, pretty(ledger))
  const ledgerDescriptor = { path: 'manifest-inputs/manifest-inputs.json', ...fileIdentityFromBytes(pretty(ledger)) }
  const profileUnsigned = {
    source_commit: SOURCE,
    release_version: '2.0.15',
    base_contract_id: baseId,
    provenance: { mode: 'local-flow', run_id: RUN_ID, request: immutableDescriptor, ledger: ledgerDescriptor },
    inventory_sha256: inventoryDescriptor.sha256,
    staged_profile_tree_sha256: stagedProfileTreeSha256,
    targets: ['darwin-arm64', 'darwin-x64', 'win32-x64'].map((target, index) => ({
      target,
      profile_generation: ['6', '7', '8'][index].repeat(64),
      component_aggregate_sha256: ['9', 'a', 'b'][index].repeat(64),
    })),
  }
  const profile = {
    schema_version: 2,
    document_type: 'emate.profile-component-aggregate',
    ...profileUnsigned,
    aggregate_sha256: sha256(Buffer.concat([
      Buffer.from('e-mate-local-profile-aggregate-v2\0', 'utf8'),
      Buffer.from(canonicalJson(profileUnsigned), 'utf8'),
    ])),
  }
  const profilePath = join(signingRoot, 'profile-component-aggregate.json')
  await writeFile(profilePath, pretty(profile))

  const receiptObject = object => ({
    platform: object.platform,
    key: object.key,
    url: object.url,
    bytes: object.bytes,
    sha256: object.sha256,
    write: 'created',
    authenticated_readback: { status: 'passed', bytes: object.bytes, sha256: object.sha256 },
    public_full_byte_readback: { status: 'passed', url: object.url, bytes: object.bytes, sha256: object.sha256 },
  })
  const receipt = {
    schema_version: 1,
    document_type: 'emate.local-cloudflare-owner-receipt',
    operation: immutable.operation,
    status: 'passed',
    authority: immutable.authority,
    release_scope: immutable.release_scope,
    macos_publication_mode: 'unsigned',
    installer_security: immutable.installer_security,
    distribution_origin: PUBLIC_ORIGIN,
    run_id: RUN_ID,
    version: '2.0.15',
    source_commit: SOURCE,
    transaction_mode: immutable.transaction_mode,
    request_sha256: immutableDescriptor.sha256,
    immutable_objects: immutable.immutable_objects.map(receiptObject),
    deleted_objects: [],
  }
  const receiptPath = join(publicationRoot, 'immutable-owner-receipt.json')
  await writeFile(receiptPath, pretty(receipt))
  const receiptDescriptor = { path: 'publication/immutable-owner-receipt.json', ...fileIdentityFromBytes(pretty(receipt)) }

  const installer = (object, name) => ({
    name,
    url: object.url,
    bytes: object.bytes,
    sha256: object.sha256,
    build_source_commit: SOURCE,
  })
  const compatibility = {
    schema_version: 1,
    document_type: 'emate.local-desktop-compatibility-attestation-request',
    status: 'ready-for-manual-dispatch',
    purpose: 'accepted-2.0.13-schema-2-provenance',
    control_plane: 'github-compatibility-attestation-carrier',
    data_plane: {
      origin: PUBLIC_ORIGIN,
      installer_download: 'cloudflare-r2-only',
      online_update: 'cloudflare-r2-only',
      rollback: 'cloudflare-r2-only',
    },
    run_id: RUN_ID,
    version: '2.0.15',
    source_commit: SOURCE,
    transaction_mode: immutable.transaction_mode,
    manual_reinstall_required_for_existing_2_0_15: true,
    immutable_publication: {
      status: 'passed',
      request: { path: immutableDescriptor.path, sha256: immutableDescriptor.sha256 },
      receipt: { path: receiptDescriptor.path, sha256: receiptDescriptor.sha256 },
    },
    workflow: {
      repository: EXPECTED_REPOSITORY,
      path: '.github/workflows/desktop-compatibility-attestation.yml',
      event: 'workflow_dispatch',
      ref: 'refs/heads/main',
      required_head: SOURCE,
      required_run_attempt: 1,
      artifact_name: `e-mate-desktop-release-${SOURCE}`,
      exact_files: [
        'desktop-candidate.json', 'e-Mate-2.0.15-mac-universal.dmg', 'e-Mate-2.0.15-win-x64-Setup.exe',
      ],
      semantics: {
        role: 'compatibility-carrier-materialization',
        legacy_build_run_id: 'actual-github-workflow-run-id',
        github_built_or_tested_installer_bytes: false,
        dispatch_performed_by_local_flow: false,
      },
    },
    inputs: {
      source_sha: SOURCE,
      version: '2.0.15',
      macos_bytes: String(mac.byteLength),
      macos_sha256: sha256(mac),
      windows_bytes: String(win.byteLength),
      windows_sha256: sha256(win),
    },
    installers: {
      darwin: installer(immutable.immutable_objects[0], 'e-Mate-2.0.15-mac-universal.dmg'),
      win32: installer(immutable.immutable_objects[1], 'e-Mate-2.0.15-win-x64-Setup.exe'),
    },
    provenance_requirements: {
      schema_version: 1,
      document_type: 'emate.github-artifact-provenance',
      source_commit: SOURCE,
      role: 'desktop_candidate',
      artifact_name: `e-mate-desktop-release-${SOURCE}`,
      artifact_id: 'required-from-github-api',
      archive_digest: 'required-from-github-api',
      run_id: 'required-from-github-api',
      run_attempt: 1,
    },
    next_owner: `${EXPECTED_ACTION_REPOSITORY}@${actionRef}`,
    forbidden_actions: [
      'build-installers', 'test-installers', 'sign-manifest', 'write-r2', 'activate-pointer', 'serve-user-downloads',
    ],
  }
  const compatibilityPath = join(publicationRoot, 'compatibility-attestation-request.json')
  await writeFile(compatibilityPath, pretty(compatibility))

  const candidate = {
    schema_version: 2,
    document_type: 'emate.desktop-artifact-candidate',
    release_status: 'admission-pending',
    version: '2.0.15',
    source_commit: SOURCE,
    schedule_protocol_floor: 1,
    artifacts: {
      darwin: { ...compatibility.installers.darwin, name: undefined, build_run_id: carrierRunId },
      win32: { ...compatibility.installers.win32, name: undefined, build_run_id: carrierRunId },
    },
  }
  delete candidate.artifacts.darwin.name
  delete candidate.artifacts.win32.name
  const github = new Schema2Github({
    source: SOURCE,
    runId: carrierRunId,
    artifactId: carrierArtifactId,
    candidate,
    mac,
    win,
    baseBytes: pretty(base),
    inventoryBytes,
  })
  const config = {
    runRoot,
    immutableRequestPath: immutablePath,
    immutableRequestSha256: immutableDescriptor.sha256,
    immutableReceiptPath: receiptPath,
    immutableReceiptSha256: receiptDescriptor.sha256,
    compatibilityRequestPath: compatibilityPath,
    compatibilityRequestSha256: sha256(pretty(compatibility)),
    profileAggregatePath: profilePath,
    profileAggregateSha256: sha256(pretty(profile)),
    compatibilityRunId: carrierRunId,
    compatibilityArtifactId: carrierArtifactId,
    actionRepository: EXPECTED_ACTION_REPOSITORY,
    actionRef,
    signingKeyId,
    privateKeyPem: keyPair.privateKey.export({ format: 'pem', type: 'pkcs8' }),
  }
  const writeFixture = async (path, value, field) => {
    const bytes = pretty(value)
    await writeFile(path, bytes)
    config[field] = sha256(bytes)
  }
  return {
    root, runRoot, keyPair, actionRef, carrierRunId, base, basePath,
    immutable, receipt, compatibility, profile, candidate, github, config,
    writeImmutable: () => writeFixture(immutablePath, immutable, 'immutableRequestSha256'),
    writeReceipt: () => writeFixture(receiptPath, receipt, 'immutableReceiptSha256'),
    writeCompatibility: () => writeFixture(compatibilityPath, compatibility, 'compatibilityRequestSha256'),
    writeProfile: () => writeFixture(profilePath, profile, 'profileAggregateSha256'),
    prepare: () => prepareLocalSchema2DesktopPublication(config, { github }),
    dispose: () => rm(root, { recursive: true, force: true }),
  }
}

class Schema2Github {
  constructor({ source, runId, artifactId, candidate, mac, win, baseBytes, inventoryBytes }) {
    this.source = source
    this.repository = {
      fullName: EXPECTED_REPOSITORY,
      visibility: 'public',
      defaultBranch: 'main',
      archived: false,
      disabled: false,
    }
    this.runs = new Map([[runId, {
      id: runId,
      status: 'completed',
      conclusion: 'success',
      headSha: source,
      headBranch: 'main',
      event: 'workflow_dispatch',
      path: '.github/workflows/desktop-compatibility-attestation.yml',
      runAttempt: 1,
    }]])
    this.jobs = new Map([[runId, [{
      name: 'Materialize exact R2 bytes for the accepted 2.0.13 schema-2 parser',
      status: 'completed',
      conclusion: 'success',
    }]]])
    this.sourceFiles = new Map([
      ['desktop/e-mate-desktop/base-contract.json', Buffer.from(baseBytes)],
      ['packages/dsh/profile/component-inventory.json', Buffer.from(inventoryBytes)],
    ])
    const files = new Map([
      ['desktop-candidate.json', bufferSource(pretty(candidate))],
      ['e-Mate-2.0.15-mac-universal.dmg', bufferSource(mac)],
      ['e-Mate-2.0.15-win-x64-Setup.exe', bufferSource(win)],
    ])
    const archiveSha256 = '7'.repeat(64)
    const archiveBytes = 4096
    this.artifact = {
      metadata: {
        id: artifactId,
        name: `e-mate-desktop-release-${source}`,
        runId,
        digest: `sha256:${archiveSha256}`,
        expired: false,
        sourceCommit: source,
        bytes: archiveBytes,
      },
      bundle: {
        archiveSha256,
        archiveBytes,
        files,
        stored: new Set(files.keys()),
        async storedEntries() { return new Set(this.stored) },
      },
    }
  }

  async getRepository() { return structuredClone(this.repository) }
  async getBranchHead() { return this.source }
  async getRun(id) { return structuredClone(this.runs.get(String(id))) }
  async getRunJobs(id) { return structuredClone(this.jobs.get(String(id))) }
  async getArtifact() { return structuredClone(this.artifact.metadata) }
  async downloadArtifact() { return this.artifact.bundle }
  async getFile(path) { return Buffer.from(this.sourceFiles.get(path)) }
  replaceCandidate(candidate) {
    this.artifact.bundle.files.set('desktop-candidate.json', bufferSource(pretty(candidate)))
  }
}

function fileIdentityFromBytes(bytes) {
  return { bytes: bytes.byteLength, sha256: sha256(bytes) }
}
