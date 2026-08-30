import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, it } from 'node:test'
import {
  CLOUDFLARE_HANDOFF_FILENAME,
  PUBLICATION_PLAN_FILENAME,
  PUBLIC_ORIGIN,
  SIGNED_MANIFEST_FILENAME,
  admitLocalDesktopCandidate,
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
