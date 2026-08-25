import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, verify } from 'node:crypto'
import { describe, it } from 'node:test'
import {
  EXPECTED_ACTION_REPOSITORY,
  EXPECTED_REPOSITORY,
  LEGACY_TOMBSTONE,
  PUBLIC_ORIGIN,
  RELEASE_SIGNATURE_CONTEXT,
  bufferSource,
  canonicalJson,
  parseExpectedCurrent,
  publishDesktopRelease,
  signPerformanceAdmission,
} from '../src/publisher.mjs'
import { R2Store, validateArchiveEntries } from '../src/main.mjs'

const SOURCE = 'a'.repeat(40)
const BASE_ID = `e-mate-desktop-profile-v7-dsh-${SOURCE.slice(0, 12)}`
const KEY_ID = 'e0a81164526dcbcd'

describe('external Desktop publication owner', () => {
  it('validates everything before writing installers, manual manifest, then the CAS pointer', async () => {
    const fixture = releaseFixture()
    const receipt = await fixture.publish()

    assert.equal(receipt.status, 'published')
    assert.deepEqual(fixture.store.writes.map(item => item.key), [
      `desktop/releases/v2.0.13/${SOURCE}/e-Mate-2.0.13-mac-universal.dmg`,
      `desktop/releases/v2.0.13/${SOURCE}/e-Mate-2.0.13-win-x64-Setup.exe`,
      'desktop/manual/v2.0.13/latest.json',
      'desktop/signed/latest.json',
    ])
    assert.ok(fixture.store.events.indexOf('public:desktop/manual/v2.0.13/latest.json')
      < fixture.store.events.indexOf('cas:desktop/signed/latest.json'))
    assert.ok(!fixture.store.writes.some(item => item.key === LEGACY_TOMBSTONE.key))

    const signed = JSON.parse(fixture.store.objects.get('desktop/signed/latest.json').body)
    const { signature, ...unsigned } = signed
    assert.equal(signature.key_id, KEY_ID)
    assert.equal(verify(
      null,
      Buffer.concat([RELEASE_SIGNATURE_CONTEXT, Buffer.from(canonicalJson(unsigned), 'utf8')]),
      fixture.keyPair.publicKey,
      Buffer.from(signature.value, 'base64'),
    ), true)
    assert.equal(receipt.manifest.identity_sha256, sha256(Buffer.from(canonicalJson(signed), 'utf8')))
  })

  it('fails closed before the first write for provenance, trust, bytes, schema, or tombstone drift', async t => {
    const cases = [
      ['unprotected main', fixture => { fixture.github.protection.enforceAdmins = false }],
      ['failed CI job', fixture => { fixture.github.jobs.get('100')[0].conclusion = 'failure' }],
      ['Base trust-key drift', fixture => {
        const base = JSON.parse(fixture.github.file('201', 'base-contract.json').buffer)
        base.profile_signing_keys[0].public_key_spki_der_base64 = Buffer.alloc(44).toString('base64')
        fixture.github.replaceFile('201', 'base-contract.json', pretty(base))
      }],
      ['Base schema drift', fixture => {
        const base = JSON.parse(fixture.github.file('201', 'base-contract.json').buffer)
        base.unreviewed_field = true
        fixture.github.replaceFile('201', 'base-contract.json', pretty(base))
      }],
      ['GitHub artifact digest drift', fixture => {
        fixture.github.artifacts.get('202').metadata.digest = `sha256:${'0'.repeat(64)}`
      }],
      ['installer-byte drift', fixture => {
        fixture.github.replaceFile('202', 'e-Mate-2.0.13-win-x64-Setup.exe', Buffer.from('other-win'))
      }],
      ['installer build-run drift', fixture => {
        const manifest = JSON.parse(fixture.github.file('201', 'desktop-release-unsigned.json').buffer)
        manifest.artifacts.win32.build_run_id = '999'
        fixture.github.replaceFile('201', 'desktop-release-unsigned.json', pretty(manifest))
      }],
      ['performance-signature drift', fixture => {
        const admission = JSON.parse(fixture.github.file('203', 'performance-admission.json').buffer)
        admission.signature.value = Buffer.alloc(64).toString('base64')
        const raw = pretty(admission)
        fixture.github.replaceFile('203', 'performance-admission.json', raw)
        const manifest = JSON.parse(fixture.github.file('201', 'desktop-release-unsigned.json').buffer)
        manifest.performance.admission_sha256 = sha256(raw)
        fixture.github.replaceFile('201', 'desktop-release-unsigned.json', pretty(manifest))
      }],
      ['unsigned-field drift', fixture => {
        const manifest = JSON.parse(fixture.github.file('201', 'desktop-release-unsigned.json').buffer)
        manifest.channel = 'stable'
        fixture.github.replaceFile('201', 'desktop-release-unsigned.json', pretty(manifest))
      }],
      ['legacy tombstone drift', fixture => {
        fixture.store.objects.get(LEGACY_TOMBSTONE.key).body = Buffer.from('drift')
      }],
      ['manual create-only collision', fixture => {
        fixture.store.objects.set('desktop/manual/v2.0.13/latest.json', objectRecord(Buffer.from('different'), {
          contentType: 'application/json', cacheControl: 'public,max-age=31536000,immutable',
        }))
      }],
    ]
    for (const [name, mutate] of cases) {
      await t.test(name, async () => {
        const fixture = releaseFixture()
        mutate(fixture)
        await assert.rejects(fixture.publish())
        assert.deepEqual(fixture.store.writes, [])
      })
    }
  })

  it('does not activate the pointer when public byte readback fails after immutable writes', async () => {
    const fixture = releaseFixture()
    fixture.store.publicTransform = (key, state) => key === 'desktop/manual/v2.0.13/latest.json' && state.exists
      ? { ...state, sha256: 'f'.repeat(64) }
      : state

    await assert.rejects(fixture.publish(), /identity drifted/u)
    assert.deepEqual(fixture.store.writes.map(item => item.key), [
      `desktop/releases/v2.0.13/${SOURCE}/e-Mate-2.0.13-mac-universal.dmg`,
      `desktop/releases/v2.0.13/${SOURCE}/e-Mate-2.0.13-win-x64-Setup.exe`,
      'desktop/manual/v2.0.13/latest.json',
    ])
    assert.equal(fixture.store.objects.has('desktop/signed/latest.json'), false)
  })

  it('resumes an identical partially or fully published release without overwriting immutable keys', async () => {
    const fixture = releaseFixture()
    const first = await fixture.publish()
    const writeCount = fixture.store.writes.length
    fixture.config.expectedSignedCurrent = {
      bytes: first.manifest.raw_bytes,
      sha256: first.manifest.raw_sha256,
    }
    const second = await fixture.publish()

    assert.equal(second.status, 'already-published')
    assert.equal(fixture.store.writes.length, writeCount)
  })

  it('leaves only immutable objects when CAS detects a concurrent pointer', async () => {
    const fixture = releaseFixture()
    fixture.store.beforeCas = key => {
      fixture.store.objects.set(key, objectRecord(Buffer.from('concurrent'), {
        contentType: 'application/json', cacheControl: 'no-store',
      }))
    }
    await assert.rejects(fixture.publish(), /CAS precondition/u)
    assert.ok(fixture.store.objects.has('desktop/manual/v2.0.13/latest.json'))
    assert.ok(!fixture.store.writes.some(item => item.key === 'desktop/signed/latest.json'))
  })

  it('requires an explicit absent or byte/hash expected pointer identity', () => {
    assert.equal(parseExpectedCurrent('absent'), null)
    assert.deepEqual(parseExpectedCurrent(`123:${'a'.repeat(64)}`), { bytes: 123, sha256: 'a'.repeat(64) })
    assert.throws(() => parseExpectedCurrent('latest'), /expected signed current/u)
  })

  it('rejects archive paths that could escape or be reinterpreted by unzip', () => {
    assert.doesNotThrow(() => validateArchiveEntries(['base-contract.json', 'evidence/receipt.json']))
    for (const path of ['../escape', '/absolute', 'wild*card', '-option', 'line\nbreak']) {
      assert.throws(() => validateArchiveEntries([path]), /artifact path/u)
    }
  })

  it('signs R2 conditional requests with SigV4 without placing secrets in the URL', async () => {
    const calls = []
    const store = new R2Store({
      accountId: 'a'.repeat(32),
      accessKeyId: 'access-id',
      secretAccessKey: 'do-not-leak-secret',
      bucket: 'e-mate-downloads',
      now: () => new Date('2026-08-25T00:00:00.000Z'),
      fetch: async (url, init) => {
        calls.push({ url, init })
        return new Response(null, { status: init.method === 'GET' ? 404 : 200 })
      },
    })
    assert.deepEqual(await store.inspect('desktop/signed/latest.json'), { exists: false })
    await store.putCreateOnly('desktop/manual/v2.0.13/latest.json', bufferSource(Buffer.from('signed')), {
      contentType: 'application/json',
      cacheControl: 'public,max-age=31536000,immutable',
    })
    await store.putCas('desktop/signed/latest.json', bufferSource(Buffer.from('signed')), {
      expectedEtag: '"expected-etag"',
      contentType: 'application/json',
      cacheControl: 'no-store',
    })

    assert.equal(calls.length, 3)
    assert.ok(!calls[0].url.includes('do-not-leak-secret'))
    assert.match(calls[0].init.headers.authorization, /^AWS4-HMAC-SHA256 Credential=access-id\//u)
    assert.equal(calls[1].init.headers['if-none-match'], '*')
    assert.match(calls[1].init.headers.authorization, /SignedHeaders=[^,]*if-none-match/u)
    assert.equal(calls[2].init.headers['if-match'], '"expected-etag"')
    assert.match(calls[2].init.headers.authorization, /SignedHeaders=[^,]*if-match/u)
    assert.ok(!JSON.stringify(calls).includes('do-not-leak-secret'))
  })
})

function releaseFixture() {
  const keyPair = generateKeyPairSync('ed25519')
  const privateKeyPem = keyPair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
  const publicKey = keyPair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
  const mac = Buffer.from('exact-mac-installer')
  const win = Buffer.from('exact-windows-installer')
  const aggregate = {
    aggregate_sha256: '1'.repeat(64),
    inventory_sha256: '2'.repeat(64),
    staged_profile_tree_sha256: '3'.repeat(64),
    targets: ['darwin-arm64', 'darwin-x64', 'win32-x64'].map(target => ({
      target,
      profile_generation: '4'.repeat(64),
      component_aggregate_sha256: '5'.repeat(64),
    })),
  }
  const artifacts = {
    darwin: manifestArtifact('darwin', mac, '102'),
    win32: manifestArtifact('win32', win, '102'),
  }
  const verifier = { contract: 'ttft-v2', gate: 'passed' }
  const performanceUnsigned = {
    schema_version: 1,
    document_type: 'emate.performance-admission',
    status: 'passed',
    performance_run_id: 'performance-run-accepted-1',
    source_commit: SOURCE,
    base_contract_id: BASE_ID,
    profile_component_aggregate_sha256: aggregate.aggregate_sha256,
    desktop_artifacts: {
      darwin: { bytes: artifacts.darwin.bytes, sha256: artifacts.darwin.sha256 },
      win32: { bytes: artifacts.win32.bytes, sha256: artifacts.win32.sha256 },
    },
    evidence_sha256: '6'.repeat(64),
    verifier,
  }
  const performanceAdmission = signPerformanceAdmission(performanceUnsigned, privateKeyPem, KEY_ID)
  const performanceBytes = pretty(performanceAdmission)
  const candidateBundleSha = '7'.repeat(64)
  const performanceBundleSha = '8'.repeat(64)
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
      {
        role: 'performance_admission',
        name: `e-mate-performance-admission-${SOURCE}`,
        artifact_id: '203',
        digest: `sha256:${performanceBundleSha}`,
        run_id: '103',
        run_attempt: 1,
      },
    ],
  }
  const manifest = {
    schema_version: 1,
    document_type: 'emate.desktop-release-manifest',
    release_status: 'admitted',
    version: '2.0.13',
    source_commit: SOURCE,
    base_contract_id: BASE_ID,
    schedule_protocol_floor: 1,
    profile_component_aggregate: aggregate,
    performance: {
      performance_run_id: performanceUnsigned.performance_run_id,
      admission_sha256: sha256(performanceBytes),
      signature_key_id: KEY_ID,
      verifier,
    },
    github_artifact_provenance: provenance,
    artifacts,
  }
  const candidate = {
    schema_version: 1,
    document_type: 'emate.desktop-artifact-candidate',
    release_status: 'performance-pending',
    version: '2.0.13',
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
  const github = new FakeGithub({
    source: SOURCE,
    artifacts: [
      artifact('201', `e-mate-desktop-admission-${SOURCE}`, '101', '9'.repeat(64), {
        'base-contract.json': pretty(base),
        'desktop-release-unsigned.json': pretty(manifest),
      }),
      artifact('202', `e-mate-desktop-release-${SOURCE}`, '102', candidateBundleSha, {
        'desktop-candidate.json': pretty(candidate),
        'e-Mate-2.0.13-mac-universal.dmg': mac,
        'e-Mate-2.0.13-win-x64-Setup.exe': win,
      }),
      artifact('203', `e-mate-performance-admission-${SOURCE}`, '103', performanceBundleSha, {
        'performance-admission.json': performanceBytes,
        'evidence/receipt.json': Buffer.from('{}'),
      }),
    ],
  })
  const store = new FakeStore(legacyManifestBytes())
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
    admissionArtifactId: '201',
    expectedSignedCurrent: null,
    signingKeyId: KEY_ID,
    privateKeyPem,
  }
  return {
    keyPair,
    github,
    store,
    config,
    publish: () => publishDesktopRelease(config, { github, store, publicReader: store.publicReader }),
  }
}

class FakeGithub {
  constructor({ source, artifacts }) {
    this.source = source
    this.protection = { requiredStatusChecks: { strict: true, contexts: ['CI admission'] }, enforceAdmins: true }
    this.runs = new Map([
      ['100', run('100', '.github/workflows/ci.yml', 'push')],
      ['101', run('101', '.github/workflows/desktop-admission.yml', 'workflow_dispatch')],
      ['102', run('102', '.github/workflows/desktop-release.yml', 'workflow_dispatch')],
      ['103', run('103', '.github/workflows/desktop-performance.yml', 'workflow_dispatch')],
    ])
    this.jobs = new Map([
      ['100', [job('CI admission')]],
      ['101', [job('Desktop release admission')]],
      ['102', [
        job('Build and verify the e-Mate profile'),
        job('Build unsigned Windows x64 installer'),
        job('Build unsigned macOS universal disk image'),
        job('Bind native artifacts to the release manifest'),
      ]],
      ['103', [job('Performance admission')]],
    ])
    this.artifacts = new Map(artifacts.map(item => [item.metadata.id, item]))
  }

  async getBranchHead() { return this.source }
  async getBranchProtection() { return this.protection }
  async getRun(id) { return structuredClone(this.runs.get(String(id))) }
  async getRunJobs(id) { return structuredClone(this.jobs.get(String(id))) }
  async getArtifact(id) { return structuredClone(this.artifacts.get(String(id)).metadata) }
  async downloadArtifact(id) { return this.artifacts.get(String(id)).bundle }
  file(id, name) { return this.artifacts.get(String(id)).bundle.files.get(name) }
  replaceFile(id, name, bytes) {
    this.artifacts.get(String(id)).bundle.files.set(name, testSource(bytes))
  }
}

class FakeStore {
  constructor(legacyBytes) {
    this.objects = new Map([[LEGACY_TOMBSTONE.key, objectRecord(legacyBytes, {
      contentType: 'application/json', cacheControl: 'no-store',
    })]])
    this.writes = []
    this.events = []
    this.publicTransform = undefined
    this.beforeCas = undefined
    this.publicReader = {
      inspect: async (key, options) => {
        this.events.push(`public:${key}`)
        const state = await this.#inspect(key, options)
        return this.publicTransform?.(key, state) ?? state
      },
    }
  }

  async inspect(key, options) {
    this.events.push(`auth:${key}`)
    return this.#inspect(key, options)
  }

  async putCreateOnly(key, source, metadata) {
    if (this.objects.has(key)) throw new Error('create-only collision')
    const body = await source.read(Number.MAX_SAFE_INTEGER)
    this.objects.set(key, objectRecord(body, metadata))
    this.writes.push({ kind: 'create', key })
    this.events.push(`create:${key}`)
  }

  async putCas(key, source, options) {
    this.beforeCas?.(key)
    const current = this.objects.get(key)
    if (options.expectedEtag === null ? current !== undefined : current?.etag !== options.expectedEtag) {
      throw new Error('CAS precondition failed')
    }
    const body = await source.read(Number.MAX_SAFE_INTEGER)
    this.objects.set(key, objectRecord(body, options))
    this.writes.push({ kind: 'cas', key })
    this.events.push(`cas:${key}`)
  }

  async #inspect(key, options = {}) {
    const record = this.objects.get(key)
    if (record === undefined) return { exists: false }
    return {
      exists: true,
      bytes: record.body.byteLength,
      sha256: sha256(record.body),
      etag: record.etag,
      contentType: record.contentType,
      cacheControl: record.cacheControl,
      ...(options.collectLimit > 0 ? { body: Buffer.from(record.body) } : {}),
    }
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

function artifact(id, name, runId, archiveSha256, files) {
  return {
    metadata: { id, name, runId, digest: `sha256:${archiveSha256}`, expired: false },
    bundle: {
      archiveSha256,
      files: new Map(Object.entries(files).map(([path, bytes]) => [path, testSource(bytes)])),
    },
  }
}

function testSource(bytes) {
  const buffer = Buffer.from(bytes)
  const source = bufferSource(buffer)
  return { ...source, buffer }
}

function manifestArtifact(platform, bytes, buildRunId) {
  const filename = platform === 'darwin'
    ? 'e-Mate-2.0.13-mac-universal.dmg'
    : 'e-Mate-2.0.13-win-x64-Setup.exe'
  return {
    url: `${PUBLIC_ORIGIN}/desktop/releases/v2.0.13/${SOURCE}/${filename}`,
    bytes: bytes.byteLength,
    sha256: sha256(bytes),
    build_source_commit: SOURCE,
    build_run_id: buildRunId,
  }
}

function legacyManifestBytes() {
  const value = {
    schema_version: 1,
    version: '2.0.12',
    source_commit: LEGACY_TOMBSTONE.sourceCommit,
    artifacts: Object.fromEntries(['darwin', 'win32'].map(platform => {
      const filename = platform === 'darwin'
        ? 'e-Mate-2.0.12-mac-universal.dmg'
        : 'e-Mate-2.0.12-win-x64-Setup.exe'
      return [platform, {
        url: `${PUBLIC_ORIGIN}/desktop/releases/v2.0.12/${LEGACY_TOMBSTONE.sourceCommit}/${filename}`,
        bytes: LEGACY_TOMBSTONE.artifacts[platform].bytes,
        sha256: LEGACY_TOMBSTONE.artifacts[platform].sha256,
        build_source_commit: LEGACY_TOMBSTONE.sourceCommit,
        build_run_id: LEGACY_TOMBSTONE.buildRunId,
      }]
    })),
  }
  const bytes = pretty(value)
  assert.equal(bytes.byteLength, LEGACY_TOMBSTONE.bytes)
  assert.equal(sha256(bytes), LEGACY_TOMBSTONE.sha256)
  return bytes
}

function objectRecord(body, metadata) {
  const bytes = Buffer.from(body)
  return {
    body: bytes,
    contentType: metadata.contentType,
    cacheControl: metadata.cacheControl,
    etag: `"${sha256(bytes).slice(0, 32)}"`,
  }
}

function pretty(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`)
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}
