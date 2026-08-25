import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, verify } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { describe, it } from 'node:test'
import {
  CLOUDFLARE_HANDOFF_FILENAME,
  DESKTOP_RELEASE_ARTIFACT_FILES,
  EXPECTED_ACTION_REPOSITORY,
  EXPECTED_REPOSITORY,
  LEGACY_TOMBSTONE,
  PERFORMANCE_EVIDENCE_FILENAME,
  PUBLICATION_PLAN_FILENAME,
  PUBLIC_ORIGIN,
  RELEASE_SIGNATURE_CONTEXT,
  SIGNED_MANIFEST_FILENAME,
  bufferSource,
  canonicalJson,
  parseExpectedCurrent,
  performanceAdmissionArtifactName,
  prepareDesktopPublication,
  signPerformanceAdmission,
} from '../src/publisher.mjs'
import { parseStoredArchiveEntries, validateArchiveEntries } from '../src/main.mjs'

const SOURCE = 'a'.repeat(40)
const BASE_ID = `e-mate-desktop-profile-v7-dsh-${SOURCE.slice(0, 12)}`
const KEY_ID = 'e0a81164526dcbcd'

describe('external Desktop Cloudflare plugin handoff owner', () => {
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
    assert.equal(verify(
      null,
      Buffer.concat([RELEASE_SIGNATURE_CONTEXT, Buffer.from(canonicalJson(unsigned), 'utf8')]),
      fixture.keyPair.publicKey,
      Buffer.from(signature.value, 'base64'),
    ), true)

    const planBytes = await result.files.get(PUBLICATION_PLAN_FILENAME).read()
    const plan = JSON.parse(planBytes)
    assert.deepEqual(Object.keys(plan), [
      'schema_version', 'document_type', 'status', 'publication_authority', 'repository',
      'source_commit', 'bucket', 'public_origin', 'github', 'signed_manifest',
      'legacy_tombstone', 'immutable_objects', 'active_pointer',
    ])
    assert.equal(plan.status, 'ready-for-cloudflare-plugin')
    assert.equal(plan.publication_authority, 'codex-cloudflare-plugin')
    assert.equal(plan.active_pointer.execution_order, 'last')
    assert.equal(plan.active_pointer.expected_current, 'absent')
    assert.equal(plan.active_pointer.cache_control, 'no-store')
    assert.deepEqual(plan.legacy_tombstone, {
      status: 'expected-unchanged',
      mutation: 'forbidden',
      key: LEGACY_TOMBSTONE.key,
      url: `${PUBLIC_ORIGIN}/${LEGACY_TOMBSTONE.key}`,
      bytes: LEGACY_TOMBSTONE.bytes,
      sha256: LEGACY_TOMBSTONE.sha256,
      content_type: 'application/json',
    })

    const [mac, win, manual] = plan.immutable_objects
    assert.deepEqual([mac.github_artifact_id, win.github_artifact_id], ['206', '207'])
    assert.deepEqual([mac.github_run_id, win.github_run_id], ['102', '102'])
    assert.deepEqual([mac.github_run_attempt, win.github_run_attempt], [1, 1])
    assert.deepEqual([mac.github_artifact_name, win.github_artifact_name], [
      `e-mate-desktop-macos-${SOURCE}`,
      `e-mate-desktop-windows-${SOURCE}`,
    ])
    assert.deepEqual([mac.artifact_path, win.artifact_path], DESKTOP_RELEASE_ARTIFACT_FILES.slice(1))
    assert.ok([mac, win].every(item => /^sha256:[0-9a-f]{64}$/u.test(item.github_artifact_digest)))
    assert.equal(manual.artifact_path, SIGNED_MANIFEST_FILENAME)
    for (const field of ['bytes', 'sha256', 'content_type']) {
      assert.equal(manual[field], plan.active_pointer[field])
    }
    assert.equal(manual.sha256, sha256(signedBytes))

    const handoff = JSON.parse(await result.files.get(CLOUDFLARE_HANDOFF_FILENAME).read())
    assert.deepEqual(Object.keys(handoff), [
      'schema_version', 'document_type', 'status', 'publication_authority', 'repository',
      'source_commit', 'action', 'github', 'files', 'production_state',
    ])
    assert.equal(handoff.status, 'ready-for-cloudflare-plugin')
    assert.deepEqual(handoff.production_state, {
      r2_write_performed: false,
      public_readback_performed: false,
      active_pointer_changed: false,
    })
    assert.equal(handoff.files.signed_manifest.sha256, sha256(signedBytes))
    assert.equal(handoff.files.publication_plan.sha256, sha256(planBytes))
    const forbiddenStatus = new RegExp(`"status":"(?:publi${'shed'}|already-publi${'shed'})"`, 'u')
    assert.doesNotMatch(JSON.stringify({ plan, handoff }), forbiddenStatus)
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
  })

  it('accepts the native same-source Windows retry only with its exact staging artifact', async () => {
    const fixture = releaseFixture()
    const manifest = JSON.parse(fixture.github.file('201', 'desktop-release-unsigned.json').buffer)
    const candidate = JSON.parse(fixture.github.file('202', 'desktop-candidate.json').buffer)
    manifest.artifacts.win32.build_run_id = '99'
    candidate.artifacts.win32.build_run_id = '99'
    fixture.github.replaceFile('201', 'desktop-release-unsigned.json', pretty(manifest))
    fixture.github.replaceFile('202', 'desktop-candidate.json', pretty(candidate))
    fixture.github.artifacts.get('207').metadata.runId = '99'
    fixture.github.runs.set('99', {
      ...run('99', '.github/workflows/desktop-release.yml', 'workflow_dispatch'),
      conclusion: 'failure',
    })
    fixture.github.jobs.set('99', [
      job('Build and verify the e-Mate profile'),
      job('Build unsigned Windows x64 installer'),
    ])
    fixture.github.jobs.set('102', [
      job('Validate reusable profile and Windows artifacts'),
      job('Build unsigned macOS universal disk image'),
      job('Bind native artifacts to the release manifest'),
    ])

    const result = await fixture.prepare()
    const plan = JSON.parse(await result.files.get(PUBLICATION_PLAN_FILENAME).read())
    assert.equal(plan.immutable_objects[1].github_run_id, '99')
  })

  it('fails closed on authority, provenance, closed-schema, staging, or trust drift', async t => {
    const cases = [
      ['unexpected repository', fixture => { fixture.config.repository = 'zyfjacksonchen-source/e-Mate' }],
      ['unprotected main', fixture => { fixture.github.protection.enforceAdmins = false }],
      ['private repository', fixture => { fixture.github.repository.visibility = 'private' }],
      ['failed CI', fixture => { fixture.github.jobs.get('100')[0].conclusion = 'failure' }],
      ['rerun CI', fixture => { fixture.github.runs.get('100').runAttempt = 2 }],
      ['rerun admission', fixture => { fixture.github.runs.get('101').runAttempt = 2 }],
      ['rerun Desktop build', fixture => { fixture.github.runs.get('102').runAttempt = 2 }],
      ['rerun performance', fixture => { fixture.github.runs.get('103').runAttempt = 2 }],
      ['extra admission file', fixture => {
        fixture.github.artifacts.get('201').bundle.files.set('extra.json', testSource('{}'))
      }],
      ['extra final candidate file', fixture => {
        fixture.github.artifacts.get('202').bundle.files.set('extra.bin', testSource('extra'))
      }],
      ['extra staging file', fixture => {
        fixture.github.artifacts.get('206').bundle.files.set('extra.bin', testSource('extra'))
      }],
      ['mac-smoke staging file', fixture => {
        fixture.github.artifacts.get('206').bundle.files.set('mac-smoke.dmg', testSource('smoke'))
      }],
      ['symlink payload cannot replace exact installer bytes', fixture => {
        fixture.github.replaceFile('206', 'e-Mate-2.0.13-mac-universal.dmg', Buffer.from('../outside'))
      }],
      ['staging artifact name drift', fixture => {
        fixture.github.artifacts.get('206').metadata.name = 'other'
      }],
      ['staging artifact run drift', fixture => {
        fixture.github.artifacts.get('207').metadata.runId = '101'
      }],
      ['compressed staging entry', fixture => {
        fixture.github.artifacts.get('206').bundle.stored.delete('e-Mate-2.0.13-mac-universal.dmg')
      }],
      ['final installer bytes drift', fixture => {
        fixture.github.replaceFile('202', 'e-Mate-2.0.13-win-x64-Setup.exe', Buffer.from('other'))
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
      '      19  Stored       19   0% 08-25-2026 00:00 00000000  e-Mate-2.0.13-mac-universal.dmg',
      '      20  Defl:N       18  10% 08-25-2026 00:00 00000000  e-Mate-2.0.13-win-x64-Setup.exe',
    ].join('\n')
    assert.deepEqual([...parseStoredArchiveEntries(listing, DESKTOP_RELEASE_ARTIFACT_FILES.slice(1))], [
      'e-Mate-2.0.13-mac-universal.dmg',
    ])
  })
})

function releaseFixture() {
  const keyPair = generateKeyPairSync('ed25519')
  const privateKeyPem = keyPair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
  const publicKey = keyPair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
  const mac = Buffer.from('exact-mac-installer')
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
  const artifacts = {
    darwin: manifestArtifact('darwin', mac, '102'),
    win32: manifestArtifact('win32', win, '102'),
  }
  const evidence = publicationEvidence('performance-run-accepted-1', SOURCE, artifacts)
  const evidenceBytes = pretty(evidence)
  const verifier = {
    contract: 'ttft-v2',
    source: 'scripts/performance-parity.mjs',
    source_commit: SOURCE,
    source_sha256: '6'.repeat(64),
    harness_commit: SOURCE,
    evidence_filename: PERFORMANCE_EVIDENCE_FILENAME,
    decision_sha256: sha256(pretty(evidence.decision)),
    gate_status: 'passed',
  }
  const performanceAdmission = signPerformanceAdmission({
    schema_version: 1,
    document_type: 'emate.performance-admission',
    status: 'passed',
    performance_run_id: evidence.performance_run_id,
    source_commit: SOURCE,
    base_contract_id: BASE_ID,
    profile_component_aggregate_sha256: aggregate.aggregate_sha256,
    desktop_artifacts: {
      darwin: { bytes: artifacts.darwin.bytes, sha256: artifacts.darwin.sha256 },
      win32: { bytes: artifacts.win32.bytes, sha256: artifacts.win32.sha256 },
    },
    evidence_sha256: sha256(evidenceBytes),
    verifier,
  }, privateKeyPem, KEY_ID)
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
        name: performanceAdmissionArtifactName(SOURCE, 1),
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
      performance_run_id: evidence.performance_run_id,
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
      artifact('203', performanceAdmissionArtifactName(SOURCE, 1), '103', performanceBundleSha, {
        'performance-admission.json': performanceBytes,
        [PERFORMANCE_EVIDENCE_FILENAME]: evidenceBytes,
        ...Object.fromEntries(publicationEvidencePaths(evidence).map(path => [path, Buffer.from('{}')])),
      }),
      artifact('206', `e-mate-desktop-macos-${SOURCE}`, '102', 'a'.repeat(64), {
        'e-Mate-2.0.13-mac-universal.dmg': mac,
      }),
      artifact('207', `e-mate-desktop-windows-${SOURCE}`, '102', 'b'.repeat(64), {
        'e-Mate-2.0.13-win-x64-Setup.exe': win,
      }),
    ],
  })
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
    macosArtifactId: '206',
    windowsArtifactId: '207',
    expectedSignedCurrent: null,
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

function publicationEvidence(performanceRunId, harnessCommit, artifacts) {
  const path = (name, candidate) => {
    const runReceipt = Object.fromEntries([
      ['raw_samples_artifact', 'raw-samples'],
      ['native_trace_artifact', 'native-session-trace'],
      ['provider_receipt_artifact', 'provider-invocation-receipt'],
      ['request_header_artifact', 'request-headers'],
      ['renderer_paint_artifact', 'renderer-paint-trace'],
      ['installed_runtime_artifact', 'installed-runtime-receipt'],
      ...(candidate ? [['enterprise_receipt_artifact', 'enterprise-runtime-receipt']] : []),
    ].map(([field, kind]) => [field, {
      kind,
      path: `evidence/${name}/${field}.json`,
      sha256: sha256(Buffer.from('{}')),
    }]))
    if (candidate) {
      runReceipt.runtime = {
        source_commit: SOURCE,
        base_contract_id: BASE_ID,
        profile_generation: '4'.repeat(64),
        composition_sha256: '5'.repeat(64),
        desktop_artifact_sha256: artifacts.darwin.sha256,
        desktop_artifact_bytes: artifacts.darwin.bytes,
      }
      runReceipt.install_receipt = {
        target: 'darwin-arm64',
        package_sha256: artifacts.darwin.sha256,
        package_bytes: artifacts.darwin.bytes,
      }
    }
    return { run_receipt: runReceipt }
  }
  return {
    schema_version: 2,
    comparison_kind: 'installed-2.0.12-vs-2.0.13',
    performance_run_id: performanceRunId,
    evidence_kind: 'production-real-provider',
    harness_commit: harnessCommit,
    paths: {
      baseline: path('baseline', false),
      emate_online: path('emate_online', true),
      emate_enterprise_unavailable_valid_cache: path('emate_enterprise_unavailable_valid_cache', true),
    },
    production_artifacts_verified: true,
    decision: { gate_status: 'passed', failures: [], production_receipt_failures: [], comparisons: {} },
  }
}

function publicationEvidencePaths(evidence) {
  return Object.values(evidence.paths).flatMap(path => Object.entries(path.run_receipt)
    .filter(([name]) => name.endsWith('_artifact'))
    .map(([, value]) => value.path))
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
    this.protection = {
      requiredStatusChecks: { strict: true, contexts: ['CI admission'] },
      enforceAdmins: true,
      requiredLinearHistory: true,
      allowForcePushes: false,
      allowDeletions: false,
    }
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

  async getRepository() { return structuredClone(this.repository) }
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
  const stored = new Set(Object.keys(files))
  return {
    metadata: { id, name, runId, digest: `sha256:${archiveSha256}`, expired: false },
    bundle: {
      archiveSha256,
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

function pretty(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`)
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}
