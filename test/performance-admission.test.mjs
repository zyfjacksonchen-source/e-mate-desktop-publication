import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, verify } from 'node:crypto'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, it } from 'node:test'
import {
  EXPECTED_ACTION_REPOSITORY,
  EXPECTED_REPOSITORY,
  DESKTOP_RELEASE_ARTIFACT_FILES,
  PERFORMANCE_EVIDENCE_FILENAME,
  PERFORMANCE_AGGREGATE_SIGNATURE_CONTEXT,
  PERFORMANCE_MODEL_LEAF_IDS,
  PERFORMANCE_MODEL_ROSTER,
  PERFORMANCE_SIGNATURE_CONTEXT,
  PERFORMANCE_VERIFIER_SOURCE,
  PROFILE_COMPONENT_AGGREGATE_FILENAME,
  PUBLIC_ORIGIN,
  bufferSource,
  canonicalJson,
  createPerformanceAggregateAdmission,
  createPerformanceAdmission,
  performanceAdmissionArtifactName,
  performanceEvidenceArtifactName,
} from '../src/publisher.mjs'
import { runPerformanceVerifier } from '../src/performance-main.mjs'

const SOURCE = 'a'.repeat(40)
const HARNESS = 'c'.repeat(40)
const BASE_ID = `e-mate-desktop-profile-v7-dsh-${SOURCE.slice(0, 12)}`
const KEY_ID = 'e0a81164526dcbcd'

describe('external performance admission owner', () => {
  it('signs only exact protected-main build bytes and passed production evidence', async () => {
    const fixture = performanceFixture()
    const result = await fixture.admit()
    assert.equal(result.artifactName, performanceAdmissionArtifactName(SOURCE, 1))
    assert.equal(result.performanceRunId, fixture.evidence.performance_run_id)
    assert.equal(result.files.has(PERFORMANCE_VERIFIER_SOURCE), false)
    assert.deepEqual([...result.files.keys()].sort(), [
      'performance-admission.json',
      PERFORMANCE_EVIDENCE_FILENAME,
      ...supportingPaths(fixture.evidence),
    ].sort())

    const raw = await result.files.get('performance-admission.json').read()
    const admission = JSON.parse(raw)
    assert.deepEqual(Object.keys(admission), [
      'schema_version', 'document_type', 'status', 'performance_run_id', 'source_commit',
      'base_contract_id', 'profile_component_aggregate_sha256', 'desktop_artifacts',
      'evidence_sha256', 'verifier', 'signature',
    ])
    assert.deepEqual(admission.verifier, {
      contract: 'ttft-v2',
      source: PERFORMANCE_VERIFIER_SOURCE,
      source_commit: SOURCE,
      source_sha256: sha256(fixture.verifierBytes),
      harness_commit: HARNESS,
      evidence_filename: PERFORMANCE_EVIDENCE_FILENAME,
      decision_sha256: sha256(pretty(fixture.verified.decision)),
      gate_status: 'passed',
    })
    assert.equal(admission.evidence_sha256, sha256(pretty(fixture.verified)))
    const { signature, ...unsigned } = admission
    assert.equal(signature.key_id, KEY_ID)
    assert.equal(verify(
      null,
      Buffer.concat([PERFORMANCE_SIGNATURE_CONTEXT, Buffer.from(canonicalJson(unsigned), 'utf8')]),
      fixture.keyPair.publicKey,
      Buffer.from(signature.value, 'base64'),
    ), true)
  })

  it('fails closed for provenance, extra files, verifier drift, fixture gates, or install drift', async t => {
    const cases = [
      ['unprotected main', fixture => { fixture.github.protection.enforceAdmins = false }],
      ['private repository', fixture => { fixture.github.repository.visibility = 'private' }],
      ['rerun CI', fixture => { fixture.github.runs.get('100').runAttempt = 2 }],
      ['rerun Desktop build', fixture => { fixture.github.runs.get('102').runAttempt = 2 }],
      ['failed TTFT job', fixture => { fixture.github.jobs.get('103')[0].conclusion = 'failure' }],
      ['failed Profile publication job', fixture => { fixture.github.jobs.get('104')[0].conclusion = 'failure' }],
      ['rerun Profile publication', fixture => { fixture.github.runs.get('104').runAttempt = 2 }],
      ['Profile artifact from another run', fixture => {
        fixture.github.artifacts.get('204').metadata.runId = '102'
      }],
      ['Profile workflow path drift', fixture => {
        fixture.github.runs.get('104').path = '.github/workflows/desktop-release.yml'
      }],
      ['completed evidence run cannot impersonate the current run', fixture => {
        Object.assign(fixture.github.runs.get('103'), { status: 'completed', conclusion: 'success' })
      }],
      ['evidence artifact from another run', fixture => {
        fixture.github.artifacts.get('203').metadata.runId = '104'
      }],
      ['current performance source drift', fixture => {
        fixture.github.runs.get('103').headSha = 'b'.repeat(40)
      }],
      ['old-attempt evidence artifact', fixture => {
        fixture.config.currentRunAttempt = '2'
        fixture.github.runs.get('103').runAttempt = 2
        fixture.github.artifacts.get('203').metadata.name = `e-mate-performance-evidence-${SOURCE}-attempt-2`
      }],
      ['Profile aggregate digest drift', fixture => {
        const aggregate = JSON.parse(fixture.github.file('203', PROFILE_COMPONENT_AGGREGATE_FILENAME).buffer)
        aggregate.staged_profile_tree_sha256 = 'f'.repeat(64)
        fixture.github.replaceFile('203', PROFILE_COMPONENT_AGGREGATE_FILENAME, pretty(aggregate))
      }],
      ['extra evidence file', fixture => {
        fixture.github.artifacts.get('203').bundle.files.set('unreviewed.txt', testSource('extra'))
      }],
      ['protected source verifier drift', fixture => {
        fixture.github.sourceFiles.set(PERFORMANCE_VERIFIER_SOURCE, Buffer.from('different'))
      }],
      ['fixture result', fixture => { fixture.verified.evidence_kind = 'keyless-target-loop-collector-fixture' }],
      ['failed gate', fixture => { fixture.verified.decision.gate_status = 'failed' }],
      ['candidate install drift', fixture => {
        fixture.verified.paths.emate_online.run_receipt.runtime.desktop_artifact_sha256 = 'f'.repeat(64)
      }],
      ['Base source drift', fixture => {
        fixture.github.sourceFiles.set('desktop/e-mate-desktop/base-contract.json', Buffer.from('{}\n'))
      }],
    ]
    for (const [name, mutate] of cases) {
      await t.test(name, async () => {
        const fixture = performanceFixture()
        mutate(fixture)
        await assert.rejects(fixture.admit())
      })
    }
  })

  it('runs the downloaded verifier without forwarding signing or provenance secrets', async t => {
    const root = await mkdtemp(join(tmpdir(), 'e-mate-performance-runner-test-'))
    t.after(() => rm(root, { recursive: true, force: true }))
    const script = Buffer.from(`
      import { readFile, writeFile } from 'node:fs/promises'
      const input = process.argv[process.argv.indexOf('--input') + 1]
      const output = process.argv[process.argv.indexOf('--output') + 1]
      if (process.env.EMATE_DESKTOP_SIGNING_PRIVATE_KEY_PEM || process.env.EMATE_GITHUB_PROVENANCE_TOKEN) process.exit(9)
      const value = JSON.parse(await readFile(input, 'utf8'))
      await writeFile(output, JSON.stringify({ ...value, verified: true }, null, 2) + '\\n')
    `)
    const bundle = {
      files: new Map([
        [PERFORMANCE_VERIFIER_SOURCE, testSource(script)],
        [PERFORMANCE_EVIDENCE_FILENAME, testSource(pretty({ probe: true }))],
      ]),
    }
    const oldKey = process.env.EMATE_DESKTOP_SIGNING_PRIVATE_KEY_PEM
    const oldToken = process.env.EMATE_GITHUB_PROVENANCE_TOKEN
    process.env.EMATE_DESKTOP_SIGNING_PRIVATE_KEY_PEM = 'must-not-leak'
    process.env.EMATE_GITHUB_PROVENANCE_TOKEN = 'must-not-leak'
    t.after(() => {
      if (oldKey === undefined) delete process.env.EMATE_DESKTOP_SIGNING_PRIVATE_KEY_PEM
      else process.env.EMATE_DESKTOP_SIGNING_PRIVATE_KEY_PEM = oldKey
      if (oldToken === undefined) delete process.env.EMATE_GITHUB_PROVENANCE_TOKEN
      else process.env.EMATE_GITHUB_PROVENANCE_TOKEN = oldToken
    })
    assert.deepEqual(JSON.parse(await runPerformanceVerifier(bundle, root)), { probe: true, verified: true })

    bundle.files.set(PERFORMANCE_VERIFIER_SOURCE, testSource('process.exit(1)\n'))
    await assert.rejects(runPerformanceVerifier(bundle, root), /performance-parity rejected/u)
  })

  it('signs one ordered four-model aggregate over four independently verified leaves', async () => {
    const fixture = performanceAggregateFixture()
    const result = await fixture.admit()
    const raw = await result.files.get('performance-admission.json').read()
    const admission = JSON.parse(raw)
    assert.equal(admission.document_type, 'emate.performance-aggregate-admission')
    assert.deepEqual(admission.roster, PERFORMANCE_MODEL_ROSTER)
    assert.deepEqual(admission.children.map(child => child.route_id), PERFORMANCE_MODEL_ROSTER.map(model => model.route_id))
    assert.equal(new Set(admission.children.map(child => child.performance_run_id)).size, 4)
    assert.equal(admission.verifier.contract, 'ttft-v2-aggregate')
    assert.equal(admission.verifier.evidence_filename, 'performance-admission.json')
    assert.ok([...result.files.keys()].every(path => path === 'performance-admission.json' || path.startsWith('children/')))
    const { signature, ...unsigned } = admission
    assert.equal(verify(
      null,
      Buffer.concat([PERFORMANCE_AGGREGATE_SIGNATURE_CONTEXT, Buffer.from(canonicalJson(unsigned), 'utf8')]),
      fixture.keyPair.publicKey,
      Buffer.from(signature.value, 'base64'),
    ), true)
  })

  it('rejects missing, duplicate, misordered, extra, or failed four-model evidence', async t => {
    const cases = [
      ['missing', fixture => { fixture.config.evidenceArtifactIds.pop() }],
      ['duplicate', fixture => { fixture.config.evidenceArtifactIds[3] = fixture.config.evidenceArtifactIds[0] }],
      ['misordered', fixture => { fixture.config.evidenceArtifactIds.reverse() }],
      ['extra file', fixture => {
        fixture.github.artifacts.get(fixture.config.evidenceArtifactIds[2]).bundle.files.set('extra.json', testSource('{}'))
      }],
      ['failed child', fixture => {
        const id = fixture.config.evidenceArtifactIds[1]
        const evidence = JSON.parse(fixture.github.file(id, PERFORMANCE_EVIDENCE_FILENAME).buffer)
        evidence.evidence_kind = 'fixture'
        fixture.github.replaceFile(id, PERFORMANCE_EVIDENCE_FILENAME, pretty(evidence))
      }],
    ]
    for (const [name, mutate] of cases) {
      await t.test(name, async () => {
        const fixture = performanceAggregateFixture()
        mutate(fixture)
        await assert.rejects(fixture.admit())
      })
    }
  })

  it('exposes a separate action with no caller path, R2 binding, or publication step', async () => {
    const action = await readFile(new URL('../performance/action.yml', import.meta.url), 'utf8')
    const main = await readFile(new URL('../src/performance-main.mjs', import.meta.url), 'utf8')
    assert.match(action, /desktop-artifact-id:/u)
    assert.match(action, /profile-release-run-id:/u)
    assert.match(action, /profile-artifact-id:/u)
    for (const input of ['luna', 'sol', 'deepseek', 'doubao']) {
      assert.match(action, new RegExp(`${input}-evidence-artifact-id:`, 'u'))
    }
    assert.match(action, /artifact-path:/u)
    assert.match(action, /performance-main\.mjs/u)
    const forbidden = new RegExp([
      'receipt-path', `EMATE_${'R2_'}`, `${'R2'}${'Store'}`, `publishDesktop${'Release'}`,
    ].join('|'), 'u')
    assert.doesNotMatch(`${action}\n${main}`, forbidden)
  })
})

function performanceFixture() {
  const keyPair = generateKeyPairSync('ed25519')
  const privateKeyPem = keyPair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
  const mac = Buffer.from('exact-mac-installer')
  const win = Buffer.from('exact-windows-installer')
  const candidate = {
    schema_version: 1,
    document_type: 'emate.desktop-artifact-candidate',
    release_status: 'performance-pending',
    version: '2.0.13',
    source_commit: SOURCE,
    schedule_protocol_floor: 1,
    artifacts: {
      darwin: artifactRecord('darwin', mac),
      win32: artifactRecord('win32', win),
    },
  }
  const aggregateUnsigned = {
    inventory_sha256: '2'.repeat(64),
    staged_profile_tree_sha256: '3'.repeat(64),
    targets: ['darwin-arm64', 'darwin-x64', 'win32-x64'].map((target, index) => ({
      target,
      profile_generation: String(index + 4).repeat(64),
      component_aggregate_sha256: String(index + 7).repeat(64),
    })),
  }
  const aggregate = {
    aggregate_sha256: '5e7e8e251474acace51ce27b379b9b9b93a2cd50c6c489740bd8c0f450a81a58',
    ...aggregateUnsigned,
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
      harness_commit: HARNESS,
      harness_version: '0.1.0-rc.7',
    },
    schedule_protocol_floor: 1,
    harness_version: '0.1.0-rc.7',
    harness_commit: HARNESS,
    runtime_imports: { '@deepseek-ai/dsh-client-runtime': '0.1.0-rc.7', react: '18.3.1' },
    profile_signing_keys: [{
      id: KEY_ID,
      algorithm: 'ed25519',
      public_key_spki_der_base64: keyPair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    }],
  }
  const evidence = performanceEvidence(candidate, aggregate)
  const verified = {
    ...structuredClone(evidence),
    production_artifacts_verified: true,
    decision: { gate_status: 'passed', failures: [], production_receipt_failures: [], comparisons: {} },
  }
  const verifierBytes = Buffer.from('export const verifier = "protected-main"\n')
  const evidenceFiles = Object.fromEntries(supportingPaths(evidence).map(path => [path, pretty({ path })]))
  const github = new FakeGithub({
    artifacts: [
      githubArtifact('202', `e-mate-desktop-release-${SOURCE}`, '102', {
        'desktop-candidate.json': pretty(candidate),
        'e-Mate-2.0.13-mac-universal.dmg': mac,
        'e-Mate-2.0.13-win-x64-Setup.exe': win,
      }),
      githubArtifact('203', performanceEvidenceArtifactName(SOURCE, 1), '103', {
        [PERFORMANCE_EVIDENCE_FILENAME]: pretty(evidence),
        [PERFORMANCE_VERIFIER_SOURCE]: verifierBytes,
        [PROFILE_COMPONENT_AGGREGATE_FILENAME]: pretty(aggregate),
        ...evidenceFiles,
      }),
      githubArtifact('204', `e-mate-profile-native-cloudflare-publication-${SOURCE}`, '104', {
        'publication-plan.json': pretty({ status: 'prepared' }),
      }),
    ],
    sourceFiles: new Map([
      ['desktop/e-mate-desktop/base-contract.json', pretty(base)],
      [PERFORMANCE_VERIFIER_SOURCE, verifierBytes],
    ]),
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
    currentRunId: '103',
    currentRunAttempt: '1',
    desktopArtifactId: '202',
    profileReleaseRunId: '104',
    profileReleaseArtifactId: '204',
    evidenceArtifactId: '203',
    signingKeyId: KEY_ID,
    privateKeyPem,
  }
  return {
    keyPair,
    github,
    config,
    evidence,
    verified,
    verifierBytes,
    admit: () => createPerformanceAdmission(config, {
      github,
      verifyPerformance: async () => pretty(verified),
    }),
  }
}

function performanceAggregateFixture() {
  const fixture = performanceFixture()
  const artifactIds = []
  for (const [index, model] of PERFORMANCE_MODEL_ROSTER.entries()) {
    const id = String(210 + index)
    const evidence = structuredClone(fixture.evidence)
    evidence.performance_run_id = `production-performance-${model.route_id}`
    evidence.performance_model = model
    for (const path of Object.values(evidence.paths)) {
      path.run_receipt.provider = model.provider
      path.run_receipt.model = model.model
    }
    const evidenceFiles = Object.fromEntries(supportingPaths(evidence).map(path => [path, pretty({ path })]))
    const artifactValue = githubArtifact(
      id,
      performanceEvidenceArtifactName(SOURCE, 1, PERFORMANCE_MODEL_LEAF_IDS[index]),
      '103',
      {
        [PERFORMANCE_EVIDENCE_FILENAME]: pretty(evidence),
        [PERFORMANCE_VERIFIER_SOURCE]: fixture.verifierBytes,
        [PROFILE_COMPONENT_AGGREGATE_FILENAME]: fixture.github.file('203', PROFILE_COMPONENT_AGGREGATE_FILENAME).buffer,
        ...evidenceFiles,
      },
    )
    fixture.github.artifacts.set(id, artifactValue)
    artifactIds.push(id)
  }
  fixture.config.evidenceArtifactIds = artifactIds
  return {
    ...fixture,
    admit: () => createPerformanceAggregateAdmission(fixture.config, {
      github: fixture.github,
      verifyPerformance: async bundle => {
        const evidence = JSON.parse(bundle.files.get(PERFORMANCE_EVIDENCE_FILENAME).buffer)
        return pretty({
          ...evidence,
          production_artifacts_verified: true,
          decision: { gate_status: 'passed', failures: [], production_receipt_failures: [], comparisons: {} },
        })
      },
    }),
  }
}

class FakeGithub {
  constructor({ artifacts, sourceFiles }) {
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
      ['102', run('102', '.github/workflows/desktop-release.yml', 'workflow_dispatch')],
      ['103', {
        ...run('103', '.github/workflows/desktop-performance.yml', 'workflow_dispatch'),
        status: 'in_progress',
        conclusion: null,
      }],
      ['104', run('104', '.github/workflows/profile-release.yml', 'workflow_dispatch')],
    ])
    this.jobs = new Map([
      ['100', [job('CI admission')]],
      ['102', [
        job('Build and verify the e-Mate profile'),
        job('Build unsigned Windows x64 installer'),
        job('Build unsigned macOS universal disk image'),
        job('Bind native artifacts to the release manifest'),
      ]],
      ['103', [job('TTFT evidence')]],
      ['104', [job('Prepare signed native Cloudflare publication bundle')]],
    ])
    this.artifacts = new Map(artifacts.map(value => [value.metadata.id, value]))
    this.sourceFiles = sourceFiles
  }

  async getRepository() { return structuredClone(this.repository) }
  async getBranchHead() { return SOURCE }
  async getBranchProtection() { return structuredClone(this.protection) }
  async getRun(id) { return structuredClone(this.runs.get(String(id))) }
  async getRunJobs(id) { return structuredClone(this.jobs.get(String(id))) }
  async getArtifact(id) { return structuredClone(this.artifacts.get(String(id)).metadata) }
  async downloadArtifact(id) { return this.artifacts.get(String(id)).bundle }
  async getFile(path) { return Buffer.from(this.sourceFiles.get(path)) }
  file(id, name) { return this.artifacts.get(String(id)).bundle.files.get(name) }
  replaceFile(id, name, bytes) {
    this.artifacts.get(String(id)).bundle.files.set(name, testSource(bytes))
  }
}

function performanceEvidence(candidate, aggregate) {
  const path = (pathName, target) => {
    const profile = aggregate.targets.find(item => item.target === target)
    const platform = target === 'win32-x64' ? 'win32' : 'darwin'
    const artifact = candidate.artifacts[platform]
    const prefix = `evidence/${pathName}`
    const receipt = Object.fromEntries([
      ['raw_samples_artifact', 'raw-samples'],
      ['native_trace_artifact', 'native-session-trace'],
      ['provider_receipt_artifact', 'provider-invocation-receipt'],
      ['request_header_artifact', 'request-headers'],
      ['renderer_paint_artifact', 'renderer-paint-trace'],
      ['installed_runtime_artifact', 'installed-runtime-receipt'],
      ...(pathName === 'baseline' ? [] : [['enterprise_receipt_artifact', 'enterprise-runtime-receipt']]),
    ].map(([field, kind]) => [field, {
      kind,
      path: `${prefix}/${field}.json`,
      sha256: sha256(pretty({ path: `${prefix}/${field}.json` })),
    }]))
    receipt.runtime = pathName === 'baseline' ? {} : {
      source_commit: SOURCE,
      base_contract_id: BASE_ID,
      profile_generation: profile.profile_generation,
      composition_sha256: profile.component_aggregate_sha256,
      desktop_artifact_sha256: artifact.sha256,
      desktop_artifact_bytes: artifact.bytes,
    }
    receipt.install_receipt = pathName === 'baseline' ? {} : {
      target,
      package_sha256: artifact.sha256,
      package_bytes: artifact.bytes,
    }
    return { run_receipt: receipt }
  }
  return {
    schema_version: 2,
    comparison_kind: 'installed-2.0.12-vs-2.0.13',
    performance_run_id: 'production-performance-run-1',
    evidence_kind: 'production-real-provider',
    harness_commit: HARNESS,
    paths: {
      baseline: path('baseline', 'darwin-arm64'),
      emate_online: path('emate_online', 'darwin-arm64'),
      emate_enterprise_unavailable_valid_cache: path('emate_enterprise_unavailable_valid_cache', 'darwin-arm64'),
    },
  }
}

function supportingPaths(evidence) {
  return Object.values(evidence.paths).flatMap(path => Object.entries(path.run_receipt)
    .filter(([name]) => name.endsWith('_artifact'))
    .map(([, value]) => value.path))
}

function artifactRecord(platform, bytes) {
  const name = platform === 'darwin'
    ? 'e-Mate-2.0.13-mac-universal.dmg'
    : 'e-Mate-2.0.13-win-x64-Setup.exe'
  return {
    url: `${PUBLIC_ORIGIN}/desktop/releases/v2.0.13/${SOURCE}/${name}`,
    bytes: bytes.byteLength,
    sha256: sha256(bytes),
    build_source_commit: SOURCE,
    build_run_id: '102',
  }
}

function githubArtifact(id, name, runId, files) {
  const archiveSha256 = String(Number(id) + 1).padStart(64, '0')
  return {
    metadata: { id, name, runId, digest: `sha256:${archiveSha256}`, expired: false },
    bundle: {
      archiveSha256,
      files: new Map(Object.entries(files).map(([path, bytes]) => [path, testSource(bytes)])),
    },
  }
}

function run(id, path, event) {
  return { id, status: 'completed', conclusion: 'success', headSha: SOURCE, headBranch: 'main', event, path, runAttempt: 1 }
}

function job(name) { return { name, status: 'completed', conclusion: 'success' } }

function testSource(bytes) {
  const buffer = Buffer.from(bytes)
  return { ...bufferSource(buffer), buffer }
}

function pretty(value) { return Buffer.from(`${JSON.stringify(value, null, 2)}\n`) }

function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex') }

assert.deepEqual(DESKTOP_RELEASE_ARTIFACT_FILES, [
  'desktop-candidate.json',
  'e-Mate-2.0.13-mac-universal.dmg',
  'e-Mate-2.0.13-win-x64-Setup.exe',
])
