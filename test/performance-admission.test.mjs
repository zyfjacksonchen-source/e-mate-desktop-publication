import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, verify } from 'node:crypto'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, it } from 'node:test'
import {
  EXPECTED_ACTION_REPOSITORY,
  EXPECTED_REPOSITORY,
  PERFORMANCE_EVIDENCE_FILENAME,
  PERFORMANCE_SIGNATURE_CONTEXT,
  PERFORMANCE_VERIFIER_SOURCE,
  PUBLIC_ORIGIN,
  bufferSource,
  canonicalJson,
  createPerformanceAdmission,
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
    assert.equal(result.artifactName, `e-mate-performance-admission-${SOURCE}`)
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
      ['failed TTFT job', fixture => { fixture.github.jobs.get('103')[0].conclusion = 'failure' }],
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

  it('exposes a separate action with no caller path, R2 binding, or publication step', async () => {
    const action = await readFile(new URL('../performance/action.yml', import.meta.url), 'utf8')
    assert.match(action, /desktop-artifact-id:/u)
    assert.match(action, /evidence-artifact-id:/u)
    assert.match(action, /artifact-path:/u)
    assert.match(action, /performance-main\.mjs/u)
    assert.doesNotMatch(action, /receipt-path|EMATE_R2_|publish/u)
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
  const aggregate = {
    aggregate_sha256: '1'.repeat(64),
    inventory_sha256: '2'.repeat(64),
    staged_profile_tree_sha256: '3'.repeat(64),
    targets: ['darwin-arm64', 'darwin-x64', 'win32-x64'].map((target, index) => ({
      target,
      profile_generation: String(index + 4).repeat(64),
      component_aggregate_sha256: String(index + 7).repeat(64),
    })),
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
        'base-contract.json': pretty(base),
        'desktop-candidate.json': pretty(candidate),
        'profile-component-aggregate.json': pretty(aggregate),
        'e-Mate-2.0.13-mac-universal.dmg': mac,
        'e-Mate-2.0.13-win-x64-Setup.exe': win,
      }),
      githubArtifact('203', `e-mate-performance-evidence-${SOURCE}`, '103', {
        [PERFORMANCE_EVIDENCE_FILENAME]: pretty(evidence),
        [PERFORMANCE_VERIFIER_SOURCE]: verifierBytes,
        ...evidenceFiles,
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
    desktopArtifactId: '202',
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
      ['103', run('103', '.github/workflows/desktop-performance.yml', 'workflow_dispatch')],
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

function testSource(bytes) { return bufferSource(Buffer.from(bytes)) }

function pretty(value) { return Buffer.from(`${JSON.stringify(value, null, 2)}\n`) }

function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex') }
