import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it } from 'node:test'
import {
  CLOUDFLARE_HANDOFF_FILENAME,
  EXPECTED_ACTION_REPOSITORY,
  EXPECTED_REPOSITORY,
  PUBLICATION_PLAN_FILENAME,
  SIGNED_MANIFEST_FILENAME,
  bufferSource,
} from '../src/publisher.mjs'
import { runLocalSchema2Action } from '../src/local-schema2-main.mjs'

const SOURCE = 'a'.repeat(40)
const ACTION_REF = 'c'.repeat(40)
const SHA = 'd'.repeat(64)
const INPUTS = [
  'source-sha', 'run-root', 'immutable-request-path', 'immutable-request-sha256',
  'immutable-receipt-path', 'immutable-receipt-sha256', 'compatibility-request-path',
  'compatibility-request-sha256', 'profile-aggregate-path', 'profile-aggregate-sha256',
  'compatibility-run-id', 'compatibility-artifact-id', 'signing-key-id',
]
const OUTPUTS = [
  'artifact-path', 'artifact-name', 'signed-manifest-path', 'publication-plan-path',
  'signer-handoff-path', 'manifest-sha256', 'publication-plan-sha256',
  'signer-handoff-sha256', 'status',
]

describe('protected local schema-2 subdirectory action', () => {
  it('exposes only exact local bindings and a closed signer receipt output', async () => {
    const action = await readFile(new URL('../local-schema2/action.yml', import.meta.url), 'utf8')
    assert.deepEqual(sectionKeys(action, 'inputs', 'outputs'), INPUTS)
    assert.deepEqual(sectionKeys(action, 'outputs', 'runs'), OUTPUTS)
    assert.match(action, /GITHUB_TOKEN: \$\{\{ github\.token \}\}/u)
    assert.match(action, /EMATE_PROFILE_SIGNING_PRIVATE_KEY: \$\{\{ env\.EMATE_PROFILE_SIGNING_PRIVATE_KEY \}\}/u)
    assert.match(action, /entry="\$\(realpath "\$action_root\/src\/local-schema2-main\.mjs"\)"/u)
    assert.doesNotMatch(section(action, 'inputs', 'outputs'), /token|secret|private-key|r2-url|credential/iu)
    assert.doesNotMatch(action, /^\s*uses:/mu)
  })

  it('executes the real composite run block from a subdirectory GITHUB_ACTION_PATH', async () => {
    const action = await readFile(new URL('../local-schema2/action.yml', import.meta.url), 'utf8')
    const repository = fileURLToPath(new URL('..', import.meta.url))
    const result = spawnSync('bash', ['-c', runBlock(action)], {
      encoding: 'utf8',
      env: {
        PATH: `${dirname(process.execPath)}:${process.env.PATH}`,
        HOME: process.env.HOME,
        GITHUB_ACTION_PATH: join(repository, 'local-schema2'),
      },
    })
    assert.equal(result.status, 1)
    assert.match(result.stderr, /LOCAL_SCHEMA2_SIGNING_FAILED/u)
    assert.match(result.stderr, /required local schema-2 binding/u)
    assert.doesNotMatch(`${result.stdout}${result.stderr}`, /MODULE_NOT_FOUND|Cannot find module/iu)
  })

  it('materializes exactly three files, then emits all outputs in one closed handoff', async () => {
    const fixture = await entryFixture()
    try {
      let received
      const result = await runLocalSchema2Action(fixture.env, {
        github: fixture.github,
        prepare: async (config, dependencies) => {
          received = { config, dependencies }
          return fixture.result
        },
      })
      assert.equal(received.dependencies.github, fixture.github)
      assert.deepEqual(received.config, fixture.expectedConfig)
      assert.deepEqual((await readdir(result.outputRoot)).sort(), [
        CLOUDFLARE_HANDOFF_FILENAME, PUBLICATION_PLAN_FILENAME, SIGNED_MANIFEST_FILENAME,
      ].sort())
      assert.equal(await readFile(join(result.outputRoot, SIGNED_MANIFEST_FILENAME), 'utf8'), 'signed\n')
      assert.equal(await readFile(join(result.outputRoot, PUBLICATION_PLAN_FILENAME), 'utf8'), 'plan\n')
      assert.equal(await readFile(join(result.outputRoot, CLOUDFLARE_HANDOFF_FILENAME), 'utf8'), 'handoff\n')
      const outputs = Object.fromEntries((await readFile(fixture.outputPath, 'utf8')).trim().split('\n')
        .map(line => line.split(/=(.*)/su).slice(0, 2)))
      assert.deepEqual(Object.keys(outputs), OUTPUTS.map(name => name.replaceAll('-', '_')))
      assert.equal(outputs.artifact_path, result.outputRoot)
      assert.equal(outputs.artifact_name, fixture.result.artifactName)
      assert.equal(outputs.manifest_sha256, fixture.result.manifestSha256)
      assert.equal(outputs.publication_plan_sha256, fixture.result.planSha256)
      assert.equal(outputs.signer_handoff_sha256, fixture.result.handoffSha256)
      assert.equal(outputs.status, 'ready-for-main-local-flow-activation')
      assert.equal((await readFile(fixture.outputPath, 'utf8')).includes(fixture.secret), false)
      assert.equal(fixture.github.disposeCount, 1)
    } finally {
      await fixture.dispose()
    }
  })

  it('rejects path, owner, source and protected workflow context drift before signing', async t => {
    const cases = [
      ['repository', fixture => { fixture.env.GITHUB_REPOSITORY = 'other/repository' }],
      ['action owner', fixture => { fixture.env.EMATE_ACTION_REPOSITORY = 'other/action' }],
      ['movable action ref', fixture => { fixture.env.EMATE_ACTION_REF = 'main' }],
      ['event', fixture => { fixture.env.GITHUB_EVENT_NAME = 'push' }],
      ['ref', fixture => { fixture.env.GITHUB_REF = 'refs/heads/release' }],
      ['unprotected ref', fixture => { fixture.env.GITHUB_REF_PROTECTED = 'false' }],
      ['workflow owner', fixture => {
        fixture.env.GITHUB_WORKFLOW_REF = `${EXPECTED_REPOSITORY}/.github/workflows/other.yml@refs/heads/main`
      }],
      ['attempt', fixture => { fixture.env.GITHUB_RUN_ATTEMPT = '2' }],
      ['workflow source', fixture => { fixture.env.GITHUB_SHA = 'b'.repeat(40) }],
      ['relative run root', fixture => { fixture.env.EMATE_RUN_ROOT = 'run' }],
      ['run root outside runner temp', fixture => { fixture.env.EMATE_RUN_ROOT = fixture.root }],
      ['invalid input digest', fixture => { fixture.env.EMATE_PROFILE_AGGREGATE_SHA256 = 'D'.repeat(64) }],
      ['missing token', fixture => { delete fixture.env.GITHUB_TOKEN }],
      ['missing signing key', fixture => { delete fixture.env.EMATE_PROFILE_SIGNING_PRIVATE_KEY }],
    ]
    for (const [name, mutate] of cases) {
      await t.test(name, async () => {
        const fixture = await entryFixture()
        let called = false
        try {
          await mutate(fixture)
          await assert.rejects(runLocalSchema2Action(fixture.env, {
            github: fixture.github,
            prepare: async () => { called = true; return fixture.result },
          }))
          assert.equal(called, false)
          assert.equal((await readFile(fixture.outputPath, 'utf8')), '')
          assert.deepEqual(await readdir(fixture.runnerTemp), ['run'])
        } finally {
          await fixture.dispose()
        }
      })
    }
  })

  it('removes partial materialization and emits no outputs when one file fails', async () => {
    const fixture = await entryFixture()
    try {
      const files = new Map(fixture.result.files)
      files.set(PUBLICATION_PLAN_FILENAME, {
        bytes: 5,
        async read() { throw new Error('fixture materialization failure') },
      })
      await assert.rejects(runLocalSchema2Action(fixture.env, {
        github: fixture.github,
        prepare: async () => ({ ...fixture.result, files }),
      }), /fixture materialization failure/u)
      assert.deepEqual(await readdir(fixture.runnerTemp), ['run'])
      assert.equal(await readFile(fixture.outputPath, 'utf8'), '')
      assert.equal(fixture.github.disposeCount, 1)
    } finally {
      await fixture.dispose()
    }
  })

  it('rejects a signer artifact name not bound to the exact source', async () => {
    const fixture = await entryFixture()
    try {
      await assert.rejects(runLocalSchema2Action(fixture.env, {
        github: fixture.github,
        prepare: async () => ({ ...fixture.result, artifactName: 'e-mate-local-schema2-signer-wrong' }),
      }), /invalid three-file handoff/u)
      assert.deepEqual(await readdir(fixture.runnerTemp), ['run'])
      assert.equal(await readFile(fixture.outputPath, 'utf8'), '')
    } finally {
      await fixture.dispose()
    }
  })

  it('never forwards or prints the signing key from the executable entry', async () => {
    const source = await readFile(new URL('../src/local-schema2-main.mjs', import.meta.url), 'utf8')
    const shared = await readFile(new URL('../src/main.mjs', import.meta.url), 'utf8')
    const childEnvironment = /function childEnvironment\(extra = \{\}\) \{[\s\S]*?^\}/mu.exec(shared)?.[0]
    assert.doesNotMatch(source, /spawn\(|execFile\(|console\.log|JSON\.stringify\(env/u)
    assert.match(source, /privateKeyPem: requiredEnv\(env, 'EMATE_PROFILE_SIGNING_PRIVATE_KEY'\)/u)
    assert.match(childEnvironment, /\['PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL'\]/u)
    assert.doesNotMatch(childEnvironment, /EMATE_PROFILE_SIGNING_PRIVATE_KEY|privateKeyPem/u)
  })
})

async function entryFixture() {
  const root = await mkdtemp(join(tmpdir(), 'e-mate-local-schema2-entry-'))
  const runnerTemp = join(root, 'runner-temp')
  const runRoot = join(runnerTemp, 'run')
  const publication = join(runRoot, 'publication')
  await mkdir(publication, { recursive: true })
  const requestPath = join(publication, 'immutable-owner-request.json')
  const receiptPath = join(publication, 'immutable-owner-receipt.json')
  const compatibilityPath = join(publication, 'compatibility-attestation-request.json')
  const aggregatePath = join(runRoot, 'profile-component-aggregate.json')
  const outputPath = join(root, 'github-output')
  await Promise.all([
    writeFile(requestPath, `${JSON.stringify({ source_commit: SOURCE }, null, 2)}\n`),
    writeFile(receiptPath, '{}\n'),
    writeFile(compatibilityPath, '{}\n'),
    writeFile(aggregatePath, '{}\n'),
    writeFile(outputPath, ''),
  ])
  const secret = 'fixture-signing-secret-never-output'
  const env = {
    GITHUB_REPOSITORY: EXPECTED_REPOSITORY,
    GITHUB_EVENT_NAME: 'workflow_dispatch',
    GITHUB_REF: 'refs/heads/main',
    GITHUB_REF_PROTECTED: 'true',
    GITHUB_WORKFLOW_REF: `${EXPECTED_REPOSITORY}/.github/workflows/desktop-publication.yml@refs/heads/main`,
    GITHUB_RUN_ATTEMPT: '1',
    GITHUB_SHA: SOURCE,
    GITHUB_TOKEN: 'fixture-read-token',
    GITHUB_OUTPUT: outputPath,
    RUNNER_TEMP: runnerTemp,
    EMATE_ACTION_REPOSITORY: EXPECTED_ACTION_REPOSITORY,
    EMATE_ACTION_REF: ACTION_REF,
    EMATE_SOURCE_SHA: SOURCE,
    EMATE_RUN_ROOT: runRoot,
    EMATE_IMMUTABLE_REQUEST_PATH: requestPath,
    EMATE_IMMUTABLE_REQUEST_SHA256: SHA,
    EMATE_IMMUTABLE_RECEIPT_PATH: receiptPath,
    EMATE_IMMUTABLE_RECEIPT_SHA256: SHA,
    EMATE_COMPATIBILITY_REQUEST_PATH: compatibilityPath,
    EMATE_COMPATIBILITY_REQUEST_SHA256: SHA,
    EMATE_PROFILE_AGGREGATE_PATH: aggregatePath,
    EMATE_PROFILE_AGGREGATE_SHA256: SHA,
    EMATE_COMPATIBILITY_RUN_ID: '900',
    EMATE_COMPATIBILITY_ARTIFACT_ID: '901',
    EMATE_SIGNING_KEY_ID: 'release-2026',
    EMATE_PROFILE_SIGNING_PRIVATE_KEY: secret,
  }
  const result = {
    artifactName: `e-mate-local-schema2-signer-${SOURCE}`,
    files: new Map([
      [SIGNED_MANIFEST_FILENAME, bufferSource(Buffer.from('signed\n'))],
      [PUBLICATION_PLAN_FILENAME, bufferSource(Buffer.from('plan\n'))],
      [CLOUDFLARE_HANDOFF_FILENAME, bufferSource(Buffer.from('handoff\n'))],
    ]),
    manifestSha256: digest('signed\n'),
    planSha256: digest('plan\n'),
    handoffSha256: digest('handoff\n'),
  }
  const github = {
    disposeCount: 0,
    async dispose() { this.disposeCount += 1 },
  }
  return {
    root, runRoot, runnerTemp, outputPath, requestPath, secret, env, result, github,
    expectedConfig: {
      runRoot,
      immutableRequestPath: requestPath,
      immutableRequestSha256: SHA,
      immutableReceiptPath: receiptPath,
      immutableReceiptSha256: SHA,
      compatibilityRequestPath: compatibilityPath,
      compatibilityRequestSha256: SHA,
      profileAggregatePath: aggregatePath,
      profileAggregateSha256: SHA,
      compatibilityRunId: '900',
      compatibilityArtifactId: '901',
      actionRepository: EXPECTED_ACTION_REPOSITORY,
      actionRef: ACTION_REF,
      signingKeyId: 'release-2026',
      privateKeyPem: secret,
    },
    dispose: () => rm(root, { recursive: true, force: true }),
  }
}

function section(text, start, end) {
  return new RegExp(`^${start}:\\n([\\s\\S]*?)^${end}:`, 'mu').exec(text)?.[1] ?? ''
}

function sectionKeys(text, start, end) {
  return [...section(text, start, end).matchAll(/^  ([a-z0-9-]+):$/gmu)].map(match => match[1])
}

function runBlock(action) {
  const block = /^      run: \|\n((?:        .*\n?)+)/mu.exec(action)?.[1]
  assert.notEqual(block, undefined)
  return block.replace(/^        /gmu, '')
}

function digest(value) {
  return createHash('sha256').update(value).digest('hex')
}
