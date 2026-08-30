#!/usr/bin/env node

import { appendFile, mkdtemp, rm } from 'node:fs/promises'
import { isAbsolute, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  CLOUDFLARE_HANDOFF_FILENAME,
  EXPECTED_ACTION_REPOSITORY,
  EXPECTED_REPOSITORY,
  PUBLICATION_PLAN_FILENAME,
  SIGNED_MANIFEST_FILENAME,
  prepareLocalSchema2DesktopPublication,
} from './publisher.mjs'
import { GithubClient, materializeOutputFiles } from './main.mjs'

const SHA40 = /^[0-9a-f]{40}$/u
const SHA256 = /^[0-9a-f]{64}$/u
const RUN_ID = /^[1-9][0-9]*$/u
const OUTPUT_FILES = [SIGNED_MANIFEST_FILENAME, PUBLICATION_PLAN_FILENAME, CLOUDFLARE_HANDOFF_FILENAME]

export async function runLocalSchema2Action(env = process.env, dependencies = {}) {
  const bindings = actionBindings(env)
  const github = dependencies.github ?? new GithubClient({
    repository: EXPECTED_REPOSITORY,
    token: bindings.githubToken,
    temporaryRoot: bindings.temporaryRoot,
  })
  const prepare = dependencies.prepare ?? prepareLocalSchema2DesktopPublication
  let outputRoot
  let disposed = false
  try {
    const result = await prepare(bindings.config, { github })
    if (!(result.files instanceof Map)
      || JSON.stringify([...result.files.keys()].sort()) !== JSON.stringify([...OUTPUT_FILES].sort())
      || !SHA256.test(result.manifestSha256 ?? '') || !SHA256.test(result.planSha256 ?? '')
      || !SHA256.test(result.handoffSha256 ?? '')
      || result.artifactName !== `e-mate-local-schema2-signer-${bindings.sourceCommit}`) {
      throw new Error('local schema-2 signer returned an invalid three-file handoff')
    }
    outputRoot = await mkdtemp(join(bindings.temporaryRoot, 'e-mate-local-schema2-signer-'))
    await materializeOutputFiles(result.files, outputRoot)
    const outputs = {
      artifact_path: outputRoot,
      artifact_name: result.artifactName,
      signed_manifest_path: join(outputRoot, SIGNED_MANIFEST_FILENAME),
      publication_plan_path: join(outputRoot, PUBLICATION_PLAN_FILENAME),
      signer_handoff_path: join(outputRoot, CLOUDFLARE_HANDOFF_FILENAME),
      manifest_sha256: result.manifestSha256,
      publication_plan_sha256: result.planSha256,
      signer_handoff_sha256: result.handoffSha256,
      status: 'ready-for-main-local-flow-activation',
    }
    await appendOutputs(bindings.outputPath, outputs)
    await github.dispose?.()
    disposed = true
    return { outputRoot, outputs }
  } catch (error) {
    if (outputRoot !== undefined) await rm(outputRoot, { recursive: true, force: true })
    if (!disposed && typeof github.dispose === 'function') {
      try { await github.dispose() } catch {}
    }
    throw error
  }
}

function actionBindings(env) {
  const sourceCommit = requiredEnv(env, 'EMATE_SOURCE_SHA')
  const actionRef = requiredEnv(env, 'EMATE_ACTION_REF')
  if (requiredEnv(env, 'GITHUB_REPOSITORY') !== EXPECTED_REPOSITORY
    || requiredEnv(env, 'EMATE_ACTION_REPOSITORY') !== EXPECTED_ACTION_REPOSITORY
    || !SHA40.test(actionRef) || !SHA40.test(sourceCommit)
    || requiredEnv(env, 'GITHUB_EVENT_NAME') !== 'workflow_dispatch'
    || requiredEnv(env, 'GITHUB_REF') !== 'refs/heads/main'
    || requiredEnv(env, 'GITHUB_REF_PROTECTED') !== 'true'
    || requiredEnv(env, 'GITHUB_WORKFLOW_REF')
      !== `${EXPECTED_REPOSITORY}/.github/workflows/desktop-publication.yml@refs/heads/main`
    || requiredEnv(env, 'GITHUB_RUN_ATTEMPT') !== '1'
    || requiredEnv(env, 'GITHUB_SHA') !== sourceCommit) {
    throw new Error('local schema-2 action requires exact protected-main workflow_dispatch attempt 1 context')
  }
  const temporaryRoot = absoluteEnv(env, 'RUNNER_TEMP')
  const runRoot = absoluteEnv(env, 'EMATE_RUN_ROOT')
  if (!strictDescendant(temporaryRoot, runRoot)) {
    throw new Error('local schema-2 run root must be inside RUNNER_TEMP')
  }
  const config = {
    runRoot,
    immutableRequestPath: absoluteEnv(env, 'EMATE_IMMUTABLE_REQUEST_PATH'),
    immutableRequestSha256: shaEnv(env, 'EMATE_IMMUTABLE_REQUEST_SHA256'),
    immutableReceiptPath: absoluteEnv(env, 'EMATE_IMMUTABLE_RECEIPT_PATH'),
    immutableReceiptSha256: shaEnv(env, 'EMATE_IMMUTABLE_RECEIPT_SHA256'),
    compatibilityRequestPath: absoluteEnv(env, 'EMATE_COMPATIBILITY_REQUEST_PATH'),
    compatibilityRequestSha256: shaEnv(env, 'EMATE_COMPATIBILITY_REQUEST_SHA256'),
    profileAggregatePath: absoluteEnv(env, 'EMATE_PROFILE_AGGREGATE_PATH'),
    profileAggregateSha256: shaEnv(env, 'EMATE_PROFILE_AGGREGATE_SHA256'),
    compatibilityRunId: numericEnv(env, 'EMATE_COMPATIBILITY_RUN_ID'),
    compatibilityArtifactId: numericEnv(env, 'EMATE_COMPATIBILITY_ARTIFACT_ID'),
    actionRepository: EXPECTED_ACTION_REPOSITORY,
    actionRef,
    signingKeyId: requiredEnv(env, 'EMATE_SIGNING_KEY_ID'),
    privateKeyPem: requiredEnv(env, 'EMATE_PROFILE_SIGNING_PRIVATE_KEY'),
  }
  return {
    sourceCommit,
    config,
    githubToken: requiredEnv(env, 'GITHUB_TOKEN'),
    temporaryRoot,
    outputPath: absoluteEnv(env, 'GITHUB_OUTPUT'),
  }
}

async function appendOutputs(path, outputs) {
  const lines = Object.entries(outputs).map(([name, value]) => {
    const text = String(value)
    if (text === '' || /[\r\n]/u.test(text)) throw new Error(`local schema-2 output ${name} is invalid`)
    return `${name}=${text}`
  })
  await appendFile(path, `${lines.join('\n')}\n`, { encoding: 'utf8' })
}

function requiredEnv(env, name) {
  const value = env[name]
  if (typeof value !== 'string' || value === '') throw new Error(`required local schema-2 binding ${name} is missing`)
  return value
}

function absoluteEnv(env, name) {
  const value = requiredEnv(env, name)
  if (!isAbsolute(value) || resolve(value) !== value) throw new Error(`local schema-2 binding ${name} is not absolute`)
  return value
}

function shaEnv(env, name) {
  const value = requiredEnv(env, name)
  if (!SHA256.test(value)) throw new Error(`local schema-2 binding ${name} is not SHA-256`)
  return value
}

function numericEnv(env, name) {
  const value = requiredEnv(env, name)
  if (!RUN_ID.test(value)) throw new Error(`local schema-2 binding ${name} is not a GitHub identity`)
  return value
}

function strictDescendant(root, path) {
  const fromRoot = relative(root, path)
  return fromRoot !== '' && fromRoot !== '..' && !fromRoot.startsWith(`..${sep}`) && !isAbsolute(fromRoot)
}

function singleLine(value) {
  return String(value).replace(/[\r\n]+/gu, ' ').slice(0, 1000)
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    await runLocalSchema2Action()
  } catch (error) {
    const message = error instanceof Error ? error.message : 'unknown local schema-2 signing failure'
    process.stderr.write(`::error::LOCAL_SCHEMA2_SIGNING_FAILED: ${singleLine(message)}\n`)
    process.exitCode = 1
  }
}
