#!/usr/bin/env node

import { spawn } from 'node:child_process'
import { appendFile, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { GithubClient, validateArchiveEntries } from './main.mjs'
import {
  MAX_PERFORMANCE_FILE_BYTES,
  PERFORMANCE_EVIDENCE_FILENAME,
  PERFORMANCE_VERIFIER_SOURCE,
  createPerformanceAggregateAdmission,
} from './publisher.mjs'

async function main() {
  const temporaryRoot = resolve(process.env.RUNNER_TEMP || tmpdir())
  const github = new GithubClient({
    repository: requiredEnv('GITHUB_REPOSITORY'),
    token: requiredEnv('EMATE_GITHUB_PROVENANCE_TOKEN'),
    temporaryRoot,
  })
  let outputRoot
  try {
    const result = await createPerformanceAggregateAdmission({
      repository: requiredEnv('GITHUB_REPOSITORY'),
      actionRepository: requiredEnv('EMATE_ACTION_REPOSITORY'),
      actionRef: requiredEnv('EMATE_ACTION_REF'),
      eventName: requiredEnv('GITHUB_EVENT_NAME'),
      ref: requiredEnv('GITHUB_REF'),
      refProtected: requiredEnv('GITHUB_REF_PROTECTED') === 'true',
      githubSha: requiredEnv('GITHUB_SHA'),
      sourceCommit: requiredEnv('EMATE_SOURCE_SHA'),
      mainCiRunId: requiredEnv('EMATE_MAIN_CI_RUN_ID'),
      currentRunId: requiredEnv('GITHUB_RUN_ID'),
      currentRunAttempt: requiredEnv('GITHUB_RUN_ATTEMPT'),
      desktopArtifactId: requiredEnv('EMATE_DESKTOP_ARTIFACT_ID'),
      profileReleaseRunId: requiredEnv('EMATE_PROFILE_RELEASE_RUN_ID'),
      profileReleaseArtifactId: requiredEnv('EMATE_PROFILE_RELEASE_ARTIFACT_ID'),
      evidenceArtifactIds: [
        requiredEnv('EMATE_LUNA_EVIDENCE_ARTIFACT_ID'),
        requiredEnv('EMATE_SOL_EVIDENCE_ARTIFACT_ID'),
        requiredEnv('EMATE_DEEPSEEK_EVIDENCE_ARTIFACT_ID'),
        requiredEnv('EMATE_DOUBAO_EVIDENCE_ARTIFACT_ID'),
      ],
      signingKeyId: requiredEnv('EMATE_SIGNING_KEY_ID'),
      privateKeyPem: requiredEnv('EMATE_DESKTOP_SIGNING_PRIVATE_KEY_PEM'),
    }, {
      github,
      verifyPerformance: bundle => runPerformanceVerifier(bundle, temporaryRoot),
    })

    outputRoot = await mkdtemp(join(temporaryRoot, 'e-mate-performance-admission-output-'))
    await materializeFiles(result.files, outputRoot)
    await setOutput('artifact_path', outputRoot)
    await setOutput('artifact_name', result.artifactName)
    await setOutput('admission_sha256', result.admissionSha256)
    await setOutput('evidence_sha256', result.evidenceSha256)
    await setOutput('performance_run_id', result.performanceRunId)
  } catch (error) {
    if (outputRoot !== undefined) await rm(outputRoot, { recursive: true, force: true })
    const message = error instanceof Error ? error.message : 'unknown performance admission failure'
    process.stderr.write(`::error::PERFORMANCE_ADMISSION_FAILED: ${singleLine(message)}\n`)
    process.exitCode = 1
  } finally {
    await github.dispose()
  }
}

export async function runPerformanceVerifier(bundle, temporaryRoot = tmpdir()) {
  validateArchiveEntries([...bundle.files.keys()])
  const root = await mkdtemp(join(resolve(temporaryRoot), 'e-mate-performance-verifier-'))
  try {
    await materializeFiles(bundle.files, root)
    const output = join(root, 'verified-performance-evidence.json')
    const child = spawn(process.execPath, [
      join(root, PERFORMANCE_VERIFIER_SOURCE),
      '--input', join(root, PERFORMANCE_EVIDENCE_FILENAME),
      '--output', output,
    ], {
      env: childEnvironment(),
      stdio: ['ignore', 'ignore', 'pipe'],
    })
    const stderr = collectStream(child.stderr, 16 * 1024).catch(() => '[oversized stderr]')
    try {
      await Promise.all([exited(child), stderr])
    } catch {
      child.kill('SIGKILL')
      await stderr
      throw new Error('performance-parity rejected the downloaded TTFT evidence')
    }
    const metadata = await stat(output)
    if (!metadata.isFile() || metadata.size <= 0 || metadata.size > MAX_PERFORMANCE_FILE_BYTES) {
      throw new Error('performance-parity output is empty or oversized')
    }
    return readFile(output)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
}

async function materializeFiles(files, root) {
  validateArchiveEntries([...files.keys()])
  for (const [path, source] of files) {
    if (source.bytes <= 0 || source.bytes > MAX_PERFORMANCE_FILE_BYTES) {
      throw new Error(`performance artifact ${path} is empty or oversized`)
    }
    const output = join(root, path)
    await mkdir(dirname(output), { recursive: true, mode: 0o700 })
    await writeFile(output, await source.read(MAX_PERFORMANCE_FILE_BYTES), { flag: 'wx', mode: 0o600 })
  }
}

function childEnvironment() {
  const env = {}
  for (const name of ['PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL']) {
    if (process.env[name] !== undefined) env[name] = process.env[name]
  }
  return env
}

function exited(child) {
  return new Promise((resolveExit, rejectExit) => {
    child.once('error', rejectExit)
    child.once('close', code => code === 0 ? resolveExit() : rejectExit(new Error(`process exited ${code}`)))
  })
}

async function collectStream(stream, limit) {
  const chunks = []
  let bytes = 0
  for await (const chunk of stream) {
    bytes += chunk.byteLength
    if (bytes > limit) throw new Error('child process output is oversized')
    chunks.push(chunk)
  }
  return Buffer.concat(chunks).toString('utf8')
}

function requiredEnv(name) {
  const value = process.env[name]
  if (value === undefined || value === '') throw new Error(`required performance admission binding ${name} is missing`)
  return value
}

async function setOutput(name, value) {
  await appendFile(requiredEnv('GITHUB_OUTPUT'), `${name}=${String(value).replaceAll('\n', '')}\n`, 'utf8')
}

function singleLine(value) {
  return String(value).replace(/[\r\n]+/gu, ' ').slice(0, 1000)
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main()
