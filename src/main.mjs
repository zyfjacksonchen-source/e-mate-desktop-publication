#!/usr/bin/env node

import { createHash } from 'node:crypto'
import {
  appendFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises'
import { createReadStream, createWriteStream } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { spawn } from 'node:child_process'
import { Transform } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { fileURLToPath } from 'node:url'
import {
  CLOUDFLARE_HANDOFF_FILENAME,
  EXPECTED_REPOSITORY,
  PUBLICATION_PLAN_FILENAME,
  SIGNED_MANIFEST_FILENAME,
  parseExpectedCurrent,
  prepareDesktopPublication,
} from './publisher.mjs'

const API_VERSION = '2022-11-28'
const MAX_API_BYTES = 2 * 1024 * 1024
const MAX_OBJECT_BYTES = 2 * 1024 * 1024 * 1024

async function main() {
  const temporaryRoot = resolve(process.env.RUNNER_TEMP || tmpdir())
  const github = new GithubClient({
    repository: requiredEnv('GITHUB_REPOSITORY'),
    token: requiredEnv('EMATE_GITHUB_PROVENANCE_TOKEN'),
    temporaryRoot,
  })
  let outputRoot
  try {
    const result = await prepareDesktopPublication({
      repository: requiredEnv('GITHUB_REPOSITORY'),
      actionRepository: requiredEnv('EMATE_ACTION_REPOSITORY'),
      actionRef: requiredEnv('EMATE_ACTION_REF'),
      eventName: requiredEnv('GITHUB_EVENT_NAME'),
      ref: requiredEnv('GITHUB_REF'),
      refProtected: requiredEnv('GITHUB_REF_PROTECTED') === 'true',
      githubSha: requiredEnv('GITHUB_SHA'),
      sourceCommit: requiredEnv('EMATE_SOURCE_SHA'),
      mainCiRunId: requiredEnv('EMATE_MAIN_CI_RUN_ID'),
      macosPublicationMode: requiredEnv('EMATE_MACOS_PUBLICATION_MODE'),
      macosSignerRunId: optionalEnv('EMATE_MACOS_SIGNER_RUN_ID'),
      admissionArtifactId: requiredEnv('EMATE_ADMISSION_ARTIFACT_ID'),
      macosSignedArtifactId: optionalEnv('EMATE_MACOS_SIGNED_ARTIFACT_ID'),
      macosUnsignedArtifactId: optionalEnv('EMATE_MACOS_UNSIGNED_ARTIFACT_ID'),
      windowsArtifactId: requiredEnv('EMATE_WINDOWS_STAGING_ARTIFACT_ID'),
      expectedSignedCurrent: parseExpectedCurrent(requiredEnv('EMATE_EXPECTED_SIGNED_CURRENT')),
      expectedLegacyCurrent: parseExpectedCurrent(requiredEnv('EMATE_EXPECTED_LEGACY_CURRENT')),
      signingKeyId: requiredEnv('EMATE_SIGNING_KEY_ID'),
      privateKeyPem: requiredEnv('EMATE_DESKTOP_SIGNING_PRIVATE_KEY_PEM'),
    }, {
      github,
    })
    outputRoot = await mkdtemp(join(temporaryRoot, 'e-mate-desktop-cloudflare-handoff-'))
    await materializeOutputFiles(result.files, outputRoot)
    await setOutput('artifact_path', outputRoot)
    await setOutput('artifact_name', result.artifactName)
    await setOutput('signed_manifest_path', join(outputRoot, SIGNED_MANIFEST_FILENAME))
    await setOutput('publication_plan_path', join(outputRoot, PUBLICATION_PLAN_FILENAME))
    await setOutput('plugin_handoff_path', join(outputRoot, CLOUDFLARE_HANDOFF_FILENAME))
    await setOutput('manifest_identity', result.manifestIdentity)
    await setOutput('manifest_sha256', result.manifestSha256)
    await setOutput('publication_plan_sha256', result.planSha256)
    await setOutput('status', 'ready-for-cloudflare-plugin')
  } catch (error) {
    if (outputRoot !== undefined) await rm(outputRoot, { recursive: true, force: true })
    const message = error instanceof Error ? error.message : 'unknown publication preparation failure'
    process.stderr.write(`::error::DESKTOP_PUBLICATION_PREPARATION_FAILED: ${singleLine(message)}\n`)
    process.exitCode = 1
  } finally {
    await github.dispose()
  }
}

async function materializeOutputFiles(files, root) {
  validateArchiveEntries([...files.keys()])
  for (const [path, source] of files) {
    if (source.bytes <= 0 || source.bytes > MAX_API_BYTES) {
      throw new Error(`publication handoff ${path} is empty or oversized`)
    }
    const output = join(root, path)
    await mkdir(dirname(output), { recursive: true, mode: 0o700 })
    await writeFile(output, await source.read(MAX_API_BYTES), { flag: 'wx', mode: 0o600 })
  }
}

export class GithubClient {
  #repository
  #token
  #temporaryRoot
  #roots = []

  constructor(options) {
    if (options.repository !== EXPECTED_REPOSITORY) throw new Error('GitHub repository is not the pinned e-Mate repository')
    this.#repository = options.repository
    this.#token = options.token
    this.#temporaryRoot = resolve(options.temporaryRoot)
  }

  async getRepository() {
    const value = await this.#json(`/repos/${this.#repository}`)
    return {
      fullName: value.full_name,
      visibility: value.visibility,
      defaultBranch: value.default_branch,
      archived: value.archived,
      disabled: value.disabled,
    }
  }

  async getBranchHead(branch) {
    const value = await this.#json(`/repos/${this.#repository}/git/ref/heads/${encodeURIComponent(branch)}`)
    return value?.object?.sha
  }

  async getRun(runId) {
    const value = await this.#json(`/repos/${this.#repository}/actions/runs/${encodeURIComponent(runId)}`)
    return {
      id: value.id,
      status: value.status,
      conclusion: value.conclusion,
      headSha: value.head_sha,
      headBranch: value.head_branch,
      event: value.event,
      path: value.path,
      runAttempt: value.run_attempt,
    }
  }

  async getRunJobs(runId) {
    const jobs = []
    for (let page = 1; page <= 10; page += 1) {
      const value = await this.#json(`/repos/${this.#repository}/actions/runs/${encodeURIComponent(runId)}/jobs?per_page=100&page=${page}`)
      if (!Array.isArray(value.jobs)) throw new Error('GitHub jobs response is invalid')
      jobs.push(...value.jobs.map(job => ({ name: job.name, status: job.status, conclusion: job.conclusion })))
      if (jobs.length >= value.total_count) return jobs
    }
    throw new Error('GitHub run has too many jobs')
  }

  async getArtifact(artifactId) {
    const value = await this.#json(`/repos/${this.#repository}/actions/artifacts/${encodeURIComponent(artifactId)}`)
    return {
      id: value.id,
      name: value.name,
      digest: value.digest,
      expired: value.expired,
      runId: value.workflow_run?.id,
      sourceCommit: value.workflow_run?.head_sha,
      bytes: value.size_in_bytes,
    }
  }

  async getFile(path, ref) {
    const encodedPath = path.split('/').map(encodeURIComponent).join('/')
    const value = await this.#json(`/repos/${this.#repository}/contents/${encodedPath}?ref=${encodeURIComponent(ref)}`)
    if (value?.type !== 'file' || value.encoding !== 'base64' || typeof value.content !== 'string'
      || !Number.isSafeInteger(value.size) || value.size <= 0 || value.size > MAX_API_BYTES) {
      throw new Error('GitHub protected-main source file is invalid')
    }
    const encoded = value.content.replace(/\s+/gu, '')
    const bytes = Buffer.from(encoded, 'base64')
    if (bytes.byteLength !== value.size || bytes.toString('base64') !== encoded) {
      throw new Error('GitHub protected-main source file encoding is invalid')
    }
    return bytes
  }

  async downloadArtifact(artifactId) {
    const root = await mkdtemp(join(this.#temporaryRoot, 'e-mate-desktop-artifact-'))
    this.#roots.push(root)
    const archive = join(root, 'artifact.zip')
    const extracted = join(root, 'files')
    await mkdir(extracted, { mode: 0o700 })
    await downloadWithGh({
      token: this.#token,
      endpoint: `repos/${this.#repository}/actions/artifacts/${encodeURIComponent(artifactId)}/zip`,
      output: archive,
    })
    const entries = (await runCapture('unzip', ['-Z1', archive])).split(/\r?\n/u).filter(Boolean)
    validateArchiveEntries(entries)
    const files = await extractArchiveFiles(archive, extracted, entries)
    return {
      archiveSha256: await digestFile(archive),
      files,
      storedEntries: () => storedArchiveEntries(archive, entries),
    }
  }

  async dispose() {
    await Promise.all(this.#roots.splice(0).map(root => rm(root, { recursive: true, force: true })))
  }

  async #json(path) {
    const response = await fetch(`https://api.github.com${path}`, {
      method: 'GET',
      redirect: 'error',
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${this.#token}`,
        'X-GitHub-Api-Version': API_VERSION,
        'User-Agent': 'e-mate-desktop-publication-action',
      },
      signal: AbortSignal.timeout(60_000),
    })
    if (response.status !== 200) throw new Error(`GitHub API rejected a publication prerequisite with HTTP ${response.status}`)
    const bytes = Buffer.from(await response.arrayBuffer())
    if (bytes.byteLength === 0 || bytes.byteLength > MAX_API_BYTES) throw new Error('GitHub API response is empty or oversized')
    try {
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
    } catch {
      throw new Error('GitHub API response is invalid JSON')
    }
  }
}

class FileSource {
  #path
  #digest

  constructor(path, bytes) {
    this.#path = path
    this.bytes = bytes
  }

  async digest() {
    await this.#assertStable()
    this.#digest ??= await digestFile(this.#path)
    return this.#digest
  }

  async read(limit = Number.MAX_SAFE_INTEGER) {
    await this.#assertStable()
    if (this.bytes > limit) throw new Error(`artifact ${basename(this.#path)} exceeds the read limit`)
    return readFile(this.#path)
  }

  async #assertStable() {
    const metadata = await lstat(this.#path)
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size !== this.bytes) {
      throw new Error(`artifact ${basename(this.#path)} changed after admission`)
    }
  }
}

async function extractArchiveFiles(archive, root, entries) {
  const files = new Map()
  let index = 0
  for (const entry of entries) {
    if (entry.endsWith('/')) continue
    const output = join(root, String(index))
    index += 1
    const bytes = await extractArchiveEntry(archive, entry, output)
    if (bytes <= 0) throw new Error('GitHub artifact file is empty')
    files.set(entry, new FileSource(output, bytes))
  }
  if (files.size === 0) throw new Error('GitHub artifact contains no files')
  return files
}

async function extractArchiveEntry(archive, entry, outputPath) {
  const output = createWriteStream(outputPath, { flags: 'wx', mode: 0o600 })
  const child = spawn('unzip', ['-p', archive, entry], {
    env: childEnvironment(),
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let bytes = 0
  const limit = new Transform({
    transform(chunk, _encoding, callback) {
      bytes += chunk.byteLength
      callback(bytes > MAX_OBJECT_BYTES ? new Error('GitHub artifact file is oversized') : null, chunk)
    },
  })
  const stderr = collectStream(child.stderr, 16 * 1024).catch(() => '[oversized stderr]')
  try {
    await Promise.all([pipeline(child.stdout, limit, output), exited(child), stderr])
  } catch {
    child.kill('SIGKILL')
    await stderr
    throw new Error('GitHub artifact extraction failed')
  }
  return bytes
}

async function storedArchiveEntries(archive, entries) {
  return parseStoredArchiveEntries(await runCapture('unzip', ['-lv', archive]), entries)
}

export function parseStoredArchiveEntries(listing, entries) {
  const lines = listing.split(/\r?\n/u)
  return new Set(entries.filter(entry => lines.some(line => line.endsWith(` ${entry}`) && /\sStored\s/u.test(line))))
}

export function validateArchiveEntries(entries) {
  const seen = new Set()
  for (const entry of entries) {
    if (entry.includes('\\') || entry.startsWith('/') || /[\u0000-\u001f\u007f*?[\]]/u.test(entry)) {
      throw new Error('GitHub artifact path is unsafe')
    }
    const parts = entry.split('/').filter(Boolean)
    if (parts.length === 0 || parts.some(part => part === '.' || part === '..' || part.startsWith('-'))) {
      throw new Error('GitHub artifact path escapes extraction root')
    }
    const normalized = parts.join('/')
    if (seen.has(normalized)) throw new Error('GitHub artifact archive repeats a path')
    seen.add(normalized)
  }
}

async function downloadWithGh(options) {
  const output = createWriteStream(options.output, { flags: 'wx', mode: 0o600 })
  const child = spawn('gh', [
    'api', '--method', 'GET',
    '-H', 'Accept: application/vnd.github+json',
    '-H', `X-GitHub-Api-Version: ${API_VERSION}`,
    options.endpoint,
  ], {
    env: childEnvironment({
      GH_TOKEN: options.token,
      GH_HOST: 'github.com',
      GH_PROMPT_DISABLED: '1',
    }),
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  const stderr = collectStream(child.stderr, 16 * 1024).catch(() => '[oversized stderr]')
  try {
    await Promise.all([pipeline(child.stdout, output), exited(child), stderr])
  } catch {
    child.kill('SIGKILL')
    await stderr
    throw new Error('GitHub artifact download failed')
  }
}

async function runCapture(command, args) {
  const child = spawn(command, args, { env: childEnvironment(), stdio: ['ignore', 'pipe', 'pipe'] })
  const stdout = collectStream(child.stdout, MAX_API_BYTES)
  const stderr = collectStream(child.stderr, 16 * 1024).catch(() => '[oversized stderr]')
  try {
    const [, value] = await Promise.all([exited(child), stdout, stderr])
    return value
  } catch {
    child.kill('SIGKILL')
    throw new Error(`${command} failed: ${singleLine(await stderr)}`)
  }
}

function childEnvironment(extra = {}) {
  const env = {}
  for (const name of ['PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL']) {
    if (process.env[name] !== undefined) env[name] = process.env[name]
  }
  return { ...env, ...extra }
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

async function digestFile(path) {
  const digest = createHash('sha256')
  for await (const chunk of createReadStream(path)) digest.update(chunk)
  return digest.digest('hex')
}

function requiredEnv(name) {
  const value = process.env[name]
  if (value === undefined || value === '') throw new Error(`required publication binding ${name} is missing`)
  return value
}

function optionalEnv(name) {
  return process.env[name] || undefined
}

async function setOutput(name, value) {
  const path = requiredEnv('GITHUB_OUTPUT')
  await appendFile(path, `${name}=${String(value).replaceAll('\n', '')}\n`, { encoding: 'utf8' })
}

function singleLine(value) {
  return String(value).replace(/[\r\n]+/gu, ' ').slice(0, 1000)
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main()
}
