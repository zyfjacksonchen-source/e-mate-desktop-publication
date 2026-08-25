#!/usr/bin/env node

import { createHash, createHmac } from 'node:crypto'
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
  EXPECTED_REPOSITORY,
  EXPECTED_R2_BUCKET,
  PUBLIC_ORIGIN,
  parseExpectedCurrent,
  publishDesktopRelease,
} from './publisher.mjs'

const API_VERSION = '2022-11-28'
const MAX_API_BYTES = 2 * 1024 * 1024
const MAX_OBJECT_BYTES = 2 * 1024 * 1024 * 1024

async function main() {
  const github = new GithubClient({
    repository: requiredEnv('GITHUB_REPOSITORY'),
    token: requiredEnv('EMATE_GITHUB_PROVENANCE_TOKEN'),
    temporaryRoot: process.env.RUNNER_TEMP || tmpdir(),
  })

  try {
    const receipt = await publishDesktopRelease({
      repository: requiredEnv('GITHUB_REPOSITORY'),
      actionRepository: requiredEnv('EMATE_ACTION_REPOSITORY'),
      actionRef: requiredEnv('EMATE_ACTION_REF'),
      eventName: requiredEnv('GITHUB_EVENT_NAME'),
      ref: requiredEnv('GITHUB_REF'),
      refProtected: requiredEnv('GITHUB_REF_PROTECTED') === 'true',
      githubSha: requiredEnv('GITHUB_SHA'),
      sourceCommit: requiredEnv('EMATE_SOURCE_SHA'),
      mainCiRunId: requiredEnv('EMATE_MAIN_CI_RUN_ID'),
      admissionArtifactId: requiredEnv('EMATE_ADMISSION_ARTIFACT_ID'),
      expectedSignedCurrent: parseExpectedCurrent(requiredEnv('EMATE_EXPECTED_SIGNED_CURRENT')),
      signingKeyId: requiredEnv('EMATE_SIGNING_KEY_ID'),
      privateKeyPem: requiredEnv('EMATE_DESKTOP_SIGNING_PRIVATE_KEY_PEM'),
    }, {
      github,
      store: new R2Store({
        accountId: requiredEnv('EMATE_R2_ACCOUNT_ID'),
        accessKeyId: requiredEnv('EMATE_R2_ACCESS_KEY_ID'),
        secretAccessKey: requiredEnv('EMATE_R2_SECRET_ACCESS_KEY'),
        bucket: EXPECTED_R2_BUCKET,
      }),
      publicReader: new HttpObjectReader(PUBLIC_ORIGIN),
    })

    const receiptPath = resolve(process.env.EMATE_RECEIPT_PATH
      || join(process.env.RUNNER_TEMP || tmpdir(), `e-mate-desktop-publication-${process.env.GITHUB_RUN_ID || 'local'}.json`))
    await mkdir(dirname(receiptPath), { recursive: true })
    await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { flag: 'wx', mode: 0o600 })
    await setOutput('receipt_path', receiptPath)
    await setOutput('manifest_identity', receipt.manifest.identity_sha256)
    await setOutput('manifest_sha256', receipt.manifest.raw_sha256)
    await setOutput('status', receipt.status)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'unknown publication failure'
    process.stderr.write(`::error::DESKTOP_PUBLICATION_FAILED: ${singleLine(message)}\n`)
    process.exitCode = 1
  } finally {
    await github.dispose()
  }
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main()
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

  async getBranchProtection(branch) {
    const value = await this.#json(`/repos/${this.#repository}/branches/${encodeURIComponent(branch)}/protection`)
    const contexts = [
      ...(value?.required_status_checks?.contexts ?? []),
      ...(value?.required_status_checks?.checks ?? []).map(check => check?.context),
    ].filter(context => typeof context === 'string')
    return {
      requiredStatusChecks: {
        strict: value?.required_status_checks?.strict === true,
        contexts: [...new Set(contexts)],
      },
      enforceAdmins: value?.enforce_admins?.enabled === true,
      requiredLinearHistory: value?.required_linear_history?.enabled === true,
      allowForcePushes: value?.allow_force_pushes?.enabled === true,
      allowDeletions: value?.allow_deletions?.enabled === true,
    }
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

export class R2Store {
  #accountId
  #accessKeyId
  #secretAccessKey
  #bucket
  #fetch
  #now

  constructor(options) {
    if (!/^[0-9a-f]{32}$/u.test(options.accountId) || !/^[A-Za-z0-9._-]{3,255}$/u.test(options.bucket)
      || typeof options.accessKeyId !== 'string' || options.accessKeyId === ''
      || typeof options.secretAccessKey !== 'string' || options.secretAccessKey === '') {
      throw new Error('R2 publication binding is invalid')
    }
    this.#accountId = options.accountId
    this.#accessKeyId = options.accessKeyId
    this.#secretAccessKey = options.secretAccessKey
    this.#bucket = options.bucket
    this.#fetch = options.fetch ?? globalThis.fetch
    this.#now = options.now ?? (() => new Date())
  }

  async inspect(key, options = {}) {
    const response = await this.#request('GET', key, { payloadHash: sha256(Buffer.alloc(0)) })
    if (response.status === 404) return { exists: false }
    if (response.status !== 200) throw new Error(`R2 read failed with HTTP ${response.status}`)
    const read = await readObjectResponse(response, options.collectLimit ?? 0)
    const etag = response.headers.get('etag')
    if (etag === null || etag === '') throw new Error('R2 object is missing its CAS ETag')
    return {
      exists: true,
      ...read,
      etag,
      contentType: response.headers.get('content-type'),
      cacheControl: response.headers.get('cache-control'),
    }
  }

  async putCreateOnly(key, source, metadata) {
    const response = await this.#request('PUT', key, {
      payloadHash: await source.digest(),
      body: source.stream(),
      headers: {
        'content-type': metadata.contentType,
        'cache-control': metadata.cacheControl,
        'if-none-match': '*',
      },
    })
    if (![200, 201, 204].includes(response.status)) {
      throw new Error(`R2 create-only write failed with HTTP ${response.status}`)
    }
  }

  async putCas(key, source, options) {
    const conditional = options.expectedEtag === null
      ? { 'if-none-match': '*' }
      : { 'if-match': options.expectedEtag }
    const response = await this.#request('PUT', key, {
      payloadHash: await source.digest(),
      body: source.stream(),
      headers: {
        'content-type': options.contentType,
        'cache-control': options.cacheControl,
        ...conditional,
      },
    })
    if (![200, 201, 204].includes(response.status)) {
      throw new Error(`R2 CAS activation failed with HTTP ${response.status}`)
    }
  }

  async #request(method, key, options) {
    validateObjectKey(key)
    const host = `${this.#accountId}.r2.cloudflarestorage.com`
    const canonicalUri = `/${encodePath(this.#bucket)}/${key.split('/').map(encodePath).join('/')}`
    const url = `https://${host}${canonicalUri}`
    const now = this.#now()
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/gu, '')
    const shortDate = amzDate.slice(0, 8)
    const headers = new Map(Object.entries({
      host,
      'x-amz-content-sha256': options.payloadHash,
      'x-amz-date': amzDate,
      ...(options.headers ?? {}),
    }).map(([name, value]) => [name.toLowerCase(), String(value).trim().replace(/\s+/gu, ' ')]))
    const signedHeaders = [...headers.keys()].sort()
    const canonicalHeaders = `${signedHeaders.map(name => `${name}:${headers.get(name)}`).join('\n')}\n`
    const canonicalRequest = [
      method,
      canonicalUri,
      '',
      canonicalHeaders,
      signedHeaders.join(';'),
      options.payloadHash,
    ].join('\n')
    const scope = `${shortDate}/auto/s3/aws4_request`
    const stringToSign = [
      'AWS4-HMAC-SHA256',
      amzDate,
      scope,
      sha256(Buffer.from(canonicalRequest, 'utf8')),
    ].join('\n')
    const dateKey = hmac(Buffer.from(`AWS4${this.#secretAccessKey}`, 'utf8'), shortDate)
    const regionKey = hmac(dateKey, 'auto')
    const serviceKey = hmac(regionKey, 's3')
    const signingKey = hmac(serviceKey, 'aws4_request')
    const signature = hmac(signingKey, stringToSign).toString('hex')
    headers.set('authorization', `AWS4-HMAC-SHA256 Credential=${this.#accessKeyId}/${scope}, SignedHeaders=${signedHeaders.join(';')}, Signature=${signature}`)
    headers.delete('host')
    const body = options.body
    return this.#fetch(url, {
      method,
      headers: Object.fromEntries(headers),
      redirect: 'error',
      signal: AbortSignal.timeout(10 * 60_000),
      ...(body === undefined ? {} : { body, duplex: 'half' }),
    })
  }
}

export class HttpObjectReader {
  #origin
  #fetch

  constructor(origin, options = {}) {
    if (origin !== PUBLIC_ORIGIN) throw new Error('public readback origin drifted')
    this.#origin = origin
    this.#fetch = options.fetch ?? globalThis.fetch
  }

  async inspect(key, options = {}) {
    validateObjectKey(key)
    const response = await this.#fetch(`${this.#origin}/${key.split('/').map(encodePath).join('/')}`, {
      method: 'GET',
      redirect: 'error',
      cache: 'no-store',
      headers: { Accept: '*/*', 'Accept-Encoding': 'identity', 'Cache-Control': 'no-cache' },
      signal: AbortSignal.timeout(10 * 60_000),
    })
    if (response.status === 404) return { exists: false }
    if (response.status !== 200) throw new Error(`public R2 readback failed with HTTP ${response.status}`)
    return {
      exists: true,
      ...await readObjectResponse(response, options.collectLimit ?? 0),
      contentType: response.headers.get('content-type'),
      cacheControl: response.headers.get('cache-control'),
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
    this.#digest ??= await digestFile(this.#path)
    return this.#digest
  }

  async read(limit = Number.MAX_SAFE_INTEGER) {
    await this.#assertStable()
    if (this.bytes > limit) throw new Error(`artifact ${basename(this.#path)} exceeds the read limit`)
    return readFile(this.#path)
  }

  stream() {
    return createReadStream(this.#path)
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

async function readObjectResponse(response, collectLimit) {
  if (response.body === null) throw new Error('object response has no body')
  const declared = response.headers.get('content-length')
  const digest = createHash('sha256')
  const chunks = []
  let bytes = 0
  for await (const chunk of response.body) {
    bytes += chunk.byteLength
    if (bytes > MAX_OBJECT_BYTES) throw new Error('object response is oversized')
    digest.update(chunk)
    if (collectLimit > 0) {
      if (bytes > collectLimit) throw new Error('object exceeds collection limit')
      chunks.push(Buffer.from(chunk))
    }
  }
  if (declared !== null && (!/^[0-9]+$/u.test(declared) || Number(declared) !== bytes)) {
    throw new Error('object Content-Length does not match its bytes')
  }
  return {
    bytes,
    sha256: digest.digest('hex'),
    ...(collectLimit > 0 ? { body: Buffer.concat(chunks) } : {}),
  }
}

function validateObjectKey(key) {
  if (typeof key !== 'string' || key === '' || key.startsWith('/') || key.endsWith('/')
    || key.includes('\\') || key.split('/').some(part => part === '' || part === '.' || part === '..')) {
    throw new Error('R2 object key is unsafe')
  }
}

function encodePath(value) {
  return encodeURIComponent(value).replace(/[!'()*]/gu, character => `%${character.charCodeAt(0).toString(16).toUpperCase()}`)
}

function hmac(key, value) {
  return createHmac('sha256', key).update(value).digest()
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function requiredEnv(name) {
  const value = process.env[name]
  if (value === undefined || value === '') throw new Error(`required publication binding ${name} is missing`)
  return value
}

async function setOutput(name, value) {
  const path = requiredEnv('GITHUB_OUTPUT')
  await appendFile(path, `${name}=${String(value).replaceAll('\n', '')}\n`, { encoding: 'utf8' })
}

function singleLine(value) {
  return String(value).replace(/[\r\n]+/gu, ' ').slice(0, 1000)
}
