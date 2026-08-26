import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { describe, it } from 'node:test'
import { handleRequest, inspectStoredArtifact } from '../worker/index.mjs'

const NOW = 1_787_680_000_000
const SOURCE = 'a'.repeat(40)
const PLAN = 'b'.repeat(64)
const TOKEN = 'A'.repeat(43)
const ARTIFACT = 'e-Mate-2.0.13-mac-universal.dmg'
const KEY = `desktop/releases/v2.0.13/${SOURCE}/${ARTIFACT}`
const ORIGIN = 'https://productionresultssa0.blob.core.windows.net'
const SOURCE_PATH = '/actions-results/unit/staging.zip'
const SOURCE_URL = `${ORIGIN}${SOURCE_PATH}?sig=short-lived`

describe('short-lived Cloudflare large-object publication bridge', () => {
  it('streams the exact stored GitHub artifact entry through random temp, verifies it, and promotes create-only', async () => {
    const fixture = makeFixture()
    const response = await fixture.call()
    assert.equal(response.status, 200)
    assert.deepEqual(await response.json(), {
      ok: true,
      status: 'uploaded',
      key: KEY,
      bytes: fixture.file.byteLength,
      sha256: sha256(fixture.file),
      plan_sha256: PLAN,
    })
    assert.deepEqual(fixture.bucket.bytes(KEY), fixture.file)
    assert.equal(fixture.source.fullRequests, 1)
    assert.ok(fixture.source.rangeRequests >= 4)
    assert.equal(fixture.bucket.listCalls, 0)
    assert.equal(fixture.bucket.deletedKeys.length, 1)
    assert.match(fixture.bucket.deletedKeys[0], /^__emate-publication-bridge\/tmp\//u)
    assert.equal([...fixture.bucket.objects.keys()].filter(key => key.includes('/claims/')).length, 1)
    assert.equal([...fixture.bucket.objects.keys()].filter(key => key.includes('/tmp/')).length, 0)

    const replay = await fixture.call()
    assert.equal(replay.status, 409)
    assert.equal((await replay.json()).code, 'authorization-used')
    assert.equal(fixture.source.fullRequests, 1)
  })

  it('accepts a create-only collision only after a fresh full identical readback', async () => {
    const fixture = makeFixture({ token: 'B'.repeat(43) })
    fixture.bucket.seed(KEY, fixture.file, objectMetadata(fixture.env))
    const response = await fixture.call()
    assert.equal(response.status, 200)
    assert.equal((await response.json()).status, 'already-present')
    assert.deepEqual(fixture.bucket.bytes(KEY), fixture.file)
  })

  it('accepts the exact four-entry closure with an optional blockmap', async () => {
    const fixture = makeFixture({ token: 'C'.repeat(43), blockmap: true })
    const response = await fixture.call()
    assert.equal(response.status, 200)
    assert.equal((await response.json()).status, 'uploaded')
    assert.equal(JSON.parse(fixture.env.EXPECTED_ARCHIVE_ENTRIES).length, 4)
    assert.equal([...fixture.bucket.objects.keys()].some(key => key.includes('/tmp/')), false)
  })

  it('fails before the first write for auth, source, plan, pointer, or size drift', async t => {
    const cases = [
      ['wrong bearer', fixture => fixture.request({ token: 'Z'.repeat(43) }), 401, 'unauthorized'],
      ['source origin drift', fixture => fixture.request({ sourceUrl: 'https://example.com/actions-results/unit/staging.zip?sig=x' }), 400, 'source-invalid'],
      ['plan drift', fixture => fixture.request({ plan: 'c'.repeat(64) }), 400, 'plan-mismatch'],
      ['pointer key', fixture => {
        fixture.env.EXPECTED_KEY = 'desktop/signed/latest.json'
        return fixture.request()
      }, 503, 'configuration-invalid'],
      ['oversized object', fixture => {
        fixture.env.EXPECTED_BYTES = String(512 * 1024 * 1024 + 1)
        return fixture.request()
      }, 503, 'configuration-invalid'],
      ['archive entry contract drift', fixture => {
        fixture.env.EXPECTED_ARCHIVE_ENTRIES = '[]'
        return fixture.request()
      }, 503, 'configuration-invalid'],
    ]
    for (const [name, makeRequest, status, code] of cases) {
      await t.test(name, async () => {
        const fixture = makeFixture()
        const response = await handleRequest(makeRequest(fixture), fixture.env, fixture.dependencies)
        assert.equal(response.status, status)
        assert.equal((await response.json()).code, code)
        assert.equal(fixture.bucket.objects.size, 0)
        assert.equal(fixture.source.fullRequests, 0)
        assert.equal(fixture.source.rangeRequests, 0)
      })
    }
  })

  it('consumes the one-time authorization but never promotes corrupt source or final bytes', async t => {
    const cases = [
      ['GitHub archive digest drift', fixture => {
        fixture.env.EXPECTED_GITHUB_ARTIFACT_DIGEST = `sha256:${'d'.repeat(64)}`
      }, 422, 'source-digest-mismatch'],
      ['installer digest drift', fixture => {
        fixture.env.EXPECTED_SHA256 = 'e'.repeat(64)
      }, 422, 'source-digest-mismatch'],
      ['compressed entry', fixture => {
        fixture.replaceArchive(storedZipEntries(fixture.archiveEntries.map(entry => ({
          ...entry,
          method: entry.name === ARTIFACT ? 8 : 0,
        }))))
      }, 422, 'archive-shape-invalid'],
      ['duplicate installer entry', fixture => {
        fixture.replaceArchive(storedZipEntries([
          fixture.archiveEntries[0],
          fixture.archiveEntries[0],
          fixture.archiveEntries[1],
        ]))
      }, 422, 'archive-shape-invalid'],
      ['traversal entry', fixture => {
        fixture.replaceArchive(storedZipEntries([
          fixture.archiveEntries[0],
          fixture.archiveEntries[1],
          { name: '../desktop-artifact-receipt.json', data: fixture.archiveEntries[2].data },
        ]))
      }, 422, 'archive-shape-invalid'],
      ['unlisted extra entry', fixture => {
        fixture.replaceArchive(storedZipEntries([
          fixture.archiveEntries[0],
          fixture.archiveEntries[1],
          { name: 'unexpected.json', data: fixture.archiveEntries[2].data },
        ]))
      }, 422, 'archive-shape-invalid'],
      ['different existing final', fixture => {
        fixture.bucket.seed(KEY, new TextEncoder().encode('wrong'), objectMetadata(fixture.env))
      }, 409, 'final-object-collision'],
    ]
    for (const [name, mutate, status, code] of cases) {
      await t.test(name, async () => {
        const fixture = makeFixture({ token: randomToken(name) })
        mutate(fixture)
        const response = await fixture.call()
        assert.equal(response.status, status)
        const payload = await response.json()
        assert.equal(payload.code, code)
        assert.match(payload.temp_key, /^__emate-publication-bridge\/tmp\//u)
        assert.equal([...fixture.bucket.objects.keys()].filter(key => key.includes('/claims/')).length, 1)
        assert.equal(fixture.bucket.deletedKeys.length, 0)
        if (name !== 'different existing final') assert.equal(fixture.bucket.objects.has(KEY), false)
      })
    }
  })

  it('retains and reports only the exact temp identity when cleanup fails after final readback', async () => {
    const fixture = makeFixture({ token: 'D'.repeat(43) })
    fixture.bucket.failDelete = true
    const response = await fixture.call()
    assert.equal(response.status, 502)
    const payload = await response.json()
    assert.equal(payload.code, 'temp-cleanup-failed')
    assert.match(payload.temp_key, /^__emate-publication-bridge\/tmp\//u)
    assert.equal(fixture.bucket.objects.has(payload.temp_key), true)
    assert.deepEqual(fixture.bucket.bytes(KEY), fixture.file)
    assert.deepEqual(fixture.bucket.deletedKeys, [payload.temp_key])
    assert.equal(fixture.bucket.deletedKeys.includes(KEY), false)
    assert.equal(fixture.bucket.deletedKeys.some(key => key.includes('/claims/')), false)
  })

  it('rejects multi-entry/data-descriptor ambiguity rather than treating a ZIP path as a raw installer', async () => {
    const file = new TextEncoder().encode('installer')
    const entries = [{ name: ARTIFACT, data: file }]
    const archive = storedZipEntries(entries, { eocdEntries: 2 })
    const source = artifactSource(archive)
    await assert.rejects(
      inspectStoredArtifact(source.fetch, SOURCE_URL, ARTIFACT, file.byteLength, archiveContract(entries), AbortSignal.timeout(1_000)),
      /archive-shape-invalid/u,
    )
  })

  it('accepts the signed data-descriptor form used by streaming ZIP writers', async () => {
    const file = new TextEncoder().encode('installer')
    const entries = [{ name: ARTIFACT, data: file, descriptor: true }]
    const archive = storedZipEntries(entries)
    const source = artifactSource(archive)
    const inspected = await inspectStoredArtifact(
      source.fetch,
      SOURCE_URL,
      ARTIFACT,
      file.byteLength,
      archiveContract(entries),
      AbortSignal.timeout(1_000),
    )
    assert.equal(inspected.entryBytes, file.byteLength)
    assert.equal(inspected.archiveBytes, archive.byteLength)
  })

  it('keeps the Worker surface and deployment contract publication-only', async () => {
    const source = await readFile(new URL('../worker/index.mjs', import.meta.url), 'utf8')
    const contract = JSON.parse(await readFile(new URL('../worker/deployment-contract.json', import.meta.url), 'utf8'))
    assert.doesNotMatch(source, /\.list\s*\(/u)
    assert.deepEqual([...source.matchAll(/\.delete\s*\(([^)]+)\)/gu)].map(match => match[1]), ['tempKey'])
    assert.doesNotMatch(source, /desktop\/(?:signed\/)?latest\.json/u)
    assert.doesNotMatch(source, /console\./u)
    assert.doesNotMatch(source, /wrangler|accessKey|secretAccess|AWS4-HMAC/u)
    assert.match(source, /etagDoesNotMatch:\s*['"]\*['"]/u)
    assert.match(source, /createMultipartUpload/u)
    assert.deepEqual(contract.r2_binding, { name: 'RELEASES', bucket_name: 'emate-desktop-downloads' })
    assert.equal(contract.publication_authority, 'codex-cloudflare-plugin')
    assert.deepEqual(contract.compatibility_flags, ['nodejs_compat'])
    assert.equal(contract.lifecycle.one_artifact_per_deployment, true)
    assert.equal(contract.lifecycle.temp_cleanup_only, true)
    assert.equal(contract.lifecycle.delete_worker_after_call, true)
    assert.deepEqual(contract.forbidden_operations, [
      'bucket-list', 'arbitrary-object-delete', 'pointer-write', 'final-overwrite', 'credential-log',
    ])
  })
})

function makeFixture(options = {}) {
  const token = options.token ?? TOKEN
  const file = new TextEncoder().encode('exact installer bytes for a streaming fixture')
  const archiveEntries = [
    { name: ARTIFACT, data: file },
    { name: 'desktop-runtime-verification.json', data: new TextEncoder().encode('{"runtime":true}\n') },
    { name: 'desktop-artifact-receipt.json', data: new TextEncoder().encode('{"receipt":true}\n') },
    ...(options.blockmap ? [{ name: `${ARTIFACT}.blockmap`, data: new TextEncoder().encode('exact blockmap') }] : []),
  ]
  let archive = storedZipEntries(archiveEntries)
  let source = artifactSource(archive)
  const bucket = new MemoryR2()
  const env = {
    RELEASES: bucket,
    AUTH_TOKEN: token,
    EXPECTED_BUCKET: 'emate-desktop-downloads',
    EXPECTED_KEY: KEY,
    EXPECTED_ARTIFACT_PATH: ARTIFACT,
    EXPECTED_BYTES: String(file.byteLength),
    EXPECTED_SHA256: sha256(file),
    EXPECTED_GITHUB_ARTIFACT_DIGEST: `sha256:${sha256(archive)}`,
    EXPECTED_ARCHIVE_ENTRIES: JSON.stringify(archiveContract(archiveEntries)),
    EXPECTED_PLAN_SHA256: PLAN,
    EXPECTED_CONTENT_TYPE: 'application/octet-stream',
    EXPECTED_CACHE_CONTROL: 'public,max-age=31536000,immutable',
    EXPECTED_SOURCE_ORIGIN: ORIGIN,
    EXPECTED_SOURCE_PATH: SOURCE_PATH,
    EXPIRES_AT: String(NOW + 5 * 60 * 1000),
  }
  const fixture = {
    bucket,
    env,
    file,
    archiveEntries,
    get source() { return source },
    get dependencies() { return { fetch: source.fetch, now: () => NOW } },
    replaceArchive(next) {
      archive = next
      source = artifactSource(archive)
      env.EXPECTED_GITHUB_ARTIFACT_DIGEST = `sha256:${sha256(archive)}`
    },
    request(overrides = {}) {
      const body = {
        schema_version: 1,
        plan_sha256: overrides.plan ?? PLAN,
        source_url: overrides.sourceUrl ?? SOURCE_URL,
      }
      return new Request('https://bridge.example/v1/ingest', {
        method: 'POST',
        headers: {
          authorization: `Bearer ${overrides.token ?? token}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify(body),
      })
    },
    call(overrides) {
      return handleRequest(this.request(overrides), env, this.dependencies)
    },
  }
  return fixture
}

function artifactSource(archive) {
  const stats = { fullRequests: 0, rangeRequests: 0 }
  return {
    ...stats,
    get fullRequests() { return stats.fullRequests },
    get rangeRequests() { return stats.rangeRequests },
    fetch: async (_url, options = {}) => {
      const range = options.headers?.range
      if (range === undefined) {
        stats.fullRequests += 1
        return new Response(archive.slice(), {
          status: 200,
          headers: {
            'content-type': 'application/zip',
            'content-length': String(archive.byteLength),
          },
        })
      }
      stats.rangeRequests += 1
      const [start, end] = resolveRange(range, archive.byteLength)
      return new Response(archive.slice(start, end + 1), {
        status: 206,
        headers: {
          'content-type': 'application/zip',
          'content-length': String(end - start + 1),
          'content-range': `bytes ${start}-${end}/${archive.byteLength}`,
        },
      })
    },
  }
}

function resolveRange(value, total) {
  const suffix = /^bytes=-([0-9]+)$/u.exec(value)
  if (suffix !== null) return [Math.max(0, total - Number(suffix[1])), total - 1]
  const explicit = /^bytes=([0-9]+)-([0-9]+)$/u.exec(value)
  if (explicit === null) throw new Error(`unexpected range ${value}`)
  const start = Number(explicit[1])
  const end = Math.min(Number(explicit[2]), total - 1)
  if (start > end) throw new Error(`invalid range ${value}`)
  return [start, end]
}

function storedZipEntries(entries, options = {}) {
  const locals = []
  const centrals = []
  let localOffset = 0
  for (const entry of entries) {
    const nameBytes = new TextEncoder().encode(entry.name)
    const local = new Uint8Array(30 + nameBytes.byteLength + entry.data.byteLength)
    const localView = new DataView(local.buffer)
    localView.setUint32(0, 0x04034b50, true)
    localView.setUint16(4, 20, true)
    localView.setUint16(6, entry.descriptor ? 1 << 3 : 0, true)
    localView.setUint16(8, entry.method ?? 0, true)
    localView.setUint32(18, entry.descriptor ? 0 : entry.data.byteLength, true)
    localView.setUint32(22, entry.descriptor ? 0 : entry.data.byteLength, true)
    localView.setUint16(26, nameBytes.byteLength, true)
    local.set(nameBytes, 30)
    local.set(entry.data, 30 + nameBytes.byteLength)

    const descriptor = entry.descriptor ? new Uint8Array(16) : new Uint8Array()
    if (entry.descriptor) {
      const descriptorView = new DataView(descriptor.buffer)
      descriptorView.setUint32(0, 0x08074b50, true)
      descriptorView.setUint32(8, entry.data.byteLength, true)
      descriptorView.setUint32(12, entry.data.byteLength, true)
    }
    locals.push(local, descriptor)

    const central = new Uint8Array(46 + nameBytes.byteLength)
    const centralView = new DataView(central.buffer)
    centralView.setUint32(0, 0x02014b50, true)
    centralView.setUint16(4, 20, true)
    centralView.setUint16(6, 20, true)
    centralView.setUint16(8, entry.descriptor ? 1 << 3 : 0, true)
    centralView.setUint16(10, entry.method ?? 0, true)
    centralView.setUint32(20, entry.data.byteLength, true)
    centralView.setUint32(24, entry.data.byteLength, true)
    centralView.setUint16(28, nameBytes.byteLength, true)
    centralView.setUint32(42, localOffset, true)
    central.set(nameBytes, 46)
    centrals.push(central)
    localOffset += local.byteLength + descriptor.byteLength
  }

  const central = concat(...centrals)
  const eocd = new Uint8Array(22)
  const eocdView = new DataView(eocd.buffer)
  const count = options.eocdEntries ?? entries.length
  eocdView.setUint32(0, 0x06054b50, true)
  eocdView.setUint16(8, count, true)
  eocdView.setUint16(10, count, true)
  eocdView.setUint32(12, central.byteLength, true)
  eocdView.setUint32(16, localOffset, true)
  return concat(...locals, central, eocd)
}

function archiveContract(entries) {
  return entries.map(entry => ({ name: entry.name, bytes: entry.data.byteLength }))
    .sort((left, right) => left.name.localeCompare(right.name))
}

function concat(...parts) {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.byteLength, 0))
  let offset = 0
  for (const part of parts) {
    result.set(part, offset)
    offset += part.byteLength
  }
  return result
}

class MemoryR2 {
  constructor() {
    this.objects = new Map()
    this.listCalls = 0
    this.deletedKeys = []
    this.failDelete = false
  }

  async put(key, value, options = {}) {
    if (options.onlyIf?.etagDoesNotMatch === '*' && this.objects.has(key)) return null
    const bytes = await bodyBytes(value)
    if (options.sha256 !== undefined) assert.equal(sha256(bytes), hex(options.sha256))
    this.seed(key, bytes, options)
    return this.object(key, false)
  }

  async get(key, options = {}) {
    const stored = this.objects.get(key)
    if (stored === undefined) return null
    if (options.onlyIf?.etagMatches !== undefined && options.onlyIf.etagMatches !== stored.etag) {
      return { ...this.object(key, false), body: undefined }
    }
    return this.object(key, true)
  }

  async createMultipartUpload(key, options = {}) {
    const parts = new Map()
    let aborted = false
    return {
      uploadPart: async (partNumber, value) => {
        if (aborted) throw new Error('aborted')
        const bytes = await bodyBytes(value)
        parts.set(partNumber, bytes)
        return { partNumber, etag: sha256(bytes) }
      },
      complete: async uploaded => {
        if (aborted) throw new Error('aborted')
        const bytes = concat(...uploaded.map(part => parts.get(part.partNumber)))
        this.seed(key, bytes, options)
        return this.object(key, false)
      },
      abort: async () => { aborted = true },
    }
  }

  seed(key, bytes, options = {}) {
    const copy = bytes instanceof Uint8Array ? bytes.slice() : new Uint8Array(bytes)
    this.objects.set(key, {
      bytes: copy,
      etag: sha256(copy),
      httpMetadata: structuredClone(options.httpMetadata ?? {}),
      customMetadata: structuredClone(options.customMetadata ?? {}),
    })
  }

  object(key, withBody) {
    const stored = this.objects.get(key)
    return {
      key,
      size: stored.bytes.byteLength,
      etag: stored.etag,
      httpMetadata: structuredClone(stored.httpMetadata),
      customMetadata: structuredClone(stored.customMetadata),
      ...(withBody ? { body: new Response(stored.bytes.slice()).body } : {}),
    }
  }

  bytes(key) {
    return this.objects.get(key)?.bytes
  }

  async list() {
    this.listCalls += 1
    throw new Error('list forbidden')
  }

  async delete(key) {
    this.deletedKeys.push(key)
    if (this.failDelete) throw new Error('temp cleanup failed')
    this.objects.delete(key)
  }
}

async function bodyBytes(value) {
  if (value instanceof ReadableStream) return new Uint8Array(await new Response(value).arrayBuffer())
  if (typeof value === 'string') return new TextEncoder().encode(value)
  if (value instanceof Uint8Array) return value.slice()
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0))
  throw new Error('unsupported body')
}

function objectMetadata(env) {
  return {
    httpMetadata: { contentType: env.EXPECTED_CONTENT_TYPE, cacheControl: env.EXPECTED_CACHE_CONTROL },
    customMetadata: {
      sha256: env.EXPECTED_SHA256,
      bytes: env.EXPECTED_BYTES,
      plan_sha256: env.EXPECTED_PLAN_SHA256,
      github_artifact_digest: env.EXPECTED_GITHUB_ARTIFACT_DIGEST,
    },
  }
}

function randomToken(value) {
  return createHash('sha256').update(value).digest('base64url')
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function hex(value) {
  return Buffer.from(value).toString('hex')
}
