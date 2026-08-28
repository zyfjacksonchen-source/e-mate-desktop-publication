import { createHash, timingSafeEqual } from 'node:crypto'

const EXPECTED_BUCKET = 'emate-desktop-downloads'
const INGEST_PATH = '/v1/ingest'
const MAX_OBJECT_BYTES = 512 * 1024 * 1024
const MAX_ARCHIVE_OVERHEAD = 256 * 1024
const MAX_BLOCKMAP_BYTES = 32 * 1024 * 1024
const MAX_REQUEST_BYTES = 8 * 1024
const MAX_RANGE_BYTES = 66 * 1024
const MAX_AUTH_WINDOW_MS = 15 * 60 * 1000
const MAX_TRANSFER_MS = 10 * 60 * 1000
const IMMUTABLE_CACHE = 'public,max-age=31536000,immutable'
const BINARY_CONTENT_TYPE = 'application/octet-stream'
const DESKTOP_CI_RECEIPT = 'desktop-artifact-receipt.json'
const DESKTOP_RUNTIME_RECEIPT = 'desktop-runtime-verification.json'
const MACOS_SIGNED_RECEIPT = 'desktop-macos-signed-receipt.json'
const MACOS_SIGNED_VERIFICATION = 'desktop-macos-signed-verification.json'
const TOKEN = /^[A-Za-z0-9_-]{43}$/u
const SHA256 = /^[0-9a-f]{64}$/u
const ARTIFACT_DIGEST = /^sha256:([0-9a-f]{64})$/u
const RELEASE_KEY = /^desktop\/releases\/v2\.0\.15\/([0-9a-f]{40})\/(e-Mate-2\.0\.15-(?:mac-universal\.dmg|win-x64-Setup\.exe))$/u
const GITHUB_BLOB_HOST = /^productionresultssa[0-9]+\.blob\.core\.windows\.net$/u
const ALLOWED_ZIP_FLAGS = (1 << 3) | (1 << 11)

export default {
  fetch(request, env) {
    return handleRequest(request, env)
  },
}

export async function handleRequest(request, env, dependencies = {}) {
  try {
    return await ingest(request, env, {
      fetch: dependencies.fetch ?? globalThis.fetch,
      now: dependencies.now ?? Date.now,
    })
  } catch (error) {
    const safe = error instanceof BridgeError ? error : new BridgeError(500, 'internal')
    return json({
      ok: false,
      code: safe.code,
      ...(safe.tempKey === undefined ? {} : { temp_key: safe.tempKey }),
    }, safe.status)
  }
}

async function ingest(request, env, dependencies) {
  const url = new URL(request.url)
  if (url.pathname !== INGEST_PATH || url.search !== '') throw new BridgeError(404, 'not-found')
  if (request.method !== 'POST') throw new BridgeError(405, 'method-not-allowed')

  const now = dependencies.now()
  const config = validateConfig(env, now)
  authenticate(request, config.authToken)
  if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
    throw new BridgeError(415, 'content-type-invalid')
  }
  const body = parseRequest(await readBounded(request.body, MAX_REQUEST_BYTES))
  if (body.plan_sha256 !== config.planSha256) throw new BridgeError(400, 'plan-mismatch')
  const sourceUrl = validateSourceUrl(body.source_url, config)

  const authorizationId = sha256(config.authToken)
  const claimKey = `__emate-publication-bridge/claims/${authorizationId}`
  const tempKey = `__emate-publication-bridge/tmp/${config.planSha256}/${authorizationId}/${config.artifactPath}`
  const claim = await env.RELEASES.put(claimKey, JSON.stringify({
    schema_version: 1,
    authorization_id: authorizationId,
    plan_sha256: config.planSha256,
    final_key: config.key,
    expires_at: config.expiresAt,
  }), {
    onlyIf: { etagDoesNotMatch: '*' },
    httpMetadata: { contentType: 'application/json', cacheControl: 'no-store' },
  })
  if (claim === null) throw new BridgeError(409, 'authorization-used')

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), MAX_TRANSFER_MS)
  try {
    const archive = await inspectStoredArtifact(
      dependencies.fetch,
      sourceUrl,
      config.artifactPath,
      config.bytes,
      config.archiveEntries,
      controller.signal,
    )
    if (archive.archiveBytes !== config.githubArtifactBytes) {
      throw new BridgeError(422, 'archive-shape-invalid')
    }
    const response = await dependencies.fetch(sourceUrl, {
      method: 'GET',
      redirect: 'error',
      signal: controller.signal,
      headers: { accept: 'application/zip' },
    })
    validateFullArchiveResponse(response, archive.archiveBytes)

    const metadata = objectMetadata(config)
    const upload = await env.RELEASES.createMultipartUpload(tempKey, metadata)
    try {
      const stream = verifiedEntryStream(response.body, archive, {
        archiveSha256: config.githubArtifactSha256,
        entrySha256: config.sha256,
      })
      const part = await upload.uploadPart(1, stream)
      await upload.complete([part])
    } catch (error) {
      await upload.abort().catch(() => {})
      throw error
    }

    const verifiedTemp = await verifyObject(env.RELEASES, tempKey, config)
    const promotionSource = await env.RELEASES.get(tempKey, { onlyIf: { etagMatches: verifiedTemp.etag } })
    if (promotionSource === null || !(promotionSource.body instanceof ReadableStream)) {
      throw new BridgeError(409, 'temporary-object-drifted')
    }
    const promoted = await env.RELEASES.put(config.key, promotionSource.body, {
      ...metadata,
      sha256: hexBytes(config.sha256),
      onlyIf: { etagDoesNotMatch: '*' },
    })
    try {
      await verifyObject(env.RELEASES, config.key, config)
    } catch {
      throw new BridgeError(409, 'final-object-collision')
    }
    try {
      await env.RELEASES.delete(tempKey)
      if (await env.RELEASES.get(tempKey) !== null) throw new Error('temporary object survived cleanup')
    } catch {
      throw new BridgeError(502, 'temp-cleanup-failed', tempKey)
    }

    return json({
      ok: true,
      status: promoted === null ? 'already-present' : 'uploaded',
      key: config.key,
      bytes: config.bytes,
      sha256: config.sha256,
      plan_sha256: config.planSha256,
    }, 200)
  } catch (error) {
    if (controller.signal.aborted) throw new BridgeError(504, 'transfer-timeout', tempKey)
    if (error instanceof BridgeError) {
      throw error.tempKey === undefined ? new BridgeError(error.status, error.code, tempKey) : error
    }
    throw new BridgeError(502, 'transfer-failed', tempKey)
  } finally {
    clearTimeout(timer)
  }
}

function validateConfig(env, now) {
  if (env?.EXPECTED_BUCKET !== EXPECTED_BUCKET || typeof env.RELEASES?.put !== 'function'
    || typeof env.RELEASES?.get !== 'function' || typeof env.RELEASES?.delete !== 'function'
    || typeof env.RELEASES?.createMultipartUpload !== 'function') {
    throw new BridgeError(503, 'configuration-invalid')
  }
  const match = RELEASE_KEY.exec(env.EXPECTED_KEY ?? '')
  const bytes = Number(env.EXPECTED_BYTES)
  const githubArtifactBytes = Number(env.EXPECTED_GITHUB_ARTIFACT_BYTES)
  const expiresAt = Number(env.EXPIRES_AT)
  const sourceOrigin = strictSourceOrigin(env.EXPECTED_SOURCE_ORIGIN)
  const publicationMetadata = expectedPublicationMetadata(
    env.EXPECTED_PUBLICATION_METADATA,
    env.EXPECTED_ARTIFACT_PATH,
  )
  const archiveEntries = expectedArchiveEntries(
    env.EXPECTED_ARCHIVE_ENTRIES,
    env.EXPECTED_ARTIFACT_PATH,
    bytes,
    publicationMetadata,
  )
  if (match === null || env.EXPECTED_ARTIFACT_PATH !== match[2]
    || !Number.isSafeInteger(bytes) || bytes <= 0 || bytes > MAX_OBJECT_BYTES
    || !Number.isSafeInteger(githubArtifactBytes) || githubArtifactBytes <= bytes
    || githubArtifactBytes > MAX_OBJECT_BYTES + MAX_ARCHIVE_OVERHEAD
    || !SHA256.test(env.EXPECTED_SHA256 ?? '')
    || !ARTIFACT_DIGEST.test(env.EXPECTED_GITHUB_ARTIFACT_DIGEST ?? '')
    || !SHA256.test(env.EXPECTED_PLAN_SHA256 ?? '')
    || env.EXPECTED_CONTENT_TYPE !== BINARY_CONTENT_TYPE
    || env.EXPECTED_CACHE_CONTROL !== IMMUTABLE_CACHE
    || publicationMetadata === null
    || archiveEntries === null
    || !TOKEN.test(env.AUTH_TOKEN ?? '')
    || !Number.isSafeInteger(expiresAt) || expiresAt <= now || expiresAt - now > MAX_AUTH_WINDOW_MS
    || sourceOrigin === null
    || typeof env.EXPECTED_SOURCE_PATH !== 'string'
    || !env.EXPECTED_SOURCE_PATH.startsWith('/actions-results/')
    || env.EXPECTED_SOURCE_PATH.includes('?') || env.EXPECTED_SOURCE_PATH.includes('#')) {
    throw new BridgeError(503, 'configuration-invalid')
  }
  return {
    artifactPath: env.EXPECTED_ARTIFACT_PATH,
    archiveEntries,
    authToken: env.AUTH_TOKEN,
    bytes,
    cacheControl: env.EXPECTED_CACHE_CONTROL,
    contentType: env.EXPECTED_CONTENT_TYPE,
    expiresAt,
    githubArtifactSha256: ARTIFACT_DIGEST.exec(env.EXPECTED_GITHUB_ARTIFACT_DIGEST)[1],
    githubArtifactBytes,
    key: env.EXPECTED_KEY,
    planSha256: env.EXPECTED_PLAN_SHA256,
    publicationMetadata,
    sha256: env.EXPECTED_SHA256,
    sourceOrigin,
    sourcePath: env.EXPECTED_SOURCE_PATH,
  }
}

function strictSourceOrigin(value) {
  try {
    const url = new URL(value)
    if (url.protocol !== 'https:' || url.username !== '' || url.password !== ''
      || url.port !== '' || url.pathname !== '/' || url.search !== '' || url.hash !== ''
      || !GITHUB_BLOB_HOST.test(url.hostname)) return null
    return url.origin
  } catch {
    return null
  }
}

function expectedPublicationMetadata(value, artifactPath) {
  let metadata
  try {
    if (typeof value !== 'string' || value.length > 512) return null
    metadata = JSON.parse(value)
  } catch {
    return null
  }
  if (!hasExactKeys(metadata, ['mode', 'signed', 'notarized', 'description'])) return null
  const macos = typeof artifactPath === 'string' && artifactPath.endsWith('-mac-universal.dmg')
  const expected = macos && metadata.mode === 'signed'
    ? { mode: 'signed', signed: true, notarized: true, description: 'Developer ID signed and notarized.' }
    : { mode: 'unsigned', signed: false, notarized: false, description: 'Unsigned and not notarized.' }
  return Object.keys(expected).every(key => metadata[key] === expected[key]) ? metadata : null
}

function expectedArchiveEntries(value, artifactPath, installerBytes, publicationMetadata) {
  let entries
  try {
    if (typeof value !== 'string' || value.length > 2048) return null
    entries = JSON.parse(value)
  } catch {
    return null
  }
  const macos = typeof artifactPath === 'string' && artifactPath.endsWith('-mac-universal.dmg')
  if (!Array.isArray(entries) || publicationMetadata === null) return null
  const names = entries.map(entry => entry?.name)
  const expected = macos && publicationMetadata.mode === 'signed'
    ? [MACOS_SIGNED_RECEIPT, MACOS_SIGNED_VERIFICATION, artifactPath, `${artifactPath}.blockmap`]
    : [DESKTOP_CI_RECEIPT, DESKTOP_RUNTIME_RECEIPT, artifactPath,
        ...(macos ? [`${artifactPath}.blockmap`] : [])]
  if (JSON.stringify(names) !== JSON.stringify(expected.sort())) return null
  if (new Set(names).size !== names.length || entries.some(entry => !hasExactKeys(entry, ['name', 'bytes'])
    || !safeArchiveName(entry.name) || !Number.isSafeInteger(entry.bytes) || entry.bytes <= 0)) return null
  for (const entry of entries) {
    if (entry.name === artifactPath && entry.bytes !== installerBytes) return null
    if (entry.name.endsWith('.json') && entry.bytes > 64 * 1024) return null
    if (entry.name.endsWith('.blockmap') && entry.bytes > MAX_BLOCKMAP_BYTES) return null
  }
  return entries
}

function safeArchiveName(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 255
    && !value.includes('/') && !value.includes('\\') && !/[\u0000-\u001f\u007f]/u.test(value)
    && value !== '.' && value !== '..' && !value.startsWith('-')
}

function authenticate(request, expected) {
  const header = request.headers.get('authorization') ?? ''
  const token = header.startsWith('Bearer ') ? header.slice(7) : ''
  const actualBytes = new TextEncoder().encode(token)
  const expectedBytes = new TextEncoder().encode(expected)
  if (actualBytes.byteLength !== expectedBytes.byteLength || !timingSafeEqual(actualBytes, expectedBytes)) {
    throw new BridgeError(401, 'unauthorized')
  }
}

function parseRequest(bytes) {
  let value
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    throw new BridgeError(400, 'request-invalid')
  }
  if (!hasExactKeys(value, ['schema_version', 'plan_sha256', 'source_url'])
    || value.schema_version !== 1 || !SHA256.test(value.plan_sha256 ?? '')
    || typeof value.source_url !== 'string' || value.source_url.length > 4096) {
    throw new BridgeError(400, 'request-invalid')
  }
  return value
}

function validateSourceUrl(value, config) {
  let url
  try {
    url = new URL(value)
  } catch {
    throw new BridgeError(400, 'source-invalid')
  }
  if (url.origin !== config.sourceOrigin || url.pathname !== config.sourcePath
    || url.username !== '' || url.password !== '' || url.port !== ''
    || url.search === '' || url.hash !== '') throw new BridgeError(400, 'source-invalid')
  return url.href
}

export async function inspectStoredArtifact(fetcher, sourceUrl, expectedName, expectedBytes, expectedEntries, signal) {
  const tail = await fetchRange(fetcher, sourceUrl, 'bytes=-65557', signal)
  const eocd = findEocd(tail)
  const expectedArchiveBytes = expectedEntries.reduce((sum, entry) => sum + entry.bytes, 0)
  if (eocd.entries !== expectedEntries.length || eocd.commentBytes !== 0 || eocd.centralBytes <= 0
    || eocd.centralBytes > MAX_RANGE_BYTES || eocd.centralOffset + eocd.centralBytes !== eocd.offset
    || eocd.archiveBytes < expectedArchiveBytes
    || eocd.archiveBytes > expectedArchiveBytes + MAX_ARCHIVE_OVERHEAD) {
    throw new BridgeError(422, 'archive-shape-invalid')
  }
  const central = await fetchRange(
    fetcher,
    sourceUrl,
    `bytes=${eocd.centralOffset}-${eocd.offset - 1}`,
    signal,
  )
  const entries = parseCentralEntries(central.bytes, expectedEntries)
  const entry = entries.find(item => item.name === expectedName)
  if (entry === undefined || entry.uncompressedBytes !== expectedBytes) {
    throw new BridgeError(422, 'archive-shape-invalid')
  }

  const localFixed = await fetchRange(
    fetcher,
    sourceUrl,
    `bytes=${entry.localOffset}-${entry.localOffset + 29}`,
    signal,
  )
  const local = parseLocalEntry(localFixed.bytes)
  const localTailBytes = local.nameBytes + local.extraBytes
  if (localTailBytes <= 0 || localTailBytes > MAX_RANGE_BYTES) throw new BridgeError(422, 'archive-shape-invalid')
  const localTailStart = entry.localOffset + 30
  const localTail = await fetchRange(
    fetcher,
    sourceUrl,
    `bytes=${localTailStart}-${localTailStart + localTailBytes - 1}`,
    signal,
  )
  validateLocalEntry(local, localTail.bytes, entry, expectedName, expectedBytes)
  const dataOffset = localTailStart + localTailBytes
  const dataEnd = dataOffset + expectedBytes
  const boundary = Math.min(
    eocd.centralOffset,
    ...entries.filter(item => item.localOffset > entry.localOffset).map(item => item.localOffset),
  )
  await validateDescriptor(fetcher, sourceUrl, dataEnd, boundary, entry, signal)
  return { archiveBytes: eocd.archiveBytes, dataOffset, dataEnd, entryBytes: expectedBytes }
}

async function validateDescriptor(fetcher, sourceUrl, dataEnd, centralOffset, entry, signal) {
  const gap = centralOffset - dataEnd
  if ((entry.flags & (1 << 3)) === 0) {
    if (gap !== 0) throw new BridgeError(422, 'archive-shape-invalid')
    return
  }
  if (gap !== 12 && gap !== 16) throw new BridgeError(422, 'archive-shape-invalid')
  const descriptor = await fetchRange(fetcher, sourceUrl, `bytes=${dataEnd}-${centralOffset - 1}`, signal)
  const view = new DataView(descriptor.bytes.buffer, descriptor.bytes.byteOffset, descriptor.bytes.byteLength)
  const offset = gap === 16 ? 4 : 0
  if (gap === 16 && view.getUint32(0, true) !== 0x08074b50) throw new BridgeError(422, 'archive-shape-invalid')
  if (view.getUint32(offset, true) !== entry.crc32
    || view.getUint32(offset + 4, true) !== entry.compressedBytes
    || view.getUint32(offset + 8, true) !== entry.uncompressedBytes) {
    throw new BridgeError(422, 'archive-shape-invalid')
  }
}

async function fetchRange(fetcher, sourceUrl, range, signal) {
  let response
  try {
    response = await fetcher(sourceUrl, {
      method: 'GET',
      redirect: 'error',
      signal,
      headers: { accept: 'application/zip', range },
    })
  } catch {
    throw new BridgeError(502, 'source-unavailable')
  }
  if (response.status !== 206 || !acceptableArchiveType(response.headers.get('content-type'))
    || !identityEncoding(response.headers.get('content-encoding'))) {
    throw new BridgeError(502, 'source-range-invalid')
  }
  const contentRange = parseContentRange(response.headers.get('content-range'))
  const bytes = await readBounded(response.body, MAX_RANGE_BYTES)
  if (contentRange === null || bytes.byteLength !== contentRange.end - contentRange.start + 1) {
    throw new BridgeError(502, 'source-range-invalid')
  }
  return { ...contentRange, bytes }
}

function findEocd(range) {
  const bytes = range.bytes
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  for (let index = bytes.byteLength - 22; index >= 0; index -= 1) {
    if (view.getUint32(index, true) !== 0x06054b50) continue
    const commentBytes = view.getUint16(index + 20, true)
    const absoluteOffset = range.start + index
    if (absoluteOffset + 22 + commentBytes !== range.total) continue
    if (view.getUint16(index + 4, true) !== 0 || view.getUint16(index + 6, true) !== 0
      || view.getUint16(index + 8, true) !== view.getUint16(index + 10, true)) {
      throw new BridgeError(422, 'archive-shape-invalid')
    }
    return {
      archiveBytes: range.total,
      centralBytes: view.getUint32(index + 12, true),
      centralOffset: view.getUint32(index + 16, true),
      commentBytes,
      entries: view.getUint16(index + 10, true),
      offset: absoluteOffset,
    }
  }
  throw new BridgeError(422, 'archive-shape-invalid')
}

function parseCentralEntries(bytes, expectedEntries) {
  const expected = new Map(expectedEntries.map(entry => [entry.name, entry]))
  const entries = []
  const seenOffsets = new Set()
  let offset = 0
  while (offset < bytes.byteLength) {
    if (bytes.byteLength - offset < 46) throw new BridgeError(422, 'archive-shape-invalid')
    const view = new DataView(bytes.buffer, bytes.byteOffset + offset, bytes.byteLength - offset)
    const flags = view.getUint16(8, true)
    const compressedBytes = view.getUint32(20, true)
    const uncompressedBytes = view.getUint32(24, true)
    const nameBytes = view.getUint16(28, true)
    const extraBytes = view.getUint16(30, true)
    const commentBytes = view.getUint16(32, true)
    const total = 46 + nameBytes + extraBytes + commentBytes
    if (view.getUint32(0, true) !== 0x02014b50 || view.getUint16(10, true) !== 0
      || (flags & ~ALLOWED_ZIP_FLAGS) !== 0 || view.getUint16(34, true) !== 0
      || commentBytes !== 0 || extraBytes > 4096 || total > bytes.byteLength - offset) {
      throw new BridgeError(422, 'archive-shape-invalid')
    }
    const name = decodeName(bytes.subarray(offset + 46, offset + 46 + nameBytes))
    const wanted = expected.get(name)
    const localOffset = view.getUint32(42, true)
    if (!safeArchiveName(name) || wanted === undefined || entries.some(entry => entry.name === name)
      || seenOffsets.has(localOffset) || compressedBytes !== wanted.bytes || uncompressedBytes !== wanted.bytes) {
      throw new BridgeError(422, 'archive-shape-invalid')
    }
    seenOffsets.add(localOffset)
    entries.push({
      name,
      compressedBytes,
      crc32: view.getUint32(16, true),
      flags,
      localOffset,
      uncompressedBytes,
    })
    offset += total
  }
  if (entries.length !== expectedEntries.length) throw new BridgeError(422, 'archive-shape-invalid')
  return entries
}

function parseLocalEntry(bytes) {
  if (bytes.byteLength !== 30) throw new BridgeError(422, 'archive-shape-invalid')
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  if (view.getUint32(0, true) !== 0x04034b50) throw new BridgeError(422, 'archive-shape-invalid')
  return {
    compressedBytes: view.getUint32(18, true),
    crc32: view.getUint32(14, true),
    extraBytes: view.getUint16(28, true),
    flags: view.getUint16(6, true),
    method: view.getUint16(8, true),
    nameBytes: view.getUint16(26, true),
    uncompressedBytes: view.getUint32(22, true),
  }
}

function validateLocalEntry(local, tail, central, expectedName, expectedBytes) {
  const name = decodeName(tail.subarray(0, local.nameBytes))
  const descriptor = (local.flags & (1 << 3)) !== 0
  if (local.flags !== central.flags || (local.flags & ~ALLOWED_ZIP_FLAGS) !== 0 || local.method !== 0
    || name !== expectedName || local.extraBytes > 4096
    || (!descriptor && (local.crc32 !== central.crc32 || local.compressedBytes !== expectedBytes
      || local.uncompressedBytes !== expectedBytes))
    || (descriptor && ((local.crc32 !== 0 && local.crc32 !== central.crc32)
      || (local.compressedBytes !== 0 && local.compressedBytes !== expectedBytes)
      || (local.uncompressedBytes !== 0 && local.uncompressedBytes !== expectedBytes)))) {
    throw new BridgeError(422, 'archive-shape-invalid')
  }
}

function validateFullArchiveResponse(response, expectedBytes) {
  if (response.status !== 200 || !(response.body instanceof ReadableStream)
    || Number(response.headers.get('content-length')) !== expectedBytes
    || !acceptableArchiveType(response.headers.get('content-type'))
    || !identityEncoding(response.headers.get('content-encoding'))) {
    throw new BridgeError(502, 'source-response-invalid')
  }
}

export function verifiedEntryStream(body, archive, expected) {
  const reader = body.getReader()
  const archiveHash = createHash('sha256')
  const entryHash = createHash('sha256')
  let archiveOffset = 0
  let entryBytes = 0
  return new ReadableStream({
    async pull(controller) {
      try {
        while (true) {
          const { done, value } = await reader.read()
          if (done) {
            if (archiveOffset !== archive.archiveBytes || entryBytes !== archive.entryBytes
              || archiveHash.digest('hex') !== expected.archiveSha256
              || entryHash.digest('hex') !== expected.entrySha256) {
              throw new BridgeError(422, 'source-digest-mismatch')
            }
            controller.close()
            return
          }
          const chunk = value instanceof Uint8Array ? value : new Uint8Array(value)
          const chunkStart = archiveOffset
          const chunkEnd = archiveOffset + chunk.byteLength
          archiveHash.update(chunk)
          archiveOffset = chunkEnd
          const overlapStart = Math.max(chunkStart, archive.dataOffset)
          const overlapEnd = Math.min(chunkEnd, archive.dataEnd)
          if (overlapStart < overlapEnd) {
            const entry = chunk.slice(overlapStart - chunkStart, overlapEnd - chunkStart)
            entryHash.update(entry)
            entryBytes += entry.byteLength
            controller.enqueue(entry)
            return
          }
        }
      } catch (error) {
        await reader.cancel(error).catch(() => {})
        controller.error(error)
      }
    },
    cancel(reason) {
      return reader.cancel(reason)
    },
  })
}

async function verifyObject(bucket, key, config) {
  const object = await bucket.get(key)
  const custom = object?.customMetadata
  if (object === null || !(object.body instanceof ReadableStream) || object.size !== config.bytes
    || object.httpMetadata?.contentType !== config.contentType
    || object.httpMetadata?.cacheControl !== config.cacheControl
    || !hasExactKeys(custom, [
      'sha256', 'bytes', 'plan_sha256', 'github_artifact_digest', 'github_artifact_bytes',
      'publication_mode', 'signed', 'notarized', 'description',
    ])
    || custom.sha256 !== config.sha256 || custom.bytes !== String(config.bytes)
    || custom.plan_sha256 !== config.planSha256
    || custom.github_artifact_digest !== `sha256:${config.githubArtifactSha256}`
    || custom.github_artifact_bytes !== String(config.githubArtifactBytes)
    || custom.publication_mode !== config.publicationMetadata.mode
    || custom.signed !== String(config.publicationMetadata.signed)
    || custom.notarized !== String(config.publicationMetadata.notarized)
    || custom.description !== config.publicationMetadata.description) {
    throw new BridgeError(409, 'object-readback-mismatch')
  }
  const digest = createHash('sha256')
  const reader = object.body.getReader()
  let bytes = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    const chunk = value instanceof Uint8Array ? value : new Uint8Array(value)
    bytes += chunk.byteLength
    if (bytes > config.bytes) throw new BridgeError(409, 'object-readback-mismatch')
    digest.update(chunk)
  }
  if (bytes !== config.bytes || digest.digest('hex') !== config.sha256) {
    throw new BridgeError(409, 'object-readback-mismatch')
  }
  return object
}

function objectMetadata(config) {
  return {
    httpMetadata: { contentType: config.contentType, cacheControl: config.cacheControl },
    customMetadata: {
      sha256: config.sha256,
      bytes: String(config.bytes),
      plan_sha256: config.planSha256,
      github_artifact_digest: `sha256:${config.githubArtifactSha256}`,
      github_artifact_bytes: String(config.githubArtifactBytes),
      publication_mode: config.publicationMetadata.mode,
      signed: String(config.publicationMetadata.signed),
      notarized: String(config.publicationMetadata.notarized),
      description: config.publicationMetadata.description,
    },
  }
}

async function readBounded(body, limit) {
  if (!(body instanceof ReadableStream)) throw new BridgeError(400, 'body-missing')
  const reader = body.getReader()
  const chunks = []
  let total = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    const chunk = value instanceof Uint8Array ? value : new Uint8Array(value)
    total += chunk.byteLength
    if (total > limit) {
      await reader.cancel().catch(() => {})
      throw new BridgeError(413, 'body-too-large')
    }
    chunks.push(chunk)
  }
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return bytes
}

function parseContentRange(value) {
  const match = /^bytes ([0-9]+)-([0-9]+)\/([1-9][0-9]*)$/u.exec(value ?? '')
  if (match === null) return null
  const [start, end, total] = match.slice(1).map(Number)
  return Number.isSafeInteger(start) && Number.isSafeInteger(end) && Number.isSafeInteger(total)
    && start <= end && end < total ? { start, end, total } : null
}

function acceptableArchiveType(value) {
  const type = value?.split(';', 1)[0].trim().toLowerCase()
  return type === 'application/zip' || type === 'application/octet-stream'
}

function identityEncoding(value) {
  return value === null || value === '' || value.toLowerCase() === 'identity'
}

function decodeName(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    throw new BridgeError(422, 'archive-shape-invalid')
  }
}

function hasExactKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort())
}

function hexBytes(value) {
  return Uint8Array.from(value.match(/../gu), byte => Number.parseInt(byte, 16))
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function json(value, status) {
  return new Response(`${JSON.stringify(value)}\n`, {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  })
}

class BridgeError extends Error {
  constructor(status, code, tempKey) {
    super(code)
    this.status = status
    this.code = code
    this.tempKey = tempKey
  }
}
