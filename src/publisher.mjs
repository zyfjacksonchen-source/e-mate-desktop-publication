import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from 'node:crypto'

export const EXPECTED_REPOSITORY = 'zyfjacksonchen-source/e-Mate-2.0.11'
export const EXPECTED_ACTION_REPOSITORY = 'zyfjacksonchen-source/e-mate-desktop-publication'
export const PUBLIC_ORIGIN = 'https://pub-ada3f610c0234a76838f4e19fe2bb25e.r2.dev'
export const EXPECTED_R2_BUCKET = 'emate-desktop-downloads'
export const RELEASE_VERSION = '2.0.13'
export const RELEASE_SIGNATURE_CONTEXT = Buffer.from('e-mate-desktop-release-manifest-v1\0', 'utf8')
export const PERFORMANCE_SIGNATURE_CONTEXT = Buffer.from('e-mate-performance-admission-v1\0', 'utf8')
export const PERFORMANCE_EVIDENCE_FILENAME = 'e-mate-performance-evidence.json'
export const PERFORMANCE_VERIFIER_SOURCE = 'scripts/performance-parity.mjs'
export const PROFILE_COMPONENT_AGGREGATE_FILENAME = 'profile-component-aggregate.json'
export const MAX_PERFORMANCE_FILE_BYTES = 64 * 1024 * 1024
const PROFILE_AGGREGATE_CONTEXT = Buffer.from('e-mate-profile-aggregate-v1\0', 'utf8')
export const DESKTOP_RELEASE_ARTIFACT_NAMES = Object.freeze({
  candidate: 'desktop-candidate.json',
  darwin: `e-Mate-${RELEASE_VERSION}-mac-universal.dmg`,
  win32: `e-Mate-${RELEASE_VERSION}-win-x64-Setup.exe`,
})
export const DESKTOP_RELEASE_ARTIFACT_FILES = Object.freeze(Object.values(DESKTOP_RELEASE_ARTIFACT_NAMES))
export const LEGACY_TOMBSTONE = Object.freeze({
  key: 'desktop/latest.json',
  bytes: 948,
  sha256: 'e6d5e045364bdac97ea7fef41b1e28a20af06c9f4ffdd85d2c136e982d12a7dc',
  version: '2.0.12',
  sourceCommit: '9fbc70ad56c4f263dfa0aa0085f19eded134e32d',
  buildRunId: '32658103294',
  artifacts: Object.freeze({
    darwin: Object.freeze({
      bytes: 390527181,
      sha256: 'd2cb459d2e8648213e0b38aa6e210c1a727937be77993b2493e2a7848d5d3b2e',
    }),
    win32: Object.freeze({
      bytes: 272939381,
      sha256: '52b84e14cce5ad49ada282b9a41913aa751db43765c8dba44088d66148dcd186',
    }),
  }),
})

const SHA256 = /^[0-9a-f]{64}$/u
const SHA40 = /^[0-9a-f]{40}$/u
const RUN_ID = /^[1-9][0-9]*$/u
const BASE_ID = /^e-mate-desktop-profile-v[1-9][0-9]*-dsh-[0-9a-f]{12}$/u
const KEY_ID = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/u
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u
const BASE_RUNTIME_PACKAGE = /^(?:@deepseek-ai\/[a-z0-9][a-z0-9._-]*|@e-mate\/desktop\/vision-toolkit|react(?:-dom)?)$/u
const TARGETS = ['darwin-arm64', 'darwin-x64', 'win32-x64']
const MAX_JSON_BYTES = 64 * 1024
const IMMUTABLE_CACHE = 'public,max-age=31536000,immutable'
const JSON_CONTENT_TYPE = 'application/json'
const BINARY_CONTENT_TYPE = 'application/octet-stream'
const PERFORMANCE_PATHS = ['baseline', 'emate_online', 'emate_enterprise_unavailable_valid_cache']
const PERFORMANCE_ARTIFACT_FIELDS = [
  ['raw_samples_artifact', 'raw-samples'],
  ['native_trace_artifact', 'native-session-trace'],
  ['provider_receipt_artifact', 'provider-invocation-receipt'],
  ['request_header_artifact', 'request-headers'],
  ['renderer_paint_artifact', 'renderer-paint-trace'],
  ['installed_runtime_artifact', 'installed-runtime-receipt'],
]

export async function createPerformanceAdmission(config, dependencies) {
  validatePerformanceInvocation(config)
  const { github, verifyPerformance } = dependencies

  await validateProtectedMain(github, config)
  await validateRun(github, config.mainCiRunId, {
    path: '.github/workflows/ci.yml',
    event: 'push',
    sourceCommit: config.sourceCommit,
    jobs: ['CI admission'],
  })

  const desktopArtifact = await github.getArtifact(config.desktopArtifactId)
  assertArtifactMetadata(desktopArtifact, {
    id: config.desktopArtifactId,
    name: `e-mate-desktop-release-${config.sourceCommit}`,
  })
  const desktopBundle = await github.downloadArtifact(config.desktopArtifactId)
  assertDownloadedArtifact(desktopBundle, desktopArtifact)
  assertNoMacSmoke(desktopBundle.files)
  const artifactNames = DESKTOP_RELEASE_ARTIFACT_NAMES
  assertExactFileSet(desktopBundle.files, DESKTOP_RELEASE_ARTIFACT_FILES)
  const candidate = parsePrettyJson(
    await readSmall(requiredFile(desktopBundle.files, artifactNames.candidate)),
    'Desktop artifact candidate',
  )
  const baseBytes = await github.getFile('desktop/e-mate-desktop/base-contract.json', config.sourceCommit)
  if (!Buffer.isBuffer(baseBytes)) throw new Error('Desktop Base contract source is invalid')
  const base = parseJson(baseBytes, 'Desktop Base contract')
  validatePerformanceCandidate(candidate, config.sourceCommit, base)
  validateBaseAndSigningKey(base, {
    baseContractId: base.id,
    scheduleProtocolFloor: candidate.schedule_protocol_floor,
    signatureKeyId: config.signingKeyId,
  }, config)

  if (String(candidate.artifacts.darwin.build_run_id) !== String(desktopArtifact.runId)) {
    throw new Error('macOS installer build run is not the exact candidate run')
  }
  const reusedWindowsRunId = String(candidate.artifacts.win32.build_run_id) === String(desktopArtifact.runId)
    ? undefined
    : String(candidate.artifacts.win32.build_run_id)
  await validateRun(github, desktopArtifact.runId, {
    path: '.github/workflows/desktop-release.yml',
    event: 'workflow_dispatch',
    sourceCommit: config.sourceCommit,
    jobs: reusedWindowsRunId === undefined
      ? [
          'Build and verify the e-Mate profile',
          'Build unsigned Windows x64 installer',
          'Build unsigned macOS universal disk image',
          'Bind native artifacts to the release manifest',
        ]
      : [
          'Validate reusable profile and Windows artifacts',
          'Build unsigned macOS universal disk image',
          'Bind native artifacts to the release manifest',
        ],
  })
  if (reusedWindowsRunId !== undefined) {
    await validateRun(github, reusedWindowsRunId, {
      path: '.github/workflows/desktop-release.yml',
      event: 'workflow_dispatch',
      sourceCommit: config.sourceCommit,
      requireSuccessfulRun: false,
      jobs: ['Build and verify the e-Mate profile', 'Build unsigned Windows x64 installer'],
    })
  }

  for (const platform of ['darwin', 'win32']) {
    const source = requiredFile(desktopBundle.files, artifactNames[platform])
    const expected = candidate.artifacts[platform]
    if (source.bytes !== expected.bytes || await source.digest() !== expected.sha256) {
      throw new Error(`GitHub ${platform} installer bytes do not match the performance candidate`)
    }
  }

  const profileReleaseArtifact = await github.getArtifact(config.profileReleaseArtifactId)
  assertArtifactMetadata(profileReleaseArtifact, {
    id: config.profileReleaseArtifactId,
    name: `e-mate-profile-native-cloudflare-publication-${config.sourceCommit}`,
    runId: config.profileReleaseRunId,
  })
  await validateRun(github, config.profileReleaseRunId, {
    path: '.github/workflows/profile-release.yml',
    event: 'workflow_dispatch',
    sourceCommit: config.sourceCommit,
    jobs: ['Prepare signed native Cloudflare publication bundle'],
  })

  const evidenceArtifact = await github.getArtifact(config.evidenceArtifactId)
  assertArtifactMetadata(evidenceArtifact, {
    id: config.evidenceArtifactId,
    name: performanceEvidenceArtifactName(config.sourceCommit, config.currentRunAttempt),
  })
  await validateCurrentPerformanceRun(github, evidenceArtifact.runId, config)
  const evidenceBundle = await github.downloadArtifact(config.evidenceArtifactId)
  assertDownloadedArtifact(evidenceBundle, evidenceArtifact)
  assertNoMacSmoke(evidenceBundle.files)
  const inputEvidenceBytes = await readPerformanceFile(requiredFile(
    evidenceBundle.files,
    PERFORMANCE_EVIDENCE_FILENAME,
  ))
  const inputEvidence = parsePrettyJson(inputEvidenceBytes, 'performance evidence')
  const expectedEvidenceFiles = performanceEvidenceFiles(inputEvidence)
  assertExactFileSet(evidenceBundle.files, [
    PERFORMANCE_VERIFIER_SOURCE,
    PROFILE_COMPONENT_AGGREGATE_FILENAME,
    ...expectedEvidenceFiles,
  ])
  const profileComponentAggregate = parsePrettyJson(
    await readSmall(requiredFile(evidenceBundle.files, PROFILE_COMPONENT_AGGREGATE_FILENAME)),
    'Profile component aggregate',
  )
  if (!profileAggregate(profileComponentAggregate)) throw new Error('Profile component aggregate is invalid')

  const verifierSource = requiredFile(evidenceBundle.files, PERFORMANCE_VERIFIER_SOURCE)
  const verifierBytes = await readPerformanceFile(verifierSource)
  const trustedVerifierBytes = await github.getFile(PERFORMANCE_VERIFIER_SOURCE, config.sourceCommit)
  if (!Buffer.isBuffer(trustedVerifierBytes) || !verifierBytes.equals(trustedVerifierBytes)) {
    throw new Error('performance verifier is not the exact protected-main source file')
  }
  const evidenceBytes = Buffer.from(await verifyPerformance(evidenceBundle))
  if (evidenceBytes.byteLength <= 0 || evidenceBytes.byteLength > MAX_PERFORMANCE_FILE_BYTES) {
    throw new Error('verified performance evidence is empty or oversized')
  }
  const evidence = parsePrettyJson(evidenceBytes, 'verified performance evidence')
  if (canonicalJson(performanceEvidenceFiles(evidence)) !== canonicalJson(expectedEvidenceFiles)) {
    throw new Error('verified performance evidence changed its artifact file set')
  }
  validateVerifiedPerformanceEvidence(
    evidence,
    inputEvidence,
    config.sourceCommit,
    base,
    profileComponentAggregate,
    candidate,
  )

  const verifier = {
    contract: 'ttft-v2',
    source: PERFORMANCE_VERIFIER_SOURCE,
    source_commit: config.sourceCommit,
    source_sha256: sha256(verifierBytes),
    harness_commit: evidence.harness_commit,
    evidence_filename: PERFORMANCE_EVIDENCE_FILENAME,
    decision_sha256: sha256(Buffer.from(`${JSON.stringify(evidence.decision, null, 2)}\n`, 'utf8')),
    gate_status: 'passed',
  }
  const unsigned = {
    schema_version: 1,
    document_type: 'emate.performance-admission',
    status: 'passed',
    performance_run_id: evidence.performance_run_id,
    source_commit: config.sourceCommit,
    base_contract_id: base.id,
    profile_component_aggregate_sha256: profileComponentAggregate.aggregate_sha256,
    desktop_artifacts: Object.fromEntries(['darwin', 'win32'].map(platform => [platform, {
      bytes: candidate.artifacts[platform].bytes,
      sha256: candidate.artifacts[platform].sha256,
    }])),
    evidence_sha256: sha256(evidenceBytes),
    verifier,
  }
  const admission = signPerformanceAdmission(unsigned, config.privateKeyPem, config.signingKeyId)
  const admissionBytes = Buffer.from(`${JSON.stringify(admission, null, 2)}\n`)
  const outputFiles = new Map([
    ['performance-admission.json', bufferSource(admissionBytes)],
    [PERFORMANCE_EVIDENCE_FILENAME, bufferSource(evidenceBytes)],
  ])
  for (const path of expectedEvidenceFiles) {
    if (path !== PERFORMANCE_EVIDENCE_FILENAME) outputFiles.set(path, requiredFile(evidenceBundle.files, path))
  }
  assertExactFileSet(outputFiles, ['performance-admission.json', ...expectedEvidenceFiles])
  return {
    artifactName: performanceAdmissionArtifactName(config.sourceCommit, config.currentRunAttempt),
    files: outputFiles,
    performanceRunId: evidence.performance_run_id,
    admissionSha256: sha256(admissionBytes),
    evidenceSha256: unsigned.evidence_sha256,
  }
}

export async function publishDesktopRelease(config, dependencies) {
  validateInvocation(config)
  const { github, store, publicReader } = dependencies

  await validateProtectedMain(github, config)
  await validateRun(github, config.mainCiRunId, {
    path: '.github/workflows/ci.yml',
    event: 'push',
    sourceCommit: config.sourceCommit,
    jobs: ['CI admission'],
  })

  const admissionArtifact = await github.getArtifact(config.admissionArtifactId)
  assertArtifactMetadata(admissionArtifact, {
    id: config.admissionArtifactId,
    name: `e-mate-desktop-admission-${config.sourceCommit}`,
  })
  await validateRun(github, admissionArtifact.runId, {
    path: '.github/workflows/desktop-admission.yml',
    event: 'workflow_dispatch',
    sourceCommit: config.sourceCommit,
    jobs: ['Desktop release admission'],
  })
  const admissionBundle = await github.downloadArtifact(config.admissionArtifactId)
  assertDownloadedArtifact(admissionBundle, admissionArtifact)
  assertNoMacSmoke(admissionBundle.files)
  assertExactFileSet(admissionBundle.files, ['base-contract.json', 'desktop-release-unsigned.json'])

  const unsignedSource = requiredFile(admissionBundle.files, 'desktop-release-unsigned.json')
  const baseSource = requiredFile(admissionBundle.files, 'base-contract.json')
  const unsignedBytes = await readSmall(unsignedSource)
  const baseBytes = await readSmall(baseSource)
  const unsigned = parsePrettyJson(unsignedBytes, 'unsigned Desktop manifest')
  const base = parseJson(baseBytes, 'Desktop Base contract')
  validateUnsignedManifest(unsigned, config.sourceCommit)
  const signing = validateBaseAndSigningKey(base, {
    baseContractId: unsigned.base_contract_id,
    scheduleProtocolFloor: unsigned.schedule_protocol_floor,
    signatureKeyId: unsigned.performance.signature_key_id,
  }, config)

  const provenance = unsigned.github_artifact_provenance
  const [candidateReference, performanceReference] = provenance.artifacts
  if (unsigned.artifacts.darwin.build_run_id !== candidateReference.run_id) {
    throw new Error('macOS installer build run is not the exact candidate run')
  }
  const reusedWindowsRunId = unsigned.artifacts.win32.build_run_id === candidateReference.run_id
    ? undefined
    : unsigned.artifacts.win32.build_run_id
  const candidateArtifact = await validateProvenanceArtifact(github, candidateReference, {
    path: '.github/workflows/desktop-release.yml',
    event: 'workflow_dispatch',
    sourceCommit: config.sourceCommit,
    jobs: reusedWindowsRunId === undefined
      ? [
          'Build and verify the e-Mate profile',
          'Build unsigned Windows x64 installer',
          'Build unsigned macOS universal disk image',
          'Bind native artifacts to the release manifest',
        ]
      : [
          'Validate reusable profile and Windows artifacts',
          'Build unsigned macOS universal disk image',
          'Bind native artifacts to the release manifest',
        ],
  })
  if (reusedWindowsRunId !== undefined) {
    await validateRun(github, reusedWindowsRunId, {
      path: '.github/workflows/desktop-release.yml',
      event: 'workflow_dispatch',
      sourceCommit: config.sourceCommit,
      requireSuccessfulRun: false,
      jobs: [
        'Build and verify the e-Mate profile',
        'Build unsigned Windows x64 installer',
      ],
    })
  }
  const performanceArtifact = await validateProvenanceArtifact(github, performanceReference, {
    path: '.github/workflows/desktop-performance.yml',
    event: 'workflow_dispatch',
    sourceCommit: config.sourceCommit,
    jobs: ['Performance admission'],
  })

  const candidateBundle = await github.downloadArtifact(candidateReference.artifact_id)
  assertDownloadedArtifact(candidateBundle, candidateArtifact)
  assertNoMacSmoke(candidateBundle.files)
  const artifactNames = DESKTOP_RELEASE_ARTIFACT_NAMES
  assertExactFileSet(candidateBundle.files, DESKTOP_RELEASE_ARTIFACT_FILES)
  const candidate = parsePrettyJson(
    await readSmall(requiredFile(candidateBundle.files, artifactNames.candidate)),
    'Desktop artifact candidate',
  )
  validateCandidate(candidate, unsigned)

  const installerSources = {}
  for (const platform of ['darwin', 'win32']) {
    const source = requiredFile(candidateBundle.files, artifactNames[platform])
    const expected = unsigned.artifacts[platform]
    if (source.bytes !== expected.bytes || await source.digest() !== expected.sha256) {
      throw new Error(`GitHub ${platform} installer bytes do not match the admitted manifest`)
    }
    installerSources[platform] = source
  }

  const performanceBundle = await github.downloadArtifact(performanceReference.artifact_id)
  assertDownloadedArtifact(performanceBundle, performanceArtifact)
  assertNoMacSmoke(performanceBundle.files)
  const evidenceSource = requiredFile(performanceBundle.files, PERFORMANCE_EVIDENCE_FILENAME)
  const evidenceBytes = await readPerformanceFile(evidenceSource)
  const evidence = parsePrettyJson(evidenceBytes, 'performance evidence')
  assertExactFileSet(performanceBundle.files, [
    'performance-admission.json',
    ...performanceEvidenceFiles(evidence),
  ])
  const performanceAdmissionSource = requiredFile(performanceBundle.files, 'performance-admission.json')
  const performanceAdmissionBytes = await readSmall(performanceAdmissionSource)
  const performanceAdmission = parsePrettyJson(performanceAdmissionBytes, 'performance admission')
  validatePerformanceAdmission(
    performanceAdmission,
    performanceAdmissionBytes,
    unsigned,
    signing.publicKey,
    config.signingKeyId,
  )
  validateAdmittedPerformanceEvidence(evidence, evidenceBytes, performanceAdmission)

  const signatureValue = sign(
    null,
    Buffer.concat([RELEASE_SIGNATURE_CONTEXT, Buffer.from(canonicalJson(unsigned), 'utf8')]),
    signing.privateKey,
  ).toString('base64')
  const signedManifest = {
    ...unsigned,
    signature: {
      algorithm: 'ed25519',
      key_id: config.signingKeyId,
      value: signatureValue,
    },
  }
  const signedBytes = Buffer.from(`${JSON.stringify(signedManifest, null, 2)}\n`)
  const signedSource = bufferSource(signedBytes)
  const signedIdentity = sha256(Buffer.from(canonicalJson(signedManifest), 'utf8'))
  const signedRawSha256 = sha256(signedBytes)

  const objects = [
    ...['darwin', 'win32'].map(platform => ({
      role: `installer-${platform}`,
      key: keyFromReleaseUrl(unsigned.artifacts[platform].url),
      source: installerSources[platform],
      contentType: BINARY_CONTENT_TYPE,
      cacheControl: IMMUTABLE_CACHE,
    })),
    {
      role: 'manual-manifest',
      key: `desktop/manual/v${RELEASE_VERSION}/latest.json`,
      source: signedSource,
      contentType: JSON_CONTENT_TYPE,
      cacheControl: IMMUTABLE_CACHE,
    },
  ]
  const pointer = {
    role: 'active-pointer',
    key: 'desktop/signed/latest.json',
    source: signedSource,
    contentType: JSON_CONTENT_TYPE,
    cacheControl: 'no-store',
  }

  // Everything below this line is publication state. Complete every validation first.
  await assertLegacyTombstone(store, publicReader)
  const preflight = new Map()
  for (const object of objects) {
    preflight.set(object.key, await preflightCreateOnlyObject(store, publicReader, object))
  }
  const expectedPointer = config.expectedSignedCurrent
  const pointerBefore = await preflightPointer(store, publicReader, pointer, expectedPointer)

  const published = []
  for (const object of objects.slice(0, 2)) {
    published.push(await ensureCreateOnly(store, object, preflight.get(object.key)))
  }
  const manual = objects[2]
  published.push(await ensureCreateOnly(store, manual, preflight.get(manual.key)))

  for (const object of objects) {
    await assertExactObject(store, object, { requireBody: object.role === 'manual-manifest' })
    await assertExactObject(publicReader, object, { requireBody: object.role === 'manual-manifest' })
  }
  await assertLegacyTombstone(store, publicReader)
  await recheckPointer(store, publicReader, pointerBefore, pointer, expectedPointer)

  let pointerOperation = 'reused'
  if (!pointerBefore.sameCandidate) {
    await store.putCas(pointer.key, pointer.source, {
      expectedEtag: pointerBefore.auth.exists ? pointerBefore.auth.etag : null,
      contentType: pointer.contentType,
      cacheControl: pointer.cacheControl,
    })
    pointerOperation = 'activated'
  }
  await assertExactObject(store, pointer, { requireBody: true })
  await assertExactObject(publicReader, pointer, { requireBody: true })
  await assertLegacyTombstone(store, publicReader)

  return {
    schema_version: 1,
    document_type: 'emate.desktop-publication-receipt',
    status: pointerOperation === 'activated' ? 'published' : 'already-published',
    repository: config.repository,
    source_commit: config.sourceCommit,
    action: {
      repository: config.actionRepository,
      commit: config.actionRef,
    },
    github: {
      main_ci_run_id: config.mainCiRunId,
      admission_artifact_id: config.admissionArtifactId,
      desktop_artifact_id: candidateReference.artifact_id,
      performance_artifact_id: performanceReference.artifact_id,
    },
    manifest: {
      version: RELEASE_VERSION,
      base_contract_id: unsigned.base_contract_id,
      schedule_protocol_floor: unsigned.schedule_protocol_floor,
      identity_sha256: signedIdentity,
      raw_bytes: signedBytes.byteLength,
      raw_sha256: signedRawSha256,
      signature_key_id: config.signingKeyId,
    },
    legacy_tombstone: {
      key: LEGACY_TOMBSTONE.key,
      bytes: LEGACY_TOMBSTONE.bytes,
      sha256: LEGACY_TOMBSTONE.sha256,
    },
    immutable_objects: published,
    active_pointer: {
      key: pointer.key,
      operation: pointerOperation,
      previous: expectedPointer === null ? null : expectedPointer,
      bytes: signedBytes.byteLength,
      sha256: signedRawSha256,
    },
  }
}

function validateInvocation(config) {
  if (process.versions.node.split('.')[0] !== '24') throw new Error('publication requires Node 24')
  if (config.repository !== EXPECTED_REPOSITORY) throw new Error('unexpected caller repository')
  if (config.actionRepository !== EXPECTED_ACTION_REPOSITORY || !SHA40.test(config.actionRef)) {
    throw new Error('external action must be referenced by an exact reviewed commit')
  }
  if (config.ref !== 'refs/heads/main' || config.refProtected !== true || config.eventName !== 'workflow_dispatch') {
    throw new Error('publication must run from a protected main workflow_dispatch')
  }
  if (!SHA40.test(config.sourceCommit) || config.githubSha !== config.sourceCommit) {
    throw new Error('caller source commit is invalid or does not match GITHUB_SHA')
  }
  if (!RUN_ID.test(config.mainCiRunId) || !RUN_ID.test(config.admissionArtifactId)) {
    throw new Error('GitHub admission identity is invalid')
  }
  if (typeof config.signingKeyId !== 'string' || config.signingKeyId === '') {
    throw new Error('Desktop signing key id is missing')
  }
  if (config.expectedSignedCurrent !== null && (!Number.isSafeInteger(config.expectedSignedCurrent.bytes)
    || config.expectedSignedCurrent.bytes <= 0 || !SHA256.test(config.expectedSignedCurrent.sha256))) {
    throw new Error('expected signed pointer identity is invalid')
  }
}

function validatePerformanceInvocation(config) {
  if (process.versions.node.split('.')[0] !== '24') throw new Error('performance admission requires Node 24')
  if (config.repository !== EXPECTED_REPOSITORY) throw new Error('unexpected caller repository')
  if (config.actionRepository !== EXPECTED_ACTION_REPOSITORY || !SHA40.test(config.actionRef)) {
    throw new Error('external action must be referenced by an exact reviewed commit')
  }
  if (config.ref !== 'refs/heads/main' || config.refProtected !== true || config.eventName !== 'workflow_dispatch') {
    throw new Error('performance admission must run from a protected main workflow_dispatch')
  }
  if (!SHA40.test(config.sourceCommit) || config.githubSha !== config.sourceCommit) {
    throw new Error('caller source commit is invalid or does not match GITHUB_SHA')
  }
  if (![config.mainCiRunId, config.currentRunId, config.currentRunAttempt, config.desktopArtifactId,
    config.profileReleaseRunId, config.profileReleaseArtifactId, config.evidenceArtifactId]
    .every(value => RUN_ID.test(value ?? ''))) {
    throw new Error('performance admission GitHub identity is invalid')
  }
  if (typeof config.signingKeyId !== 'string' || config.signingKeyId === '') {
    throw new Error('Desktop signing key id is missing')
  }
}

async function validateProtectedMain(github, config) {
  const repository = await github.getRepository()
  if (repository.fullName !== EXPECTED_REPOSITORY || repository.visibility !== 'public'
    || repository.defaultBranch !== 'main' || repository.archived !== false || repository.disabled !== false) {
    throw new Error('production repository authority drifted')
  }
  const current = await github.getBranchHead('main')
  if (current !== config.sourceCommit) throw new Error('main no longer points to the admitted source commit')
  const protection = await github.getBranchProtection('main')
  if (protection?.requiredStatusChecks?.strict !== true
    || !protection.requiredStatusChecks.contexts.includes('CI admission')
    || protection.enforceAdmins !== true || protection.requiredLinearHistory !== true
    || protection.allowForcePushes !== false || protection.allowDeletions !== false) {
    throw new Error('main is not protected by strict CI admission for administrators')
  }
}

async function validateRun(github, runId, expected) {
  if (!RUN_ID.test(String(runId))) throw new Error('GitHub run id is invalid')
  const run = await github.getRun(String(runId))
  if (String(run.id) !== String(runId) || run.status !== 'completed'
    || expected.requireSuccessfulRun !== false && run.conclusion !== 'success'
    || run.headSha !== expected.sourceCommit || run.headBranch !== 'main'
    || run.path !== expected.path || run.event !== expected.event
    || run.runAttempt !== 1) {
    throw new Error(`GitHub run ${runId} is not the exact successful protected-main ${expected.path} run`)
  }
  const jobs = await github.getRunJobs(String(runId))
  for (const name of expected.jobs) {
    if (!jobs.some(job => job.name === name && job.status === 'completed' && job.conclusion === 'success')) {
      throw new Error(`GitHub run ${runId} is missing successful job ${name}`)
    }
  }
  return run
}

async function validateCurrentPerformanceRun(github, runId, config) {
  if (String(runId) !== config.currentRunId) {
    throw new Error('performance evidence artifact is not from the current workflow run')
  }
  const run = await github.getRun(config.currentRunId)
  if (config.currentRunAttempt !== '1' || String(run.id) !== config.currentRunId
    || run.status !== 'in_progress' || run.conclusion !== null
    || run.headSha !== config.sourceCommit || run.headBranch !== 'main'
    || run.path !== '.github/workflows/desktop-performance.yml' || run.event !== 'workflow_dispatch'
    || run.runAttempt !== 1) {
    throw new Error('performance evidence artifact is not from the exact current protected-main run attempt')
  }
  const jobs = await github.getRunJobs(config.currentRunId)
  if (!jobs.some(job => job.name === 'TTFT evidence'
    && job.status === 'completed' && job.conclusion === 'success')) {
    throw new Error('current performance run is missing successful TTFT evidence')
  }
  return run
}

async function validateProvenanceArtifact(github, reference, runExpected) {
  const artifact = await github.getArtifact(reference.artifact_id)
  assertArtifactMetadata(artifact, {
    id: reference.artifact_id,
    name: reference.name,
    digest: reference.digest,
    runId: reference.run_id,
  })
  const run = await validateRun(github, reference.run_id, runExpected)
  if (run.runAttempt !== reference.run_attempt) throw new Error('GitHub artifact run attempt drifted')
  return artifact
}

function assertArtifactMetadata(actual, expected) {
  if (String(actual?.id) !== String(expected.id) || actual.name !== expected.name
    || actual.expired !== false || !/^sha256:[0-9a-f]{64}$/u.test(actual.digest ?? '')
    || expected.digest !== undefined && actual.digest !== expected.digest
    || expected.runId !== undefined && String(actual.runId) !== String(expected.runId)) {
    throw new Error(`GitHub artifact ${expected.id} provenance is invalid`)
  }
}

function assertDownloadedArtifact(bundle, metadata) {
  if (bundle.archiveSha256 !== metadata.digest.slice('sha256:'.length)) {
    throw new Error(`downloaded GitHub artifact ${metadata.id} digest drifted`)
  }
}

function validateUnsignedManifest(value, sourceCommit) {
  const keys = [
    'schema_version', 'document_type', 'release_status', 'version', 'source_commit',
    'base_contract_id', 'schedule_protocol_floor', 'profile_component_aggregate',
    'performance', 'github_artifact_provenance', 'artifacts',
  ]
  if (!hasExactKeys(value, keys) || value.schema_version !== 1
    || value.document_type !== 'emate.desktop-release-manifest' || value.release_status !== 'admitted'
    || value.version !== RELEASE_VERSION || value.source_commit !== sourceCommit
    || !BASE_ID.test(value.base_contract_id) || !positiveInteger(value.schedule_protocol_floor)
    || !profileAggregate(value.profile_component_aggregate)
    || !performanceSummary(value.performance)
    || !githubProvenance(value.github_artifact_provenance, sourceCommit)
    || !hasExactKeys(value.artifacts, ['darwin', 'win32'])) {
    throw new Error('unsigned Desktop manifest is not the exact admitted 11-field schema')
  }
  for (const platform of ['darwin', 'win32']) validateArtifactRecord(platform, value.artifacts[platform], value)
  canonicalJson(value)
}

function validateArtifactRecord(platform, record, manifest) {
  if (!hasExactKeys(record, ['url', 'bytes', 'sha256', 'build_source_commit', 'build_run_id'])
    || !positiveInteger(record.bytes) || !SHA256.test(record.sha256 ?? '')
    || record.build_source_commit !== manifest.source_commit || !RUN_ID.test(record.build_run_id ?? '')) {
    throw new Error(`unsigned ${platform} artifact record is invalid`)
  }
  const expectedName = platform === 'darwin'
    ? `e-Mate-${RELEASE_VERSION}-mac-universal.dmg`
    : `e-Mate-${RELEASE_VERSION}-win-x64-Setup.exe`
  const expected = `${PUBLIC_ORIGIN}/desktop/releases/v${RELEASE_VERSION}/${manifest.source_commit}/${expectedName}`
  if (record.url !== expected) throw new Error(`unsigned ${platform} artifact URL is not immutable`)
}

function validateCandidate(candidate, manifest) {
  if (!hasExactKeys(candidate, [
    'schema_version', 'document_type', 'release_status', 'version', 'source_commit',
    'schedule_protocol_floor', 'artifacts',
  ]) || candidate.schema_version !== 1 || candidate.document_type !== 'emate.desktop-artifact-candidate'
    || candidate.release_status !== 'performance-pending' || candidate.version !== RELEASE_VERSION
    || candidate.source_commit !== manifest.source_commit
    || candidate.schedule_protocol_floor !== manifest.schedule_protocol_floor
    || canonicalJson(candidate.artifacts) !== canonicalJson(manifest.artifacts)) {
    throw new Error('performance-pending candidate does not match the admitted manifest')
  }
}

function validatePerformanceCandidate(candidate, sourceCommit, base) {
  if (!hasExactKeys(candidate, [
    'schema_version', 'document_type', 'release_status', 'version', 'source_commit',
    'schedule_protocol_floor', 'artifacts',
  ]) || candidate.schema_version !== 1 || candidate.document_type !== 'emate.desktop-artifact-candidate'
    || candidate.release_status !== 'performance-pending' || candidate.version !== RELEASE_VERSION
    || candidate.source_commit !== sourceCommit || !positiveInteger(candidate.schedule_protocol_floor)
    || candidate.schedule_protocol_floor !== base.schedule_protocol_floor
    || !hasExactKeys(candidate.artifacts, ['darwin', 'win32'])) {
    throw new Error('performance-pending candidate identity is invalid')
  }
  for (const platform of ['darwin', 'win32']) validateArtifactRecord(platform, candidate.artifacts[platform], candidate)
}

function validateBaseAndSigningKey(base, expected, config) {
  if (!hasExactKeys(base, [
    'schema_version', 'id', 'desktop_api', 'profile_format', 'desktop_reference',
    'schedule_protocol_floor', 'harness_version', 'harness_commit', 'runtime_imports', 'profile_signing_keys',
  ]) || base.schema_version !== 1 || base.id !== expected.baseContractId
    || !BASE_ID.test(base.id) || !positiveInteger(base.desktop_api) || !positiveInteger(base.profile_format)
    || base.schedule_protocol_floor !== expected.scheduleProtocolFloor
    || typeof base.harness_version !== 'string' || !VERSION.test(base.harness_version)
    || !SHA40.test(base.harness_commit ?? '')
    || !hasExactKeys(base.desktop_reference, [
      'repository', 'commit', 'harness_repository', 'harness_commit', 'harness_version',
    ]) || typeof base.desktop_reference.repository !== 'string' || base.desktop_reference.repository === ''
    || !SHA40.test(base.desktop_reference.commit ?? '')
    || typeof base.desktop_reference.harness_repository !== 'string'
    || base.desktop_reference.harness_repository === ''
    || !SHA40.test(base.desktop_reference.harness_commit ?? '')
    || typeof base.desktop_reference.harness_version !== 'string'
    || !VERSION.test(base.desktop_reference.harness_version)
    || !isRecord(base.runtime_imports) || !Array.isArray(base.profile_signing_keys)
    || base.profile_signing_keys.length === 0) {
    throw new Error('Desktop Base contract does not bind the unsigned manifest')
  }
  const runtimeImports = Object.entries(base.runtime_imports)
  if (runtimeImports.some(([name, version]) => !BASE_RUNTIME_PACKAGE.test(name)
    || typeof version !== 'string' || !VERSION.test(version))
    || runtimeImports.some(([name], index) => index > 0 && runtimeImports[index - 1][0] >= name)
    || base.profile_signing_keys.some((key, index, keys) => !hasExactKeys(key, [
      'id', 'algorithm', 'public_key_spki_der_base64',
    ]) || !KEY_ID.test(key.id ?? '') || key.algorithm !== 'ed25519'
      || strictBase64(key.public_key_spki_der_base64) === undefined
      || index > 0 && keys[index - 1].id >= key.id)) {
    throw new Error('Desktop Base contract trust surface is invalid')
  }
  try {
    if (base.profile_signing_keys.some(key => createPublicKey({
      key: strictBase64(key.public_key_spki_der_base64), format: 'der', type: 'spki',
    }).asymmetricKeyType !== 'ed25519')) throw new Error()
  } catch {
    throw new Error('Desktop Base contract trust surface is invalid')
  }
  if (new Set(base.profile_signing_keys.map(key => key.id)).size !== base.profile_signing_keys.length) {
    throw new Error('Desktop Base contract trust surface is invalid')
  }
  let privateKey
  let publicDer
  try {
    privateKey = createPrivateKey(config.privateKeyPem)
    publicDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
  } catch {
    throw new Error('Desktop Ed25519 private key is invalid')
  }
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('Desktop signing key is not Ed25519')
  const trusted = base.profile_signing_keys.find(key => key?.id === config.signingKeyId)
  const trustedDer = strictBase64(trusted?.public_key_spki_der_base64)
  if (!hasExactKeys(trusted, ['id', 'algorithm', 'public_key_spki_der_base64'])
    || trusted.algorithm !== 'ed25519' || trustedDer === undefined
    || !publicDer.equals(trustedDer) || expected.signatureKeyId !== config.signingKeyId) {
    throw new Error('Desktop signing key is not the exact Base trust key')
  }
  return { privateKey, publicKey: createPublicKey(privateKey) }
}

function validatePerformanceAdmission(admission, rawBytes, manifest, publicKey, keyId) {
  const keys = [
    'schema_version', 'document_type', 'status', 'performance_run_id', 'source_commit',
    'base_contract_id', 'profile_component_aggregate_sha256', 'desktop_artifacts',
    'evidence_sha256', 'verifier', 'signature',
  ]
  if (!hasExactKeys(admission, keys) || admission.schema_version !== 1
    || admission.document_type !== 'emate.performance-admission' || admission.status !== 'passed'
    || admission.performance_run_id !== manifest.performance.performance_run_id
    || admission.source_commit !== manifest.source_commit || admission.base_contract_id !== manifest.base_contract_id
    || admission.profile_component_aggregate_sha256 !== manifest.profile_component_aggregate.aggregate_sha256
    || !SHA256.test(admission.evidence_sha256 ?? '')
    || !performanceVerifier(admission.verifier, admission.source_commit)
    || canonicalJson(admission.verifier) !== canonicalJson(manifest.performance.verifier)
    || !hasExactKeys(admission.desktop_artifacts, ['darwin', 'win32'])
    || sha256(rawBytes) !== manifest.performance.admission_sha256
    || !hasExactKeys(admission.signature, ['algorithm', 'key_id', 'value'])
    || admission.signature.algorithm !== 'ed25519' || admission.signature.key_id !== keyId
    || admission.signature.key_id !== manifest.performance.signature_key_id) {
    throw new Error('signed performance admission does not bind the Desktop release')
  }
  for (const platform of ['darwin', 'win32']) {
    const item = admission.desktop_artifacts[platform]
    const expected = manifest.artifacts[platform]
    if (!hasExactKeys(item, ['bytes', 'sha256']) || item.bytes !== expected.bytes || item.sha256 !== expected.sha256) {
      throw new Error(`performance admission ${platform} artifact drifted`)
    }
  }
  const signatureBytes = strictBase64(admission.signature.value)
  const { signature, ...unsigned } = admission
  if (signatureBytes?.byteLength !== 64 || !verify(
    null,
    Buffer.concat([PERFORMANCE_SIGNATURE_CONTEXT, Buffer.from(canonicalJson(unsigned), 'utf8')]),
    publicKey,
    signatureBytes,
  )) throw new Error('performance admission signature is invalid')
}

function profileAggregate(value) {
  if (!hasExactKeys(value, ['aggregate_sha256', 'inventory_sha256', 'staged_profile_tree_sha256', 'targets'])
    || !SHA256.test(value.aggregate_sha256 ?? '') || !SHA256.test(value.inventory_sha256 ?? '')
    || !SHA256.test(value.staged_profile_tree_sha256 ?? '') || !Array.isArray(value.targets)
    || value.targets.length !== TARGETS.length
    || !value.targets.every((target, index) => hasExactKeys(target, [
      'target', 'profile_generation', 'component_aggregate_sha256',
    ]) && target.target === TARGETS[index] && SHA256.test(target.profile_generation ?? '')
      && SHA256.test(target.component_aggregate_sha256 ?? ''))) return false
  const { aggregate_sha256: digest, ...unsigned } = value
  return digest === sha256(Buffer.concat([
    PROFILE_AGGREGATE_CONTEXT,
    Buffer.from(canonicalJson(unsigned), 'utf8'),
  ]))
}

function performanceSummary(value) {
  return hasExactKeys(value, ['performance_run_id', 'admission_sha256', 'signature_key_id', 'verifier'])
    && typeof value.performance_run_id === 'string' && value.performance_run_id.length >= 16
    && SHA256.test(value.admission_sha256 ?? '') && typeof value.signature_key_id === 'string'
    && value.signature_key_id.length > 0 && performanceVerifier(value.verifier)
}

function performanceVerifier(value, sourceCommit) {
  return hasExactKeys(value, [
    'contract', 'source', 'source_commit', 'source_sha256', 'harness_commit',
    'evidence_filename', 'decision_sha256', 'gate_status',
  ]) && value.contract === 'ttft-v2' && value.source === PERFORMANCE_VERIFIER_SOURCE
    && (sourceCommit === undefined ? SHA40.test(value.source_commit ?? '') : value.source_commit === sourceCommit)
    && SHA256.test(value.source_sha256 ?? '') && SHA40.test(value.harness_commit ?? '')
    && value.evidence_filename === PERFORMANCE_EVIDENCE_FILENAME
    && SHA256.test(value.decision_sha256 ?? '') && value.gate_status === 'passed'
}

function performanceEvidenceFiles(evidence) {
  if (!isRecord(evidence.paths) || !hasExactKeys(evidence.paths, PERFORMANCE_PATHS)) {
    throw new Error('performance evidence path set is invalid')
  }
  const files = [PERFORMANCE_EVIDENCE_FILENAME]
  const seen = new Set(files)
  for (const pathName of PERFORMANCE_PATHS) {
    const receipt = evidence.paths[pathName]?.run_receipt
    if (!isRecord(receipt)) throw new Error(`performance evidence ${pathName} receipt is missing`)
    const fields = pathName === 'baseline'
      ? PERFORMANCE_ARTIFACT_FIELDS
      : [...PERFORMANCE_ARTIFACT_FIELDS, ['enterprise_receipt_artifact', 'enterprise-runtime-receipt']]
    for (const [field, kind] of fields) {
      const descriptor = receipt[field]
      if (!hasExactKeys(descriptor, ['kind', 'path', 'sha256']) || descriptor.kind !== kind
        || !safeArtifactPath(descriptor.path) || !SHA256.test(descriptor.sha256 ?? '')
        || descriptor.path === PERFORMANCE_EVIDENCE_FILENAME
        || descriptor.path === PERFORMANCE_VERIFIER_SOURCE
        || descriptor.path === PROFILE_COMPONENT_AGGREGATE_FILENAME
        || descriptor.path === 'performance-admission.json'
        || seen.has(descriptor.path)) {
        throw new Error(`performance evidence ${field} descriptor is invalid`)
      }
      seen.add(descriptor.path)
      files.push(descriptor.path)
    }
  }
  return files.sort()
}

function safeArtifactPath(value) {
  return typeof value === 'string' && value !== '' && !value.startsWith('/') && !value.endsWith('/')
    && !value.includes('\\') && value.split('/').every(part => part !== '' && part !== '.' && part !== '..')
}

function validateVerifiedPerformanceEvidence(evidence, input, sourceCommit, base, aggregate, candidate) {
  if (evidence.evidence_kind !== 'production-real-provider'
    || evidence.production_artifacts_verified !== true
    || evidence.performance_run_id !== input.performance_run_id
    || typeof evidence.performance_run_id !== 'string' || evidence.performance_run_id.length < 16
    || evidence.harness_commit !== base.harness_commit
    || evidence.decision?.gate_status !== 'passed'
    || !Array.isArray(evidence.decision.failures) || evidence.decision.failures.length !== 0
    || !Array.isArray(evidence.decision.production_receipt_failures)
    || evidence.decision.production_receipt_failures.length !== 0) {
    throw new Error('performance-parity did not produce passed production evidence')
  }
  for (const pathName of PERFORMANCE_PATHS.slice(1)) {
    const receipt = evidence.paths[pathName]?.run_receipt
    const runtime = receipt?.runtime
    const install = receipt?.install_receipt
    const target = aggregate.targets.find(item => item.target === install?.target)
    const platform = install?.target === 'win32-x64' ? 'win32' : 'darwin'
    const artifact = candidate.artifacts[platform]
    if (target === undefined || runtime?.source_commit !== sourceCommit
      || runtime?.base_contract_id !== base.id
      || runtime?.profile_generation !== target.profile_generation
      || runtime?.composition_sha256 !== target.component_aggregate_sha256
      || runtime?.desktop_artifact_sha256 !== artifact.sha256
      || runtime?.desktop_artifact_bytes !== artifact.bytes
      || install?.package_sha256 !== artifact.sha256 || install?.package_bytes !== artifact.bytes) {
      throw new Error(`performance evidence ${pathName} does not bind the admitted Base/Profile/install bytes`)
    }
  }
}

function validateAdmittedPerformanceEvidence(evidence, evidenceBytes, admission) {
  if (sha256(evidenceBytes) !== admission.evidence_sha256
    || evidence.performance_run_id !== admission.performance_run_id
    || evidence.evidence_kind !== 'production-real-provider'
    || evidence.production_artifacts_verified !== true
    || evidence.harness_commit !== admission.verifier.harness_commit
    || evidence.decision?.gate_status !== 'passed'
    || sha256(Buffer.from(`${JSON.stringify(evidence.decision, null, 2)}\n`, 'utf8'))
      !== admission.verifier.decision_sha256) {
    throw new Error('performance evidence does not match the signed admission')
  }
}

function githubProvenance(value, sourceCommit) {
  const roles = ['desktop_candidate', 'performance_admission']
  return hasExactKeys(value, ['schema_version', 'document_type', 'source_commit', 'artifacts'])
    && value.schema_version === 1 && value.document_type === 'emate.github-artifact-provenance'
    && value.source_commit === sourceCommit && Array.isArray(value.artifacts)
    && value.artifacts.length === roles.length
    && value.artifacts.every((artifact, index) => hasExactKeys(artifact, [
      'role', 'name', 'artifact_id', 'digest', 'run_id', 'run_attempt',
    ]) && artifact.role === roles[index]
      && artifact.name === (index === 0
        ? `e-mate-desktop-release-${sourceCommit}`
        : performanceAdmissionArtifactName(sourceCommit, artifact.run_attempt))
      && RUN_ID.test(artifact.artifact_id ?? '') && /^sha256:[0-9a-f]{64}$/u.test(artifact.digest ?? '')
      && RUN_ID.test(artifact.run_id ?? '') && artifact.run_attempt === 1)
}

async function assertLegacyTombstone(store, publicReader) {
  for (const reader of [store, publicReader]) {
    const state = await reader.inspect(LEGACY_TOMBSTONE.key, { collectLimit: MAX_JSON_BYTES })
    if (!state.exists || state.bytes !== LEGACY_TOMBSTONE.bytes || state.sha256 !== LEGACY_TOMBSTONE.sha256
      || state.cacheControl !== 'no-store' || !state.contentType?.startsWith(JSON_CONTENT_TYPE)
      || !Buffer.isBuffer(state.body)) throw new Error('legacy 2.0.12 tombstone identity drifted')
    const value = parseJson(state.body, 'legacy tombstone')
    if (!hasExactKeys(value, ['schema_version', 'version', 'source_commit', 'artifacts'])
      || value.schema_version !== 1 || value.version !== LEGACY_TOMBSTONE.version
      || value.source_commit !== LEGACY_TOMBSTONE.sourceCommit
      || !hasExactKeys(value.artifacts, ['darwin', 'win32'])) {
      throw new Error('legacy 2.0.12 tombstone schema drifted')
    }
    for (const platform of ['darwin', 'win32']) {
      const artifact = value.artifacts[platform]
      const expected = LEGACY_TOMBSTONE.artifacts[platform]
      if (!hasExactKeys(artifact, ['url', 'bytes', 'sha256', 'build_source_commit', 'build_run_id'])
        || artifact.bytes !== expected.bytes || artifact.sha256 !== expected.sha256
        || artifact.build_source_commit !== LEGACY_TOMBSTONE.sourceCommit
        || artifact.build_run_id !== LEGACY_TOMBSTONE.buildRunId) {
        throw new Error(`legacy 2.0.12 ${platform} identity drifted`)
      }
    }
  }
}

async function preflightCreateOnlyObject(store, publicReader, object) {
  const auth = await store.inspect(object.key)
  const publicState = await publicReader.inspect(object.key)
  if (auth.exists !== publicState.exists) throw new Error(`R2/public state split for ${object.key}`)
  if (!auth.exists) return { auth, public: publicState, same: false }
  await assertStateMatches(auth, object)
  await assertStateMatches(publicState, object)
  return { auth, public: publicState, same: true }
}

async function preflightPointer(store, publicReader, pointer, expected) {
  const auth = await store.inspect(pointer.key)
  const publicState = await publicReader.inspect(pointer.key)
  if (auth.exists !== publicState.exists) throw new Error('signed pointer authenticated/public state split')
  if (expected === null) {
    if (auth.exists) throw new Error('signed pointer exists but expected current is absent')
    return { auth, public: publicState, sameCandidate: false }
  }
  if (!auth.exists || auth.bytes !== expected.bytes || auth.sha256 !== expected.sha256
    || publicState.bytes !== expected.bytes || publicState.sha256 !== expected.sha256) {
    throw new Error('signed pointer does not match expected current identity')
  }
  assertPointerMetadata(auth)
  assertPointerMetadata(publicState)
  const sameCandidate = auth.bytes === pointer.source.bytes && auth.sha256 === await pointer.source.digest()
  if (!sameCandidate) throw new Error('2.0.13 publisher cannot replace a different signed pointer')
  return { auth, public: publicState, sameCandidate }
}

async function recheckPointer(store, publicReader, before, pointer, expected) {
  const auth = await store.inspect(pointer.key)
  const publicState = await publicReader.inspect(pointer.key)
  if (before.sameCandidate) {
    await assertStateMatches(auth, pointer)
    await assertStateMatches(publicState, pointer)
    return
  }
  if (expected !== null || auth.exists || publicState.exists) throw new Error('signed pointer changed before CAS activation')
}

async function ensureCreateOnly(store, object, state) {
  let operation = 'reused'
  if (!state.same) {
    await store.putCreateOnly(object.key, object.source, {
      contentType: object.contentType,
      cacheControl: object.cacheControl,
    })
    operation = 'created'
  }
  return {
    role: object.role,
    key: object.key,
    operation,
    bytes: object.source.bytes,
    sha256: await object.source.digest(),
  }
}

async function assertExactObject(reader, object, options = {}) {
  const state = await reader.inspect(object.key, {
    collectLimit: options.requireBody ? MAX_JSON_BYTES : 0,
  })
  await assertStateMatches(state, object)
  if (options.requireBody && (!Buffer.isBuffer(state.body)
    || !state.body.equals(await object.source.read(MAX_JSON_BYTES)))) {
    throw new Error(`R2 object bytes drifted for ${object.key}`)
  }
}

async function assertStateMatches(state, object) {
  if (!state.exists || state.bytes !== object.source.bytes || state.sha256 !== await object.source.digest()
    || state.cacheControl !== object.cacheControl || !state.contentType?.startsWith(object.contentType)) {
    throw new Error(`R2 object identity drifted for ${object.key}`)
  }
}

function assertPointerMetadata(state) {
  if (state.cacheControl !== 'no-store' || !state.contentType?.startsWith(JSON_CONTENT_TYPE)) {
    throw new Error('signed pointer metadata drifted')
  }
}

function keyFromReleaseUrl(value) {
  const url = new URL(value)
  if (url.origin !== PUBLIC_ORIGIN || url.username !== '' || url.password !== ''
    || url.search !== '' || url.hash !== '') throw new Error('release URL escaped the public origin')
  return url.pathname.slice(1)
}

function requiredFile(files, name) {
  const source = files.get(name)
  if (source === undefined) throw new Error(`GitHub artifact is missing ${name}`)
  return source
}

function assertExactFileSet(files, expected) {
  const actual = [...files.keys()].sort()
  const wanted = [...expected].sort()
  if (canonicalJson(actual) !== canonicalJson(wanted)) {
    throw new Error(`GitHub artifact file set drifted: ${actual.join(', ')}`)
  }
}

function assertNoMacSmoke(files) {
  if ([...files.keys()].some(path => /mac-smoke/iu.test(path))) throw new Error('mac-smoke is never publishable')
}

async function readSmall(source) {
  if (source.bytes <= 0 || source.bytes > MAX_JSON_BYTES) throw new Error('release JSON is empty or oversized')
  return source.read(MAX_JSON_BYTES)
}

async function readPerformanceFile(source) {
  if (source.bytes <= 0 || source.bytes > MAX_PERFORMANCE_FILE_BYTES) {
    throw new Error('performance file is empty or oversized')
  }
  return source.read(MAX_PERFORMANCE_FILE_BYTES)
}

function parsePrettyJson(bytes, name) {
  const value = parseJson(bytes, name)
  const normalized = Buffer.from(`${JSON.stringify(value, null, 2)}\n`)
  if (!bytes.equals(normalized)) throw new Error(`${name} is not the exact deterministic JSON artifact`)
  return value
}

function parseJson(bytes, name) {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    const value = JSON.parse(text)
    if (!isRecord(value)) throw new Error()
    return value
  } catch {
    throw new Error(`${name} is invalid JSON`)
  }
}

export function canonicalJson(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new Error('non-canonical number')
    return String(value)
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`
  }
  throw new Error('unsupported canonical JSON value')
}

export function bufferSource(bytes) {
  const buffer = Buffer.from(bytes)
  const digest = sha256(buffer)
  return {
    bytes: buffer.byteLength,
    async digest() { return digest },
    async read(limit = Number.MAX_SAFE_INTEGER) {
      if (buffer.byteLength > limit) throw new Error('source exceeds read limit')
      return Buffer.from(buffer)
    },
    stream() { return Buffer.from(buffer) },
  }
}

export function signPerformanceAdmission(unsigned, privateKeyPem, keyId) {
  const privateKey = createPrivateKey(privateKeyPem)
  const value = sign(
    null,
    Buffer.concat([PERFORMANCE_SIGNATURE_CONTEXT, Buffer.from(canonicalJson(unsigned), 'utf8')]),
    privateKey,
  ).toString('base64')
  return { ...unsigned, signature: { algorithm: 'ed25519', key_id: keyId, value } }
}

export function performanceEvidenceArtifactName(sourceCommit, runAttempt) {
  return performanceArtifactName('evidence', sourceCommit, runAttempt)
}

export function performanceAdmissionArtifactName(sourceCommit, runAttempt) {
  return performanceArtifactName('admission', sourceCommit, runAttempt)
}

function performanceArtifactName(kind, sourceCommit, runAttempt) {
  if (!['evidence', 'admission'].includes(kind) || !SHA40.test(sourceCommit)
    || String(runAttempt) !== '1') throw new Error('performance artifact identity is invalid')
  return `e-mate-performance-${kind}-${sourceCommit}-attempt-${runAttempt}`
}

export function parseExpectedCurrent(value) {
  if (value === 'absent') return null
  const match = /^([1-9][0-9]*):([0-9a-f]{64})$/u.exec(value)
  if (match === null) throw new Error('expected signed current must be absent or <bytes>:<sha256>')
  const bytes = Number(match[1])
  if (!Number.isSafeInteger(bytes)) throw new Error('expected signed current bytes overflow')
  return { bytes, sha256: match[2] }
}

function strictBase64(value) {
  if (typeof value !== 'string' || value === '') return
  const bytes = Buffer.from(value, 'base64')
  return bytes.toString('base64') === value ? bytes : undefined
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function hasExactKeys(value, keys) {
  return isRecord(value) && Object.keys(value).length === keys.length && keys.every(key => key in value)
}

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function positiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0
}
