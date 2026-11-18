/**
 * Local filesystem with per-call write policy and optional read authority.
 * Without readAccess, reads retain LocalFileSystem behavior. Explicit Linux
 * read roots use descriptor-relative traversal without symlink components and
 * reject expired authority before and after I/O. Strict writes use workspace
 * roots rather than host temporary directories.
 *
 * Strict mutations pin parent directories and reject linked final-component
 * reads; ordinary write-only policies retain their canonical-path fence.
 * Untrusted process isolation belongs to the shell sandbox provider.
 *
 * @module @deepseek-ai/dsh-fs-sandbox
 */

import { Context } from '@deepseek-ai/cordis'
import { readdir } from 'node:fs/promises'
import { isAbsolute, relative, resolve, join, sep } from 'node:path'
import { LocalFileSystem } from '@deepseek-ai/dsh-fs-local'
import type { Config as LocalConfig, LocalMutationLease } from '@deepseek-ai/dsh-fs-local'
import { FsError, FsTargetKey } from '@deepseek-ai/dsh-fs'
import type { FsDeleteOutcome, FsMoveOutcome, FsEditOutcome, FsEditRequest, FsTarget, FsVersion, FsWriteIntent, FsWriteOutcome, FsInfo, FsDirEntry, FsPathInfo } from '@deepseek-ai/dsh-fs'
import { canonicalPath, workspaceWritableRoots, writableRoots } from '@deepseek-ai/dsh-sandbox'
import type { SandboxExecutionPolicy, SandboxMode } from '@deepseek-ai/dsh-sandbox'
import type {} from '@deepseek-ai/dsh-sandbox-policy'
import { isPathUnder } from './containment.ts'
import { descriptorTarget, openReadable, openWritableParent, readableRoot } from './read-access.ts'

/**
 * Plugin config: the local backend's knobs verbatim (`cwd` resolution default
 * and `diffBasisMaxBytes` overwrite-presentation bound). The sandbox default
 * (mode + `workspace-write` fallback root) is NOT here — `ctx.sandboxPolicy`
 * resolves each calling session for every enforcing capability.
 */
export type Config = LocalConfig

/**
 * Sandbox-enforcing filesystem backend. Registers as `ctx.fs` (loading it
 * INSTEAD OF `dsh-fs-local`, together with a `ctx.sandboxPolicy`, is the whole
 * swap — the model-facing tools are untouched). Its configured default mode is
 * the capability fact exposed by {@link sandboxMode}; `dsh-tool-fs` resolves
 * each session's mode and cwd into a policy for every mutation, while an
 * approved escalation may stamp a strictly wider mode for one call.
 */
export class SandboxedFileSystem extends LocalFileSystem {
  static inject = ['sandboxPolicy']

  private readonly defaultMode: SandboxMode

  /** Pin strict mutation parents while the inherited logical-path lock is held. */
  protected override async prepareMutationTarget(target: FsTarget, createParents: boolean): Promise<LocalMutationLease> {
    const policy = target.sandboxPolicy
    if (policy?.readAccess === undefined || policy.mode === 'danger-full-access') return super.prepareMutationTarget(target, createParents)
    const lease = this.ctx.sandboxPolicy.leaseReadAccess(policy)
    try {
      const opened = await openWritableParent(target, policy, lease.signal, createParents)
      return { target: { ...opened.target, noFollow: true, authoritySignal: lease.signal },
        dispose: async () => { lease.dispose(); await opened.parent.close() } }
    } catch (error) { lease.dispose(); throw error }
  }
  constructor(ctx: Context, config: Config) {
    super(ctx, config)
    this.defaultMode = ctx.sandboxPolicy.defaultMode
  }

  /** The deployment default mode — the capability fact the tool layer reads to advertise escalation. */
  override get sandboxMode(): SandboxMode {
    return this.defaultMode
  }

  override async resolve(
    path: string, opts?: { cwd?: string; signal?: AbortSignal; sandboxPolicy?: SandboxExecutionPolicy },
  ): Promise<FsTarget> {
    const policy = opts?.sandboxPolicy
    if (policy?.readAccess === undefined || policy.mode === 'danger-full-access') return super.resolve(path, opts)
    opts?.signal?.throwIfAborted()
    this.ctx.sandboxPolicy.assertReadAccess(policy)
    const displayPath = resolve(opts?.cwd ?? this.config.cwd, path)
    readableRoot(displayPath, policy)
    return { targetKey: FsTargetKey(displayPath), displayPath, sandboxPolicy: policy }
  }

  private async readTarget<T>(target: FsTarget, signal: AbortSignal | undefined, read: (pinned: FsTarget) => Promise<T>): Promise<T> {
    const policy = target.sandboxPolicy
    if (policy?.readAccess === undefined || policy.mode === 'danger-full-access') return read(target)
    this.ctx.sandboxPolicy.assertReadAccess(policy)
    const handle = await openReadable(target, policy, signal)
    try {
      this.ctx.sandboxPolicy.assertReadAccess(policy)
      const result = await read(descriptorTarget(target, handle))
      this.ctx.sandboxPolicy.assertReadAccess(policy)
      return result
    } finally { await handle.close() }
  }

  override async stat(target: FsTarget, signal?: AbortSignal): Promise<FsInfo | undefined> {
    try { return await this.readTarget(target, signal, pinned => super.stat(pinned, signal)) }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined; throw error }
  }

  override async lstat(
    path: string, opts?: { cwd?: string; sandboxPolicy?: SandboxExecutionPolicy }, signal?: AbortSignal,
  ): Promise<FsPathInfo | undefined> {
    if (opts?.sandboxPolicy?.readAccess === undefined || opts.sandboxPolicy.mode === 'danger-full-access') return super.lstat(path, opts, signal)
    const target = await this.resolve(path, { ...opts, ...signal === undefined ? {} : { signal } })
    return this.stat(target, signal)
  }

  override async readText(target: FsTarget, signal?: AbortSignal): Promise<string> {
    return this.readTarget(target, signal, pinned => super.readText(pinned, signal))
  }

  override async watch(target: FsTarget, changed: (error?: Error) => void, signal: AbortSignal): Promise<() => Promise<void>> {
    if (target.sandboxPolicy?.readAccess !== undefined && target.sandboxPolicy.mode !== 'danger-full-access') {
      throw new FsError('File watching is unavailable with explicit read authority', 'FS_SANDBOX_DENIED')
    }
    return super.watch(target, changed, signal)
  }

  override async readBytes(target: FsTarget, signal: AbortSignal | undefined, maxBytes: number): Promise<Uint8Array> {
    return this.readTarget(target, signal, pinned => super.readBytes(pinned, signal, maxBytes))
  }

  override async readByteRange(target: FsTarget, range: { offset: number; length: number }, signal?: AbortSignal): Promise<Uint8Array> {
    return this.readTarget(target, signal, pinned => super.readByteRange(pinned, range, signal))
  }

  override async streamText(target: FsTarget, signal?: AbortSignal): Promise<AsyncIterable<string>> {
    const policy = target.sandboxPolicy
    if (policy?.readAccess === undefined || policy.mode === 'danger-full-access') return super.streamText(target, signal)
    this.ctx.sandboxPolicy.assertReadAccess(policy)
    const authority = this.ctx.sandboxPolicy
    const readStream = (pinned: FsTarget) => super.streamText(pinned, signal)
    return (async function* () {
      authority.assertReadAccess(policy)
      const handle = await openReadable(target, policy, signal)
      try {
        for await (const chunk of await readStream(descriptorTarget(target, handle))) {
          authority.assertReadAccess(policy)
          yield chunk
        }
      } finally { await handle.close() }
    })()
  }

  override async listDir(target: FsTarget, signal?: AbortSignal): Promise<FsDirEntry[]> {
    const sandboxPolicy = target.sandboxPolicy
    if (sandboxPolicy?.readAccess === undefined || sandboxPolicy.mode === 'danger-full-access') return super.listDir(target, signal)
    return this.readTarget(target, signal, async (pinned) => {
      const entries = await readdir(String(pinned.targetKey), { withFileTypes: true })
      signal?.throwIfAborted()
      // Do not follow or expose symlink-derived targets while enumerating.
      return entries.filter(entry => entry.isFile() || entry.isDirectory()).map((entry) => {
        const displayPath = join(target.displayPath, entry.name)
        return { name: entry.name, type: entry.isDirectory() ? 'directory' : 'file',
          target: { displayPath, targetKey: FsTargetKey(displayPath), sandboxPolicy } }
      })
    })
  }

  /**
   * Fence the write by the per-call policy, then delegate to the inherited
   * atomic write. See {@link checkedTarget}.
   * @param target - the resolved target to write.
   * @param content - the full new file content.
   * @param expected - the write intent guarding the write; omit for unconditional.
   * @param signal - aborts before atomic publication takes effect.
   * @param sandboxPolicy - the per-call mode and workspace root; omit to use
   *   the deployment fallback.
   * @returns the write outcome from the inherited backend.
   */
  override async writeText(
    target: FsTarget,
    content: string,
    expected?: FsWriteIntent,
    signal?: AbortSignal,
    sandboxPolicy?: SandboxExecutionPolicy,
  ): Promise<FsWriteOutcome> {
    return super.writeText(await this.checkedTarget(target, sandboxPolicy), content, expected, signal)
  }

  /**
   * Fence the edit by the per-call policy, then delegate to the inherited
   * atomic edit. See {@link checkedTarget}.
   * @param target - the resolved target to edit.
   * @param edit - the literal search/replace request.
   * @param expected - the version guard; omit for an unconditional edit.
   * @param signal - aborts before atomic publication takes effect.
   * @param sandboxPolicy - the per-call mode and workspace root; omit to use
   *   the deployment fallback.
   * @returns the edit outcome from the inherited backend.
   */
  override async editText(
    target: FsTarget,
    edit: FsEditRequest,
    expected?: { version: FsVersion },
    signal?: AbortSignal,
    sandboxPolicy?: SandboxExecutionPolicy,
  ): Promise<FsEditOutcome> {
    return super.editText(await this.checkedTarget(target, sandboxPolicy), edit, expected, signal)
  }

  /**
   * Fence the mutation before delegating to the local provider.
   * @param sandboxPolicy - per-call mode and workspace root; omit for the deployment fallback.
   */
  override async patchText(
    target: FsTarget, hunks: Parameters<LocalFileSystem['patchText']>[1], expected?: { version: FsVersion },
    signal?: AbortSignal, sandboxPolicy?: SandboxExecutionPolicy,
  ): Promise<FsEditOutcome> {
    return super.patchText(await this.checkedTarget(target, sandboxPolicy), hunks, expected, signal)
  }

  /**
   * Fence the mutation before delegating to the local provider.
   * @param sandboxPolicy - per-call mode and workspace root; omit for the deployment fallback.
   */
  override async deleteFile(
    target: FsTarget, expected?: { version: FsVersion }, signal?: AbortSignal, sandboxPolicy?: SandboxExecutionPolicy,
  ): Promise<FsDeleteOutcome> {
    return super.deleteFile(await this.checkedTarget(target, sandboxPolicy), expected, signal)
  }

  /**
   * Fence the mutation before delegating to the local provider.
   * @param sandboxPolicy - per-call mode and workspace root; omit for the deployment fallback.
   */
  override async moveFile(
    source: FsTarget, destination: FsTarget, options: Parameters<LocalFileSystem['moveFile']>[2],
    signal?: AbortSignal, sandboxPolicy?: SandboxExecutionPolicy,
  ): Promise<FsMoveOutcome> {
    const checkedSource = await this.checkedTarget(source, sandboxPolicy)
    const checkedDestination = await this.checkedTarget(destination, sandboxPolicy)
    return super.moveFile(checkedSource, checkedDestination, options, signal)
  }

  /**
   * Resolve write authority before taking the mutation lock. Strict targets
   * retain their lexical identity for descriptor traversal under that lock;
   * legacy policies retain their canonical-path containment behavior.
   */
  private async checkedTarget(target: FsTarget, sandboxPolicy?: SandboxExecutionPolicy): Promise<FsTarget> {
    const policy = sandboxPolicy ?? target.sandboxPolicy ?? this.ctx.sandboxPolicy.resolve()
    this.ctx.sandboxPolicy.assertReadAccess(policy)
    const { mode } = policy
    if (mode === 'danger-full-access') return target.sandboxPolicy === undefined ? target : { ...target, sandboxPolicy: policy }
    if (policy.readAccess !== undefined && canonicalPath(policy.workspaceRoot) !== policy.workspaceRoot) {
      throw new FsError('Workspace root must remain a physical directory', 'FS_SANDBOX_DENIED')
    }
    if (mode === 'read-only') {
      throw new FsError(`cannot write "${target.displayPath}": file access denied under read-only mode`, 'FS_SANDBOX_DENIED')
    }
    if (policy.readAccess !== undefined) {
      const displayPath = resolve(target.displayPath)
      readableRoot(displayPath, policy)
      const writable = workspaceWritableRoots(policy).some((root) => {
        const part = relative(root, displayPath)
        return part === '' || part !== '..' && !part.startsWith('..' + sep) && !isAbsolute(part)
      })
      if (!writable) throw new FsError('Mutation is outside this execution\'s writable roots', 'FS_SANDBOX_DENIED')
      return { displayPath, targetKey: FsTargetKey(displayPath), sandboxPolicy: policy }
    }
    // workspace-write: containment on the FRESH canonical path (catches a
    // symlink ancestor swapped since the tool resolved this target), and the
    // mutation delegates with THIS fresh target — never the stale one.
    const fresh = await this.resolve(target.displayPath)
    let contained = false
    for (const root of writableRoots(policy)) {
      if (await isPathUnder(fresh.targetKey, root)) {
        contained = true
        break
      }
    }
    if (!contained) {
      throw new FsError(`cannot write "${target.displayPath}": file access denied under workspace-write mode`, 'FS_SANDBOX_DENIED')
    }
    return fresh
  }
}

export default SandboxedFileSystem
