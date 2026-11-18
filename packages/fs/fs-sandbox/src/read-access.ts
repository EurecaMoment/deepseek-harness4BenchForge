/** Linux descriptor-relative reads: every component is opened without following links. */
import { constants } from 'node:fs'
import { mkdir, open, realpath } from 'node:fs/promises'
import type { FileHandle } from 'node:fs/promises'
import { basename, dirname, isAbsolute, relative, resolve, sep } from 'node:path'
import { FsError, FsTargetKey } from '@deepseek-ai/dsh-fs'
import type { FsTarget } from '@deepseek-ai/dsh-fs'
import type { SandboxExecutionPolicy } from '@deepseek-ai/dsh-sandbox'

/**
 * Resolve a requested lexical path beneath an explicitly granted root.
 * @param path - absolute requested path.
 * @param policy - complete read authority.
 * @returns the most specific containing root, or throws on denied access.
 */
export function readableRoot(path: string, policy: SandboxExecutionPolicy): string {
  const candidate = resolve(path)
  const root = [...policy.readAccess?.roots ?? [], ...policy.readAccess?.artifacts?.map(file => file.path) ?? []].filter((root) => {
    const part = relative(resolve(root), candidate)
    return part === '' || part !== '..' && !part.startsWith('..' + sep) && !isAbsolute(part)
  }).sort((a, b) => b.length - a.length)[0]
  if (root === undefined) throw new FsError('File is outside this execution\'s readable roots', 'FS_SANDBOX_DENIED')
  return resolve(root)
}

/**
 * Open an authorized inode without following any symlink ancestor.
 * @param target - requested lexical path, already bound to a read policy.
 * @param policy - trusted physical read roots.
 * @param signal - optional cancellation before and between opens.
 * @returns an owned descriptor; the caller closes it after consuming the inode.
 */
export async function openReadable(target: FsTarget, policy: SandboxExecutionPolicy, signal?: AbortSignal): Promise<FileHandle> {
  signal?.throwIfAborted()
  const root = readableRoot(target.displayPath, policy)
  if (process.platform !== 'linux') throw new FsError('Isolated host-file reads require the Linux descriptor provider', 'FS_SANDBOX_DENIED')
  if (await realpath(root) !== root) throw new FsError('Readable roots must remain physical paths', 'FS_SANDBOX_DENIED')
  const parts = resolve(target.displayPath).split(sep).filter(Boolean)
  let handle: FileHandle | undefined
  try {
    handle = await open('/', constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW)
    for (const part of parts) {
      if (!(await handle.stat()).isDirectory()) throw new FsError('Read ancestor is not a directory', 'FS_SANDBOX_DENIED')
      signal?.throwIfAborted()
      const next = await open(`/proc/self/fd/${handle.fd}/${part}`, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
      await handle.close()
      handle = next
    }
    const info = await handle.stat()
    if (!info.isFile() && !info.isDirectory()) throw new FsError('Only regular files and directories are readable', 'FS_SANDBOX_DENIED')
    const artifact = policy.readAccess?.artifacts?.find(file => file.path === resolve(target.displayPath))
    if (artifact) {
      const identity = await handle.stat({ bigint: true })
      if (!identity.isFile() || String(identity.dev) !== artifact.device || String(identity.ino) !== artifact.inode) {
        throw new FsError('Trusted output file was replaced', 'FS_SANDBOX_DENIED')
      }
    }
    signal?.throwIfAborted()
    return handle
  } catch (error) {
    await handle?.close()
    if ((error as NodeJS.ErrnoException).code === 'ELOOP') {
      throw new FsError('Symlink traversal is not permitted by this read authority', 'FS_SANDBOX_DENIED', { cause: error })
    }
    throw error
  }
}

/**
 * Address an opened inode through Linux's process descriptor directory.
 * @param target - display identity and read authority to preserve.
 * @param handle - live descriptor owned by the caller.
 * @returns a temporary target usable only while that descriptor remains open.
 */
export function descriptorTarget(target: FsTarget, handle: FileHandle): FsTarget {
  return { ...target, targetKey: FsTargetKey(`/proc/self/fd/${handle.fd}`) }
}

/**
 * Pin a writable parent directory, creating absent descendants without following links.
 * @param target - lexical destination already checked against writable roots.
 * @param policy - explicit readable roots and current generation.
 * @param signal - cancellation between traversal steps.
 * @param createParents - permit creating absent descendants for writes and move destinations.
 * @returns the descriptor-backed mutation path and its owned parent descriptor.
 */
export async function openWritableParent(
  target: FsTarget, policy: SandboxExecutionPolicy, signal: AbortSignal, createParents: boolean,
): Promise<{ target: FsTarget; parent: FileHandle }> {
  const root = readableRoot(target.displayPath, policy)
  const parentPath = dirname(target.displayPath)
  const suffix = relative(root, parentPath)
  if (suffix === '..' || suffix.startsWith('..' + sep) || isAbsolute(suffix)) {
    throw new FsError('Cannot mutate a read root itself', 'FS_SANDBOX_DENIED')
  }
  let parent = await openReadable({ displayPath: root, targetKey: FsTargetKey(root), sandboxPolicy: policy }, policy, signal)
  try {
    for (const part of suffix.split(sep).filter(Boolean)) {
      signal.throwIfAborted()
      const path = `/proc/self/fd/${parent.fd}/${part}`
      if (createParents) {
        try { await mkdir(path) }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error }
      }
      const next = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW)
      await parent.close()
      parent = next
    }
    signal.throwIfAborted()
    return { target: { ...target, targetKey: FsTargetKey(`/proc/self/fd/${parent.fd}/${basename(target.displayPath)}`) }, parent }
  } catch (error) {
    await parent.close()
    if (['ELOOP', 'ENOTDIR'].includes((error as NodeJS.ErrnoException).code ?? '')) {
      throw new FsError('Mutation ancestors must remain physical directories', 'FS_SANDBOX_DENIED', { cause: error })
    }
    throw error
  }
}
