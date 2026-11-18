/**
 * Internal platform-profile builders for the local sandbox provider.
 *
 * @module @deepseek-ai/dsh-sandbox-local/profiles
 */

import { grantArgs as landlockGrantArgs } from '@deepseek-ai/node-addon-system/landlock-run'
import { existsSync, lstatSync, realpathSync, statSync } from 'node:fs'
import { isAbsolute, relative, resolve, sep } from 'node:path'
import { workspaceWritableRoots, writableRoots } from '@deepseek-ai/dsh-sandbox'
import type { SandboxPolicy } from '@deepseek-ai/dsh-sandbox'

/**
 * Build the bwrap profile arguments for one file-effect policy.
 * @param policy - file-effect policy to express as bwrap mounts.
 * @returns profile arguments before the trailing separator and command argv.
 */
export function bwrapProfileArgs(policy: SandboxPolicy): string[] {
  if (policy.readAccess !== undefined) return restrictedBwrapProfileArgs(policy)
  const args = ['--ro-bind', '/', '/', '--dev', '/dev', '--unshare-pid', '--proc', '/proc', '--die-with-parent']
  if (policy.mode === 'workspace-write') {
    args.push('--tmpfs', '/tmp')
    for (const root of workspaceWritableRoots(policy)) args.push('--bind', root, root)
  }
  return args
}

function restrictedBwrapProfileArgs(policy: SandboxPolicy): string[] {
  const requested = [...policy.readAccess?.roots ?? [], ...policy.readAccess?.artifacts?.map(file => file.path) ?? []]
  const roots = [...new Set(requested)].map((root) => {
    if (!isAbsolute(root) || root.includes('\0') || resolve(root) === '/') {
      throw new Error('sandbox-local: isolated read roots must be explicit absolute paths, never /')
    }
    const source = realpathSync.native(root)
    if (source !== resolve(root)) throw new Error('sandbox-local: isolated read roots must be physical paths')
    const info = statSync(source)
    if (!info.isFile() && !info.isDirectory()) throw new Error('sandbox-local: read roots must be regular files or directories')
    const artifact = policy.readAccess?.artifacts?.find(file => file.path === root)
    if (artifact) {
      const identity = statSync(source, { bigint: true })
      if (!identity.isFile() || String(identity.dev) !== artifact.device || String(identity.ino) !== artifact.inode) {
        throw new Error('sandbox-local: trusted output file was replaced')
      }
    }
    return { root: resolve(root), source }
  }).sort((a, b) => a.root.length - b.root.length)
  const args = ['--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
    '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'HOME', policy.workspaceRoot,
    '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TMPDIR', '/tmp',
    '--tmpfs', '/tmp', '--dev', '/dev', '--proc', '/proc']
  for (const { root, source } of roots) args.push('--ro-bind', source, root)
  for (const alias of ['/bin', '/sbin', '/lib', '/lib64']) {
    if (!existsSync(alias) || !lstatSync(alias).isSymbolicLink()) continue
    const target = realpathSync.native(alias)
    if (roots.some(({ root }) => root === target || target.startsWith(root + sep))) {
      args.push('--symlink', target, alias)
    }
  }
  for (const writable of workspaceWritableRoots(policy)) {
    if (!roots.some(({ root }) => {
      const child = relative(root, writable)
      return child === '' || child !== '..' && !child.startsWith('..' + sep) && !isAbsolute(child)
    })) throw new Error('sandbox-local: a writable root must also be explicitly readable')
    args.push('--bind', writable, writable)
  }
  return args
}

/**
 * Build the Landlock launcher grants for one file-effect policy.
 * @param policy - file-effect policy to express as Landlock allow-list grants.
 * @returns launcher grant arguments before the trailing separator and command argv.
 */
export function landlockProfileArgs(policy: SandboxPolicy): string[] {
  if (policy.readAccess !== undefined) throw new Error('sandbox-local: isolated read access requires bubblewrap')
  const readWrite = ['/dev/null']
  if (policy.mode === 'workspace-write') {
    readWrite.push('/tmp', ...workspaceWritableRoots(policy))
  }
  return landlockGrantArgs({ readOnly: ['/'], readWrite })
}

/** Quote one path as an SBPL string literal. */
function sbplString(path: string): string {
  return `"${path.replaceAll('\\', String.raw`\\`).replaceAll('"', String.raw`\"`)}"`
}

/**
 * Build the sandbox-exec arguments and SBPL profile for one policy. The
 * workspace-owned writable roots (workspace plus explicit extra directories)
 * come from the shared {@link writableRoots} helper (canonical, deduplicated)
 * so the Seatbelt grant and the in-process fs fence
 * (`@deepseek-ai/dsh-fs-sandbox`) can never drift apart; the helper adds the
 * documented Seatbelt temp areas.
 * @param policy - file-effect policy to express as an SBPL profile.
 * @returns sandbox-exec arguments before the trailing separator and command argv.
 */
export function seatbeltProfileArgs(policy: SandboxPolicy): string[] {
  if (policy.readAccess !== undefined) throw new Error('sandbox-local: isolated read access requires bubblewrap')
  const forms = ['(version 1)', '(allow default)', '(deny file-write*)', `(allow file-write* (literal ${sbplString('/dev/null')}))`]
  const roots = writableRoots(policy)
  if (roots.length > 0) {
    forms.push(`(allow file-write* ${roots.map(root => `(subpath ${sbplString(root)})`).join(' ')})`)
  }
  return ['-p', forms.join(' ')]
}
