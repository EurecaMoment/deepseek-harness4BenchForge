/** Kernel population evidence for a systemd scope on unified or hybrid cgroup hosts. */
import { readFileSync } from 'node:fs'
import { posix } from 'node:path'

const unescapeField = (value: string): string => value.replace(/\\([0-7]{3})/gu,
  (_match: string, octal: string) => String.fromCharCode(Number.parseInt(octal, 8)))

/**
 * Read the recursive population bit from the scope's cgroup-v2 mount.
 * Missing mounts, unreadable files and malformed evidence remain unknown.
 * @param controlGroup - absolute ControlGroup reported by the scope's user manager.
 * @param readText - kernel-file reader, replaceable by deterministic tests.
 * @returns true while any descendant is populated, false only for explicit populated 0.
 */
export function linuxCgroupPopulated(
  controlGroup: string,
  readText: (path: string) => string = path => readFileSync(path, 'utf8'),
): boolean | undefined {
  if (!controlGroup.startsWith('/') || posix.normalize(controlGroup) !== controlGroup) return undefined
  let mounts: string
  try { mounts = readText('/proc/self/mountinfo') } catch (_unreadableMounts) { return undefined }
  for (const line of mounts.split('\n')) {
    const [fields, filesystem] = line.split(' - ')
    if (!fields || !filesystem?.startsWith('cgroup2 ')) continue
    const columns = fields.split(' ')
    const root = columns[3] && unescapeField(columns[3])
    const mount = columns[4] && unescapeField(columns[4])
    if (!root?.startsWith('/') || !mount?.startsWith('/')) continue
    const relative = posix.relative(root, controlGroup)
    if (relative === '..' || relative.startsWith('../') || posix.isAbsolute(relative)) continue
    let events: string
    try { events = readText(posix.join(mount, relative, 'cgroup.events')) } catch (_unreadableEvents) { continue }
    const population = events.split('\n').filter(row => /^populated(?:\s|$)/u.test(row))
    if (population.length !== 1) continue
    if (population[0] === 'populated 0') return false
    if (population[0] === 'populated 1') return true
  }
  return undefined
}
