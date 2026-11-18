import { randomUUID } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { linuxCgroupPopulated } from '../src/linux-cgroup.ts'

const group = '/user.slice/user-42.slice/user@42.service/dsh.scope'
const unified = '36 35 0:30 / /sys/fs/cgroup/unified rw,nosuid - cgroup2 cgroup2 rw,nsdelegate\n'

function files(mounts: string, events: Record<string, string>) {
  return (path: string): string => {
    if (path === '/proc/self/mountinfo') return mounts
    if (events[path] !== undefined) return events[path]
    throw Object.assign(new Error('unreadable kernel file'), { code: 'ENOENT' })
  }
}

describe('recursive kernel population', () => {
  it.each([0, 1])('reads populated %s from a hybrid cgroup-v2 mount', (population) => {
    const read = files(unified, { [`/sys/fs/cgroup/unified${group}/cgroup.events`]: `populated ${population}\nfrozen 0\n` })
    expect(linuxCgroupPopulated(group, read)).toBe(population === 1)
  })

  it('maps a delegated mount root and escaped mountpoint', () => {
    const mounts = '36 35 0:30 /user.slice /cgroup\\040mount rw - cgroup2 cgroup2 rw\n'
    const read = files(mounts, { '/cgroup mount/user-42.slice/user@42.service/dsh.scope/cgroup.events': 'populated 0\n' })
    expect(linuxCgroupPopulated(group, read)).toBe(false)
  })

  it.each(['', 'populated 2\n', 'populated 0\npopulated 1\n', 'populated\n'])('keeps malformed evidence unknown: %j', (events) => {
    expect(linuxCgroupPopulated(group, files(unified, { [`/sys/fs/cgroup/unified${group}/cgroup.events`]: events }))).toBeUndefined()
  })

  it('keeps missing kernel evidence unknown rather than treating it as empty', () => {
    expect(linuxCgroupPopulated(group, files(unified, {}))).toBeUndefined()
    expect(linuxCgroupPopulated(group, () => { throw new Error('permission denied') })).toBeUndefined()
    expect(linuxCgroupPopulated(group, files(unified.replace('cgroup2 cgroup2', 'cgroup cgroup'), {}))).toBeUndefined()
  })

  it('uses the host reader without declaring a nonexistent scope empty', () => {
    expect(linuxCgroupPopulated(`/dsh-test-${randomUUID()}.scope`)).toBeUndefined()
  })

  it.each([
    '36 35 0:30',
    '36 35 0:30 relative /sys/fs/cgroup rw',
    '36 35 0:30 /',
    '36 35 0:30 / relative rw',
  ])('ignores incomplete or relative mount fields: %s', (fields) => {
    expect(linuxCgroupPopulated(group, files(`${fields} - cgroup2 cgroup2 rw\n`, {}))).toBeUndefined()
  })

  it('does not read outside the mounted hierarchy or accept a relative scope', () => {
    expect(linuxCgroupPopulated('relative', files(unified, {}))).toBeUndefined()
    expect(linuxCgroupPopulated('/../other', files(unified, {}))).toBeUndefined()
    expect(linuxCgroupPopulated(group, files(unified.replace(' / /sys', ' /other /sys'), {}))).toBeUndefined()
  })
})
