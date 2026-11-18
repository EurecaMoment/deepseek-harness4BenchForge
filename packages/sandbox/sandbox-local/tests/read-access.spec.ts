/** Real Linux confinement checks for explicit read grants. */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { describe, expect, it, onTestFinished } from 'vitest'
import { bwrapProfileArgs } from '../src/profiles.ts'

const linux = process.platform === 'linux'
const bwrap = linux && spawnSync('bwrap', ['--ro-bind', '/', '/', '--unshare-all', '--', '/bin/true']).status === 0

describe.skipIf(!linux)('isolated read profile', () => {
  function fixture() {
    const root = realpathSync.native(mkdtempSync(join(tmpdir(), 'dsh-read-access-')))
    onTestFinished(() => { rmSync(root, { recursive: true, force: true }) })
    const a = join(root, 'a'), b = join(root, 'b')
    mkdirSync(a); mkdirSync(b)
    writeFileSync(join(a, 'owned'), 'owned')
    writeFileSync(join(b, 'secret'), 'other-session')
    symlinkSync(b, join(a, 'escape'))
    const runtime = ['/usr/bin', '/usr/lib', '/usr/lib64', '/etc/ld.so.cache']
      .filter(path => existsSync(path)).map(path => realpathSync.native(path))
    const policy = { mode: 'workspace-write' as const, workspaceRoot: a,
      readAccess: { policyId: 'a', epoch: 1, roots: [a, ...runtime] } }
    return { a, b, policy }
  }

  it('uses explicit mounts with isolated network and rejects mutable grant aliases', () => {
    const { a, policy } = fixture()
    const args = bwrapProfileArgs(policy)
    expect(args).toContain('--unshare-all')
    expect(args.join(' ')).not.toContain('--ro-bind / /')
    expect(() => bwrapProfileArgs({ ...policy, readAccess: { ...policy.readAccess, roots: [join(a, 'escape')] } })).toThrow('physical')
  })

  it.skipIf(!bwrap)('executes in A without reading B through absolute paths, symlinks, or host temp', () => {
    const { a, b, policy } = fixture()
    const command = 'cat "$1/owned"; test ! -e "$2/secret" && test ! -e "$1/escape/secret" && printf ok > "$1/result"'
    const result = spawnSync('bwrap', [...bwrapProfileArgs(policy), '--', '/bin/bash', '-c', command, 'test', a, b], { encoding: 'utf8' })
    expect(result.status, result.stderr).toBe(0)
    expect(result.stdout).toBe('owned')
    expect(readFileSync(join(a, 'result'), 'utf8')).toBe('ok')
  })
})
