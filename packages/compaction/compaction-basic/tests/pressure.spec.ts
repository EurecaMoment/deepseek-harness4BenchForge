import { describe, expect, it } from 'vitest'
import { brandString } from '@deepseek-ai/dsh-brand'
import { Session, SessionSeq, type SessionId } from '@deepseek-ai/dsh-session'
import { PressureCompactionScheduler } from '../src/pressure.ts'
import type { PressureInput } from '../src/pressure.ts'
import { CompactionReductionError } from '../src/region.ts'

const INPUT: PressureInput = {
  header: { config: { provider: 'test', model: 'model' } },
  summaryRoute: { provider: 'test', model: 'model' },
  nodes: [{ seq: SessionSeq(1), tokens: 500, heuristicTokens: 500 }],
}

describe('pressure retry scheduling', () => {
  it('retries no-reduction only after selected content or a route changes', () => {
    const scheduler = new PressureCompactionScheduler()
    const session = Session.create(brandString<SessionId>('pressure-scheduling'))
    for (const changed of [
      { ...INPUT, nodes: [{ seq: SessionSeq(1), tokens: 400, heuristicTokens: 500 }] },
      { ...INPUT, nodes: [{ seq: SessionSeq(2), tokens: 500, heuristicTokens: 500 }] },
      { ...INPUT, header: { config: { provider: 'test', model: 'other' } } },
      { ...INPUT, summaryRoute: { provider: 'summary', model: 'other' } },
    ]) {
      scheduler.failed(session, INPUT, new CompactionReductionError('no reduction'), 8)
      expect(scheduler.allows(session, { ...INPUT })).toBe(false)
      expect(scheduler.allows(session, changed)).toBe(true)
      expect(scheduler.allows(session, INPUT)).toBe(true)
    }
  })

  it('paces failures across changing inputs but allows a new route immediately', () => {
    const scheduler = new PressureCompactionScheduler()
    const session = Session.create(brandString<SessionId>('pressure-backoff'))
    scheduler.failed(session, INPUT, new Error('request failed'), 2)
    expect(scheduler.allows(session, { ...INPUT, nodes: [] })).toBe(false)
    expect(scheduler.allows(session, INPUT)).toBe(false)
    expect(scheduler.allows(session, INPUT)).toBe(true)
    scheduler.failed(session, INPUT, new Error('request failed'), 2)
    expect(scheduler.allows(session, { ...INPUT, summaryRoute: undefined })).toBe(true)
    scheduler.failed(session, INPUT, new Error('request failed'), 0)
    expect(scheduler.allows(session, INPUT)).toBe(true)
    const other = Session.create(brandString<SessionId>('independent-pressure'))
    scheduler.failed(session, INPUT, new CompactionReductionError('no reduction'), 2)
    expect(scheduler.allows(other, INPUT)).toBe(true)
  })
})
