/**
 * Proactive compaction scheduling and the latest durable checkpoint identity.
 * Retry pacing is process-local; checkpoint recognition is replayable.
 *
 * @module @deepseek-ai/dsh-compaction-basic/pressure
 */

import { isDeepStrictEqual } from 'node:util'
import { z } from 'zod'
import type { EpochHeader, Session } from '@deepseek-ai/dsh-session'
import type { ProjectionDefinition } from '@deepseek-ai/dsh-session-projection'
import type { TokenMeasurement } from '@deepseek-ai/dsh-token-meter'
import { CompactionReductionError } from './region.ts'

/** The newest checkpoint sequence, restored without reading historical messages. */
export const pressureCheckpointProjectionDefinition = {
  key: 'compactionPressureCheckpoint',
  stateVersion: 1,
  stateSchema: z.number().int().nonnegative().nullable(),
  init: (): number | null => null,
  apply: (state, event) => event.type === 'user/message' && event.data.source.kind === 'compact-checkpoint'
    ? event.seq
    : state,
} satisfies ProjectionDefinition<'compactionPressureCheckpoint', number | null>

/** Immutable inputs whose changes make a pressure summary worth reconsidering. */
export interface PressureInput {
  readonly header: EpochHeader
  readonly summaryRoute: { provider: string; model: string } | undefined
  readonly nodes: TokenMeasurement['nodes']
}

type DeferredPressure =
  | { readonly kind: 'no-reduction'; readonly input: PressureInput }
  | { readonly kind: 'failure'; readonly input: PressureInput; remainingChecks: number }

/** Owns one discardable retry decision per live Session, without timers or model effects. */
export class PressureCompactionScheduler {
  private readonly deferred = new WeakMap<Session, DeferredPressure>()

  /**
   * Consume one proactive check; new routes bypass failure pacing.
   * @param session - owner of the scheduling decision.
   * @param input - current selected node identities, token prices, and routes.
   * @returns whether a summary may run now.
   */
  allows(session: Session, input: PressureInput): boolean {
    const previous = this.deferred.get(session)
    if (previous === undefined) return true
    if (previous.kind === 'no-reduction') {
      if (isDeepStrictEqual(previous.input, input)) return false
    } else if (isDeepStrictEqual(previous.input.header.config, input.header.config)
      && isDeepStrictEqual(previous.input.summaryRoute, input.summaryRoute)
      && previous.remainingChecks > 0) {
      previous.remainingChecks -= 1
      return false
    }
    this.deferred.delete(session)
    return true
  }

  /**
   * Suppress unchanged non-reducing input, or pace an operational failure.
   * @param session - owner of the completed failed attempt.
   * @param input - input that actually failed.
   * @param error - failure whose type distinguishes no reduction from a request failure.
   * @param retrySteps - number of subsequent checks to skip after an operational failure.
   */
  failed(session: Session, input: PressureInput, error: unknown, retrySteps: number): void {
    this.deferred.set(session, error instanceof CompactionReductionError
      ? { kind: 'no-reduction', input }
      : { kind: 'failure', input, remainingChecks: retrySteps })
  }
}
