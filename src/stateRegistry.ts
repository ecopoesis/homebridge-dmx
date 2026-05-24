// StateRegistry — central store of every fixture's HomeKit-visible state.
//
// Every StickFixture and ZoneFixture reads/writes through here. Whenever a
// fixture's state changes, listeners fire so zones can refresh their own
// HomeKit characteristics (and vice versa: setting a zone updates each
// member's state in the registry, which fires events, which prompt the
// per-fixture accessories to update their HomeKit-displayed state).
//
// Majority rule for zone state: see pickMajority() — count occurrences of
// each value across (alphabetically-sorted) members; largest count wins;
// ties are broken in favour of the value held by the alphabetically-first
// member.

import { HomeKitLightState } from './color/types.js';

export type StateChangeListener = (fixtureId: string) => void;

const DEFAULT_STATE: HomeKitLightState = { on: false, brightness: 100 };

export class StateRegistry {
  private states = new Map<string, HomeKitLightState>();
  private listeners = new Set<StateChangeListener>();

  get(id: string): HomeKitLightState {
    return this.states.get(id) ?? { ...DEFAULT_STATE };
  }

  /** Replace a fixture's state and fire change listeners. */
  set(id: string, state: HomeKitLightState): void {
    this.states.set(id, { ...state });
    for (const l of this.listeners) l(id);
  }

  /** Merge a partial update into a fixture's state, returning the new full
   *  state. Fires listeners. */
  update(id: string, patch: Partial<HomeKitLightState>): HomeKitLightState {
    const next: HomeKitLightState = { ...this.get(id), ...patch };
    this.set(id, next);
    return next;
  }

  onChange(cb: StateChangeListener): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }
}

/** Bucket members' values; return the value with the largest bucket. Ties
 *  break in favour of the value held by the first member in
 *  alphabetical-id order. */
export function pickMajority<T>(items: Array<{ id: string; v: T }>): T | undefined {
  if (items.length === 0) return undefined;
  const sorted = items.slice().sort((a, b) => a.id.localeCompare(b.id));
  const counts = new Map<T, { count: number; firstIdx: number }>();
  for (let i = 0; i < sorted.length; i++) {
    const v = sorted[i].v;
    const rec = counts.get(v);
    if (rec) rec.count++;
    else counts.set(v, { count: 1, firstIdx: i });
  }
  let bestV: T = sorted[0].v;
  let bestRec = counts.get(bestV)!;
  for (const [v, rec] of counts) {
    if (rec.count > bestRec.count ||
        (rec.count === bestRec.count && rec.firstIdx < bestRec.firstIdx)) {
      bestV = v;
      bestRec = rec;
    }
  }
  return bestV;
}
