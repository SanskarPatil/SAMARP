import { Incident } from '../types';

/** Client ring-buffer bound (design.md: 500-item ring). */
export const MAX_RING_BUFFER_SIZE = 500;

/**
 * Where the incidents on screen come from.
 *  - 'live': only what the read-only API / WebSocket delivered. Never mixed with fixtures.
 *  - 'demo': only the bundled synthetic fixtures, shown behind an explicit toggle
 *            with a DEMO DATA banner.
 */
export type DataSource = 'live' | 'demo';

/** Upsert by incident_id, newest first, bounded. Pure: never mutates its inputs. */
export function mergeIncidents(current: readonly Incident[], incoming: readonly Incident[], max = MAX_RING_BUFFER_SIZE): Incident[] {
  const byId = new Map<string, Incident>();
  for (const item of current) byId.set(item.incident_id, item);
  for (const item of incoming) byId.set(item.incident_id, item);
  return Array.from(byId.values())
    .sort((a, b) => new Date(b.last_observed || b.timestamp).getTime() - new Date(a.last_observed || a.timestamp).getTime())
    .slice(0, max);
}

/** Pick the incident list for the active source. Live and demo lists are kept apart. */
export function visibleIncidents(source: DataSource, live: readonly Incident[], demo: readonly Incident[]): readonly Incident[] {
  return source === 'demo' ? demo : live;
}

export type Reconciliation =
  | { state: 'unknown' }
  | { state: 'match'; feed: number; api: number }
  | { state: 'capped'; feed: number; api: number }
  | { state: 'mismatch'; feed: number; api: number };

/**
 * Compare the live feed with the API's own incident count (GET /health total_incidents).
 * 'capped' means the API holds more than the client ring buffer can show.
 */
export function reconcile(feedCount: number, apiTotal: number | null | undefined, max = MAX_RING_BUFFER_SIZE): Reconciliation {
  if (apiTotal === null || apiTotal === undefined) return { state: 'unknown' };
  if (feedCount === apiTotal) return { state: 'match', feed: feedCount, api: apiTotal };
  if (apiTotal > max && feedCount === max) return { state: 'capped', feed: feedCount, api: apiTotal };
  return { state: 'mismatch', feed: feedCount, api: apiTotal };
}
