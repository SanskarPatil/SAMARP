import { describe, expect, it } from 'vitest';
import { Incident } from '../types';
import { CANONICAL_MOCK_FIXTURES } from './mockFixtures';
import { MAX_RING_BUFFER_SIZE, mergeIncidents, reconcile, visibleIncidents } from './incidentStore';

function incident(id: string, t: string): Incident {
  return { ...CANONICAL_MOCK_FIXTURES[0], incident_id: id, timestamp: t, last_observed: t } as Incident;
}

describe('live vs demo separation', () => {
  it('live view never contains a demo fixture', () => {
    const live = mergeIncidents([], [incident('aaaaaaaaaaaaaaaa', '2026-03-12T01:47:50Z')]);
    const shown = visibleIncidents('live', live, CANONICAL_MOCK_FIXTURES);
    const demoIds = new Set(CANONICAL_MOCK_FIXTURES.map((i) => i.incident_id));
    expect(shown.some((i) => demoIds.has(i.incident_id))).toBe(false);
    expect(shown).toHaveLength(1);
  });

  it('empty live feed stays empty (no fixture fallback)', () => {
    expect(visibleIncidents('live', [], CANONICAL_MOCK_FIXTURES)).toHaveLength(0);
  });

  it('demo view shows only fixtures', () => {
    const live = [incident('bbbbbbbbbbbbbbbb', '2026-03-12T01:47:50Z')];
    expect(visibleIncidents('demo', live, CANONICAL_MOCK_FIXTURES)).toEqual(CANONICAL_MOCK_FIXTURES);
  });
});

describe('mergeIncidents', () => {
  it('upserts by id, newest first, and is bounded', () => {
    const a1 = incident('a000000000000001', '2026-03-12T01:00:00Z');
    const a1b = { ...a1, status: 'UPDATED' } as Incident;
    const b = incident('b000000000000002', '2026-03-12T02:00:00Z');
    const merged = mergeIncidents([a1], [a1b, b]);
    expect(merged.map((i) => i.incident_id)).toEqual(['b000000000000002', 'a000000000000001']);
    expect(merged[1].status).toBe('UPDATED');
    const many = Array.from({ length: MAX_RING_BUFFER_SIZE + 20 }, (_, n) => incident(n.toString(16).padStart(16, '0'), new Date(1_700_000_000_000 + n * 1000).toISOString()));
    expect(mergeIncidents([], many)).toHaveLength(MAX_RING_BUFFER_SIZE);
  });
});

describe('reconcile', () => {
  it('reports match, mismatch, capped and unknown', () => {
    expect(reconcile(10, 10).state).toBe('match');
    expect(reconcile(9, 10).state).toBe('mismatch');
    expect(reconcile(500, 812).state).toBe('capped');
    expect(reconcile(3, null).state).toBe('unknown');
  });
});
