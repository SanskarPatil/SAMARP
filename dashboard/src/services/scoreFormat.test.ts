import { describe, expect, it } from 'vitest';
import { formatConfidence, formatRawScore } from './scoreFormat';

describe('score formatting', () => {
  it('caps huge robust-z for display only', () => {
    expect(formatRawScore(5999, 'robust_z')).toBe('>99');
    expect(formatRawScore(18.54, 'robust_z')).toBe('18.5');
    expect(formatRawScore(0.991, 'anomaly_score')).toBe('0.99');
    expect(formatRawScore(null, 'rule_score')).toBe('N/A');
  });

  it('shows a percent sign only when calibrated', () => {
    expect(formatConfidence({ confidence: 0.94, calibrated: true, calibrated_on: 'platt_dga' })).toBe('94.0%');
    expect(formatConfidence({ confidence: 0.632, calibrated: false, calibrated_on: 'uncalibrated' })).toBe('0.63');
  });
});
