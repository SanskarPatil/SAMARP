import { Incident } from '../types';

/** Raw detector score for display. Very large robust-z values are capped visually; the stored value is unchanged. */
export function formatRawScore(score: number | null | undefined, scoreType: string): string {
  if (score === null || score === undefined || !Number.isFinite(score)) return 'N/A';
  if (scoreType === 'robust_z' && score > 99) return '>99';
  return score.toFixed(scoreType === 'robust_z' ? 1 : 2);
}

export const CALIBRATION_LABEL: Record<string, string> = {
  platt_dga: 'Platt-calibrated (DGA model)',
  synthetic_replay: 'Calibrated on synthetic replay',
  uncalibrated: 'Uncalibrated mapping (not a probability)',
};

/** Confidence text: percent only when calibrated, otherwise a bare 0-1 number. */
export function formatConfidence(incident: Pick<Incident, 'confidence' | 'calibrated' | 'calibrated_on'>): string {
  const c = incident.confidence;
  if (c === null || c === undefined) return 'N/A';
  return incident.calibrated ? `${(c * 100).toFixed(1)}%` : c.toFixed(2);
}
