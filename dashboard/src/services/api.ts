import { Incident, SensorCapabilities, SystemHealth } from '../types';

const API_BASE = '';

// Used only while the API is unreachable: nothing is claimed as observable.
export const FALLBACK_CAPABILITIES: SensorCapabilities = {
  input_mode: 'unavailable',
  ipv4: 'NOT_OBSERVABLE',
  ipv6: 'NOT_OBSERVABLE',
  dns_names: 'NOT_OBSERVABLE',
  dns_responses: 'NOT_OBSERVABLE',
  tls_handshake: 'NOT_OBSERVABLE',
  quic_metadata: 'NOT_OBSERVABLE',
  ja3: 'NOT_OBSERVABLE',
  ja3s: 'NOT_OBSERVABLE',
  ja4: 'NOT_OBSERVABLE',
  flow_records: 'NOT_OBSERVABLE',
  flow_sampling: 'NOT_OBSERVABLE',
  geo: 'NOT_OBSERVABLE',
  capture_loss: 'NOT_OBSERVABLE',
  bidirectional_visibility: 'NOT_OBSERVABLE',
};

/** GET /health. Throws when the API is unreachable - callers show "API offline", never a fake count. */
export async function getHealth(): Promise<SystemHealth> {
  const res = await fetch(`${API_BASE}/health`, { method: 'GET' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

export async function getCapabilities(): Promise<SensorCapabilities> {
  try {
    const res = await fetch(`${API_BASE}/capabilities`, { method: 'GET' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch {
    return FALLBACK_CAPABILITIES;
  }
}

export async function getIncidents(filters?: {
  status?: string;
  ps_class?: string;
  severity?: string;
  limit?: number;
  offset?: number;
}): Promise<Incident[]> {
  const query = new URLSearchParams();
  if (filters?.status) query.set('status', filters.status);
  if (filters?.ps_class) query.set('ps_class', filters.ps_class);
  if (filters?.severity) query.set('severity', filters.severity);
  if (filters?.limit) query.set('limit', String(filters.limit));
  if (filters?.offset) query.set('offset', String(filters.offset));

  const url = `${API_BASE}/incidents${query.toString() ? `?${query.toString()}` : ''}`;
  const res = await fetch(url, { method: 'GET' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

export async function getIncident(incidentId: string): Promise<Incident> {
  const res = await fetch(`${API_BASE}/incidents/${encodeURIComponent(incidentId)}`, { method: 'GET' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

export function getExportJsonUrl(): string {
  return `${API_BASE}/export/json`;
}

export function getExportCsvUrl(): string {
  return `${API_BASE}/export/csv`;
}
