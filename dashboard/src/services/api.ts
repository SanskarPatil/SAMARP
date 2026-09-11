import { Incident, SensorCapabilities, SystemHealth } from '../types';

const API_BASE = '';

export const FALLBACK_CAPABILITIES: SensorCapabilities = {
  input_mode: 'pcap_replay',
  ipv4: 'OBSERVABLE',
  ipv6: 'OBSERVABLE',
  dns_names: 'OBSERVABLE',
  dns_responses: 'OBSERVABLE',
  tls_handshake: 'OBSERVABLE',
  quic_metadata: 'OBSERVABLE',
  ja3: 'OBSERVABLE',
  ja3s: 'OBSERVABLE',
  ja4: 'OBSERVABLE',
  flow_records: 'NOT_OBSERVABLE',
  flow_sampling: 'NOT_OBSERVABLE',
  geo: 'NOT_OBSERVABLE',
  capture_loss: 'OBSERVABLE',
  bidirectional_visibility: 'OBSERVABLE',
};

export async function getHealth(): Promise<SystemHealth> {
  try {
    const res = await fetch(`${API_BASE}/health`, { method: 'GET' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch {
    return {
      status: 'offline_mock',
      read_only: true,
      uptime_seconds: 0,
      total_incidents: 6,
      total_updates: 6,
      chain_seq: 6,
      input_mode: 'pcap_replay',
    };
  }
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
