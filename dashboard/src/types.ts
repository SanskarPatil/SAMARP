/**
 * TypeScript interface contracts mirroring schemas/alert.schema.json and normalized_event.schema.json.
 */

export type PSClass =
  | 'Volumetric DDoS / flooding'
  | 'Port scanning / reconnaissance'
  | 'Botnet C2 beaconing'
  | 'DGA / DNS tunnelling'
  | 'Malware in encrypted sessions'
  | 'Data exfiltration';

export type FlowRefType = 'flow_5tuple' | 'aggregate' | 'entity';

export type ScoreType = 'robust_z' | 'anomaly_score' | 'model_probability' | 'rule_score';

export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type IncidentStatus = 'NEW' | 'ACTIVE' | 'UPDATED' | 'RESOLVED';

export type CapabilityStateValue = 'OBSERVABLE' | 'DEGRADED' | 'NOT_OBSERVABLE';

export interface AlertCapability {
  detector_state: CapabilityStateValue;
  input_mode: string;
  missing_evidence?: string[];
  sampled?: boolean | null;
  sampling_rate?: number | null;
}

export interface IncidentEvidence {
  interpretation?: string;
  dst_ip?: string;
  dst_port?: number;
  src_ip?: string;
  src_port?: number;
  packet_rate?: number;
  byte_rate?: number;
  syn_ratio?: number;
  ports_probed?: number;
  scan_type?: string;
  iat_median?: number;
  iat_cv?: number;
  iat_p95?: number;
  intervals_observed?: number;
  domain?: string;
  qtype_distribution?: Record<string, number>;
  query_length_mean?: number;
  entropy_mean?: number;
  ja3?: string | null;
  ja3s?: string | null;
  ja4?: string | null;
  server_name?: string | null;
  packet_size_first_n?: number[] | null;
  direction_first_n?: string[] | null;
  bytes_out?: number;
  bytes_in?: number;
  byte_ratio?: number;
  half_open_concurrency?: number | null;
  connection_duration_p95?: number | null;
  bytes_per_connection?: number | null;
  reserved_source_share?: number | null;
  [key: string]: any;
}

export interface Incident {
  schema_version: string;
  timestamp: string;
  observed_time?: string;
  flow_id: string;
  flow_ref_type: FlowRefType;
  contributing_flow_ids?: string[];
  ps_class: PSClass;
  threat_class: string;
  detector: string;
  confidence: number | null;
  score: number | null;
  score_type: ScoreType;
  calibrated: boolean;
  evidence: IncidentEvidence;
  baseline?: Record<string, any> | null;
  threshold?: Record<string, any> | null;
  window?: {
    start?: string;
    end?: string;
    duration_s?: number;
  } | null;
  incident_id: string;
  dedup_key?: string | null;
  status: IncidentStatus;
  severity: Severity;
  first_observed?: string | null;
  last_observed?: string | null;
  event_count?: number | null;
  capability: AlertCapability;
  sensor?: {
    suricata_version?: string | null;
    kernel_drops?: number | null;
    sensor_drop_pct?: number | null;
    is_lower_bound?: boolean | null;
  } | null;
  model_version?: string | null;
  intel_version?: string | null;
  latency_ms?: number | null;
  recommendation?: string | null;
  seq?: number | null;
  prev_hash?: string | null;
  entry_hash?: string | null;
  payload_hash?: string | null;
}

export interface SensorCapabilities {
  input_mode: string;
  ipv4?: CapabilityStateValue;
  ipv6?: CapabilityStateValue;
  dns_names?: CapabilityStateValue;
  dns_responses?: CapabilityStateValue;
  tls_handshake?: CapabilityStateValue;
  quic_metadata?: CapabilityStateValue;
  ja3?: CapabilityStateValue;
  ja3s?: CapabilityStateValue;
  ja4?: CapabilityStateValue;
  flow_records?: CapabilityStateValue;
  flow_sampling?: CapabilityStateValue;
  geo?: CapabilityStateValue;
  capture_loss?: CapabilityStateValue;
  bidirectional_visibility?: CapabilityStateValue;
  [key: string]: any;
}

export interface SystemHealth {
  status: string;
  read_only: boolean;
  uptime_seconds: number;
  total_incidents: number;
  total_updates: number;
  chain_seq: number;
  input_mode: string;
  timestamp?: string;
}

export type ConnectionMode = 'LIVE' | 'REPLAY' | 'FIXTURE';
