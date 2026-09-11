import React, { useState } from 'react';
import { Incident } from '../types';
import {
  ShieldAlert,
  Copy,
  Check,
  Clock,
  Eye,
  AlertTriangle,
  EyeOff,
  FileCheck2,
  Lock,
  Layers,
  HelpCircle,
} from 'lucide-react';

interface EvidenceDrawerProps {
  incident: Incident | null;
  onClose?: () => void;
}

export const EvidenceDrawer: React.FC<EvidenceDrawerProps> = ({ incident }) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  if (!incident) {
    return (
      <div className="drawer-container empty">
        <HelpCircle size={40} className="text-slate-600 mb-3" />
        <p className="text-slate-400 font-medium">Select an incident to view evidence</p>
        <p className="text-slate-500 text-xs mt-1">Real-time feature values, baseline, thresholds, and hash chain</p>
      </div>
    );
  }

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const {
    incident_id,
    ps_class,
    threat_class,
    detector,
    status,
    severity,
    confidence,
    score,
    score_type,
    calibrated,
    evidence,
    baseline,
    threshold,
    capability,
    first_observed,
    last_observed,
    event_count,
    flow_id,
    flow_ref_type,
    recommendation,
    seq,
    prev_hash,
    entry_hash,
    payload_hash,
    latency_ms,
  } = incident;

  // Filter out interpretation for the feature table
  const featureEntries = Object.entries(evidence || {}).filter(([k]) => k !== 'interpretation');

  return (
    <div className="drawer-container">
      {/* Header */}
      <div className="drawer-header">
        <div className="drawer-title-group">
          <div className={`severity-tag ${severity.toLowerCase()}`}>
            <ShieldAlert size={14} />
            <span>{severity}</span>
          </div>
          <span className={`status-pill status-${status.toLowerCase()}`}>{status}</span>
          <span className="detector-tag">{detector} module</span>
        </div>

        <h2 className="drawer-incident-title">{ps_class}</h2>
        <div className="threat-label">Internal: <code>{threat_class}</code></div>

        {/* Identity & Timestamps */}
        <div className="drawer-meta-grid">
          <div className="meta-card">
            <span className="meta-card-label">Incident ID (16-hex)</span>
            <div className="meta-card-val">
              <code>{incident_id}</code>
              <button
                className="copy-btn"
                onClick={() => copyToClipboard(incident_id, 'inc_id')}
                title="Copy Incident ID"
              >
                {copiedKey === 'inc_id' ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
              </button>
            </div>
          </div>

          <div className="meta-card">
            <span className="meta-card-label">Flow ID ({flow_ref_type})</span>
            <div className="meta-card-val">
              <code>{flow_id}</code>
              <button
                className="copy-btn"
                onClick={() => copyToClipboard(flow_id, 'flow_id')}
                title="Copy Flow ID"
              >
                {copiedKey === 'flow_id' ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
              </button>
            </div>
          </div>

          <div className="meta-card">
            <span className="meta-card-label">Observations</span>
            <div className="meta-card-val">
              <Layers size={12} className="text-slate-400 mr-1" />
              <span>{event_count || 1} events collapsed</span>
            </div>
          </div>

          <div className="meta-card">
            <span className="meta-card-label">Observed Window</span>
            <div className="meta-card-val text-xs" title={`From ${first_observed || 'N/A'} to ${last_observed || 'N/A'}`}>
              <Clock size={12} className="text-slate-400 mr-1" />
              <span>{last_observed ? new Date(last_observed).toLocaleTimeString() : '--:--:--'}</span>
            </div>
          </div>
        </div>
      </div>

      <div className="drawer-body">
        {/* Interpretation Box */}
        {evidence.interpretation && (
          <div className="drawer-section interpretation-box">
            <div className="section-title">Detection Rationale</div>
            <p className="interpretation-text">{evidence.interpretation}</p>
          </div>
        )}

        {/* Confidence / Score Breakdown */}
        <div className="drawer-section">
          <div className="section-title">Detector Scoring Contract</div>
          <div className="score-box">
            <div className="score-main">
              {calibrated && confidence !== null ? (
                <>
                  <span className="score-val text-emerald-400">{(confidence * 100).toFixed(1)}%</span>
                  <div className="score-meta">
                    <span className="score-type-badge calibrated">Calibrated Probability</span>
                    <span className="score-note">Model-calibrated against offline holdout corpus</span>
                  </div>
                </>
              ) : (
                <>
                  <span className="score-val text-amber-400">{score !== null ? score.toFixed(1) : 'N/A'}</span>
                  <div className="score-meta">
                    <span className="score-type-badge uncalibrated">{score_type}</span>
                    <span className="score-note">Risk / anomaly metric (Uncalibrated &bull; No percent sign)</span>
                  </div>
                </>
              )}
            </div>
            {latency_ms !== null && latency_ms !== undefined && (
              <div className="latency-indicator" title="Measured observation-to-emission latency (SLO p95 < 2000 ms)">
                <span>Detection Latency:</span> <strong>{latency_ms.toFixed(1)} ms</strong>
              </div>
            )}
          </div>
        </div>

        {/* Observed Features Table */}
        <div className="drawer-section">
          <div className="section-title">Observed Feature Values</div>
          <div className="features-table-container">
            <table className="features-table">
              <thead>
                <tr>
                  <th>Feature Name</th>
                  <th>Observed Value</th>
                </tr>
              </thead>
              <tbody>
                {featureEntries.map(([key, val]) => (
                  <tr key={key}>
                    <td className="font-mono text-xs text-slate-300">{key}</td>
                    <td className="font-mono text-xs text-sky-300">
                      {typeof val === 'object' && val !== null ? JSON.stringify(val) : String(val)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Baseline & Threshold Comparison */}
        {(baseline || threshold) && (
          <div className="drawer-section">
            <div className="section-title">Baseline Comparison & Thresholds</div>
            <div className="comparison-grid">
              {baseline && (
                <div className="comparison-card">
                  <div className="comparison-card-title">Benign Baseline Reference</div>
                  <pre className="comparison-pre">{JSON.stringify(baseline, null, 2)}</pre>
                </div>
              )}
              {threshold && (
                <div className="comparison-card">
                  <div className="comparison-card-title">Enforced Threshold (thresholds.yaml)</div>
                  <pre className="comparison-pre">{JSON.stringify(threshold, null, 2)}</pre>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Observability Limitation Axis */}
        <div className="drawer-section">
          <div className="section-title">Capability & Visibility Limitations</div>
          <div className={`capability-card ${capability.detector_state.toLowerCase()}`}>
            <div className="capability-card-header">
              <span className="cap-icon">
                {capability.detector_state === 'OBSERVABLE' && <Eye size={16} className="text-emerald-400" />}
                {capability.detector_state === 'DEGRADED' && <AlertTriangle size={16} className="text-amber-400" />}
                {capability.detector_state === 'NOT_OBSERVABLE' && <EyeOff size={16} className="text-rose-400" />}
              </span>
              <span className="cap-state-text">State: {capability.detector_state}</span>
              <span className="cap-input-text font-mono">({capability.input_mode})</span>
            </div>
            {capability.missing_evidence && capability.missing_evidence.length > 0 ? (
              <div className="missing-evidence-box">
                <span className="missing-label">Declared Missing Evidence:</span>
                <div className="missing-pills">
                  {capability.missing_evidence.map((item) => (
                    <span key={item} className="missing-pill">
                      {item}
                    </span>
                  ))}
                </div>
                <p className="missing-policy-note">
                  PS26145 Rule: Missing evidence is never masked as benign. Visibility limitations are surfaced to the operator.
                </p>
              </div>
            ) : (
              <p className="all-observable-note">All required detector features are fully observable on this input path.</p>
            )}
          </div>
        </div>

        {/* Cryptographic Hash Chain Audit */}
        <div className="drawer-section">
          <div className="section-title">Cryptographic Tamper-Evident Hash Chain</div>
          <div className="hash-chain-card">
            <div className="hash-chain-header">
              <FileCheck2 size={16} className="text-emerald-400 mr-2" />
              <span className="font-semibold text-emerald-400">Tamper-Evident Chain Entry</span>
              <span className="hash-chain-seq">Seq: #{seq ?? 1}</span>
            </div>

            <div className="hash-field">
              <span className="hash-label">Entry Hash (prev_hash || seq || id || time || payload):</span>
              <code className="hash-val" title={entry_hash || ''}>
                {entry_hash ? `${entry_hash.slice(0, 16)}...${entry_hash.slice(-16)}` : 'Generating...'}
              </code>
            </div>

            <div className="hash-field">
              <span className="hash-label">Payload Hash (sha256 canonical JSON):</span>
              <code className="hash-val" title={payload_hash || ''}>
                {payload_hash ? `${payload_hash.slice(0, 16)}...${payload_hash.slice(-16)}` : 'Generating...'}
              </code>
            </div>

            <div className="hash-field">
              <span className="hash-label">Previous Link Hash:</span>
              <code className="hash-val" title={prev_hash || ''}>
                {prev_hash ? `${prev_hash.slice(0, 16)}...${prev_hash.slice(-16)}` : 'Genesis'}
              </code>
            </div>

            <div className="hash-verified-note">
              <Lock size={12} className="text-emerald-400 mr-1 inline" />
              <span>Exportable via GET /export/json &bull; Verifiable with standalone tests/verify_hash_chain.py</span>
            </div>
          </div>
        </div>

        {/* Advisory Guidance */}
        <div className="drawer-section">
          <div className="section-title">Advisory Operator Recommendation</div>
          <div className="advisory-card">
            <p className="advisory-text">
              {recommendation || 'ADVISORY TEXT ONLY. Investigate affected host and review network telemetry.'}
            </p>
            <div className="advisory-disclaimer">
              <strong>MANDATORY SYSTEM NOTICE:</strong> PASSIVE MONITORING ONLY. There is no automated mitigation button,
              command, or active return path anywhere in the system.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
