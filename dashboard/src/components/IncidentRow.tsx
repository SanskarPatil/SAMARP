import React from 'react';
import { Incident } from '../types';
import { CALIBRATION_LABEL, formatConfidence, formatRawScore } from '../services/scoreFormat';
import { ShieldAlert, AlertCircle, Clock, Hash, Layers } from 'lucide-react';

interface IncidentRowProps {
  incident: Incident;
  isSelected: boolean;
  onSelect: () => void;
  isDemo?: boolean;
}

export const IncidentRow: React.FC<IncidentRowProps> = ({ incident, isSelected, onSelect, isDemo = false }) => {
  const {
    incident_id,
    ps_class,
    threat_class,
    severity,
    status,
    event_count,
    score,
    score_type,
    calibrated,
    evidence,
    flow_id,
    flow_ref_type,
    last_observed,
    timestamp,
  } = incident;

  // Extract concise key metric for quick operator scanning
  const getKeyMetric = () => {
    if (evidence.packet_rate) return `${evidence.packet_rate.toLocaleString()} pps`;
    if (evidence.ports_probed) return `${evidence.ports_probed} ports scanned`;
    if (evidence.iat_cv !== undefined) return `Periodicity CV: ${evidence.iat_cv}`;
    if (evidence.domain) return `Domain: ${evidence.domain.slice(0, 24)}...`;
    if (evidence.ja3) return `JA3: ${evidence.ja3.slice(0, 10)}...`;
    if (evidence.byte_ratio) return `Out/In Ratio: ${evidence.byte_ratio}x`;
    if (evidence.interpretation) return evidence.interpretation.slice(0, 36) + '...';
    return `Score: ${score ?? 'N/A'}`;
  };

  const formatTime = (tsStr?: string | null) => {
    if (!tsStr) return '--:--:--';
    try {
      const dt = new Date(tsStr);
      return dt.toLocaleTimeString();
    } catch {
      return tsStr.slice(11, 19);
    }
  };

  return (
    <div
      onClick={onSelect}
      className={`incident-row ${isSelected ? 'selected' : ''} severity-${severity.toLowerCase()}`}
    >
      <div className="incident-row-main">
        {/* Severity Badge */}
        <div className={`severity-badge ${severity.toLowerCase()}`}>
          {severity === 'CRITICAL' ? <ShieldAlert size={13} /> : <AlertCircle size={13} />}
          <span>{severity}</span>
        </div>

        {/* Threat Class & Key Details */}
        <div className="incident-info">
          <div className="ps-class-title">
            {isDemo && <span className="demo-tag" title="Synthetic demo fixture, not a detection">DEMO</span>}
            {ps_class}
          </div>
          <div className="threat-subline">
            <span className="threat-class-tag">{threat_class}</span>
            <span className="key-metric-tag">{getKeyMetric()}</span>
          </div>
        </div>

        {/* Confidence or Anomaly Score (Strict formatting) */}
        <div className="score-display">
          <div
            className={calibrated ? 'calibrated-confidence' : 'uncalibrated-score'}
            title={`Confidence ${formatConfidence(incident)} (${CALIBRATION_LABEL[incident.calibrated_on ?? 'uncalibrated']}); raw ${score_type} ${formatRawScore(score, score_type)}`}
          >
            <span className="score-number">{formatConfidence(incident)}</span>
            <span className="score-label">{calibrated ? 'calibrated' : 'uncal. conf'}</span>
          </div>
        </div>

        {/* Status Pill */}
        <div className="status-col">
          <span className={`status-pill status-${status.toLowerCase()}`}>{status}</span>
          {event_count && event_count > 1 && (
            <span className="event-count-badge" title="Accumulated observation count">
              <Layers size={10} /> {event_count}
            </span>
          )}
        </div>

        {/* Identity & Timestamp */}
        <div className="meta-col">
          <div className="time-display" title={`Timestamp: ${last_observed || timestamp}`}>
            <Clock size={11} />
            <span>{formatTime(last_observed || timestamp)}</span>
          </div>
          <div className="id-display" title={`Incident ID: ${incident_id} | Flow: ${flow_id} (${flow_ref_type})`}>
            <Hash size={10} />
            <span>{incident_id.slice(0, 8)}</span>
          </div>
        </div>
      </div>
    </div>
  );
};
