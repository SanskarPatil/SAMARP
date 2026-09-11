import React from 'react';
import { SensorCapabilities, CapabilityStateValue } from '../types';
import { Eye, AlertTriangle, EyeOff, Info } from 'lucide-react';

interface CapabilityBannerProps {
  capabilities: SensorCapabilities;
}

export const CapabilityBanner: React.FC<CapabilityBannerProps> = ({ capabilities }) => {
  const fields: { key: keyof SensorCapabilities; label: string }[] = [
    { key: 'ipv4', label: 'IPv4' },
    { key: 'ipv6', label: 'IPv6' },
    { key: 'dns_names', label: 'DNS Names' },
    { key: 'tls_handshake', label: 'TLS Handshake' },
    { key: 'quic_metadata', label: 'QUIC Meta' },
    { key: 'ja3', label: 'JA3' },
    { key: 'ja3s', label: 'JA3S' },
    { key: 'ja4', label: 'JA4' },
    { key: 'flow_records', label: 'Flow Records' },
    { key: 'capture_loss', label: 'Loss Tracker' },
    { key: 'bidirectional_visibility', label: 'Bidirectional' },
  ];

  const getStatusBadge = (state: CapabilityStateValue | undefined) => {
    switch (state) {
      case 'OBSERVABLE':
        return (
          <span className="cap-pill observable" title="Feature is actively observable by the sensor">
            <Eye size={11} /> Observable
          </span>
        );
      case 'DEGRADED':
        return (
          <span className="cap-pill degraded" title="Feature is degraded or sampled">
            <AlertTriangle size={11} /> Degraded
          </span>
        );
      case 'NOT_OBSERVABLE':
      default:
        return (
          <span className="cap-pill not-observable" title="Feature is not observable from this input mode">
            <EyeOff size={11} /> Not Observable
          </span>
        );
    }
  };

  return (
    <div className="capability-banner">
      <div className="capability-header">
        <div className="capability-mode">
          <span className="mode-label">INPUT CONTRACT:</span>
          <span className="mode-value">{(capabilities.input_mode || 'pcap_replay').toUpperCase()}</span>
        </div>
        <div className="capability-policy" title="PS26145 Section 14: Passive inspection only, zero decryption.">
          <Info size={13} className="text-sky-400" />
          <span>Passive metadata analysis &bull; Zero payload decryption &bull; Unobservable features declared explicitly</span>
        </div>
      </div>

      <div className="capability-grid">
        {fields.map(({ key, label }) => {
          const state = capabilities[key] as CapabilityStateValue | undefined;
          return (
            <div key={key} className="cap-item">
              <span className="cap-label">{label}:</span>
              {getStatusBadge(state)}
            </div>
          );
        })}
      </div>
    </div>
  );
};
