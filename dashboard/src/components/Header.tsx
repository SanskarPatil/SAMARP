import React from 'react';
import { ConnectionMode, SystemHealth } from '../types';
import { Reconciliation } from '../services/incidentStore';
import { getExportJsonUrl, getExportCsvUrl } from '../services/api';
import { Radio, Database, Download, FileSpreadsheet, PlayCircle, FlaskConical, ShieldCheck, Scale, WifiOff } from 'lucide-react';

interface HeaderProps {
  connectionMode: ConnectionMode;
  isWsConnected: boolean;
  health: SystemHealth | null;
  onOpenDemoTour: () => void;
  isDemo: boolean;
  onToggleDemoData: () => void;
  reconciliation: Reconciliation;
}

export const Header: React.FC<HeaderProps> = ({
  connectionMode,
  isWsConnected,
  health,
  onOpenDemoTour,
  isDemo,
  onToggleDemoData,
  reconciliation,
}) => {
  const feedLabel = isDemo
    ? 'DEMO DATA'
    : isWsConnected
      ? 'LIVE FEED'
      : connectionMode === 'FIXTURE'
        ? 'DEMO DATA'
        : 'REPLAY MODE';

  const reconChip = (() => {
    if (isDemo) return null;
    if (!health) {
      return (
        <div className="status-chip offline" title="GET /health is unreachable. The live feed shows only what the API delivered.">
          <WifiOff size={13} />
          <span>API OFFLINE</span>
        </div>
      );
    }
    if (reconciliation.state === 'unknown') return null;
    const ok = reconciliation.state === 'match' || reconciliation.state === 'capped';
    const text =
      reconciliation.state === 'match'
        ? `FEED ${reconciliation.feed} = API ${reconciliation.api}`
        : reconciliation.state === 'capped'
          ? `FEED ${reconciliation.feed} (ring cap) / API ${reconciliation.api}`
          : `FEED ${reconciliation.feed} ≠ API ${reconciliation.api}`;
    return (
      <div
        className={`status-chip ${ok ? 'recon-ok' : 'recon-bad'}`}
        data-testid="feed-api-reconciliation"
        title="Incidents shown in the live feed vs total_incidents reported by GET /health"
      >
        <Scale size={13} />
        <span>{text}</span>
      </div>
    );
  })();

  return (
    <header className="topbar">
      <div className="topbar-identity">
        <span className="wordmark">CYBER SENTINEL</span>
        <span className="wordmark-rule" aria-hidden="true" />
        <span className="wordmark-sub">Unidirectional Threat Monitor</span>
        <span className="spec-badge">PS26145</span>
      </div>

      <div className="topbar-status">
        <div className={`status-chip ${isDemo ? 'demo' : isWsConnected ? 'live' : 'replay'}`}>
          <Radio size={13} className={isWsConnected ? 'pulse' : ''} />
          <span>{feedLabel}</span>
        </div>

        <div
          className="status-chip readonly"
          title="Plane B serves GET and WebSocket only. No mutating route and no return path across the boundary exist."
        >
          <ShieldCheck size={13} />
          <span>READ-ONLY</span>
        </div>

        {reconChip}

        {health && !isDemo && (
          <div className="status-chip chain" title="Cryptographically chained sequence count in the SQLite store">
            <Database size={13} />
            <span>CHAIN #{health.chain_seq}</span>
          </div>
        )}
      </div>

      <div className="topbar-actions">
        <a
          href={getExportJsonUrl()}
          download="incidents_hash_chain.json"
          className="btn btn-secondary"
          title="Download the complete lossless hash chain as canonical JSON"
        >
          <Download size={14} />
          <span>JSON chain</span>
        </a>

        <a
          href={getExportCsvUrl()}
          download="incidents.csv"
          className="btn btn-secondary"
          title="Download flattened incidents as CSV"
        >
          <FileSpreadsheet size={14} />
          <span>CSV</span>
        </a>

        <button
          onClick={onToggleDemoData}
          className={`btn ${isDemo ? 'btn-demo-on' : 'btn-secondary'}`}
          aria-pressed={isDemo}
          title={isDemo ? 'Return to the live read-only feed' : 'Show bundled synthetic fixtures instead of the live feed'}
        >
          <FlaskConical size={14} />
          <span>{isDemo ? 'Demo data: ON' : 'Demo data: OFF'}</span>
        </button>

        <button onClick={onOpenDemoTour} className="btn btn-primary" title="Open the guided walkthrough">
          <PlayCircle size={15} />
          <span>Walkthrough</span>
        </button>
      </div>
    </header>
  );
};
