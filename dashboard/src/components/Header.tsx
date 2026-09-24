import React from 'react';
import { ConnectionMode, SystemHealth } from '../types';
import { getExportJsonUrl, getExportCsvUrl } from '../services/api';
import { Radio, Database, Download, FileSpreadsheet, PlayCircle, RefreshCw, ShieldCheck } from 'lucide-react';

interface HeaderProps {
  connectionMode: ConnectionMode;
  isWsConnected: boolean;
  health: SystemHealth | null;
  onOpenDemoTour: () => void;
  onLoadMockFixtures: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  connectionMode,
  isWsConnected,
  health,
  onOpenDemoTour,
  onLoadMockFixtures,
}) => {
  const feedLabel = isWsConnected
    ? 'LIVE FEED'
    : connectionMode === 'FIXTURE'
      ? 'DEMO FIXTURES'
      : 'REPLAY MODE';

  return (
    <header className="topbar">
      <div className="topbar-identity">
        <span className="wordmark">CYBER SENTINEL</span>
        <span className="wordmark-rule" aria-hidden="true" />
        <span className="wordmark-sub">Unidirectional Threat Monitor</span>
        <span className="spec-badge">PS26145</span>
      </div>

      <div className="topbar-status">
        <div className={`status-chip ${isWsConnected ? 'live' : 'replay'}`}>
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

        {health && (
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
          onClick={onLoadMockFixtures}
          className="btn btn-secondary"
          title="Load the canonical demo fixtures"
        >
          <RefreshCw size={14} />
          <span>Demo data</span>
        </button>

        <button onClick={onOpenDemoTour} className="btn btn-primary" title="Open the guided walkthrough">
          <PlayCircle size={15} />
          <span>Walkthrough</span>
        </button>
      </div>
    </header>
  );
};
