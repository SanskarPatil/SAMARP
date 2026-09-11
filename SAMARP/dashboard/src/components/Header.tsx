import React from 'react';
import { ConnectionMode, SystemHealth } from '../types';
import { getExportJsonUrl, getExportCsvUrl } from '../services/api';
import { Shield, Radio, Database, Download, FileSpreadsheet, PlayCircle, RefreshCw } from 'lucide-react';

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
  return (
    <header className="header-container">
      <div className="header-left">
        <div className="logo-group">
          <Shield className="logo-icon text-sky-400" size={28} />
          <div>
            <div className="title-row">
              <span className="app-title">CYBER SENTINEL</span>
              <span className="spec-badge">PS26145</span>
            </div>
            <div className="subtitle">Passive Network Threat Intelligence & Monitoring Console</div>
          </div>
        </div>

        {/* Plane B Read-Only & Live Status Badges */}
        <div className="status-badge-group">
          <div className={`status-badge ${isWsConnected ? 'live' : 'replay'}`}>
            <Radio size={14} className={isWsConnected ? 'pulse' : ''} />
            <span>{isWsConnected ? 'LIVE FEED' : connectionMode === 'FIXTURE' ? 'DEMO FIXTURES' : 'REPLAY MODE'}</span>
          </div>

          <div className="read-only-badge" title="Plane B strictly permits GET and WebSocket. No return path or mutating routes exist.">
            <span className="dot bg-emerald-400"></span>
            <span>PLANE B: READ-ONLY</span>
          </div>

          {health && (
            <div className="health-stat" title="Cryptographically chained sequence count across SQLite store">
              <Database size={13} />
              <span>Chain Seq: #{health.chain_seq}</span>
            </div>
          )}
        </div>
      </div>

      <div className="header-right">
        {/* Export Buttons */}
        <div className="action-button-group">
          <a
            href={getExportJsonUrl()}
            download="incidents_hash_chain.json"
            className="btn btn-secondary"
            title="Download complete lossless hash chain in canonical JSON format"
          >
            <Download size={14} />
            <span>Export JSON (Chain)</span>
          </a>

          <a
            href={getExportCsvUrl()}
            download="incidents.csv"
            className="btn btn-secondary"
            title="Download flattened incident spreadsheet in CSV format"
          >
            <FileSpreadsheet size={14} />
            <span>Export CSV</span>
          </a>

          <button
            onClick={onLoadMockFixtures}
            className="btn btn-secondary"
            title="Reset and load canonical V6.3 demo fixtures"
          >
            <RefreshCw size={14} />
            <span>Demo Data</span>
          </button>

          <button
            onClick={onOpenDemoTour}
            className="btn btn-primary"
            title="Launch 7-minute hackathon judge walkthrough"
          >
            <PlayCircle size={15} />
            <span>7-Min Demo Tour</span>
          </button>
        </div>
      </div>
    </header>
  );
};
