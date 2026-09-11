import React from 'react';
import { Incident, PSClass, Severity } from '../types';
import { IncidentRow } from './IncidentRow';
import { Search, Filter, ShieldAlert, AlertTriangle, AlertCircle, Info, CheckCircle2 } from 'lucide-react';

interface IncidentFeedProps {
  incidents: Incident[];
  totalCount: number;
  selectedIncidentId: string | null;
  onSelectIncident: (id: string) => void;
  severityCounts: Record<Severity, number>;
  filters: {
    psClassFilter: string | null;
    setPsClassFilter: (val: string | null) => void;
    severityFilter: string | null;
    setSeverityFilter: (val: string | null) => void;
    statusFilter: string | null;
    setStatusFilter: (val: string | null) => void;
    searchQuery: string;
    setSearchQuery: (val: string) => void;
  };
}

const PS_CLASSES: PSClass[] = [
  'Volumetric DDoS / flooding',
  'Port scanning / reconnaissance',
  'Botnet C2 beaconing',
  'DGA / DNS tunnelling',
  'Malware in encrypted sessions',
  'Data exfiltration',
];

export const IncidentFeed: React.FC<IncidentFeedProps> = ({
  incidents,
  totalCount,
  selectedIncidentId,
  onSelectIncident,
  severityCounts,
  filters,
}) => {
  const {
    psClassFilter,
    setPsClassFilter,
    severityFilter,
    setSeverityFilter,
    statusFilter,
    setStatusFilter,
    searchQuery,
    setSearchQuery,
  } = filters;

  return (
    <div className="feed-container">
      {/* Severity Counters Bar */}
      <div className="severity-summary-bar">
        <div className="summary-card total" onClick={() => setSeverityFilter(null)}>
          <span className="summary-label">TOTAL</span>
          <span className="summary-value">{totalCount}</span>
        </div>
        <div
          className={`summary-card critical ${severityFilter === 'CRITICAL' ? 'active' : ''}`}
          onClick={() => setSeverityFilter(severityFilter === 'CRITICAL' ? null : 'CRITICAL')}
        >
          <div className="summary-header">
            <ShieldAlert size={12} />
            <span className="summary-label">CRITICAL</span>
          </div>
          <span className="summary-value">{severityCounts.CRITICAL}</span>
        </div>
        <div
          className={`summary-card high ${severityFilter === 'HIGH' ? 'active' : ''}`}
          onClick={() => setSeverityFilter(severityFilter === 'HIGH' ? null : 'HIGH')}
        >
          <div className="summary-header">
            <AlertTriangle size={12} />
            <span className="summary-label">HIGH</span>
          </div>
          <span className="summary-value">{severityCounts.HIGH}</span>
        </div>
        <div
          className={`summary-card medium ${severityFilter === 'MEDIUM' ? 'active' : ''}`}
          onClick={() => setSeverityFilter(severityFilter === 'MEDIUM' ? null : 'MEDIUM')}
        >
          <div className="summary-header">
            <AlertCircle size={12} />
            <span className="summary-label">MEDIUM</span>
          </div>
          <span className="summary-value">{severityCounts.MEDIUM}</span>
        </div>
        <div
          className={`summary-card low ${severityFilter === 'LOW' ? 'active' : ''}`}
          onClick={() => setSeverityFilter(severityFilter === 'LOW' ? null : 'LOW')}
        >
          <div className="summary-header">
            <Info size={12} />
            <span className="summary-label">LOW</span>
          </div>
          <span className="summary-value">{severityCounts.LOW}</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="filter-controls-bar">
        <div className="search-box">
          <Search size={14} className="search-icon" />
          <input
            type="text"
            placeholder="Search incident ID, IP, threat class, evidence..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
          {searchQuery && (
            <button className="clear-btn" onClick={() => setSearchQuery('')}>
              &times;
            </button>
          )}
        </div>

        <div className="dropdown-group">
          <div className="select-wrapper">
            <Filter size={12} />
            <select
              value={statusFilter || ''}
              onChange={(e) => setStatusFilter(e.target.value || null)}
            >
              <option value="">All Statuses</option>
              <option value="NEW">NEW</option>
              <option value="ACTIVE">ACTIVE</option>
              <option value="UPDATED">UPDATED</option>
              <option value="RESOLVED">RESOLVED</option>
            </select>
          </div>

          <div className="select-wrapper">
            <select
              value={severityFilter || ''}
              onChange={(e) => setSeverityFilter(e.target.value || null)}
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
              <option value="INFO">INFO</option>
            </select>
          </div>
        </div>
      </div>

      {/* PS Threat Class Pills */}
      <div className="threat-class-pills">
        <button
          className={`class-pill ${psClassFilter === null ? 'active' : ''}`}
          onClick={() => setPsClassFilter(null)}
        >
          All Classes ({totalCount})
        </button>
        {PS_CLASSES.map((cls) => (
          <button
            key={cls}
            className={`class-pill ${psClassFilter === cls ? 'active' : ''}`}
            onClick={() => setPsClassFilter(psClassFilter === cls ? null : cls)}
          >
            {cls}
          </button>
        ))}
      </div>

      {/* Incident List */}
      <div className="incident-list-viewport">
        {incidents.length === 0 ? (
          <div className="empty-feed">
            <CheckCircle2 size={32} className="text-slate-500 mb-2" />
            <p className="empty-title">No matching incidents observed</p>
            <p className="empty-subtitle">
              Passive sensor is monitoring. Adjust active filters or click &quot;Demo Data&quot; in the header.
            </p>
          </div>
        ) : (
          incidents.map((inc) => (
            <IncidentRow
              key={inc.incident_id}
              incident={inc}
              isSelected={inc.incident_id === selectedIncidentId}
              onSelect={() => onSelectIncident(inc.incident_id)}
            />
          ))
        )}
      </div>
    </div>
  );
};
