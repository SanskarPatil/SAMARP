import React, { useState, useEffect, useMemo } from 'react';
import { useIncidents } from './hooks/useIncidents';
import { Header } from './components/Header';
import { CapabilityBanner } from './components/CapabilityBanner';
import { IncidentFeed } from './components/IncidentFeed';
import { EvidenceDrawer } from './components/EvidenceDrawer';
import { DemoTourModal } from './components/DemoTourModal';
import { CyberGlobe } from './components/CyberGlobe';
import { Severity } from './types';
import { Globe2, ListFilter, ShieldCheck, Activity, Lock } from 'lucide-react';

const SEVERITY_ACCENTS: Record<Severity, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFO: '#38bdf8',
};

const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export const App: React.FC = () => {
  const {
    incidents,
    allIncidentsCount,
    selectedIncident,
    selectedIncidentId,
    setSelectedIncidentId,
    capabilities,
    health,
    connectionMode,
    isWsConnected,
    severityCounts,
    filters,
    isDemo,
    toggleDemoData,
    reconciliation,
  } = useIncidents();

  const [isTourOpen, setIsTourOpen] = useState(false);

  // Selected incident drives the focused accent used by the drawer and feed selection.
  useEffect(() => {
    const accent = selectedIncident ? SEVERITY_ACCENTS[selectedIncident.severity] : '#38bdf8';
    document.documentElement.style.setProperty('--severity-accent', accent);
  }, [selectedIncident]);

  // Highest live severity drives the ambient accent: globe atmosphere, rail, stage edges.
  const dominantSeverity = useMemo<Severity>(() => {
    let top: Severity = 'INFO';
    for (const inc of incidents) {
      if (SEVERITY_RANK[inc.severity] > SEVERITY_RANK[top]) top = inc.severity;
    }
    return top;
  }, [incidents]);

  useEffect(() => {
    document.documentElement.style.setProperty('--ambient-accent', SEVERITY_ACCENTS[dominantSeverity]);
    document.documentElement.dataset.ambient = dominantSeverity.toLowerCase();
  }, [dominantSeverity]);

  const handleSelectIncidentByClass = (psClass: string) => {
    const match = incidents.find((i) => i.ps_class === psClass);
    if (match) {
      setSelectedIncidentId(match.incident_id);
    }
  };

  const observedClasses = useMemo(() => {
    const set = new Set(incidents.map((i) => i.ps_class));
    return set.size;
  }, [incidents]);

  return (
    <div className="app-container">
      <aside className="rail" aria-label="Console sections">
        <div className="rail-mark" title="Cyber Sentinel">
          <ShieldCheck size={20} />
        </div>
        <nav className="rail-nav">
          <a className="rail-item active" href="#globe-stage" title="Threat globe">
            <Globe2 size={18} />
          </a>
          <a className="rail-item" href="#incident-feed" title="Incident feed">
            <ListFilter size={18} />
          </a>
          <a className="rail-item" href="#evidence-drawer" title="Evidence">
            <Activity size={18} />
          </a>
        </nav>
        <div className="rail-foot" title="Plane B accepts GET and WebSocket only">
          <Lock size={16} />
        </div>
      </aside>

      <div className="app-frame">
        <Header
          connectionMode={connectionMode}
          isWsConnected={isWsConnected}
          health={health}
          onOpenDemoTour={() => setIsTourOpen(true)}
          isDemo={isDemo}
          onToggleDemoData={toggleDemoData}
          reconciliation={reconciliation}
        />

        {isDemo && (
          <div className="demo-banner" role="alert" data-testid="demo-data-banner">
            <strong>DEMO DATA</strong>
            <span>Synthetic fixtures bundled with the dashboard, not from the sensor. The live feed is hidden while this is on.</span>
            <button className="btn btn-secondary" onClick={toggleDemoData}>Back to live feed</button>
          </div>
        )}

        <CapabilityBanner capabilities={capabilities} />

        <main className="console-layout">
          <section className="stage-pane" id="globe-stage">
            <div className="stage-shell">
              <CyberGlobe
                incidents={incidents}
                selectedIncidentId={selectedIncidentId}
                onSelectIncident={(id) => setSelectedIncidentId(id)}
                capabilities={capabilities}
                isLive={isWsConnected}
              />

              <div className="hud hud-topleft">
                <span className="hud-label">Incidents held</span>
                <span className="hud-value">{allIncidentsCount}</span>
                <span className="hud-foot">500-item ring buffer</span>
              </div>

              <div className="hud hud-topright">
                <span className="hud-label">Highest live severity</span>
                <span className={`hud-value sev-${dominantSeverity.toLowerCase()}`}>{dominantSeverity}</span>
                <span className="hud-foot">{severityCounts.CRITICAL} critical · {severityCounts.HIGH} high</span>
              </div>

              <div className="hud hud-bottomleft">
                <span className="hud-label">PS classes observed</span>
                <span className="hud-value">{observedClasses}<span className="hud-of"> / 6</span></span>
                <span className="hud-foot">Seven detector modules</span>
              </div>

              <div className="hud hud-bottomright">
                <span className="hud-label">Hash chain</span>
                <span className="hud-value">#{health?.chain_seq ?? 0}</span>
                <span className="hud-foot">{health?.total_updates ?? 0} chained updates</span>
              </div>
            </div>
          </section>

          <section className="feed-pane" id="incident-feed">
            <IncidentFeed
              incidents={incidents}
              totalCount={allIncidentsCount}
              selectedIncidentId={selectedIncidentId}
              onSelectIncident={(id) => setSelectedIncidentId(id)}
              severityCounts={severityCounts}
              isDemo={isDemo}
              filters={filters}
            />
          </section>

          <section className="drawer-pane" id="evidence-drawer">
            <EvidenceDrawer incident={selectedIncident} isDemo={isDemo} />
          </section>
        </main>
      </div>

      <DemoTourModal
        isOpen={isTourOpen}
        onClose={() => setIsTourOpen(false)}
        onSelectIncidentByClass={handleSelectIncidentByClass}
      />
    </div>
  );
};

export default App;
