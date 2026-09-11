import React, { useState, useEffect } from 'react';
import { useIncidents } from './hooks/useIncidents';
import { Header } from './components/Header';
import { CapabilityBanner } from './components/CapabilityBanner';
import { IncidentFeed } from './components/IncidentFeed';
import { EvidenceDrawer } from './components/EvidenceDrawer';
import { DemoTourModal } from './components/DemoTourModal';

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
    loadMockFixtures,
  } = useIncidents();

  const [isTourOpen, setIsTourOpen] = useState(false);

  // Maintain single CSS severity accent variable per V6.3 section 15.4
  useEffect(() => {
    if (selectedIncident) {
      const severity = selectedIncident.severity.toLowerCase();
      let accentColor = '#38bdf8'; // info / default sky
      if (severity === 'critical') accentColor = '#ef4444'; // red
      else if (severity === 'high') accentColor = '#f97316'; // orange
      else if (severity === 'medium') accentColor = '#eab308'; // yellow
      else if (severity === 'low') accentColor = '#3b82f6'; // blue

      document.documentElement.style.setProperty('--severity-accent', accentColor);
    }
  }, [selectedIncident]);

  const handleSelectIncidentByClass = (psClass: string) => {
    const match = incidents.find((i) => i.ps_class === psClass);
    if (match) {
      setSelectedIncidentId(match.incident_id);
    }
  };

  return (
    <div className="app-container">
      {/* Top Application Header */}
      <Header
        connectionMode={connectionMode}
        isWsConnected={isWsConnected}
        health={health}
        onOpenDemoTour={() => setIsTourOpen(true)}
        onLoadMockFixtures={loadMockFixtures}
      />

      {/* Sensor Capability / Visibility Banner */}
      <CapabilityBanner capabilities={capabilities} />

      {/* Main Operator Layout: Incident Feed + Evidence Drawer */}
      <main className="main-content-layout">
        <section className="feed-pane">
          <IncidentFeed
            incidents={incidents}
            totalCount={allIncidentsCount}
            selectedIncidentId={selectedIncidentId}
            onSelectIncident={(id) => setSelectedIncidentId(id)}
            severityCounts={severityCounts}
            filters={filters}
          />
        </section>

        <section className="drawer-pane">
          <EvidenceDrawer incident={selectedIncident} />
        </section>
      </main>

      {/* 7-Minute Hackathon Demo Tour Modal */}
      <DemoTourModal
        isOpen={isTourOpen}
        onClose={() => setIsTourOpen(false)}
        onSelectIncidentByClass={handleSelectIncidentByClass}
      />
    </div>
  );
};

export default App;
