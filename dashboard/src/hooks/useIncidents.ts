import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { Incident, SensorCapabilities, SystemHealth, ConnectionMode, Severity } from '../types';
import { getHealth, getCapabilities, getIncidents, FALLBACK_CAPABILITIES } from '../services/api';
import { IncidentWebSocketClient } from '../services/websocket';
import { CANONICAL_MOCK_FIXTURES } from '../services/mockFixtures';
import { DataSource, MAX_RING_BUFFER_SIZE, mergeIncidents as mergeInto, reconcile, visibleIncidents } from '../services/incidentStore';

export function useIncidents() {
  // Live incidents come ONLY from the read-only API / WebSocket. They start empty
  // and are never mixed with fixtures. Demo fixtures live in a separate list and
  // are shown only while the explicit DEMO DATA toggle is on.
  const [liveIncidents, setLiveIncidents] = useState<Incident[]>([]);
  const [dataSource, setDataSource] = useState<DataSource>('live');
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [capabilities, setCapabilities] = useState<SensorCapabilities>(FALLBACK_CAPABILITIES);
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [connectionMode, setConnectionMode] = useState<ConnectionMode>('LIVE');
  const [isWsConnected, setIsWsConnected] = useState<boolean>(false);

  // Filters
  const [psClassFilter, setPsClassFilter] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');

  const wsClientRef = useRef<IncidentWebSocketClient | null>(null);

  // Helper to merge batch into 500-item ring buffer
  const mergeIncidents = useCallback((incoming: Incident[]) => {
    setLiveIncidents((current) => mergeInto(current, incoming, MAX_RING_BUFFER_SIZE));
  }, []);

  const incidents = visibleIncidents(dataSource, liveIncidents, CANONICAL_MOCK_FIXTURES) as Incident[];

  // Poll health and capabilities
  useEffect(() => {
    let isMounted = true;

    async function loadInitial() {
      try {
        const [h, cap, incList] = await Promise.all([
          getHealth().catch(() => null),
          getCapabilities(),
          getIncidents({ limit: MAX_RING_BUFFER_SIZE }).catch(() => []),
        ]);

        if (!isMounted) return;

        setHealth(h);
        setCapabilities(cap);

        if (incList && incList.length > 0) {
          mergeIncidents(incList);
          setSelectedIncidentId((prev) => prev || incList[0].incident_id);
        }
      } catch {
        // API unreachable: live feed stays empty. No fixture fallback.
      }
    }

    loadInitial();

    const timer = setInterval(async () => {
      if (!isMounted) return;
      try {
        const h = await getHealth();
        if (isMounted) setHealth(h);
      } catch {
        if (isMounted) setHealth(null); // API offline: shown as such, never faked
      }
    }, 5000);

    return () => {
      isMounted = false;
      clearInterval(timer);
    };
  }, [mergeIncidents]);

  // WebSocket lifecycle
  useEffect(() => {
    const client = new IncidentWebSocketClient({
      onSnapshot: (initialIncidents, cap) => {
        setIsWsConnected(true);
        setConnectionMode('LIVE');
        if (cap) setCapabilities(cap);
        if (initialIncidents && initialIncidents.length > 0) {
          mergeIncidents(initialIncidents);
          setSelectedIncidentId((prev) => prev || initialIncidents[0].incident_id);
        }
      },
      onBatch: (batchedIncidents) => {
        if (batchedIncidents && batchedIncidents.length > 0) {
          mergeIncidents(batchedIncidents);
        }
      },
      onStatusChange: (connected) => {
        setIsWsConnected(connected);
        if (!connected) {
          setConnectionMode((prev) => (prev === 'LIVE' ? 'REPLAY' : prev));
        }
      },
    });

    wsClientRef.current = client;
    client.connect();

    return () => {
      client.disconnect();
    };
  }, [mergeIncidents]);

  // Filtered incidents
  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      if (psClassFilter && inc.ps_class !== psClassFilter) return false;
      if (severityFilter && inc.severity !== severityFilter) return false;
      if (statusFilter && inc.status !== statusFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesId = inc.incident_id.toLowerCase().includes(q);
        const matchesFlow = inc.flow_id.toLowerCase().includes(q);
        const matchesThreat = inc.threat_class.toLowerCase().includes(q);
        const matchesClass = inc.ps_class.toLowerCase().includes(q);
        const matchesSrc = inc.evidence?.src_ip?.toLowerCase().includes(q) || false;
        const matchesDst = inc.evidence?.dst_ip?.toLowerCase().includes(q) || false;
        const matchesInterpretation = inc.evidence?.interpretation?.toLowerCase().includes(q) || false;

        if (!matchesId && !matchesFlow && !matchesThreat && !matchesClass && !matchesSrc && !matchesDst && !matchesInterpretation) {
          return false;
        }
      }
      return true;
    });
  }, [incidents, psClassFilter, severityFilter, statusFilter, searchQuery]);

  // Selected incident object
  const selectedIncident = useMemo(() => {
    if (!selectedIncidentId) return filteredIncidents[0] || null;
    return incidents.find((i) => i.incident_id === selectedIncidentId) || filteredIncidents[0] || null;
  }, [incidents, selectedIncidentId, filteredIncidents]);

  // Severity counts
  const severityCounts = useMemo(() => {
    const counts: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };
    for (const inc of incidents) {
      if (counts[inc.severity] !== undefined) {
        counts[inc.severity]++;
      }
    }
    return counts;
  }, [incidents]);

  // Explicit DEMO DATA toggle. Switches the whole view to fixtures and back;
  // live data keeps accumulating underneath and is never merged with fixtures.
  const isDemo = dataSource === 'demo';
  const toggleDemoData = useCallback(() => {
    setDataSource((prev) => {
      const next: DataSource = prev === 'demo' ? 'live' : 'demo';
      setSelectedIncidentId(next === 'demo' ? CANONICAL_MOCK_FIXTURES[0].incident_id : null);
      return next;
    });
  }, []);

  // Live feed vs API count (GET /health total_incidents). Only meaningful in live mode.
  const reconciliation = reconcile(liveIncidents.length, health?.total_incidents);

  return {
    incidents: filteredIncidents,
    allIncidentsCount: incidents.length,
    selectedIncident,
    selectedIncidentId,
    setSelectedIncidentId,
    capabilities,
    health,
    connectionMode: isDemo ? ('FIXTURE' as ConnectionMode) : connectionMode,
    setConnectionMode,
    isWsConnected,
    severityCounts,
    filters: {
      psClassFilter,
      setPsClassFilter,
      severityFilter,
      setSeverityFilter,
      statusFilter,
      setStatusFilter,
      searchQuery,
      setSearchQuery,
    },
    isDemo,
    toggleDemoData,
    liveCount: liveIncidents.length,
    reconciliation,
  };
}
