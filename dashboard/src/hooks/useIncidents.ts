import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { Incident, SensorCapabilities, SystemHealth, ConnectionMode, Severity } from '../types';
import { getHealth, getCapabilities, getIncidents, FALLBACK_CAPABILITIES } from '../services/api';
import { IncidentWebSocketClient } from '../services/websocket';
import { CANONICAL_MOCK_FIXTURES } from '../services/mockFixtures';

const MAX_RING_BUFFER_SIZE = 500;

export function useIncidents() {
  const [incidents, setIncidents] = useState<Incident[]>(CANONICAL_MOCK_FIXTURES);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(CANONICAL_MOCK_FIXTURES[0].incident_id);
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
    setIncidents((current) => {
      const map = new Map<string, Incident>();
      // Index existing
      for (const item of current) {
        map.set(item.incident_id, item);
      }
      // Upsert incoming
      for (const item of incoming) {
        map.set(item.incident_id, item);
      }

      // Convert back and sort descending by last_observed or seq
      const list = Array.from(map.values()).sort((a, b) => {
        const timeA = new Date(a.last_observed || a.timestamp).getTime();
        const timeB = new Date(b.last_observed || b.timestamp).getTime();
        return timeB - timeA;
      });

      // Bounded client ring buffer of 500
      return list.slice(0, MAX_RING_BUFFER_SIZE);
    });
  }, []);

  // Poll health and capabilities
  useEffect(() => {
    let isMounted = true;

    async function loadInitial() {
      try {
        const [h, cap, incList] = await Promise.all([
          getHealth(),
          getCapabilities(),
          getIncidents({ limit: 100 }).catch(() => []),
        ]);

        if (!isMounted) return;

        setHealth(h);
        setCapabilities(cap);

        if (incList && incList.length > 0) {
          mergeIncidents(incList);
          if (!selectedIncidentId) {
            setSelectedIncidentId(incList[0].incident_id);
          }
        }
      } catch {
        // Retain fallback mock data
      }
    }

    loadInitial();

    const timer = setInterval(async () => {
      if (!isMounted) return;
      try {
        const h = await getHealth();
        if (isMounted) setHealth(h);
      } catch {
        // Ignored in offline mode
      }
    }, 5000);

    return () => {
      isMounted = false;
      clearInterval(timer);
    };
  }, [mergeIncidents, selectedIncidentId]);

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

  // Load canonical mock fixtures manually (demo mode)
  const loadMockFixtures = useCallback(() => {
    mergeIncidents(CANONICAL_MOCK_FIXTURES);
    setSelectedIncidentId(CANONICAL_MOCK_FIXTURES[0].incident_id);
    setConnectionMode('FIXTURE');
  }, [mergeIncidents]);

  return {
    incidents: filteredIncidents,
    allIncidentsCount: incidents.length,
    selectedIncident,
    selectedIncidentId,
    setSelectedIncidentId,
    capabilities,
    health,
    connectionMode,
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
    loadMockFixtures,
  };
}
