/**
 * PCAP Replay Controller & Simulation Engine
 * Replays realistic unidirectional PCAP packet streams with variable speed,
 * live metric updates, incident triggering, and scrub bar.
 */

class PCAPReplayEngine {
  constructor() {
    this.isPlaying = false;
    this.playbackSpeed = 1.0;
    this.currentProfileIndex = 0;
    this.currentPacketIndex = 412000;
    this.totalPackets = 1284392;
    this.timer = null;
    this.lastTickTime = performance.now();

    // Baseline stream metrics
    this.flowsPerSec = 1520;
    this.packetsPerSec = 29432;
    this.throughputMbps = 364.2;
    this.unidirectionalPct = 98.7;
    this.suspiciousFlows = 143;
    this.uniqueSrcIps = 48;
    this.uniqueDstIps = 12;
    this.packetsDropped = 171;
    this.captureLossPct = 0.58;

    // Callbacks
    this.onMetricUpdate = null;
    this.onPacketStream = null;
    this.onThreatTriggered = null;
    this.onProgressUpdate = null;

    this.profiles = typeof PCAP_PROFILES !== 'undefined' ? PCAP_PROFILES : [
      { id: "pcap-scada", name: "scada_modbus_unidirectional_attack.pcap", totalPackets: 1284392, pps: 2840, throughputMbps: 18.4, dominantThreat: "SCADA_INJECTION" },
      { id: "pcap-ddos", name: "ddos_amplification_diode_flood.pcap", totalPackets: 3840210, pps: 29432, throughputMbps: 364.0, dominantThreat: "DDOS_AMPLIFICATION" },
      { id: "pcap-c2", name: "c2_covert_timing_exfiltration.pcap", totalPackets: 890450, pps: 820, throughputMbps: 4.2, dominantThreat: "C2_BEACON" },
      { id: "pcap-mixed", name: "mixed_enterprise_unidirectional_capture.pcap", totalPackets: 5410980, pps: 12400, throughputMbps: 84.5, dominantThreat: "ENCRYPTED_MALWARE" }
    ];

    this.loadProfile(0);
  }

  loadProfile(index) {
    this.currentProfileIndex = index % this.profiles.length;
    const profile = this.profiles[this.currentProfileIndex];
    this.totalPackets = profile.totalPackets;
    this.currentPacketIndex = Math.floor(this.totalPackets * 0.35);
    this.packetsPerSec = profile.pps || 14200;
    this.throughputMbps = profile.throughputMbps || 84.0;
    this.flowsPerSec = Math.floor(this.packetsPerSec / 19);

    if (this.onProgressUpdate) {
      this.onProgressUpdate(this.getProgress());
    }
  }

  play() {
    if (this.isPlaying) return;
    this.isPlaying = true;
    this.lastTickTime = performance.now();
    this.scheduleNextTick();
  }

  pause() {
    this.isPlaying = false;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }

  stop() {
    this.pause();
    this.currentPacketIndex = 0;
    if (this.onProgressUpdate) {
      this.onProgressUpdate(this.getProgress());
    }
  }

  setSpeed(speed) {
    this.playbackSpeed = parseFloat(speed) || 1.0;
  }

  seek(pct) {
    const clamped = Math.max(0, Math.min(1, pct));
    this.currentPacketIndex = Math.floor(this.totalPackets * clamped);
    if (this.onProgressUpdate) {
      this.onProgressUpdate(this.getProgress());
    }
  }

  getProgress() {
    const pct = Math.min(100, (this.currentPacketIndex / this.totalPackets) * 100);
    return {
      current: this.currentPacketIndex,
      total: this.totalPackets,
      percentage: pct.toFixed(1),
      profile: this.profiles[this.currentProfileIndex]
    };
  }

  scheduleNextTick() {
    if (!this.isPlaying) return;
    const interval = Math.max(100, 400 / this.playbackSpeed);

    this.timer = setTimeout(() => {
      this.tick();
      this.scheduleNextTick();
    }, interval);
  }

  tick() {
    if (!this.isPlaying) return;

    // Advance packets
    const step = Math.floor((this.packetsPerSec * 0.4) * this.playbackSpeed);
    this.currentPacketIndex += step;
    if (this.currentPacketIndex >= this.totalPackets) {
      this.currentPacketIndex = 0; // Loop or cycle
    }

    // Dynamic metrics fluctuation (organic technical feel)
    const jitter = (Math.random() - 0.49) * 0.04;
    this.packetsPerSec = Math.max(1200, Math.round(this.packetsPerSec * (1 + jitter)));
    this.flowsPerSec = Math.max(80, Math.round(this.packetsPerSec / (18 + Math.random() * 3)));
    this.throughputMbps = parseFloat((this.packetsPerSec * 0.0124).toFixed(1));
    this.packetsDropped = Math.max(0, Math.round(this.packetsPerSec * 0.0058 + (Math.random() * 20 - 10)));
    this.captureLossPct = parseFloat(((this.packetsDropped / (this.packetsPerSec + this.packetsDropped)) * 100).toFixed(2));

    if (this.onMetricUpdate) {
      this.onMetricUpdate({
        flowsPerSec: this.flowsPerSec,
        packetsPerSec: this.packetsPerSec,
        throughputMbps: this.throughputMbps,
        unidirectionalPct: this.unidirectionalPct,
        suspiciousFlows: this.suspiciousFlows,
        uniqueSrcIps: this.uniqueSrcIps,
        uniqueDstIps: this.uniqueDstIps,
        packetsDropped: this.packetsDropped,
        captureLossPct: this.captureLossPct
      });
    }

    if (this.onProgressUpdate) {
      this.onProgressUpdate(this.getProgress());
    }

    // Occasional trigger of realistic simulated packets into visualizer
    if (this.onPacketStream) {
      const isSuspicious = Math.random() < 0.22;
      this.onPacketStream(isSuspicious);
    }

    // Trigger incident periodically during replay
    if (Math.random() < 0.12 && this.onThreatTriggered) {
      const threatKeys = ["DDOS_AMPLIFICATION", "SCADA_INJECTION", "PORT_SCAN", "C2_BEACON", "ENCRYPTED_MALWARE", "DGA_DNS", "EXFILTRATION"];
      const chosenKey = threatKeys[Math.floor(Math.random() * threatKeys.length)];
      if (typeof THREAT_DATABASE !== 'undefined' && THREAT_DATABASE[chosenKey]) {
        this.onThreatTriggered(THREAT_DATABASE[chosenKey]);
      }
    }
  }
}

window.PCAPReplayInstance = new PCAPReplayEngine();
