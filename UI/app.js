/**
 * Main Controller for AI Unidirectional Cyber Threat Detection Web Portal
 * Coordinates Cyber Globe, Attack Simulator, Deep Inspector, XAI Scorer, and Playbooks.
 */

class PortalController {
  constructor() {
    this.totalPackets = 2480;
    this.onTheWayCount = 15720;
    this.deliveredCount = 56410;
    this.waitingCount = 8240;
    this.shutterClosed = false;
    this.currentReport = null;
    this.incidentCount = 142;

    this.initAudio();
    this.initNavigation();
    this.initGlobe();
    this.initSimulator();
    this.initSOCFeatures();
    this.initEventListeners();
    this.initAttackPreviews();

    // Default inspection state
    this.renderInspector(THREAT_DATABASE.SCADA_INJECTION);
    this.renderXAI(THREAT_DATABASE.SCADA_INJECTION);
  }

  /* --------------------------------------------------------------------------
     Web Audio API Cyber Synthesizer
     -------------------------------------------------------------------------- */
  initAudio() {
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      this.audioCtx = new AudioCtx();
    } catch (e) {
      this.audioCtx = null;
    }
  }

  beep(freq = 600, duration = 0.08, type = 'sine') {
    if (!this.audioCtx) return;
    try {
      if (this.audioCtx.state === 'suspended') {
        this.audioCtx.resume();
      }
      const osc = this.audioCtx.createOscillator();
      const gain = this.audioCtx.createGain();
      osc.type = type;
      osc.frequency.setValueAtTime(freq, this.audioCtx.currentTime);
      gain.gain.setValueAtTime(0.05, this.audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, this.audioCtx.currentTime + duration);
      osc.connect(gain);
      gain.connect(this.audioCtx.destination);
      osc.start();
      osc.stop(this.audioCtx.currentTime + duration);
    } catch (e) {}
  }

  /* --------------------------------------------------------------------------
     Navigation & Tab Switching
     -------------------------------------------------------------------------- */
  initNavigation() {
    const navItems = document.querySelectorAll('.nav-item[data-tab]');
    const subNavBtns = document.querySelectorAll('.sub-nav-btn[data-tab]');

    const switchTab = (tabId) => {
      navItems.forEach(n => n.classList.toggle('active', n.getAttribute('data-tab') === tabId));
      subNavBtns.forEach(b => b.classList.toggle('active', b.getAttribute('data-tab') === tabId));

      document.querySelectorAll('.view-section').forEach(sec => sec.classList.remove('active'));
      const target = document.getElementById(tabId);
      if (target) {
        target.classList.add('active');
        if (tabId === 'tab-soc' && this.flowVisualizer) {
          this.flowVisualizer.resize();
          if (this.pipelineVisualizer) this.pipelineVisualizer.resize();
        } else if (tabId === 'tab-dashboard' && this.globe) {
          this.globe.resize();
        } else if (tabId === 'tab-simulator' && this.simulator) {
          this.simulator.resize();
        }
      }
      this.beep(480, 0.04, 'triangle');
    };

    navItems.forEach(btn => btn.addEventListener('click', () => switchTab(btn.getAttribute('data-tab'))));
    subNavBtns.forEach(btn => btn.addEventListener('click', () => switchTab(btn.getAttribute('data-tab'))));

    const backBtn = document.getElementById('topbarBackBtn');
    if (backBtn) {
      backBtn.addEventListener('click', () => switchTab('tab-dashboard'));
    }
  }

  /* --------------------------------------------------------------------------
     Cyber Globe Initialization
     -------------------------------------------------------------------------- */
  initGlobe() {
    this.globe = new CyberGlobe('cyberGlobeCanvas');

    // 3D / 2D view toggles
    const btn3D = document.getElementById('btn3DMode');
    const btn2D = document.getElementById('btn2DMode');

    if (btn3D && btn2D) {
      btn3D.addEventListener('click', () => {
        btn3D.classList.add('active');
        btn2D.classList.remove('active');
        this.globe.setMode('3D');
        this.showToast("Switched to 3D Orbital Cyber Globe", "info");
      });

      btn2D.addEventListener('click', () => {
        btn2D.classList.add('active');
        btn3D.classList.remove('active');
        this.globe.setMode('2D');
        this.showToast("Switched to 2D Planar Network Topology", "info");
      });
    }

    // Day / Night toggles
    const btnNight = document.getElementById('btnNightMode');
    const btnDay = document.getElementById('btnDayMode');
    if (btnNight && btnDay) {
      btnNight.addEventListener('click', () => {
        btnNight.classList.add('active');
        btnDay.classList.remove('active');
        document.body.style.filter = "none";
      });
      btnDay.addEventListener('click', () => {
        btnDay.classList.add('active');
        btnNight.classList.remove('active');
        this.showToast("Day mode simulation engaged", "info");
      });
    }
  }

  /* --------------------------------------------------------------------------
     Attack Simulator Initialization
     -------------------------------------------------------------------------- */
  initSimulator() {
    this.simulator = new UnidirectionalSimulator('simCanvas');

    this.simulator.onPacketArrival = (report, pkt) => {
      this.totalPackets++;
      const elTot = document.getElementById('hudTotalPackets');
      if (elTot) elTot.textContent = `${(this.totalPackets / 1000).toFixed(1)}k+`;

      if (pkt && pkt.isAttack) {
        // Attack packet intercepted!
        this.waitingCount++;
        const elWait = document.getElementById('hudWaiting');
        if (elWait) elWait.textContent = `${(this.waitingCount / 1000).toFixed(1)}k+`;

        // Trigger globe attack wave
        if (this.globe) this.globe.triggerAttackWave("#f43f5e");

        // Update threat displays
        this.currentReport = report;
        this.renderInspector(report);
        this.renderXAI(report);
        this.updateScoreGauge(report.threatScore, report.severity);

        // Alert sound & Threat Alert Popup ONLY when simulated attack detection event occurs
        this.beep(880, 0.15, 'sawtooth');
        this.triggerThreatAlert(report);
      } else {
        // Benign packet
        this.deliveredCount++;
        const elDeliv = document.getElementById('hudDelivered');
        if (elDeliv) elDeliv.textContent = `${(this.deliveredCount / 1000).toFixed(1)}k+`;
      }
    };
  }

  /* --------------------------------------------------------------------------
     Event Listeners for Controls & Attack Injector
     -------------------------------------------------------------------------- */
  initEventListeners() {
    // Attack Launch button
    const btnInject = document.getElementById('btnInjectAttack');
    const selectAttack = document.getElementById('attackSelect');
    if (btnInject && selectAttack) {
      btnInject.addEventListener('click', () => {
        const key = selectAttack.value;
        this.simulator.injectPacket(key, true);
        if (this.globe) this.globe.triggerAttackWave("#f43f5e");
        this.beep(380, 0.08, 'square');
      });
    }

    // Rate slider
    const rateSlider = document.getElementById('rateSlider');
    const rateVal = document.getElementById('rateVal');
    if (rateSlider && rateVal) {
      rateSlider.addEventListener('input', (e) => {
        const val = parseInt(e.target.value);
        rateVal.textContent = val;
        this.simulator.setRate(val);
      });
    }

    // Continuous toggle
    const contToggle = document.getElementById('continuousStreamToggle');
    if (contToggle) {
      contToggle.addEventListener('change', (e) => {
        this.simulator.setContinuous(e.target.checked);
      });
    }

    // Optical Shutter Toggle
    const btnShutter = document.getElementById('btnToggleShutter');
    const pbBtnShutter = document.getElementById('pbBtnShutter');
    const handleShutter = () => {
      this.shutterClosed = !this.shutterClosed;
      this.simulator.setShutter(this.shutterClosed);

      const statusBadge = document.getElementById('diodeStatusBadge');

      if (this.shutterClosed) {
        if (btnShutter) {
          btnShutter.textContent = "Disengage Shutter (Restore Link)";
          btnShutter.style.background = "var(--crimson-alert)";
          btnShutter.style.color = "#fff";
        }
        if (pbBtnShutter) pbBtnShutter.textContent = "Restore Optical Link";
        if (statusBadge) {
          statusBadge.style.background = "rgba(244,63,94,0.15)";
          statusBadge.style.borderColor = "var(--crimson-alert)";
          statusBadge.style.color = "var(--crimson-alert)";
          statusBadge.innerHTML = `<span class="dot-live" style="background: var(--crimson-alert); box-shadow: 0 0 8px var(--crimson-alert);"></span><span>SHUTTER CUTOFF</span>`;
        }
        this.beep(240, 0.25, 'sawtooth');
        this.showToast("🛑 Mechanical Optical Shutter Closed. Unidirectional laser severed.", "critical");
      } else {
        if (btnShutter) {
          btnShutter.textContent = "Engage Optical Shutter (Sever Link)";
          btnShutter.style.background = "rgba(244, 63, 94, 0.15)";
          btnShutter.style.color = "var(--crimson-alert)";
        }
        if (pbBtnShutter) pbBtnShutter.textContent = "Trigger Shutter Drop";
        if (statusBadge) {
          statusBadge.style.background = "rgba(16, 185, 129, 0.15)";
          statusBadge.style.borderColor = "rgba(16, 185, 129, 0.35)";
          statusBadge.style.color = "var(--green-light)";
          statusBadge.innerHTML = `<span class="dot-live"></span><span>PREMIUM DIODE</span>`;
        }
        this.showToast("✅ Optical Shutter opened. 1-Way transmission active.", "info");
      }
    };

    if (btnShutter) btnShutter.addEventListener('click', handleShutter);
    if (pbBtnShutter) pbBtnShutter.addEventListener('click', handleShutter);

    // Playbook buttons
    const pbBtnFlush = document.getElementById('pbBtnFlush');
    if (pbBtnFlush) {
      pbBtnFlush.addEventListener('click', () => {
        this.beep(520, 0.08, 'sine');
        this.showToast("⚡ RX Photodiode FIFO ring buffer flushed. 0 pending bytes dropped.", "info");
      });
    }

    const pbBtnIsolate = document.getElementById('pbBtnIsolate');
    if (pbBtnIsolate) {
      pbBtnIsolate.addEventListener('click', () => {
        this.beep(350, 0.1, 'square');
        this.showToast("🔒 Enclave IP 10.0.4.15 isolated in airgapped quarantine VLAN.", "warning");
      });
    }

    const pbBtnExportRules = document.getElementById('pbBtnExportRules');
    if (pbBtnExportRules) {
      pbBtnExportRules.addEventListener('click', () => {
        this.beep(640, 0.08, 'sine');
        this.showToast("📝 Generated eBPF XDP filter: `sec_filter_unidir.o` saved to SOC repository.", "info");
      });
    }
  }

  /* --------------------------------------------------------------------------
     Cyber Sentinel SOC Operations Center & PCAP Replay Integration
     -------------------------------------------------------------------------- */
  initSOCFeatures() {
    // 1. Initialize Visualizers
    if (typeof FlowVisualizerClass !== 'undefined') {
      this.flowVisualizer = new FlowVisualizerClass('liveFlowCanvas');
    }
    if (typeof PipelineVisualizerClass !== 'undefined') {
      this.pipelineVisualizer = new PipelineVisualizerClass('pipelineCanvas');
    }
    if (typeof WaveformVisualizerClass !== 'undefined') {
      this.waveformVisualizer = new WaveformVisualizerClass('waveformCanvas');
    }

    // 2. Initialize PCAP Replay Controller
    this.initPCAPControls();

    // 3. Populate Suspicious Sources Table
    this.renderSuspiciousSourcesTable();

    // 4. Initialize Threat Investigation Modal
    this.initInvestigationModal();

    // 5. Populate Initial Incident Feed
    this.initIncidentFeed();

    // 6. Global Search filter
    const searchInput = document.getElementById('globalSearchInput');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase().trim();
        this.filterSourcesTable(query);
      });
    }
  }

  initPCAPControls() {
    const replay = window.PCAPReplayInstance;
    if (!replay) return;

    const playBtn = document.getElementById('pcapPlayBtn');
    const pauseBtn = document.getElementById('pcapPauseBtn');
    const stopBtn = document.getElementById('pcapStopBtn');
    const profileSelect = document.getElementById('pcapSelectProfile');
    const scrubberTrack = document.getElementById('pcapScrubberTrack');
    const scrubberFill = document.getElementById('pcapScrubberFill');
    const progressText = document.getElementById('pcapProgressText');
    const nameDisplay = document.getElementById('pcapNameDisplay');
    const speedPills = document.querySelectorAll('.speed-pill-btn');

    if (playBtn) {
      playBtn.addEventListener('click', () => {
        replay.play();
        playBtn.classList.add('active');
        if (pauseBtn) pauseBtn.classList.remove('active');
        this.beep(520, 0.05, 'sine');
        this.showToast("▶ PCAP Replay Stream Active", "info");
      });
    }

    if (pauseBtn) {
      pauseBtn.addEventListener('click', () => {
        replay.pause();
        pauseBtn.classList.add('active');
        if (playBtn) playBtn.classList.remove('active');
        this.beep(400, 0.05, 'sine');
        this.showToast("⏸ PCAP Replay Paused", "warning");
      });
    }

    if (stopBtn) {
      stopBtn.addEventListener('click', () => {
        replay.stop();
        if (playBtn) playBtn.classList.remove('active');
        if (pauseBtn) pauseBtn.classList.remove('active');
        this.beep(300, 0.08, 'sawtooth');
        this.showToast("⏹ PCAP Replay Reset to Frame 0", "info");
      });
    }

    if (profileSelect) {
      profileSelect.addEventListener('change', (e) => {
        const idx = parseInt(e.target.value);
        replay.loadProfile(idx);
        const p = replay.profiles[idx];
        if (nameDisplay) nameDisplay.textContent = p.name;
        this.showToast(`Loaded Capture: ${p.name}`, "info");
      });
    }

    speedPills.forEach(btn => {
      btn.addEventListener('click', () => {
        speedPills.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const speed = parseFloat(btn.getAttribute('data-speed'));
        replay.setSpeed(speed);
        this.beep(600, 0.04, 'sine');
      });
    });

    if (scrubberTrack) {
      scrubberTrack.addEventListener('click', (e) => {
        const rect = scrubberTrack.getBoundingClientRect();
        const clickX = e.clientX - rect.left;
        const pct = clickX / rect.width;
        replay.seek(pct);
      });
    }

    // Replay Callbacks
    replay.onMetricUpdate = (metrics) => {
      const elFlows = document.getElementById('ovFlowsSec');
      const elPackets = document.getElementById('ovPacketsSec');
      const elThroughput = document.getElementById('ovThroughput');
      const elUnidir = document.getElementById('ovUnidirectional');
      const elSuspicious = document.getElementById('ovSuspicious');
      const elRate = document.getElementById('ovDetectionRate');
      const elSrc = document.getElementById('ovUniqueSrc');
      const elDst = document.getElementById('ovUniqueDst');
      const elDropped = document.getElementById('ovDropped');
      const topFlows = document.getElementById('topbarFlows');
      const topThroughput = document.getElementById('topbarThroughput');

      if (elFlows) elFlows.textContent = metrics.flowsPerSec >= 1000 ? `${(metrics.flowsPerSec / 1000).toFixed(1)}K` : metrics.flowsPerSec;
      if (elPackets) elPackets.textContent = `${(metrics.packetsPerSec / 1000).toFixed(1)}K`;
      if (elThroughput) elThroughput.textContent = `${metrics.throughputMbps} Mbps`;
      if (elUnidir) elUnidir.textContent = `${metrics.unidirectionalPct}%`;
      if (elSuspicious) elSuspicious.textContent = metrics.suspiciousFlows;
      if (elRate) elRate.textContent = "96.8%";
      if (elSrc) elSrc.textContent = metrics.uniqueSrcIps;
      if (elDst) elDst.textContent = metrics.uniqueDstIps;
      if (elDropped) elDropped.textContent = `${metrics.packetsDropped} /s`;
      if (topFlows) topFlows.textContent = metrics.flowsPerSec >= 1000 ? `${(metrics.flowsPerSec / 1000).toFixed(1)}K` : metrics.flowsPerSec;
      if (topThroughput) topThroughput.textContent = `${metrics.throughputMbps} Mbps`;

      const socFlows = document.getElementById('socFlowsAnalyzed');
      if (socFlows && window.AIEngineInstance) {
        socFlows.textContent = window.AIEngineInstance.flowsAnalyzed.toLocaleString();
      }
    };

    replay.onProgressUpdate = (prog) => {
      if (progressText) {
        progressText.textContent = `${prog.current.toLocaleString()} / ${prog.total.toLocaleString()} pkts (${prog.percentage}%)`;
      }
      if (scrubberFill) {
        scrubberFill.style.width = `${prog.percentage}%`;
      }
      if (nameDisplay && prog.profile) {
        nameDisplay.textContent = prog.profile.name;
      }
    };

    replay.onThreatTriggered = (threat) => {
      this.handleNewThreat(threat);
    };

    // Auto start replay playback
    setTimeout(() => {
      replay.play();
    }, 500);
  }

  handleNewThreat(threat) {
    if (!threat) return;
    const report = window.AIEngineInstance.analyzePacket(threat);

    // 1. Add to incident feed
    this.addIncidentToFeed(report);

    // 2. Add to flow visualizer
    if (this.flowVisualizer) {
      this.flowVisualizer.addFlow({
        id: `flow-${Date.now()}`,
        srcIp: report.srcIp,
        dstIp: report.dstIp,
        proto: report.protocol,
        packets: report.payloadSize * 4,
        bytes: `${(report.payloadSize * 0.12).toFixed(1)} KB`,
        duration: "4.8s",
        status: report.severity.toUpperCase(),
        score: report.threatScore,
        speed: report.threatScore > 80 ? 4.5 : 2.5,
        color: report.threatScore > 80 ? "#f43f5e" : "#f59e0b"
      });
    }

    // 3. Trigger globe wave if available
    if (this.globe) {
      this.globe.triggerAttackWave(report.threatScore > 80 ? "#f43f5e" : "#f59e0b");
    }

    // 4. Update AI engine status badges
    const predEl = document.getElementById('socCurrentPred');
    if (predEl) predEl.textContent = `${report.name} (${report.confidence}%)`;

    // 5. Update confidence meters
    this.updateConfidenceBars(report);
  }

  updateConfidenceBars(report) {
    if (!report) return;
    const updateBar = (idVal, idBar, val) => {
      const elVal = document.getElementById(idVal);
      const elBar = document.getElementById(idBar);
      if (elVal) elVal.textContent = `${val.toFixed(1)}%`;
      if (elBar) elBar.style.width = `${val.toFixed(1)}%`;
    };

    if (report.category === 'DDoS') updateBar('confValDDoS', 'confBarDDoS', report.confidence);
    else if (report.category.includes('SCADA')) updateBar('confValSCADA', 'confBarSCADA', report.confidence);
    else if (report.category === 'C2') updateBar('confValC2', 'confBarC2', report.confidence);
    else if (report.category.includes('Exfiltration')) updateBar('confValExfil', 'confBarExfil', report.confidence);
    else if (report.category === 'Scan') updateBar('confValScan', 'confBarScan', report.confidence);
  }

  /* --------------------------------------------------------------------------
     Suspicious Sources Table
     -------------------------------------------------------------------------- */
  renderSuspiciousSourcesTable() {
    const tbody = document.getElementById('suspiciousSourcesTableBody');
    if (!tbody || typeof SUSPICIOUS_SOURCES_DATA === 'undefined') return;

    tbody.innerHTML = SUSPICIOUS_SOURCES_DATA.map(item => `
      <tr data-key="${item.key}">
        <td style="color: var(--cyan-neon); font-weight: 700;">${item.ip}</td>
        <td><span style="color: ${item.score > 90 ? 'var(--crimson-alert)' : 'var(--amber-gold)'}; font-weight: 700;">${item.threat}</span></td>
        <td><strong style="color: #fff;">${item.score}%</strong></td>
        <td>${item.flows.toLocaleString()}</td>
        <td>${item.packets.toLocaleString()}</td>
        <td>${item.bytes}</td>
        <td style="color: var(--text-muted);">${item.firstSeen}</td>
        <td style="color: var(--text-secondary);">${item.lastSeen}</td>
        <td>
          <button class="btn-investigate" data-threat-key="${item.key}">INVESTIGATE</button>
        </td>
      </tr>
    `).join('');

    tbody.querySelectorAll('tr').forEach(tr => {
      tr.addEventListener('click', (e) => {
        const key = tr.getAttribute('data-key');
        if (THREAT_DATABASE[key]) {
          this.openInvestigationModal(THREAT_DATABASE[key]);
        }
      });
    });

    tbody.querySelectorAll('.btn-investigate').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const key = btn.getAttribute('data-threat-key');
        if (THREAT_DATABASE[key]) {
          this.openInvestigationModal(THREAT_DATABASE[key]);
        }
      });
    });
  }

  filterSourcesTable(query) {
    const tbody = document.getElementById('suspiciousSourcesTableBody');
    if (!tbody) return;
    const rows = tbody.querySelectorAll('tr');
    rows.forEach(row => {
      const text = row.textContent.toLowerCase();
      row.style.display = text.includes(query) ? '' : 'none';
    });
  }

  /* --------------------------------------------------------------------------
     Threat Investigation Forensic Modal
     -------------------------------------------------------------------------- */
  initInvestigationModal() {
    const backdrop = document.getElementById('investigationModalBackdrop');
    const closeBtn = document.getElementById('invModalCloseBtn');
    const btnCloseFooter = document.getElementById('invBtnClose');
    const btnResolve = document.getElementById('invBtnResolve');
    const btnShutter = document.getElementById('invBtnShutter');

    const closeModal = () => {
      if (backdrop) backdrop.classList.remove('open');
    };

    if (closeBtn) closeBtn.addEventListener('click', closeModal);
    if (btnCloseFooter) btnCloseFooter.addEventListener('click', closeModal);
    if (backdrop) {
      backdrop.addEventListener('click', (e) => {
        if (e.target === backdrop) closeModal();
      });
    }

    if (btnResolve) {
      btnResolve.addEventListener('click', () => {
        const statusEl = document.getElementById('invStatus');
        if (statusEl) {
          statusEl.textContent = "RESOLVED & MITIGATED";
          statusEl.style.color = "var(--green-light)";
        }
        btnResolve.textContent = "Resolved ✓";
        btnResolve.style.background = "rgba(16, 185, 129, 0.2)";
        this.beep(720, 0.1, 'sine');
        this.showToast("Case marked as Resolved in SOC Incident Log.", "info");
      });
    }

    if (btnShutter) {
      btnShutter.addEventListener('click', () => {
        const btnMainShutter = document.getElementById('btnToggleShutter');
        if (btnMainShutter) btnMainShutter.click();
        this.showToast("Engaged Physical Optical Shutter from Investigation Panel.", "critical");
      });
    }
  }

  openInvestigationModal(threatData) {
    const backdrop = document.getElementById('investigationModalBackdrop');
    if (!backdrop || !threatData) return;

    this.beep(520, 0.06, 'triangle');

    // Populate Fields
    const setTxt = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val !== undefined ? val : "N/A";
    };

    setTxt('invModalCaseTag', threatData.id || `CASE-${Date.now().toString().slice(-4)}`);
    setTxt('invThreatCategory', threatData.name || threatData.category);
    setTxt('invSeverity', (threatData.severity || "Critical").toUpperCase());
    setTxt('invConfidence', `${threatData.confidence || 96.8}%`);
    setTxt('invStatus', "ACTIVE THREAT");

    const behavior = threatData.behavior || {};
    setTxt('invPackets', behavior.packets ? behavior.packets.toLocaleString() : (threatData.payloadSize * 14).toLocaleString());
    setTxt('invBytes', behavior.bytes || `${threatData.payloadSize || 84} Bytes`);
    setTxt('invDuration', behavior.avgDuration || "42.0 sec");

    setTxt('invSrcIp', threatData.srcIp || "192.168.10.198");
    setTxt('invSrcPort', threatData.srcPort || 49152);
    setTxt('invFirstSeen', "21:26:42");
    setTxt('invLastSeen', new Date().toLocaleTimeString('en-US', { hour12: false }));

    setTxt('invDstIp', threatData.dstIp || "10.0.4.15");
    setTxt('invDstPort', threatData.dstPort || 443);
    setTxt('invProto', threatData.protocol || "UDP");
    setTxt('invDescription', threatData.description || threatData.explanation);

    // Why Flagged Checklist
    const whyList = document.getElementById('invWhyFlaggedList');
    if (whyList) {
      const reasons = threatData.whyFlagged || (window.AIEngineInstance && window.AIEngineInstance.generateTrueExplanationFactors(threatData)) || [
        "✓ High packet velocity exceeding baseline",
        "✓ Large deviation from learned sensor baseline",
        "✓ Single destination concentration"
      ];
      whyList.innerHTML = reasons.map(r => `<div class="xai-factor-item">${r}</div>`).join('');
    }

    // DNS & TLS
    const dns = threatData.dnsIntel || {};
    setTxt('invDomain', dns.domain || "internal-scada-link.net");
    const tls = threatData.tlsMetadata || {};
    setTxt('invTlsVer', tls.version || "TLS 1.3");
    setTxt('invJa3', tls.ja3 || "e7d705a328636224e...");
    setTxt('invJa4', tls.ja4 || "t13d1516h2_8daaf61...");

    // Geolocation
    const geo = threatData.geo || {};
    setTxt('invGeoLocation', geo.country ? `${geo.country} • ${geo.region}, ${geo.city}` : "India • Gujarat, Ahmedabad");
    setTxt('invGeoIsp', geo.isp || "Enterprise Optical Gateway");

    backdrop.classList.add('open');
  }

  /* --------------------------------------------------------------------------
     Incident Feed & Alert Banner
     -------------------------------------------------------------------------- */
  initIncidentFeed() {
    const feed = document.getElementById('socIncidentFeedList');
    if (!feed) return;

    // Seed initial incidents
    const initialKeys = ["DDOS_AMPLIFICATION", "PORT_SCAN", "C2_BEACON", "SCADA_INJECTION"];
    initialKeys.forEach(k => {
      if (THREAT_DATABASE[k]) {
        const item = THREAT_DATABASE[k];
        feed.appendChild(this.createIncidentDOM(item));
      }
    });
  }

  createIncidentDOM(item) {
    const div = document.createElement('div');
    const isCritical = item.severity === 'Critical' || item.threatScore > 85;
    div.className = `incident-item ${isCritical ? 'critical' : 'high'}`;

    div.innerHTML = `
      <div class="incident-info-col">
        <div class="incident-header-row">
          <span class="incident-title">${item.name}</span>
          <span class="incident-badge ${isCritical ? 'active' : 'monitored'}">${item.severity ? item.severity.toUpperCase() : 'ACTIVE'}</span>
        </div>
        <div class="incident-meta">
          <span>Src: <strong style="color: #fff;">${item.srcIp}</strong></span> &bull;
          <span>Conf: <strong style="color: var(--green-light);">${item.confidence || 96}%</strong></span> &bull;
          <span>${new Date().toLocaleTimeString('en-US', { hour12: false })}</span>
        </div>
      </div>
      <button class="btn-investigate" data-key="${item.id}">INVESTIGATE</button>
    `;

    const btn = div.querySelector('.btn-investigate');
    if (btn) {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        this.openInvestigationModal(item);
      });
    }

    div.addEventListener('click', () => {
      this.openInvestigationModal(item);
    });

    return div;
  }

  addIncidentToFeed(threat) {
    const feed = document.getElementById('socIncidentFeedList');
    if (!feed || !threat) return;

    const el = this.createIncidentDOM(threat);
    feed.insertBefore(el, feed.firstChild);

    if (feed.children.length > 15) {
      feed.removeChild(feed.lastChild);
    }

    this.incidentCount++;
    const badge = document.getElementById('incidentCountBadge');
    if (badge) badge.textContent = `${this.incidentCount} INCIDENTS`;

    // Add timeline marker
    const timeline = document.getElementById('socTimelineEvents');
    if (timeline) {
      const dot = document.createElement('span');
      dot.className = `timeline-dot ${threat.severity === 'Critical' ? 'critical' : 'high'}`;
      dot.title = `${new Date().toLocaleTimeString('en-US', { hour12: false, minute: '2-digit', second: '2-digit' })} - ${threat.name}`;
      dot.addEventListener('click', () => this.openInvestigationModal(threat));
      timeline.appendChild(dot);
      if (timeline.children.length > 12) {
        timeline.removeChild(timeline.firstChild);
      }
    }
  }

  triggerThreatAlert(threat) {
    const banner = document.getElementById('threatAlertBanner');
    const nameEl = document.getElementById('alertThreatName');
    const srcEl = document.getElementById('alertThreatSource');
    const invBtn = document.getElementById('alertInvestigateBtn');

    if (!banner) return;
    if (nameEl) nameEl.textContent = threat.name;
    if (srcEl) srcEl.textContent = `Src: ${threat.srcIp} • Conf: ${threat.confidence}%`;

    if (invBtn) {
      invBtn.onclick = () => {
        banner.style.display = 'none';
        this.openInvestigationModal(threat);
      };
    }

    banner.style.display = 'flex';

    // Auto hide after 6 seconds
    if (this.alertTimeout) clearTimeout(this.alertTimeout);
    this.alertTimeout = setTimeout(() => {
      banner.style.display = 'none';
    }, 6000);
  }

  initAttackPreviews() {
    const select = document.getElementById('attackSelect');
    const desc = document.getElementById('attackPreviewDesc');
    if (select && desc) {
      select.addEventListener('change', () => {
        const item = THREAT_DATABASE[select.value];
        if (item) {
          desc.textContent = item.description;
        }
      });
    }
  }

  /* --------------------------------------------------------------------------
     Render Deep Packet & Headers Inspector
     -------------------------------------------------------------------------- */
  renderInspector(data) {
    const fSrcMac = document.getElementById('fSrcMac');
    const fDstMac = document.getElementById('fDstMac');
    const fEtherType = document.getElementById('fEtherType');
    const fSrcIp = document.getElementById('fSrcIp');
    const fDstIp = document.getElementById('fDstIp');
    const fProto = document.getElementById('fProto');
    const fTtlFlags = document.getElementById('fTtlFlags');
    const fChecksum = document.getElementById('fChecksum');
    const fSrcPort = document.getElementById('fSrcPort');
    const fDstPort = document.getElementById('fDstPort');
    const fUdpLen = document.getElementById('fUdpLen');
    const fEntropy = document.getElementById('fEntropy');
    const fJitter = document.getElementById('fJitter');
    const fModbusCode = document.getElementById('fModbusCode');
    const fPayloadSize = document.getElementById('fPayloadSize');

    const headers = data.headers || {};
    const l2 = headers.l2 || {};
    const l3 = headers.l3 || {};
    const l4 = headers.l4 || {};

    if (fSrcMac) fSrcMac.textContent = l2.srcMac || "00:1A:2B:3C:4D:5E";
    if (fDstMac) fDstMac.textContent = l2.dstMac || "00:50:56:C0:00:08";
    if (fEtherType) fEtherType.textContent = l2.etherType || "0x0800 (IPv4)";

    if (fSrcIp) fSrcIp.textContent = data.srcIp || l3.srcIp || "192.168.10.45";
    if (fDstIp) fDstIp.textContent = data.dstIp || l3.dstIp || "10.0.4.120";
    if (fProto) fProto.textContent = l3.protocol || data.protocol || "17 (UDP)";
    if (fTtlFlags) fTtlFlags.textContent = `${l3.ttl || 64} • ${l3.flags || "DF"}`;
    if (fChecksum) fChecksum.textContent = l3.checksum || "0x3B99 [Valid]";

    if (fSrcPort) fSrcPort.textContent = data.srcPort || l4.srcPort || 50201;
    if (fDstPort) fDstPort.textContent = data.dstPort || l4.dstPort || 502;
    if (fUdpLen) fUdpLen.textContent = `${data.payloadSize || 64} Bytes`;

    if (fEntropy) {
      fEntropy.textContent = `${data.entropy} bits/B`;
      fEntropy.style.color = data.entropy > 5.5 ? "var(--crimson-alert)" : "var(--green-light)";
    }
    if (fJitter) fJitter.textContent = `${data.iatVariance}s variance`;
    if (fModbusCode) fModbusCode.textContent = data.modbusFunction || "N/A";
    if (fPayloadSize) fPayloadSize.textContent = `${data.payloadSize || 64} Bytes`;

    // Hex Dump & ASCII
    const hexContainer = document.getElementById('hexDumpContainer');
    if (hexContainer && data.payloadHex) {
      const hexBytes = data.payloadHex.split(' ');
      const asciiChars = data.payloadAscii || "...";
      let hexHtml = `<div class="hex-header-row">OFFSET   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII</div>`;

      for (let i = 0; i < hexBytes.length; i += 16) {
        const offset = i.toString(16).padStart(8, '0');
        const chunkHex = hexBytes.slice(i, i + 16).join(' ');
        const chunkAscii = asciiChars.slice(i, i + 16) || "................";
        const isMalicious = data.threatScore > 50;
        hexHtml += `<div>${offset} <span class="hex-bytes ${isMalicious ? 'danger' : ''}">${chunkHex}</span> <span class="hex-ascii">${chunkAscii}</span></div>`;
      }
      hexContainer.innerHTML = hexHtml;
    }
  }

  /* --------------------------------------------------------------------------
     Render Explainable AI (XAI) Scorer
     -------------------------------------------------------------------------- */
  renderXAI(data) {
    const scoreNum = document.getElementById('xaiScoreNum');
    const scoreCircle = document.getElementById('xaiScoreCircle');
    const severityTag = document.getElementById('xaiSeverityTag');
    const confidence = document.getElementById('xaiConfidence');
    const threatName = document.getElementById('xaiThreatName');
    const explanation = document.getElementById('xaiExplanationText');
    const featureBarsList = document.getElementById('xaiFeatureBarsList');

    const score = data.threatScore !== undefined ? data.threatScore : 18;
    const sev = data.severity || (score > 80 ? "Critical" : score > 50 ? "High" : "Low");

    if (scoreNum) scoreNum.textContent = score;
    if (confidence) confidence.textContent = `${data.confidence || 97.4}%`;
    if (threatName) threatName.textContent = data.name || "Telemetry Stream";
    if (explanation) explanation.textContent = data.explanation || "Analyzed by Unidirectional Ensemble Classifier.";

    // Update circular SVG gauge
    if (scoreCircle) {
      const circumference = 471; // 2 * PI * 75
      const offset = circumference - (score / 100) * circumference;
      scoreCircle.style.strokeDashoffset = offset;

      if (score >= 80) {
        scoreCircle.style.stroke = "var(--crimson-alert)";
        if (severityTag) {
          severityTag.textContent = "CRITICAL";
          severityTag.style.background = "rgba(244,63,94,0.15)";
          severityTag.style.color = "var(--crimson-alert)";
        }
      } else if (score >= 50) {
        scoreCircle.style.stroke = "var(--amber-gold)";
        if (severityTag) {
          severityTag.textContent = "HIGH RISK";
          severityTag.style.background = "rgba(245,158,11,0.15)";
          severityTag.style.color = "var(--amber-gold)";
        }
      } else {
        scoreCircle.style.stroke = "var(--green-light)";
        if (severityTag) {
          severityTag.textContent = "NORMAL";
          severityTag.style.background = "rgba(16,185,129,0.15)";
          severityTag.style.color = "var(--green-light)";
        }
      }
    }

    // Populate feature attribution bars
    if (featureBarsList && data.xaiFeatures) {
      featureBarsList.innerHTML = data.xaiFeatures.map(f => `
        <div class="xai-bar-row">
          <div class="xai-bar-header">
            <span class="xai-bar-name">${f.name} <span style="font-size: 11px; color: ${f.color};">(${f.impact})</span></span>
            <span class="xai-bar-val">${f.value}</span>
          </div>
          <div class="xai-bar-track">
            <div class="xai-bar-fill" style="width: ${Math.min(100, f.weight * 2)}%; background: ${f.color};"></div>
          </div>
        </div>
      `).join('');
    }
  }

  updateScoreGauge(score, sev) {
    const scoreNum = document.getElementById('xaiScoreNum');
    const scoreCircle = document.getElementById('xaiScoreCircle');
    const severityTag = document.getElementById('xaiSeverityTag');

    if (scoreNum) scoreNum.textContent = score;
    if (scoreCircle) {
      const circumference = 471;
      const offset = circumference - (score / 100) * circumference;
      scoreCircle.style.strokeDashoffset = offset;
      scoreCircle.style.stroke = score > 80 ? "var(--crimson-alert)" : score > 50 ? "var(--amber-gold)" : "var(--green-light)";
    }
    if (severityTag) {
      severityTag.textContent = sev ? sev.toUpperCase() : "ALERT";
    }
  }

  /* --------------------------------------------------------------------------
     Toast Notification System
     -------------------------------------------------------------------------- */
  showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }
}

// Launch Portal on Window Load
window.addEventListener('DOMContentLoaded', () => {
  window.PortalApp = new PortalController();
});
