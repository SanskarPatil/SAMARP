/**
 * Live Unidirectional Traffic Flow Visualizer & Pipeline Animator
 * Renders moving particles on unidirectional IP flow lines, the AI Detection Pipeline,
 * and the Capture Health live waveform.
 */

class FlowVisualizer {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.particles = [];
    this.activeFlows = [
      { id: "flow-1", srcIp: "10.20.14.8", dstIp: "10.0.4.15", proto: "UDP (443)", packets: 18294, bytes: "14.2 MB", duration: "71s", status: "CRITICAL", score: 97, speed: 4.8, color: "#f43f5e" },
      { id: "flow-2", srcIp: "192.168.1.20", dstIp: "10.20.4.12", proto: "Modbus-UDP", packets: 1420, bytes: "84.2 KB", duration: "18s", status: "NORMAL", score: 6, speed: 1.8, color: "#10b981" },
      { id: "flow-3", srcIp: "10.12.4.21", dstIp: "10.0.4.18", proto: "TCP SYN", packets: 884, bytes: "35.3 KB", duration: "4s", status: "HIGH", score: 88, speed: 3.6, color: "#f59e0b" },
      { id: "flow-4", srcIp: "192.168.1.21", dstIp: "10.20.4.18", proto: "Syslog (514)", packets: 620, bytes: "42.0 KB", duration: "12s", status: "NORMAL", score: 12, speed: 1.6, color: "#38bdf8" },
      { id: "flow-5", srcIp: "172.16.8.44", dstIp: "10.0.4.55", proto: "TLS 1.3", packets: 420, bytes: "354 KB", duration: "42s", status: "HIGH", score: 91, speed: 3.2, color: "#f59e0b" },
      { id: "flow-6", srcIp: "192.168.1.33", dstIp: "10.20.4.55", proto: "Modbus 502", packets: 2940, bytes: "188 KB", duration: "95s", status: "NORMAL", score: 8, speed: 2.0, color: "#10b981" }
    ];

    this.initParticles();
    this.resize();
    window.addEventListener('resize', () => this.resize());
    this.animate = this.animate.bind(this);
    requestAnimationFrame(this.animate);
  }

  resize() {
    if (!this.canvas) return;
    const rect = this.canvas.parentElement ? this.canvas.parentElement.getBoundingClientRect() : {};
    this.canvas.width = rect.width && rect.width > 200 ? rect.width : 780;
    this.canvas.height = 290;
    this.width = this.canvas.width;
    this.height = this.canvas.height;
  }

  initParticles() {
    this.particles = [];
    this.activeFlows.forEach((flow, flowIndex) => {
      // Create 3-4 initial particles per flow line
      for (let i = 0; i < 4; i++) {
        this.particles.push({
          flowIndex: flowIndex,
          progress: i * 0.25 + Math.random() * 0.1,
          size: flow.score > 80 ? 4.5 : 3.0,
          color: flow.color
        });
      }
    });
  }

  addFlow(flowData) {
    // Unshift or replace flow
    this.activeFlows.unshift(flowData);
    if (this.activeFlows.length > 6) {
      this.activeFlows.pop();
    }
    this.initParticles();
  }

  animate(time) {
    if (!this.canvas || !this.ctx) return;
    const ctx = this.ctx;
    ctx.clearRect(0, 0, this.width, this.height);

    const rowHeight = 44;
    const startY = 24;

    // Header labels
    ctx.font = "600 10px 'JetBrains Mono', monospace";
    ctx.fillStyle = "rgba(148, 163, 184, 0.7)";
    ctx.fillText("SOURCE IP", 14, 12);
    ctx.fillText("UNIDIRECTIONAL DIODE FLOW", this.width * 0.35, 12);
    ctx.fillText("DESTINATION", this.width - 150, 12);

    // Draw each flow line
    this.activeFlows.forEach((flow, i) => {
      const y = startY + i * rowHeight + 14;
      const isCritical = flow.score >= 85;
      const isSuspicious = flow.score >= 50 && flow.score < 85;

      // Source IP block
      ctx.fillStyle = "#ffffff";
      ctx.font = "700 11px 'JetBrains Mono', monospace";
      ctx.fillText(flow.srcIp, 14, y - 2);

      ctx.fillStyle = "rgba(148, 163, 184, 0.6)";
      ctx.font = "500 9px sans-serif";
      ctx.fillText(flow.proto, 14, y + 10);

      // Line coordinates
      const lineStartX = 150;
      const lineEndX = this.width - 160;

      // Background flow track line
      ctx.beginPath();
      ctx.moveTo(lineStartX, y);
      ctx.lineTo(lineEndX, y);
      ctx.lineWidth = isCritical ? 2.5 : 1.5;
      ctx.strokeStyle = isCritical 
        ? "rgba(244, 63, 94, 0.4)" 
        : isSuspicious 
        ? "rgba(245, 158, 11, 0.3)" 
        : "rgba(56, 189, 248, 0.18)";
      ctx.stroke();

      // Pulsing alert glow around critical flow line
      if (isCritical) {
        ctx.beginPath();
        ctx.moveTo(lineStartX, y);
        ctx.lineTo(lineEndX, y);
        ctx.lineWidth = 6;
        const pulseAlpha = 0.15 + Math.sin(time * 0.008) * 0.1;
        ctx.strokeStyle = `rgba(244, 63, 94, ${pulseAlpha})`;
        ctx.stroke();
      }

      // Unidirectional Arrow Head (──►)
      ctx.beginPath();
      ctx.moveTo(lineEndX - 8, y - 5);
      ctx.lineTo(lineEndX, y);
      ctx.lineTo(lineEndX - 8, y + 5);
      ctx.fillStyle = isCritical ? "#f43f5e" : isSuspicious ? "#f59e0b" : "#38bdf8";
      ctx.fill();

      // Destination IP block
      ctx.fillStyle = "#ffffff";
      ctx.font = "700 11px 'JetBrains Mono', monospace";
      ctx.fillText(flow.dstIp, this.width - 140, y - 2);

      // Flow stats badges
      ctx.fillStyle = isCritical ? "rgba(244, 63, 94, 0.9)" : isSuspicious ? "rgba(245, 158, 11, 0.9)" : "rgba(16, 185, 129, 0.9)";
      ctx.font = "700 9px 'JetBrains Mono', monospace";
      ctx.fillText(`${flow.status} (${flow.score}%)`, this.width - 140, y + 10);
    });

    // Animate moving particles along flow lines
    this.particles.forEach(p => {
      const flow = this.activeFlows[p.flowIndex];
      if (!flow) return;

      const y = startY + p.flowIndex * rowHeight + 14;
      const lineStartX = 150;
      const lineEndX = this.width - 160;
      const currentX = lineStartX + p.progress * (lineEndX - lineStartX);

      // Draw particle dot
      ctx.beginPath();
      ctx.arc(currentX, y, p.size, 0, Math.PI * 2);
      ctx.fillStyle = flow.color;
      ctx.shadowColor = flow.color;
      ctx.shadowBlur = flow.score > 80 ? 10 : 5;
      ctx.fill();
      ctx.shadowBlur = 0; // reset

      // Draw particle trail
      ctx.beginPath();
      ctx.moveTo(currentX - 12, y);
      ctx.lineTo(currentX, y);
      ctx.strokeStyle = flow.color;
      ctx.lineWidth = p.size * 0.8;
      ctx.stroke();

      // Advance progress based on flow speed
      const speedFactor = 0.003 * flow.speed;
      p.progress += speedFactor;
      if (p.progress > 1.0) {
        p.progress = 0;
      }
    });

    requestAnimationFrame(this.animate);
  }
}

/**
 * AI Detection Pipeline Visualizer
 * Renders PCAP -> FLOW -> FEATURES -> AI MODEL -> THREAT SCORE -> CLASSIFICATION -> INCIDENT
 */
class PipelineVisualizer {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.stageDotProgress = 0;
    this.activeStage = 2;
    this.stages = [
      { name: "TRAFFIC", desc: "Unidirectional Ingress", icon: "🌐" },
      { name: "FLOW EXTRACT", desc: "Zero-Return Session", icon: "⚡" },
      { name: "FEATURE ENGINE", desc: "Entropy & Jitter", icon: "🔬" },
      { name: "AI / ML MODEL", desc: "Supervised Ensemble", icon: "🧠" },
      { name: "THREAT SCORE", desc: "Anomaly Distance", icon: "🎯" },
      { name: "CLASSIFY", desc: "Multi-Class Tag", icon: "📊" },
      { name: "INCIDENT", desc: "SOC Dispatch", icon: "🚨" }
    ];

    this.resize();
    window.addEventListener('resize', () => this.resize());
    this.animate = this.animate.bind(this);
    requestAnimationFrame(this.animate);
  }

  resize() {
    if (!this.canvas) return;
    const rect = this.canvas.parentElement ? this.canvas.parentElement.getBoundingClientRect() : {};
    this.canvas.width = rect.width && rect.width > 200 ? rect.width : 780;
    this.canvas.height = 68;
    this.width = this.canvas.width;
    this.height = this.canvas.height;
  }

  animate(time) {
    if (!this.canvas || !this.ctx) return;
    const ctx = this.ctx;
    ctx.clearRect(0, 0, this.width, this.height);

    const stepWidth = this.width / this.stages.length;
    const centerY = 34;

    // Draw connecting track
    ctx.beginPath();
    ctx.moveTo(stepWidth / 2, centerY);
    ctx.lineTo(this.width - stepWidth / 2, centerY);
    ctx.lineWidth = 2;
    ctx.strokeStyle = "rgba(56, 189, 248, 0.2)";
    ctx.stroke();

    // Moving packet dot along pipeline
    this.stageDotProgress += 0.006;
    if (this.stageDotProgress > 1.0) this.stageDotProgress = 0;
    const dotX = (stepWidth / 2) + this.stageDotProgress * (this.width - stepWidth);

    ctx.beginPath();
    ctx.arc(dotX, centerY, 5, 0, Math.PI * 2);
    ctx.fillStyle = "#00f0ff";
    ctx.shadowColor = "#00f0ff";
    ctx.shadowBlur = 12;
    ctx.fill();
    ctx.shadowBlur = 0;

    // Draw stages
    this.stages.forEach((stage, i) => {
      const x = (i + 0.5) * stepWidth;
      const isPast = dotX >= x;
      const isCurrent = Math.abs(dotX - x) < stepWidth * 0.5;

      // Node circle
      ctx.beginPath();
      ctx.arc(x, centerY, isCurrent ? 12 : 9, 0, Math.PI * 2);
      ctx.fillStyle = isCurrent ? "rgba(0, 240, 255, 0.25)" : isPast ? "rgba(16, 185, 129, 0.2)" : "rgba(30, 41, 59, 0.8)";
      ctx.strokeStyle = isCurrent ? "#00f0ff" : isPast ? "#10b981" : "rgba(148, 163, 184, 0.3)";
      ctx.lineWidth = isCurrent ? 2 : 1;
      ctx.fill();
      ctx.stroke();

      // Node label
      ctx.font = isCurrent ? "700 9px 'JetBrains Mono', monospace" : "600 8px 'JetBrains Mono', monospace";
      ctx.fillStyle = isCurrent ? "#00f0ff" : isPast ? "#10b981" : "rgba(148, 163, 184, 0.6)";
      ctx.textAlign = "center";
      ctx.fillText(stage.name, x, centerY - 16);

      ctx.font = "500 7px sans-serif";
      ctx.fillStyle = "rgba(148, 163, 184, 0.5)";
      ctx.fillText(stage.desc, x, centerY + 22);
    });

    requestAnimationFrame(this.animate);
  }
}

/**
 * Capture Health Live Waveform Canvas
 */
class WaveformVisualizer {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.points = new Array(50).fill(25);

    this.resize();
    window.addEventListener('resize', () => this.resize());
    this.animate = this.animate.bind(this);
    requestAnimationFrame(this.animate);
  }

  resize() {
    if (!this.canvas) return;
    const rect = this.canvas.parentElement ? this.canvas.parentElement.getBoundingClientRect() : {};
    this.canvas.width = rect.width || 220;
    this.canvas.height = 42;
    this.width = this.canvas.width;
    this.height = this.canvas.height;
  }

  animate(time) {
    if (!this.canvas || !this.ctx) return;
    const ctx = this.ctx;
    ctx.clearRect(0, 0, this.width, this.height);

    // Shift and push new synthetic telemetry wave
    this.points.shift();
    const newY = 20 + Math.sin(time * 0.01) * 8 + (Math.random() * 6 - 3);
    this.points.push(newY);

    ctx.beginPath();
    const step = this.width / (this.points.length - 1);
    this.points.forEach((pt, i) => {
      const x = i * step;
      if (i === 0) ctx.moveTo(x, pt);
      else ctx.lineTo(x, pt);
    });

    ctx.strokeStyle = "#10b981";
    ctx.lineWidth = 1.8;
    ctx.stroke();

    requestAnimationFrame(this.animate);
  }
}

window.FlowVisualizerClass = FlowVisualizer;
window.PipelineVisualizerClass = PipelineVisualizer;
window.WaveformVisualizerClass = WaveformVisualizer;
