/**
 * Unidirectional Physical Data Diode Attack Simulator
 * Renders 1-way physical optical transmission:
 * Source Host -> TX Laser Emitter -> Optical Fiber Diode -> RX Photodiode -> AI Inspection Gate -> Destination Enclave.
 */

class UnidirectionalSimulator {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.packets = [];
    this.particles = [];
    this.opticalShutterClosed = false;
    this.continuousBaseline = true;
    this.packetRate = 6; // packets per sec
    this.lastBaselineTime = 0;
    this.onPacketArrival = null;

    this.resize();
    window.addEventListener('resize', () => this.resize());
    this.animate = this.animate.bind(this);
    requestAnimationFrame(this.animate);
  }

  resize() {
    if (!this.canvas) return;
    const rect = this.canvas.parentElement.getBoundingClientRect();
    this.canvas.width = rect.width || 800;
    this.canvas.height = 240;
    this.width = this.canvas.width;
    this.height = this.canvas.height;
  }

  setShutter(isClosed) {
    this.opticalShutterClosed = isClosed;
  }

  setRate(rate) {
    this.packetRate = Math.max(1, Math.min(50, rate));
  }

  setContinuous(enable) {
    this.continuousBaseline = enable;
  }

  injectPacket(packetKey, isAttack = false) {
    const template = THREAT_DATABASE[packetKey] || THREAT_DATABASE.NORMAL_TELEMETRY;
    const laneY = this.height / 2;

    const pkt = {
      id: `PKT-${Date.now().toString().slice(-4)}`,
      data: { ...template },
      x: 75,
      y: laneY + (Math.random() * 12 - 6),
      vx: isAttack ? 8.5 : (3.8 + Math.random() * 0.8),
      size: isAttack ? 8 : 5,
      color: isAttack ? "#f43f5e" : "#10b981",
      trailColor: isAttack ? "rgba(244, 63, 94, 0.4)" : "rgba(16, 185, 129, 0.35)",
      isAttack: isAttack,
      stage: "SOURCE",
      blocked: false,
      opacity: 1
    };

    this.packets.push(pkt);
    this.createBurst(75, laneY, pkt.color, 8);
  }

  createBurst(x, y, color, count = 10) {
    for (let i = 0; i < count; i++) {
      const angle = Math.random() * Math.PI * 2;
      const speed = Math.random() * 3 + 1;
      this.particles.push({
        x: x,
        y: y,
        vx: Math.cos(angle) * speed,
        vy: Math.sin(angle) * speed,
        size: Math.random() * 2.5 + 1,
        color: color,
        life: 1.0,
        decay: Math.random() * 0.04 + 0.02
      });
    }
  }

  animate(time) {
    if (!this.canvas || !this.ctx) return;
    this.ctx.clearRect(0, 0, this.width, this.height);

    // Auto-generate baseline normal packets
    if (this.continuousBaseline && !this.opticalShutterClosed) {
      const interval = 1000 / this.packetRate;
      if (time - this.lastBaselineTime > interval) {
        this.injectPacket("NORMAL_TELEMETRY", false);
        this.lastBaselineTime = time;
      }
    }

    // Draw Infrastructure Hardware Topology
    this.drawInfrastructure();

    // Update & Render Packets
    this.updatePackets();

    // Update & Render Particle Sparks
    this.updateParticles();

    requestAnimationFrame(this.animate);
  }

  drawInfrastructure() {
    const ctx = this.ctx;
    const w = this.width;
    const h = this.height;
    const midY = h / 2;

    // Node coordinates across horizontal axis
    const srcX = 65;
    const txLaserX = w * 0.28;
    const diodeMidX = w * 0.50;
    const rxPhotoX = w * 0.72;
    const dstX = w - 65;

    // 1. Fiber Optic Light Guide (Horizontal Channel)
    const fiberGrad = ctx.createLinearGradient(txLaserX, midY, rxPhotoX, midY);
    fiberGrad.addColorStop(0, '#38bdf8');
    fiberGrad.addColorStop(0.5, '#00f0ff');
    fiberGrad.addColorStop(1, '#10b981');

    ctx.strokeStyle = this.opticalShutterClosed ? 'rgba(244, 63, 94, 0.2)' : 'rgba(56, 189, 248, 0.2)';
    ctx.lineWidth = 14;
    ctx.lineCap = 'round';
    ctx.beginPath();
    ctx.moveTo(txLaserX, midY);
    ctx.lineTo(rxPhotoX, midY);
    ctx.stroke();

    // Core single-mode optical strand
    ctx.strokeStyle = this.opticalShutterClosed ? '#f43f5e' : '#00f0ff';
    ctx.lineWidth = 2.5;
    ctx.beginPath();
    ctx.moveTo(txLaserX, midY);
    ctx.lineTo(rxPhotoX, midY);
    ctx.stroke();

    // Unidirectional Flow Arrows (1-Way Only)
    for (let x = txLaserX + 30; x < rxPhotoX - 20; x += 40) {
      ctx.fillStyle = this.opticalShutterClosed ? 'rgba(244, 63, 94, 0.4)' : 'rgba(0, 240, 255, 0.6)';
      ctx.beginPath();
      ctx.moveTo(x, midY - 4);
      ctx.lineTo(x + 6, midY);
      ctx.lineTo(x, midY + 4);
      ctx.fill();
    }

    // 2. Hardware Enclave & Diode Nodes
    this.drawHardwareNode(srcX, midY, "SRC HOST", "192.168.10.x", "#38bdf8", "Untrusted Ingress");
    this.drawHardwareNode(txLaserX, midY, "TX LASER", "850nm SFP+", "#38bdf8", "Electrical -> Light");
    this.drawDataDiodeNode(diodeMidX, midY);
    this.drawHardwareNode(rxPhotoX, midY, "RX PHOTODIODE", "InGaAs PIN", "#10b981", "Light -> Electrical");
    this.drawHardwareNode(dstX, midY, "DST ENCLAVE", "10.0.4.x", "#00f0ff", "Critical SCADA");

    // 3. Optical Mechanical Shutter
    if (this.opticalShutterClosed) {
      ctx.fillStyle = '#f43f5e';
      ctx.shadowColor = '#f43f5e';
      ctx.shadowBlur = 12;
      ctx.fillRect(diodeMidX - 4, midY - 24, 8, 48);
      ctx.shadowBlur = 0;

      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 9px monospace';
      ctx.textAlign = 'center';
      ctx.fillText('SHUTTER CLOSED', diodeMidX, midY - 30);
    }
  }

  drawHardwareNode(x, y, title, sub, color, role) {
    const ctx = this.ctx;
    ctx.save();

    // Outer glow card
    ctx.fillStyle = '#121829';
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    const boxW = 86;
    const boxH = 54;
    ctx.beginPath();
    ctx.roundRect(x - boxW / 2, y - boxH / 2, boxW, boxH, 8);
    ctx.fill();
    ctx.stroke();

    // Texts
    ctx.textAlign = 'center';
    ctx.fillStyle = '#ffffff';
    ctx.font = 'bold 10px "JetBrains Mono", monospace';
    ctx.fillText(title, x, y - 8);

    ctx.fillStyle = color;
    ctx.font = '9px "JetBrains Mono", monospace';
    ctx.fillText(sub, x, y + 6);

    ctx.fillStyle = 'rgba(255,255,255,0.45)';
    ctx.font = '8px sans-serif';
    ctx.fillText(role, x, y + 18);

    ctx.restore();
  }

  drawDataDiodeNode(x, y) {
    const ctx = this.ctx;
    ctx.save();

    const boxW = 110;
    const boxH = 64;
    ctx.fillStyle = '#0f172a';
    ctx.strokeStyle = this.opticalShutterClosed ? '#f43f5e' : '#00f0ff';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.roundRect(x - boxW / 2, y - boxH / 2, boxW, boxH, 10);
    ctx.fill();
    ctx.stroke();

    // Laser symbol
    ctx.fillStyle = this.opticalShutterClosed ? '#f43f5e' : '#ccff00';
    ctx.textAlign = 'center';
    ctx.font = 'bold 11px "JetBrains Mono", monospace';
    ctx.fillText('OPTICAL DIODE', x, y - 10);

    ctx.font = '9px monospace';
    ctx.fillStyle = '#38bdf8';
    ctx.fillText('1-WAY PHYSICAL BARRIER', x, y + 5);

    ctx.fillStyle = 'rgba(255,255,255,0.4)';
    ctx.font = '8px monospace';
    ctx.fillText('BACKCHANNEL = 0 bps', x, y + 18);

    ctx.restore();
  }

  updatePackets() {
    const ctx = this.ctx;
    const diodeMidX = this.width * 0.50;
    const rxPhotoX = this.width * 0.72;
    const dstX = this.width - 65;

    for (let i = this.packets.length - 1; i >= 0; i--) {
      const pkt = this.packets[i];
      pkt.x += pkt.vx;

      // Optical Shutter Check
      if (this.opticalShutterClosed && pkt.x >= diodeMidX - 6 && pkt.x <= diodeMidX + 6) {
        pkt.blocked = true;
        this.createBurst(pkt.x, pkt.y, '#f43f5e', 14);
        this.packets.splice(i, 1);
        continue;
      }

      // Reached Photodiode & AI Inspection Gate
      if (pkt.x >= rxPhotoX && pkt.stage === "SOURCE") {
        pkt.stage = "INSPECTED";
        const aiReport = window.AIEngineInstance.analyzePacket(pkt.data);
        if (this.onPacketArrival) {
          this.onPacketArrival(aiReport, pkt);
        }
        this.createBurst(pkt.x, pkt.y, pkt.isAttack ? '#f43f5e' : '#10b981', 8);
      }

      // Reached Destination Enclave
      if (pkt.x >= dstX) {
        this.createBurst(dstX, pkt.y, pkt.color, 6);
        this.packets.splice(i, 1);
        continue;
      }

      // Draw Packet Photon
      ctx.save();
      ctx.fillStyle = pkt.color;
      ctx.shadowColor = pkt.color;
      ctx.shadowBlur = pkt.isAttack ? 14 : 8;

      ctx.beginPath();
      ctx.arc(pkt.x, pkt.y, pkt.size, 0, Math.PI * 2);
      ctx.fill();

      // Tail trail
      ctx.strokeStyle = pkt.trailColor;
      ctx.lineWidth = pkt.size * 0.7;
      ctx.beginPath();
      ctx.moveTo(pkt.x - 14, pkt.y);
      ctx.lineTo(pkt.x, pkt.y);
      ctx.stroke();

      ctx.restore();
    }
  }

  updateParticles() {
    const ctx = this.ctx;
    for (let i = this.particles.length - 1; i >= 0; i--) {
      const p = this.particles[i];
      p.x += p.vx;
      p.y += p.vy;
      p.life -= p.decay;

      if (p.life <= 0) {
        this.particles.splice(i, 1);
        continue;
      }

      ctx.fillStyle = p.color;
      ctx.globalAlpha = p.life;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.globalAlpha = 1.0;
  }
}

window.UnidirectionalSimulator = UnidirectionalSimulator;
