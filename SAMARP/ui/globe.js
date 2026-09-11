/**
 * Cyber Globe & Unidirectional Network Topology Visualizer
 * Fast, pure Canvas 3D & 2D interactive projection engine matching the reference dashboard.
 * Features:
 * - Previous classic Earth animation (clean point cloud landmasses, latitude/longitude rings, atmosphere halo)
 * - ATTACKER LOCATION clearly identified with glowing warning beacon and IP
 * - SERVER LOCATION clearly identified with white concentric bullseye rings and IP
 * - OPTICAL DATA DIODE physical one-way gateway
 * - Directional trajectory flow animation with moving chevron arrows and photon packets
 */

class CyberGlobe {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.is3D = true;

    // Camera angles oriented to show Americas with Attacker & Server in view
    this.rotationX = 0.25;
    this.rotationY = 0.85;
    this.autoRotateSpeed = 0.0025;
    this.isDragging = false;
    this.lastMouseX = 0;
    this.lastMouseY = 0;

    this.radarRadius = 0;
    this.radarAlpha = 1;
    this.pulsePhase = 0;
    this.serverFlash = 0;
    this.particles = [];
    this.arcPackets = [];

    this.initNodes();
    this.initContinents();
    this.resize();

    window.addEventListener('resize', () => this.resize());
    this.initInteractions();
    this.animate = this.animate.bind(this);
    requestAnimationFrame(this.animate);
  }

  resize() {
    if (!this.canvas) return;
    const rect = this.canvas.parentElement ? this.canvas.parentElement.getBoundingClientRect() : {};
    this.canvas.width = rect.width && rect.width > 100 ? rect.width : (window.innerWidth ? Math.max(800, window.innerWidth - 120) : 1200);
    this.canvas.height = rect.height && rect.height > 100 ? rect.height : 720;
    this.width = this.canvas.width;
    this.height = this.canvas.height;
    this.radius = Math.min(this.width, this.height) * 0.38;
    this.centerX = this.width / 2;
    this.centerY = this.height / 2;
  }

  setMode(mode) {
    this.is3D = (mode === '3D');
  }

  /* --------------------------------------------------------------------------
     Telemetry Nodes: Attacker Location -> Optical Diode -> Server Location
     -------------------------------------------------------------------------- */
  initNodes() {
    this.nodes = [
      // 0. Attacker Location (North America)
      {
        id: "ATTACKER",
        label: "ATTACKER LOCATION",
        subLabel: "10.20.14.8 [DDoS Flood]",
        lat: 38.90,
        lon: -77.03, // US East
        type: "attacker",
        color: "#f43f5e"
      },

      // 1. Optical Data Diode (Caribbean Gateway)
      {
        id: "OPTICAL_DIODE",
        label: "OPTICAL DATA DIODE",
        subLabel: "10.10.1.1 [TX->RX 850nm]",
        lat: 10.0,
        lon: -75.0,
        type: "diode",
        color: "#38bdf8"
      },

      // 2. Protected Server Location (South America - Central Bullseye)
      {
        id: "SECURE_SERVER",
        label: "SERVER LOCATION",
        subLabel: "10.0.4.15 [Enclave Core]",
        lat: -15.78,
        lon: -47.92, // Central South America / Brazil
        type: "server",
        color: "#ffffff"
      },

      // 3. Secondary Attacker (Europe C2 Relay)
      {
        id: "C2_ATTACKER",
        label: "C2 BOTNET RELAY",
        subLabel: "198.51.100.24 [Beacon]",
        lat: 51.5,
        lon: -0.12, // Europe
        type: "attacker",
        color: "#f59e0b"
      },

      // 4. Perimeter Sensors (Asia / India)
      {
        id: "PLANT_SENSORS",
        label: "PERIMETER RTU SENSORS",
        subLabel: "203.0.113.85 [Telemetry]",
        lat: 28.61,
        lon: 77.20,
        type: "sensor",
        color: "#34d399"
      }
    ];

    // Trajectory Arcs (Directional 1-way: Attacker -> Diode -> Server)
    this.arcs = [
      { from: this.nodes[0], to: this.nodes[1], color: "#f43f5e", isAttack: true, label: "Attack Ingress" },
      { from: this.nodes[1], to: this.nodes[2], color: "#00f0ff", isAttack: false, label: "1-Way Diode Flow" },
      { from: this.nodes[3], to: this.nodes[1], color: "#f59e0b", isAttack: true, label: "C2 Flow" },
      { from: this.nodes[4], to: this.nodes[1], color: "#34d399", isAttack: false, label: "Sensor Flow" }
    ];
  }

  /* --------------------------------------------------------------------------
     Classic Earth Continent Point Cloud
     -------------------------------------------------------------------------- */
  initContinents() {
    this.landPoints = [];
    const numPoints = 950;
    for (let i = 0; i < numPoints; i++) {
      let lat, lon;
      const cluster = Math.random();
      if (cluster < 0.35) {
        // Americas (Dense coverage for Attacker & Server continents)
        lat = (Math.random() * 115 - 55) * (Math.PI / 180);
        lon = (Math.random() * 85 - 125) * (Math.PI / 180);
      } else if (cluster < 0.65) {
        // Eurasia & India
        lat = (Math.random() * 65 + 10) * (Math.PI / 180);
        lon = (Math.random() * 110 + 20) * (Math.PI / 180);
      } else if (cluster < 0.82) {
        // Africa
        lat = (Math.random() * 65 - 35) * (Math.PI / 180);
        lon = (Math.random() * 50 + 10) * (Math.PI / 180);
      } else {
        // Australia / Pacific
        lat = (Math.random() * 40 - 35) * (Math.PI / 180);
        lon = (Math.random() * 60 + 115) * (Math.PI / 180);
      }
      this.landPoints.push({ lat, lon });
    }
  }

  initInteractions() {
    this.canvas.addEventListener('mousedown', (e) => {
      this.isDragging = true;
      this.lastMouseX = e.clientX;
      this.lastMouseY = e.clientY;
    });

    window.addEventListener('mouseup', () => {
      this.isDragging = false;
    });

    window.addEventListener('mousemove', (e) => {
      if (!this.isDragging || !this.is3D) return;
      const dx = e.clientX - this.lastMouseX;
      const dy = e.clientY - this.lastMouseY;
      this.rotationY += dx * 0.006;
      this.rotationX += dy * 0.006;
      this.rotationX = Math.max(-1.1, Math.min(1.1, this.rotationX));
      this.lastMouseX = e.clientX;
      this.lastMouseY = e.clientY;
    });
  }

  triggerAttackWave(attackColor = "#f43f5e") {
    // Generate packet burst along the unidirectional arc from Attacker to Diode
    for (let i = 0; i < 10; i++) {
      this.arcPackets.push({
        arcIdx: 0,
        progress: -i * 0.09,
        speed: 0.018,
        color: attackColor,
        isAttack: true
      });
    }
  }

  project3D(lat, lon) {
    const phi = lat;
    const theta = lon + this.rotationY;

    let x = this.radius * Math.cos(phi) * Math.sin(theta);
    let y = -this.radius * Math.sin(phi);
    let z = this.radius * Math.cos(phi) * Math.cos(theta);

    // Rotate around X axis
    const cosX = Math.cos(this.rotationX);
    const sinX = Math.sin(this.rotationX);
    const yRot = y * cosX - z * sinX;
    const zRot = y * sinX + z * cosX;

    return {
      x: this.centerX + x,
      y: this.centerY + yRot,
      z: zRot,
      visible: zRot > -this.radius * 0.2
    };
  }

  project2D(lat, lon) {
    const x = this.centerX + (lon / Math.PI) * (this.radius * 1.5);
    const y = this.centerY - (lat / (Math.PI / 2)) * (this.radius * 0.9);
    return { x, y, z: 1, visible: true };
  }

  project(lat, lon) {
    return this.is3D ? this.project3D(lat, lon) : this.project2D(lat, lon);
  }

  /* --------------------------------------------------------------------------
     Main Render Loop
     -------------------------------------------------------------------------- */
  animate() {
    if (!this.canvas || !this.ctx) return;
    this.ctx.clearRect(0, 0, this.width, this.height);

    if (this.is3D && !this.isDragging) {
      this.rotationY += this.autoRotateSpeed;
    }
    this.pulsePhase += 0.05;

    // 1. Atmospheric Space Glow & Planet Sphere
    this.drawAtmosphere();

    // 2. Latitude & Longitude Coordinates
    this.drawContours();

    // 3. Continent Point Cloud with Glowing City Accents
    this.drawLandmasses();

    // 4. Directional Trajectory Arcs with Flow Chevrons
    this.drawArcs();

    // 5. Directional Photon Packets Moving Attacker -> Diode -> Server
    this.drawPackets();

    // 6. Concentric Bullseye Target Rings on Server Location
    this.drawTargetingRings();

    // 7. Attacker, Diode & Server Badges and Markers
    this.drawNodes();

    requestAnimationFrame(this.animate);
  }

  /* --------------------------------------------------------------------------
     Atmospheric Glow & Earth Body
     -------------------------------------------------------------------------- */
  drawAtmosphere() {
    const ctx = this.ctx;
    if (this.is3D) {
      // Outer planetary cyan/blue halo
      const glowGrad = ctx.createRadialGradient(
        this.centerX, this.centerY, this.radius * 0.85,
        this.centerX, this.centerY, this.radius * 1.35
      );
      glowGrad.addColorStop(0, 'rgba(56, 189, 248, 0.12)');
      glowGrad.addColorStop(0.5, 'rgba(0, 240, 255, 0.04)');
      glowGrad.addColorStop(1, 'rgba(10, 15, 29, 0)');
      ctx.fillStyle = glowGrad;
      ctx.beginPath();
      ctx.arc(this.centerX, this.centerY, this.radius * 1.35, 0, Math.PI * 2);
      ctx.fill();

      // Globe sphere body
      const sphereGrad = ctx.createRadialGradient(
        this.centerX - this.radius * 0.3, this.centerY - this.radius * 0.3, this.radius * 0.1,
        this.centerX, this.centerY, this.radius
      );
      sphereGrad.addColorStop(0, '#101d36');
      sphereGrad.addColorStop(0.7, '#0b1324');
      sphereGrad.addColorStop(1, '#070b14');
      ctx.fillStyle = sphereGrad;
      ctx.beginPath();
      ctx.arc(this.centerX, this.centerY, this.radius, 0, Math.PI * 2);
      ctx.fill();

      // Thin globe border rim
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.3)';
      ctx.lineWidth = 1.2;
      ctx.stroke();
    } else {
      // 2D Topology Grid Background
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.05)';
      ctx.lineWidth = 1;
      const step = 40;
      for (let x = 0; x < this.width; x += step) {
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, this.height); ctx.stroke();
      }
      for (let y = 0; y < this.height; y += step) {
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(this.width, y); ctx.stroke();
      }
    }
  }

  /* --------------------------------------------------------------------------
     Latitude & Longitude Coordinates
     -------------------------------------------------------------------------- */
  drawContours() {
    const ctx = this.ctx;
    ctx.lineWidth = 0.8;
    ctx.strokeStyle = 'rgba(56, 189, 248, 0.12)';

    if (this.is3D) {
      // Longitude meridians
      for (let lonDeg = 0; lonDeg < 360; lonDeg += 30) {
        const lon = (lonDeg * Math.PI) / 180;
        ctx.beginPath();
        let started = false;
        for (let latDeg = -85; latDeg <= 85; latDeg += 8) {
          const lat = (latDeg * Math.PI) / 180;
          const p = this.project3D(lat, lon);
          if (p.visible) {
            if (!started) { ctx.moveTo(p.x, p.y); started = true; }
            else { ctx.lineTo(p.x, p.y); }
          } else {
            started = false;
          }
        }
        ctx.stroke();
      }

      // Latitude parallels
      for (let latDeg = -60; latDeg <= 60; latDeg += 30) {
        const lat = (latDeg * Math.PI) / 180;
        ctx.beginPath();
        let started = false;
        for (let lonDeg = 0; lonDeg <= 360; lonDeg += 8) {
          const lon = (lonDeg * Math.PI) / 180;
          const p = this.project3D(lat, lon);
          if (p.visible) {
            if (!started) { ctx.moveTo(p.x, p.y); started = true; }
            else { ctx.lineTo(p.x, p.y); }
          } else {
            started = false;
          }
        }
        ctx.stroke();
      }
    }
  }

  /* --------------------------------------------------------------------------
     Continent Landmasses & Glowing City Lights
     -------------------------------------------------------------------------- */
  drawLandmasses() {
    const ctx = this.ctx;
    for (let i = 0; i < this.landPoints.length; i++) {
      const pt = this.landPoints[i];
      const p = this.project(pt.lat, pt.lon);
      if (!p.visible) continue;

      const alpha = this.is3D ? Math.max(0.1, (p.z + this.radius) / (this.radius * 2)) : 0.6;
      ctx.fillStyle = `rgba(56, 189, 248, ${alpha * 0.75})`;
      ctx.beginPath();
      ctx.arc(p.x, p.y, 1.25, 0, Math.PI * 2);
      ctx.fill();

      // Glowing city light accents
      if (i % 6 === 0) {
        ctx.fillStyle = `rgba(0, 240, 255, ${alpha * 0.9})`;
        ctx.beginPath();
        ctx.arc(p.x, p.y, 1.9, 0, Math.PI * 2);
        ctx.fill();
      }
    }
  }

  /* --------------------------------------------------------------------------
     Directional Arcs with Moving Chevrons (Attacker -> Diode -> Server)
     -------------------------------------------------------------------------- */
  drawArcs() {
    const ctx = this.ctx;
    for (let a = 0; a < this.arcs.length; a++) {
      const arc = this.arcs[a];
      const fromP = this.project((arc.from.lat * Math.PI) / 180, (arc.from.lon * Math.PI) / 180);
      const toP = this.project((arc.to.lat * Math.PI) / 180, (arc.to.lon * Math.PI) / 180);

      if (!fromP.visible && !toP.visible) continue;

      // Draw curved trajectory
      ctx.strokeStyle = arc.color;
      ctx.lineWidth = arc.isAttack ? 1.8 : 1.4;
      ctx.shadowColor = arc.color;
      ctx.shadowBlur = arc.isAttack ? 8 : 4;
      ctx.beginPath();
      ctx.moveTo(fromP.x, fromP.y);

      // Quadratic curve pulled outward to simulate orbital altitude
      const midX = (fromP.x + toP.x) / 2;
      const midY = (fromP.y + toP.y) / 2 - 38;
      ctx.quadraticCurveTo(midX, midY, toP.x, toP.y);
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Directional Flow Chevrons (indicating one-way travel towards Server)
      const numArrows = 2;
      for (let k = 1; k <= numArrows; k++) {
        const t = ((k / (numArrows + 1)) + (this.pulsePhase * 0.12)) % 1.0;
        const curX = (1 - t) * (1 - t) * fromP.x + 2 * (1 - t) * t * midX + t * t * toP.x;
        const curY = (1 - t) * (1 - t) * fromP.y + 2 * (1 - t) * t * midY + t * t * toP.y;

        const dx = 2 * (1 - t) * (midX - fromP.x) + 2 * t * (toP.x - midX);
        const dy = 2 * (1 - t) * (midY - fromP.y) + 2 * t * (toP.y - midY);
        const angle = Math.atan2(dy, dx);

        ctx.save();
        ctx.translate(curX, curY);
        ctx.rotate(angle);
        ctx.strokeStyle = arc.color;
        ctx.lineWidth = 1.6;
        ctx.beginPath();
        ctx.moveTo(-4, -3);
        ctx.lineTo(2, 0);
        ctx.lineTo(-4, 3);
        ctx.stroke();
        ctx.restore();
      }
    }
  }

  /* --------------------------------------------------------------------------
     Directional Packet Animation (Attacker -> Diode -> Server)
     -------------------------------------------------------------------------- */
  drawPackets() {
    const ctx = this.ctx;

    // Constantly generate unidirectional streams
    if (Math.random() < 0.18) {
      const isAttack = Math.random() < 0.65;
      this.arcPackets.push({
        arcIdx: isAttack ? (Math.random() < 0.7 ? 0 : 2) : (Math.random() < 0.5 ? 1 : 3),
        progress: 0,
        speed: 0.012 + Math.random() * 0.012,
        color: isAttack ? "#f43f5e" : "#00f0ff",
        isAttack: isAttack
      });
    }

    for (let i = this.arcPackets.length - 1; i >= 0; i--) {
      const pkt = this.arcPackets[i];
      pkt.progress += pkt.speed;

      if (pkt.progress >= 1.0) {
        // If packet reached the diode, cascade forward to server
        if (pkt.arcIdx === 0 || pkt.arcIdx === 2) {
          this.arcPackets.push({
            arcIdx: 1, // Diode -> Server
            progress: 0,
            speed: 0.02,
            color: pkt.isAttack ? "#f43f5e" : "#00f0ff",
            isAttack: pkt.isAttack
          });
        } else if (pkt.arcIdx === 1) {
          // Packet arrived at Server Location -> trigger target ripple flash
          this.serverFlash = 1.0;
        }
        this.arcPackets.splice(i, 1);
        continue;
      }

      if (pkt.progress < 0) continue;

      const arc = this.arcs[pkt.arcIdx];
      const fromP = this.project((arc.from.lat * Math.PI) / 180, (arc.from.lon * Math.PI) / 180);
      const toP = this.project((arc.to.lat * Math.PI) / 180, (arc.to.lon * Math.PI) / 180);

      const midX = (fromP.x + toP.x) / 2;
      const midY = (fromP.y + toP.y) / 2 - 38;

      // Quadratic interpolation
      const t = pkt.progress;
      const curX = (1 - t) * (1 - t) * fromP.x + 2 * (1 - t) * t * midX + t * t * toP.x;
      const curY = (1 - t) * (1 - t) * fromP.y + 2 * (1 - t) * t * midY + t * t * toP.y;

      // Packet photon glow
      ctx.fillStyle = pkt.color;
      ctx.shadowColor = pkt.color;
      ctx.shadowBlur = 12;
      ctx.beginPath();
      ctx.arc(curX, curY, pkt.isAttack ? 4.0 : 2.8, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 0;
    }
  }

  /* --------------------------------------------------------------------------
     Concentric Bullseye Target Rings over Server Location (Matching Screenshot)
     -------------------------------------------------------------------------- */
  drawTargetingRings() {
    const ctx = this.ctx;
    const serverNode = this.nodes[2]; // Server Location (South America)
    const p = this.project((serverNode.lat * Math.PI) / 180, (serverNode.lon * Math.PI) / 180);

    if (!p.visible) return;

    // Expanding radar scan rings
    this.radarRadius += 0.5;
    if (this.radarRadius > 38) this.radarRadius = 0;
    const ringAlpha = 1 - (this.radarRadius / 38);

    ctx.strokeStyle = `rgba(0, 240, 255, ${ringAlpha * 0.8})`;
    ctx.lineWidth = 1.4;
    ctx.beginPath();
    ctx.arc(p.x, p.y, this.radarRadius, 0, Math.PI * 2);
    ctx.stroke();

    // Solid inner circular target ring (identical to reference image)
    ctx.strokeStyle = '#ffffff';
    ctx.lineWidth = 2.0;
    ctx.beginPath();
    ctx.arc(p.x, p.y, 14, 0, Math.PI * 2);
    ctx.stroke();

    // Impact flash when packets reach the server
    if (this.serverFlash > 0) {
      ctx.fillStyle = `rgba(255, 255, 255, ${this.serverFlash * 0.4})`;
      ctx.beginPath();
      ctx.arc(p.x, p.y, 16, 0, Math.PI * 2);
      ctx.fill();
      this.serverFlash -= 0.04;
    }

    // Outer subtle contour ring
    ctx.strokeStyle = 'rgba(56, 189, 248, 0.35)';
    ctx.lineWidth = 1.0;
    ctx.beginPath();
    ctx.arc(p.x, p.y, 22, 0, Math.PI * 2);
    ctx.stroke();
  }

  /* --------------------------------------------------------------------------
     Attacker, Server & Diode Telemetry Nodes and Badges
     -------------------------------------------------------------------------- */
  drawNodes() {
    const ctx = this.ctx;
    for (const node of this.nodes) {
      const p = this.project((node.lat * Math.PI) / 180, (node.lon * Math.PI) / 180);
      if (!p.visible) continue;

      if (node.type === "server") {
        // Glowing white center core
        ctx.fillStyle = "#ffffff";
        ctx.shadowColor = "rgba(255, 255, 255, 0.9)";
        ctx.shadowBlur = 12;
        ctx.beginPath();
        ctx.arc(p.x, p.y, 6.0, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;

        // Server Label Badge
        ctx.font = "bold 10px 'Plus Jakarta Sans', sans-serif";
        ctx.fillStyle = "#ffffff";
        ctx.fillText("🛡️ " + node.label, p.x + 24, p.y - 2);

        ctx.font = "9px 'JetBrains Mono', monospace";
        ctx.fillStyle = "var(--cyan-neon, #00f0ff)";
        ctx.fillText(node.subLabel, p.x + 24, p.y + 10);

      } else if (node.type === "attacker") {
        // Red/Amber warning pulse
        ctx.fillStyle = node.color;
        ctx.shadowColor = node.color;
        ctx.shadowBlur = 12;
        ctx.beginPath();
        ctx.arc(p.x, p.y, 4.5, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;

        // Pulsing warning ring
        const ringR = 8 + 3 * Math.sin(this.pulsePhase * 2);
        ctx.strokeStyle = node.color;
        ctx.lineWidth = 1.4;
        ctx.beginPath();
        ctx.arc(p.x, p.y, ringR, 0, Math.PI * 2);
        ctx.stroke();

        // Attacker Label Badge
        ctx.font = "bold 10px 'Plus Jakarta Sans', sans-serif";
        ctx.fillStyle = node.color;
        ctx.fillText("🚨 " + node.label, p.x + 14, p.y - 3);

        ctx.font = "9px 'JetBrains Mono', monospace";
        ctx.fillStyle = "rgba(255, 255, 255, 0.85)";
        ctx.fillText(node.subLabel, p.x + 14, p.y + 9);

      } else if (node.type === "diode") {
        // Optical Diode Gateway Node
        ctx.fillStyle = "#38bdf8";
        ctx.beginPath();
        ctx.arc(p.x, p.y, 4.0, 0, Math.PI * 2);
        ctx.fill();

        ctx.strokeStyle = "rgba(56, 189, 248, 0.6)";
        ctx.lineWidth = 1.2;
        ctx.beginPath();
        ctx.arc(p.x, p.y, 7, 0, Math.PI * 2);
        ctx.stroke();

        // Diode Label
        ctx.font = "bold 9px 'Plus Jakarta Sans', sans-serif";
        ctx.fillStyle = "#38bdf8";
        ctx.fillText("⚡ " + node.label, p.x + 12, p.y - 2);

        ctx.font = "8px 'JetBrains Mono', monospace";
        ctx.fillStyle = "var(--green-light, #10b981)";
        ctx.fillText("ONE-WAY INGRESS ──►", p.x + 12, p.y + 9);

      } else {
        // Normal sensor node
        ctx.fillStyle = node.color;
        ctx.beginPath();
        ctx.arc(p.x, p.y, 3.5, 0, Math.PI * 2);
        ctx.fill();

        ctx.font = "9px 'JetBrains Mono', monospace";
        ctx.fillStyle = "rgba(248, 250, 252, 0.75)";
        ctx.fillText(node.label, p.x + 10, p.y + 3);
      }
    }
  }
}

window.CyberGlobe = CyberGlobe;
