import React, { useEffect, useRef, useCallback } from 'react';
import { Incident, SensorCapabilities, Severity } from '../types';

/**
 * Rotating Earth canvas for the monitoring console.
 *
 * Geographic honesty contract
 * ---------------------------
 * schemas/alert.schema.json carries no latitude, longitude, country or ASN field,
 * and `capabilities.geo` is NOT_OBSERVABLE on every input mode this build supports.
 * The globe therefore places NOTHING on the Earth's surface by location.
 *
 * Incidents are drawn on an index ring OUTSIDE the sphere, ordered by observation
 * time. Ring position encodes recency, never geography. The surface-pin path below
 * activates only when the sensor actually reports geo as OBSERVABLE and an incident
 * carries real coordinates; until then it never runs and no coordinate is invented.
 */

const SEVERITY_COLORS: Record<Severity, string> = {
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

/** Most recent incidents drawn on the index ring. Bounded for legibility and frame cost. */
const MAX_RING_MARKERS = 48;

/** Deterministic PRNG so the land point cloud is identical on every load. */
function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

interface LandPoint {
  lat: number;
  lon: number;
}

/**
 * Schematic landmass point cloud. This is decorative cartography for orientation only;
 * it is not survey data and nothing in the incident stream is positioned against it.
 */
function buildLandPoints(): LandPoint[] {
  const rand = mulberry32(0x5e11e1);
  const bands: { weight: number; lat: [number, number]; lon: [number, number] }[] = [
    { weight: 0.16, lat: [25, 72], lon: [-168, -55] },
    { weight: 0.12, lat: [-56, 14], lon: [-82, -35] },
    { weight: 0.14, lat: [36, 71], lon: [-10, 42] },
    { weight: 0.16, lat: [-35, 37], lon: [-18, 51] },
    { weight: 0.24, lat: [8, 70], lon: [44, 145] },
    { weight: 0.1, lat: [-44, -11], lon: [113, 154] },
    { weight: 0.08, lat: [-8, 22], lon: [95, 140] },
  ];

  const points: LandPoint[] = [];
  const total = 1100;
  for (const band of bands) {
    const count = Math.round(total * band.weight);
    for (let i = 0; i < count; i++) {
      const lat = band.lat[0] + rand() * (band.lat[1] - band.lat[0]);
      const lon = band.lon[0] + rand() * (band.lon[1] - band.lon[0]);
      points.push({ lat: (lat * Math.PI) / 180, lon: (lon * Math.PI) / 180 });
    }
  }
  return points;
}

const LAND_POINTS = buildLandPoints();

interface RingMarker {
  incidentId: string;
  severity: Severity;
  psClass: string;
  x: number;
  y: number;
  radius: number;
}

interface CyberGlobeProps {
  incidents: Incident[];
  selectedIncidentId: string | null;
  onSelectIncident: (id: string) => void;
  capabilities: SensorCapabilities;
  isLive: boolean;
}

export const CyberGlobe: React.FC<CyberGlobeProps> = ({
  incidents,
  selectedIncidentId,
  onSelectIncident,
  capabilities,
  isLive,
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const frameRef = useRef<number | null>(null);
  const markersRef = useRef<RingMarker[]>([]);
  const hoverRef = useRef<string | null>(null);

  // Mutable render inputs, so the animation loop never restarts on data change.
  const dataRef = useRef({ incidents, selectedIncidentId, isLive });
  dataRef.current = { incidents, selectedIncidentId, isLive };

  const geoState = capabilities.geo || 'NOT_OBSERVABLE';
  const geoObservable = geoState === 'OBSERVABLE';

  const handleClick = useCallback(
    (event: React.MouseEvent<HTMLCanvasElement>) => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      const px = event.clientX - rect.left;
      const py = event.clientY - rect.top;

      let closest: RingMarker | null = null;
      let closestDist = 18;
      for (const marker of markersRef.current) {
        const dist = Math.hypot(marker.x - px, marker.y - py);
        if (dist < closestDist) {
          closestDist = dist;
          closest = marker;
        }
      }
      if (closest) onSelectIncident(closest.incidentId);
    },
    [onSelectIncident],
  );

  const handleMove = useCallback((event: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const px = event.clientX - rect.left;
    const py = event.clientY - rect.top;

    let found: string | null = null;
    for (const marker of markersRef.current) {
      if (Math.hypot(marker.x - px, marker.y - py) < 16) {
        found = marker.incidentId;
        break;
      }
    }
    hoverRef.current = found;
    canvas.style.cursor = found ? 'pointer' : 'grab';
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    const wrap = wrapRef.current;
    if (!canvas || !wrap) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    let width = 0;
    let height = 0;
    let cx = 0;
    let cy = 0;
    let radius = 0;
    let rotation = 0;
    let tilt = 0.42;
    let sweep = 0;
    let dragging = false;
    let lastX = 0;
    let lastY = 0;
    let dpr = 1;

    const applySize = () => {
      const rect = wrap.getBoundingClientRect();
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = Math.max(320, rect.width);
      height = Math.max(260, rect.height);
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      cx = width / 2;
      cy = height / 2;
      radius = Math.min(width, height) * 0.3;
    };

    applySize();
    const observer = new ResizeObserver(applySize);
    observer.observe(wrap);

    const onDown = (e: MouseEvent) => {
      dragging = true;
      lastX = e.clientX;
      lastY = e.clientY;
      canvas.style.cursor = 'grabbing';
    };
    const onUp = () => {
      dragging = false;
      canvas.style.cursor = 'grab';
    };
    const onMove = (e: MouseEvent) => {
      if (!dragging) return;
      rotation += (e.clientX - lastX) * 0.006;
      tilt = Math.max(-1.05, Math.min(1.05, tilt + (e.clientY - lastY) * 0.005));
      lastX = e.clientX;
      lastY = e.clientY;
    };

    canvas.addEventListener('mousedown', onDown);
    window.addEventListener('mouseup', onUp);
    window.addEventListener('mousemove', onMove);
    canvas.style.cursor = 'grab';

    const project = (lat: number, lon: number) => {
      const theta = lon + rotation;
      const x = radius * Math.cos(lat) * Math.sin(theta);
      const y0 = radius * Math.sin(lat);
      const z0 = radius * Math.cos(lat) * Math.cos(theta);
      const y = y0 * Math.cos(tilt) - z0 * Math.sin(tilt);
      const z = y0 * Math.sin(tilt) + z0 * Math.cos(tilt);
      return { x: cx + x, y: cy - y, z };
    };

    const render = (time: number) => {
      const { incidents: liveIncidents, selectedIncidentId: selectedId, isLive: live } = dataRef.current;

      // Dominant severity drives the whole atmosphere. Default accent is the system blue.
      let dominant: Severity = 'INFO';
      for (const inc of liveIncidents) {
        if (SEVERITY_RANK[inc.severity] > SEVERITY_RANK[dominant]) dominant = inc.severity;
      }
      const accent = SEVERITY_COLORS[dominant];

      ctx.clearRect(0, 0, width, height);

      // Atmosphere bloom
      const bloom = ctx.createRadialGradient(cx, cy, radius * 0.72, cx, cy, radius * 1.85);
      bloom.addColorStop(0, hexAlpha(accent, 0.18));
      bloom.addColorStop(0.45, hexAlpha(accent, 0.06));
      bloom.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.fillStyle = bloom;
      ctx.beginPath();
      ctx.arc(cx, cy, radius * 1.85, 0, Math.PI * 2);
      ctx.fill();

      // Ocean body
      const body = ctx.createRadialGradient(
        cx - radius * 0.35,
        cy - radius * 0.4,
        radius * 0.1,
        cx,
        cy,
        radius,
      );
      body.addColorStop(0, '#12243d');
      body.addColorStop(0.6, '#0a1626');
      body.addColorStop(1, '#05090f');
      ctx.fillStyle = body;
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.fill();

      // Limb
      ctx.strokeStyle = hexAlpha(accent, 0.5);
      ctx.lineWidth = 1.1;
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.stroke();

      // Graticule — parallels
      ctx.lineWidth = 0.6;
      for (let latDeg = -60; latDeg <= 60; latDeg += 30) {
        const lat = (latDeg * Math.PI) / 180;
        ctx.beginPath();
        let started = false;
        for (let lonDeg = -180; lonDeg <= 180; lonDeg += 4) {
          const p = project(lat, (lonDeg * Math.PI) / 180);
          if (p.z < 0) {
            started = false;
            continue;
          }
          if (!started) {
            ctx.moveTo(p.x, p.y);
            started = true;
          } else {
            ctx.lineTo(p.x, p.y);
          }
        }
        ctx.strokeStyle = 'rgba(120, 170, 225, 0.14)';
        ctx.stroke();
      }

      // Graticule — meridians
      for (let lonDeg = -180; lonDeg < 180; lonDeg += 30) {
        const lon = (lonDeg * Math.PI) / 180;
        ctx.beginPath();
        let started = false;
        for (let latDeg = -90; latDeg <= 90; latDeg += 4) {
          const p = project((latDeg * Math.PI) / 180, lon);
          if (p.z < 0) {
            started = false;
            continue;
          }
          if (!started) {
            ctx.moveTo(p.x, p.y);
            started = true;
          } else {
            ctx.lineTo(p.x, p.y);
          }
        }
        ctx.strokeStyle = 'rgba(120, 170, 225, 0.1)';
        ctx.stroke();
      }

      // Landmass point cloud
      for (const point of LAND_POINTS) {
        const p = project(point.lat, point.lon);
        if (p.z < 0) continue;
        const depth = p.z / radius;
        ctx.fillStyle = `rgba(125, 205, 255, ${0.16 + depth * 0.5})`;
        const size = 0.7 + depth * 1.1;
        ctx.fillRect(p.x - size / 2, p.y - size / 2, size, size);
      }

      // Surface pins: only when the sensor genuinely reports geographic evidence.
      if (geoObservable) {
        for (const inc of liveIncidents) {
          const lat = (inc.evidence as Record<string, unknown>).latitude;
          const lon = (inc.evidence as Record<string, unknown>).longitude;
          if (typeof lat !== 'number' || typeof lon !== 'number') continue;
          const p = project((lat * Math.PI) / 180, (lon * Math.PI) / 180);
          if (p.z < 0) continue;
          ctx.fillStyle = SEVERITY_COLORS[inc.severity];
          ctx.beginPath();
          ctx.arc(p.x, p.y, 3.5, 0, Math.PI * 2);
          ctx.fill();
        }
      }

      // Radar sweep — cadence follows real incident volume, not a decorative timer.
      if (!reduceMotion) {
        sweep += 0.004 + Math.min(liveIncidents.length, 40) * 0.00022;
        if (sweep > Math.PI * 2) sweep -= Math.PI * 2;
        const sweepGrad = ctx.createLinearGradient(
          cx,
          cy,
          cx + Math.cos(sweep) * radius,
          cy + Math.sin(sweep) * radius,
        );
        sweepGrad.addColorStop(0, hexAlpha(accent, 0.0));
        sweepGrad.addColorStop(1, hexAlpha(accent, 0.28));
        ctx.save();
        ctx.beginPath();
        ctx.arc(cx, cy, radius, 0, Math.PI * 2);
        ctx.clip();
        ctx.strokeStyle = sweepGrad;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(cx + Math.cos(sweep) * radius, cy + Math.sin(sweep) * radius);
        ctx.stroke();
        ctx.restore();
      }

      // Index ring. Position encodes recency only — never a location.
      const ringRadius = radius * 1.42;
      ctx.strokeStyle = 'rgba(120, 170, 225, 0.16)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.ellipse(cx, cy, ringRadius, ringRadius * 0.46, 0, 0, Math.PI * 2);
      ctx.stroke();

      const ordered = liveIncidents.slice(0, MAX_RING_MARKERS);
      const markers: RingMarker[] = [];
      const pulse = reduceMotion ? 0 : (Math.sin(time / 420) + 1) / 2;

      ordered.forEach((inc, index) => {
        const angle = (index / Math.max(ordered.length, 1)) * Math.PI * 2 - Math.PI / 2;
        const mx = cx + Math.cos(angle) * ringRadius;
        const my = cy + Math.sin(angle) * ringRadius * 0.46;
        const color = SEVERITY_COLORS[inc.severity];
        const isSelected = inc.incident_id === selectedId;
        const isHovered = inc.incident_id === hoverRef.current;
        const size = isSelected ? 6 : isHovered ? 5 : 3.4;

        // Tick toward the sphere, so the ring reads as an index, not an orbit of places.
        ctx.strokeStyle = hexAlpha(color, isSelected ? 0.7 : 0.28);
        ctx.lineWidth = isSelected ? 1.5 : 1;
        ctx.beginPath();
        ctx.moveTo(cx + Math.cos(angle) * (ringRadius - 10), cy + Math.sin(angle) * (ringRadius - 10) * 0.46);
        ctx.lineTo(mx, my);
        ctx.stroke();

        if (isSelected || inc.severity === 'CRITICAL') {
          ctx.fillStyle = hexAlpha(color, 0.16 + pulse * 0.2);
          ctx.beginPath();
          ctx.arc(mx, my, size + 5 + pulse * 4, 0, Math.PI * 2);
          ctx.fill();
        }

        ctx.fillStyle = color;
        ctx.beginPath();
        ctx.arc(mx, my, size, 0, Math.PI * 2);
        ctx.fill();

        if (isSelected) {
          ctx.strokeStyle = '#ffffff';
          ctx.lineWidth = 1.2;
          ctx.beginPath();
          ctx.arc(mx, my, size + 3, 0, Math.PI * 2);
          ctx.stroke();
        }

        markers.push({
          incidentId: inc.incident_id,
          severity: inc.severity,
          psClass: inc.ps_class,
          x: mx,
          y: my,
          radius: size,
        });
      });

      markersRef.current = markers;

      // Hover readout, drawn in canvas so it tracks the marker exactly.
      const hovered = markers.find((m) => m.incidentId === hoverRef.current);
      if (hovered) {
        const label = `${hovered.severity} · ${hovered.psClass}`;
        ctx.font = '11px ui-monospace, SFMono-Regular, Consolas, monospace';
        const textWidth = ctx.measureText(label).width;
        const boxX = Math.min(Math.max(hovered.x - textWidth / 2 - 8, 6), width - textWidth - 22);
        const boxY = hovered.y - 30;
        ctx.fillStyle = 'rgba(5, 6, 8, 0.92)';
        ctx.strokeStyle = hexAlpha(SEVERITY_COLORS[hovered.severity], 0.6);
        ctx.lineWidth = 1;
        roundRect(ctx, boxX, boxY, textWidth + 16, 22, 4);
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#e8eef7';
        ctx.fillText(label, boxX + 8, boxY + 15);
      }

      if (!reduceMotion && !dragging && live) {
        rotation += 0.0016;
      }

      frameRef.current = requestAnimationFrame(render);
    };

    frameRef.current = requestAnimationFrame(render);

    return () => {
      if (frameRef.current !== null) cancelAnimationFrame(frameRef.current);
      observer.disconnect();
      canvas.removeEventListener('mousedown', onDown);
      window.removeEventListener('mouseup', onUp);
      window.removeEventListener('mousemove', onMove);
    };
  }, [geoObservable]);

  return (
    <div className="globe-stage" ref={wrapRef}>
      <canvas
        ref={canvasRef}
        className="globe-canvas"
        onClick={handleClick}
        onMouseMove={handleMove}
      />

      <div className="globe-legend">
        <span className="globe-legend-title">Incident index ring</span>
        <span className="globe-legend-body">
          Newest first, clockwise. Ring position is order of observation.
        </span>
      </div>

      <div className={`globe-geo-chip geo-${geoState.toLowerCase()}`}>
        <span className="geo-dot" />
        <span className="geo-state">GEO {geoState}</span>
        <span className="geo-note">
          {geoObservable
            ? 'Surface pins show reported coordinates only.'
            : 'No incident is placed by location.'}
        </span>
      </div>
    </div>
  );
};

function hexAlpha(hex: string, alpha: number): string {
  const value = hex.replace('#', '');
  const r = parseInt(value.slice(0, 2), 16);
  const g = parseInt(value.slice(2, 4), 16);
  const b = parseInt(value.slice(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

function roundRect(
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  w: number,
  h: number,
  r: number,
): void {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.lineTo(x + w - r, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + r);
  ctx.lineTo(x + w, y + h - r);
  ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
  ctx.lineTo(x + r, y + h);
  ctx.quadraticCurveTo(x, y + h, x, y + h - r);
  ctx.lineTo(x, y + r);
  ctx.quadraticCurveTo(x, y, x + r, y);
  ctx.closePath();
}

export default CyberGlobe;
