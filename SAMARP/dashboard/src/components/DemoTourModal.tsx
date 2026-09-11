import React, { useState } from 'react';
import { X, ChevronRight, ChevronLeft, Shield, CheckCircle2, Play, ExternalLink } from 'lucide-react';
import { getExportJsonUrl } from '../services/api';

interface DemoTourModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectIncidentByClass: (psClass: string) => void;
}

interface TourStep {
  minute: number;
  title: string;
  psClass?: string;
  focus: string;
  bullets: string[];
  proofCommand?: string;
}

const TOUR_STEPS: TourStep[] = [
  {
    minute: 1,
    title: 'Passive Sensor Spine & Read-Only Separation',
    focus: 'Two-Plane Architecture & Capability Visibility',
    bullets: [
      'Plane B is strictly read-only: Only GET and WebSocket are exposed.',
      'Contract test asserts no non-GET routes exist on the monitoring app (POST/PUT/DELETE return 405).',
      'Input capability matrix explicitly marks OBSERVABLE, DEGRADED, and NOT_OBSERVABLE.',
      'Missing evidence is never masked as benign.',
    ],
    proofCommand: 'pytest tests/api/test_api_and_persistence.py -k test_plane_b_strictly_read_only',
  },
  {
    minute: 2,
    title: 'Volumetric DDoS & Slowloris Flooding',
    psClass: 'Volumetric DDoS / flooding',
    focus: 'Aggregate Collapse & Bounded Concurrency',
    bullets: [
      'Over 10,000+ pps flood collapses into a single evolving aggregate incident (flow_ref_type: aggregate).',
      'Deterministic 16-hex incident ID sha256(canonical(dedup_key))[:16].',
      'Slowloris concurrency, connection duration, and bytes-per-connection are tracked without state explosion.',
      'Raw score labeled robust_z — uncalibrated, never presented as a probability.',
    ],
  },
  {
    minute: 3,
    title: 'Port Scanning / Reconnaissance',
    psClass: 'Port scanning / reconnaissance',
    focus: 'Source Entity Tracking & Spread Detection',
    bullets: [
      'Tracks vertical port spread (single target) and horizontal host spread (multiple targets).',
      'Uses flow_ref_type: entity with source entity identity.',
      'Degraded input modes (such as IPFIX without flags) are declared explicitly in the capability block.',
    ],
  },
  {
    minute: 4,
    title: 'DGA / DNS Tunnelling Detection',
    psClass: 'DGA / DNS tunnelling',
    focus: 'Model Calibration & QType Distribution',
    bullets: [
      'Lexical entropy and n-gram analysis against the Tranco allowlist.',
      'Only model probabilities with calibrated: true append a percent sign (e.g. 94.0%).',
      'Evidence drawer displays qtype_distribution (TXT, CNAME, A shares) — a PS-mandated discriminator.',
    ],
  },
  {
    minute: 5,
    title: 'Malware in Encrypted Sessions (TLS/QUIC)',
    psClass: 'Malware in encrypted sessions',
    focus: 'Passive Fingerprinting Without Decryption',
    bullets: [
      'JA3, JA3S, and JA4 hashes extracted from handshakes without payload inspection.',
      'First-N packet sizes and directional sequence captured passively.',
      'Strictly framed as suspicion/anomaly rather than malware identification.',
      'Zero TLS decryption keys required or accepted.',
    ],
  },
  {
    minute: 6,
    title: 'Botnet C2 Beaconing & Data Exfiltration',
    psClass: 'Botnet C2 beaconing',
    focus: 'Inter-Arrival Periodicity & Volume Anomaly',
    bullets: [
      'C2: Inter-arrival time (IAT) analysis detecting CV <= 0.15 regular heartbeats.',
      'Exfiltration: Outbound/inbound byte ratio >= 10 and robust z-score >= 5.',
      'Lifecycle evolution: Transitions cleanly from NEW -> ACTIVE -> UPDATED -> RESOLVED.',
    ],
  },
  {
    minute: 7,
    title: 'Cryptographic Hash Chain & Verification',
    focus: 'Tamper-Evident Auditability & Lossless Export',
    bullets: [
      'Every incident update is hash-chained: sha256(prev_hash || seq || id || time || payload).',
      '64-character SHA-256 digests; genesis block is 64 zeros.',
      'Click "Export JSON" to retrieve the canonical chain.',
      'Standalone script verify_hash_chain.py verifies the export with zero runtime state.',
    ],
    proofCommand: 'python tests/hash_chain/verify_hash_chain.py export.json',
  },
];

export const DemoTourModal: React.FC<DemoTourModalProps> = ({ isOpen, onClose, onSelectIncidentByClass }) => {
  const [currentStep, setCurrentStep] = useState(0);

  if (!isOpen) return null;

  const step = TOUR_STEPS[currentStep];

  const handleNext = () => {
    if (currentStep < TOUR_STEPS.length - 1) {
      const next = currentStep + 1;
      setCurrentStep(next);
      if (TOUR_STEPS[next].psClass) {
        onSelectIncidentByClass(TOUR_STEPS[next].psClass!);
      }
    }
  };

  const handlePrev = () => {
    if (currentStep > 0) {
      const prev = currentStep - 1;
      setCurrentStep(prev);
      if (TOUR_STEPS[prev].psClass) {
        onSelectIncidentByClass(TOUR_STEPS[prev].psClass!);
      }
    }
  };

  const handleJump = (idx: number) => {
    setCurrentStep(idx);
    if (TOUR_STEPS[idx].psClass) {
      onSelectIncidentByClass(TOUR_STEPS[idx].psClass!);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="demo-modal-container">
        {/* Modal Header */}
        <div className="demo-modal-header">
          <div className="flex items-center gap-2">
            <Shield className="text-sky-400" size={22} />
            <h3 className="demo-modal-title">7-Minute Hackathon Presentation Guide</h3>
          </div>
          <button className="modal-close-btn" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        {/* Step Indicators */}
        <div className="demo-step-timeline">
          {TOUR_STEPS.map((s, idx) => (
            <button
              key={s.minute}
              className={`timeline-step ${idx === currentStep ? 'active' : idx < currentStep ? 'completed' : ''}`}
              onClick={() => handleJump(idx)}
            >
              <span className="step-num">Min {s.minute}</span>
              <span className="step-short">{s.title.split(' ')[0]}</span>
            </button>
          ))}
        </div>

        {/* Step Content */}
        <div className="demo-step-body">
          <div className="step-badge-row">
            <span className="step-minute-pill">MINUTE {step.minute} OF 7</span>
            <span className="step-focus-pill">{step.focus}</span>
          </div>

          <h2 className="step-title">{step.title}</h2>

          <ul className="step-bullet-list">
            {step.bullets.map((b, i) => (
              <li key={i} className="step-bullet-item">
                <CheckCircle2 size={16} className="text-emerald-400 shrink-0 mt-0.5" />
                <span>{b}</span>
              </li>
            ))}
          </ul>

          {step.proofCommand && (
            <div className="proof-command-box">
              <span className="proof-label">Verification Command:</span>
              <code className="proof-code">{step.proofCommand}</code>
            </div>
          )}

          {step.minute === 7 && (
            <div className="export-demo-actions">
              <a href={getExportJsonUrl()} download="incidents.json" className="btn btn-primary">
                <ExternalLink size={14} /> Download Canonical Hash Chain JSON
              </a>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="demo-modal-footer">
          <button className="btn btn-secondary" onClick={handlePrev} disabled={currentStep === 0}>
            <ChevronLeft size={16} /> Previous
          </button>

          <div className="step-counter">Step {currentStep + 1} / {TOUR_STEPS.length}</div>

          {currentStep < TOUR_STEPS.length - 1 ? (
            <button className="btn btn-primary" onClick={handleNext}>
              Next <ChevronRight size={16} />
            </button>
          ) : (
            <button className="btn btn-primary" onClick={onClose}>
              Finish Tour <Play size={14} />
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
