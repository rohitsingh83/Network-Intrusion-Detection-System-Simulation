import React from 'react';

const SeverityBadge = ({ severity }) => {
  const sev = (severity || 'INFO').toUpperCase();

  const config = {
    CRITICAL: {
      color: '#ef4444',
      bg: 'rgba(239, 68, 68, 0.16)',
      border: 'rgba(239, 68, 68, 0.45)',
      glow: '0 0 10px rgba(239, 68, 68, 0.35)',
      dotClass: 'radar-red'
    },
    HIGH: {
      color: '#f97316',
      bg: 'rgba(249, 115, 22, 0.16)',
      border: 'rgba(249, 115, 22, 0.45)',
      glow: '0 0 10px rgba(249, 115, 22, 0.35)',
      dotClass: 'radar-red'
    },
    MEDIUM: {
      color: '#eab308',
      bg: 'rgba(234, 179, 8, 0.16)',
      border: 'rgba(234, 179, 8, 0.45)',
      glow: 'none',
      dotClass: null
    },
    LOW: {
      color: '#38bdf8',
      bg: 'rgba(56, 189, 248, 0.16)',
      border: 'rgba(56, 189, 248, 0.4)',
      glow: 'none',
      dotClass: null
    },
    INFO: {
      color: '#94a3b8',
      bg: 'rgba(148, 163, 184, 0.12)',
      border: 'rgba(148, 163, 184, 0.3)',
      glow: 'none',
      dotClass: null
    }
  };

  const current = config[sev] || config.INFO;

  return (
    <span
      className="badge"
      style={{
        backgroundColor: current.bg,
        color: current.color,
        borderColor: current.border,
        boxShadow: current.glow,
      }}
    >
      {current.dotClass && <span className={`radar-dot ${current.dotClass}`} style={{ width: '6px', height: '6px' }} />}
      {sev}
    </span>
  );
};

export default SeverityBadge;
