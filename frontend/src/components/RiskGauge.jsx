import React from 'react';

const RiskGauge = ({ score = 0, size = 'compact', showLabel = false }) => {
  const numScore = Math.max(0, Math.min(100, Math.round(score)));

  const getTier = (val) => {
    if (val >= 80) return { label: 'CRITICAL', color: '#ef4444', bg: 'rgba(239, 68, 68, 0.15)', glow: '0 0 12px rgba(239, 68, 68, 0.6)' };
    if (val >= 60) return { label: 'HIGH', color: '#f97316', bg: 'rgba(249, 115, 22, 0.15)', glow: '0 0 10px rgba(249, 115, 22, 0.5)' };
    if (val >= 40) return { label: 'SUSPICIOUS', color: '#eab308', bg: 'rgba(234, 179, 8, 0.15)', glow: '0 0 8px rgba(234, 179, 8, 0.4)' };
    if (val >= 20) return { label: 'LOW RISK', color: '#38bdf8', bg: 'rgba(56, 189, 248, 0.15)', glow: '0 0 6px rgba(56, 189, 248, 0.3)' };
    return { label: 'NORMAL', color: '#22c55e', bg: 'rgba(34, 197, 94, 0.15)', glow: '0 0 6px rgba(34, 197, 94, 0.3)' };
  };

  const tier = getTier(numScore);

  if (size === 'large') {
    return (
      <div style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '1.25rem',
        borderRadius: '12px',
        background: 'radial-gradient(circle at center, rgba(19, 26, 43, 0.9) 0%, rgba(10, 14, 26, 0.95) 100%)',
        border: `1px solid ${tier.color}40`,
        boxShadow: tier.glow,
        position: 'relative',
        overflow: 'hidden'
      }}>
        <div style={{
          fontSize: '3rem',
          fontWeight: '900',
          fontFamily: 'monospace',
          color: tier.color,
          textShadow: tier.glow,
          lineHeight: 1
        }}>
          {numScore}
        </div>
        <div style={{
          fontSize: '0.75rem',
          color: '#94a3b8',
          letterSpacing: '0.1em',
          textTransform: 'uppercase',
          marginTop: '6px'
        }}>
          / 100 RISK INDEX
        </div>

        <div style={{
          marginTop: '12px',
          width: '100%',
          height: '8px',
          backgroundColor: 'rgba(255, 255, 255, 0.07)',
          borderRadius: '4px',
          overflow: 'hidden',
          padding: '1px'
        }}>
          <div style={{
            width: `${numScore}%`,
            height: '100%',
            borderRadius: '3px',
            background: `linear-gradient(90deg, #22c55e 0%, #eab308 50%, ${tier.color} 100%)`,
            boxShadow: tier.glow,
            transition: 'width 0.6s cubic-bezier(0.4, 0, 0.2, 1)'
          }} />
        </div>

        <div style={{
          marginTop: '10px',
          padding: '2px 10px',
          borderRadius: '4px',
          backgroundColor: tier.bg,
          border: `1px solid ${tier.color}60`,
          color: tier.color,
          fontSize: '0.75rem',
          fontWeight: '800',
          letterSpacing: '0.08em'
        }}>
          {tier.label}
        </div>
      </div>
    );
  }

  // Compact Mode (for tables & cards)
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', width: '100%', minWidth: '90px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{
          fontFamily: 'monospace',
          fontWeight: '800',
          fontSize: '0.85rem',
          color: tier.color
        }}>
          {numScore}
        </span>
        {showLabel && (
          <span style={{ fontSize: '0.65rem', fontWeight: '700', color: tier.color, letterSpacing: '0.05em' }}>
            {tier.label}
          </span>
        )}
      </div>

      <div style={{
        width: '100%',
        height: '6px',
        backgroundColor: 'rgba(255, 255, 255, 0.08)',
        borderRadius: '3px',
        overflow: 'hidden',
        border: '1px solid rgba(255, 255, 255, 0.04)'
      }}>
        <div style={{
          width: `${numScore}%`,
          height: '100%',
          borderRadius: '2px',
          backgroundColor: tier.color,
          boxShadow: `0 0 6px ${tier.color}80`,
          transition: 'width 0.4s ease'
        }} />
      </div>
    </div>
  );
};

export default RiskGauge;
