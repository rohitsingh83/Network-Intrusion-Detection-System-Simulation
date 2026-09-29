import React from 'react';

const RiskGauge = ({ score }) => {
  const getColor = (val) => {
    if (val < 20) return 'var(--color-normal)';
    if (val < 50) return 'var(--color-low)';
    if (val < 75) return 'var(--color-medium)';
    if (val < 90) return 'var(--color-high)';
    return 'var(--color-critical)';
  };

  return (
    <div style={{ display: 'flex', alignItems: 'center', width: '100%', gap: '8px' }}>
      <span style={{ fontWeight: '600', fontSize: '0.875rem', width: '24px' }}>{score}</span>
      <div style={{ flex: 1, backgroundColor: 'rgba(255,255,255,0.1)', height: '6px', borderRadius: '3px', overflow: 'hidden' }}>
        <div style={{
          width: `${score}%`,
          height: '100%',
          backgroundColor: getColor(score),
          transition: 'width 0.5s ease-in-out'
        }}></div>
      </div>
    </div>
  );
};

export default RiskGauge;
