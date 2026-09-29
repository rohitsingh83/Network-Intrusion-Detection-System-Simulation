import React from 'react';

const SeverityBadge = ({ severity }) => {
  const getSeverityColor = (sev) => {
    switch (sev?.toUpperCase()) {
      case 'CRITICAL': return 'var(--color-critical)';
      case 'HIGH': return 'var(--color-high)';
      case 'MEDIUM': return 'var(--color-medium)';
      case 'LOW': return 'var(--color-low)';
      default: return 'var(--color-info)';
    }
  };

  const getSeverityBg = (sev) => {
    switch (sev?.toUpperCase()) {
      case 'CRITICAL': return 'var(--bg-critical)';
      case 'HIGH': return 'var(--bg-high)';
      case 'MEDIUM': return 'var(--bg-medium)';
      case 'LOW': return 'var(--bg-low)';
      default: return 'var(--bg-info)';
    }
  };

  return (
    <span style={{
      backgroundColor: getSeverityBg(severity),
      color: getSeverityColor(severity),
      padding: '0.25rem 0.75rem',
      borderRadius: '9999px',
      fontSize: '0.75rem',
      fontWeight: '600',
      display: 'inline-block',
      textAlign: 'center'
    }}>
      {severity}
    </span>
  );
};

export default SeverityBadge;
