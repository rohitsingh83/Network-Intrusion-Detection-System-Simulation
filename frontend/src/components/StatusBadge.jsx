import React from 'react';

const StatusBadge = ({ status }) => {
  const getStatusColor = (stat) => {
    switch (stat?.toUpperCase()) {
      case 'NEW': return 'var(--color-low)';
      case 'INVESTIGATING': return 'var(--color-high)';
      case 'RESOLVED': return 'var(--color-normal)';
      case 'FALSE_POSITIVE': return 'var(--color-info)';
      default: return 'var(--color-info)';
    }
  };

  const getStatusBg = (stat) => {
    switch (stat?.toUpperCase()) {
      case 'NEW': return 'var(--bg-low)';
      case 'INVESTIGATING': return 'var(--bg-high)';
      case 'RESOLVED': return 'var(--bg-normal)';
      case 'FALSE_POSITIVE': return 'var(--bg-info)';
      default: return 'var(--bg-info)';
    }
  };

  return (
    <span style={{
      backgroundColor: getStatusBg(status),
      color: getStatusColor(status),
      padding: '0.25rem 0.75rem',
      borderRadius: '4px',
      fontSize: '0.75rem',
      fontWeight: '600',
      display: 'inline-block',
      textAlign: 'center'
    }}>
      {status?.replace('_', ' ')}
    </span>
  );
};

export default StatusBadge;
