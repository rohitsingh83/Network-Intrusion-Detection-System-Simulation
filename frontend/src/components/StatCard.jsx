import React from 'react';

const StatCard = ({ title, value, icon: Icon, color, subtitle, isPulsing }) => {
  return (
    <div className={`card stat-card ${isPulsing ? 'pulsing' : ''}`}>
      <div className="stat-header">
        <h3 className="stat-title">{title}</h3>
        {Icon && <Icon size={20} color={color} />}
      </div>
      <div className="stat-value" style={{ color: color }}>
        {value}
      </div>
      {subtitle && <div className="stat-subtitle">{subtitle}</div>}
      <style>{`
        .stat-card {
          display: flex;
          flex-direction: column;
        }
        .stat-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 0.5rem;
        }
        .stat-title {
          font-size: 0.875rem;
          color: var(--text-secondary);
          font-weight: 500;
        }
        .stat-value {
          font-size: 2rem;
          font-weight: 700;
          margin-bottom: 0.25rem;
        }
        .stat-subtitle {
          font-size: 0.75rem;
          color: var(--text-secondary);
        }
        .pulsing {
          animation: pulse 2s infinite;
        }
        @keyframes pulse {
          0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); }
          70% { box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); }
          100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
        }
      `}</style>
    </div>
  );
};

export default StatCard;
