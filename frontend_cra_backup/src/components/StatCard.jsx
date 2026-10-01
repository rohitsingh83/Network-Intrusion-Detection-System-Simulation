import React from 'react';

const StatCard = ({ title, value, icon: Icon, color, subtitle, isPulsing, trend, badge }) => {
  const displayVal = typeof value === 'number' ? value.toLocaleString() : (value || 0);

  return (
    <div className={`card stat-card ${isPulsing ? 'pulsing-critical' : ''}`} style={{ borderTop: `2px solid ${color}` }}>
      <div className="stat-top">
        <span className="stat-label">{title}</span>
        <div className="stat-icon-wrapper" style={{ backgroundColor: `${color}18`, borderColor: `${color}40` }}>
          {Icon && <Icon size={17} color={color} />}
        </div>
      </div>

      <div className="stat-middle">
        <div className="stat-number mono" style={{ color: color }}>
          {displayVal}
        </div>
      </div>

      <div className="stat-bottom">
        {badge ? (
          <span className="stat-badge" style={{ backgroundColor: `${color}20`, color: color, borderColor: `${color}40` }}>
            {badge}
          </span>
        ) : subtitle ? (
          <span className="stat-subtext">{subtitle}</span>
        ) : (
          <span className="stat-subtext">Telemetry active</span>
        )}
      </div>

      <style>{`
        .stat-card {
          display: flex;
          flex-direction: column;
          justify-content: space-between;
          padding: 1.15rem;
          min-height: 120px;
          position: relative;
        }
        .stat-top {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 0.65rem;
        }
        .stat-label {
          font-size: 0.75rem;
          font-weight: 700;
          color: var(--text-secondary);
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }
        .stat-icon-wrapper {
          width: 32px;
          height: 32px;
          border-radius: 8px;
          border: 1px solid;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .stat-middle {
          margin-bottom: 0.45rem;
        }
        .stat-number {
          font-size: 1.85rem;
          font-weight: 800;
          letter-spacing: -0.03em;
          line-height: 1;
        }
        .stat-bottom {
          display: flex;
          align-items: center;
        }
        .stat-badge {
          font-size: 0.65rem;
          font-weight: 700;
          padding: 0.15rem 0.45rem;
          border-radius: 4px;
          border: 1px solid;
          letter-spacing: 0.04em;
        }
        .stat-subtext {
          font-size: 0.72rem;
          color: var(--text-muted);
        }
        .pulsing-critical {
          animation: criticalPulse 1.8s infinite;
        }
        @keyframes criticalPulse {
          0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.5); }
          70% { box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); }
          100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
        }
      `}</style>
    </div>
  );
};

export default StatCard;
