import React from 'react';
import { Radio, Clock, CheckCircle2, ShieldCheck, AlertOctagon } from 'lucide-react';

const StatusBadge = ({ status }) => {
  const stat = (status || 'NEW').toUpperCase();

  const getStyle = () => {
    switch (stat) {
      case 'NEW':
        return {
          bg: 'rgba(56, 189, 248, 0.12)',
          border: '1px solid rgba(56, 189, 248, 0.35)',
          color: '#38bdf8',
          glow: '0 0 10px rgba(56, 189, 248, 0.25)',
          icon: <Radio size={12} className="radar-blue" style={{ marginRight: '5px' }} />
        };
      case 'INVESTIGATING':
        return {
          bg: 'rgba(245, 158, 11, 0.12)',
          border: '1px solid rgba(245, 158, 11, 0.35)',
          color: '#fbbf24',
          glow: '0 0 10px rgba(245, 158, 11, 0.25)',
          icon: <Clock size={12} style={{ marginRight: '5px' }} />
        };
      case 'RESOLVED':
        return {
          bg: 'rgba(34, 197, 94, 0.12)',
          border: '1px solid rgba(34, 197, 94, 0.35)',
          color: '#4ade80',
          glow: '0 0 10px rgba(34, 197, 94, 0.25)',
          icon: <CheckCircle2 size={12} style={{ marginRight: '5px' }} />
        };
      case 'FALSE_POSITIVE':
        return {
          bg: 'rgba(148, 163, 184, 0.12)',
          border: '1px solid rgba(148, 163, 184, 0.3)',
          color: '#94a3b8',
          glow: 'none',
          icon: <ShieldCheck size={12} style={{ marginRight: '5px' }} />
        };
      default:
        return {
          bg: 'rgba(148, 163, 184, 0.1)',
          border: '1px solid rgba(148, 163, 184, 0.2)',
          color: '#cbd5e1',
          glow: 'none',
          icon: <AlertOctagon size={12} style={{ marginRight: '5px' }} />
        };
    }
  };

  const style = getStyle();

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '3px 10px',
        borderRadius: '6px',
        fontSize: '0.72rem',
        fontWeight: '700',
        letterSpacing: '0.04em',
        textTransform: 'uppercase',
        backgroundColor: style.bg,
        border: style.border,
        color: style.color,
        boxShadow: style.glow,
        whiteSpace: 'nowrap'
      }}
    >
      {style.icon}
      {stat.replace('_', ' ')}
    </span>
  );
};

export default StatusBadge;
