import React, { useState, useEffect } from 'react';
import SeverityBadge from '../components/SeverityBadge';
import * as api from '../services/api';
import { 
  ShieldCheck, Sliders, Play, RotateCcw, Zap, 
  Search, AlertTriangle, Layers, Save, CheckCircle2
} from 'lucide-react';

const Rules = () => {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [toastMessage, setToastMessage] = useState(null);
  const [testingRuleId, setTestingRuleId] = useState(null);

  const fetchRules = async () => {
    setLoading(true);
    const data = await api.getRules();
    setRules(data);
    setLoading(false);
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const handleToggle = async (ruleId, currentEnabled) => {
    const nextState = currentEnabled ? 0 : 1;
    await api.updateRule(ruleId, { enabled: nextState });
    setRules(rules.map(r => r.rule_id === ruleId ? { ...r, enabled: nextState } : r));
    showToast(`Rule ${ruleId} ${nextState ? 'ENABLED' : 'DISABLED'}`);
  };

  const handleThresholdChange = async (ruleId, newThreshold) => {
    const parsed = parseFloat(newThreshold);
    if (isNaN(parsed)) return;
    await api.updateRule(ruleId, { threshold: parsed });
    setRules(rules.map(r => r.rule_id === ruleId ? { ...r, threshold: parsed } : r));
    showToast(`Threshold updated for ${ruleId} -> ${parsed}`);
  };

  const handleTestRule = (rule) => {
    setTestingRuleId(rule.rule_id);
    let attackType = 'syn_flood';
    if (rule.rule_id === 'IDS-001') attackType = 'dos';
    if (rule.rule_id === 'IDS-002') attackType = 'brute_force';
    if (rule.rule_id === 'IDS-003') attackType = 'port_scan';
    if (rule.rule_id === 'IDS-004') attackType = 'syn_flood';
    if (rule.rule_id === 'IDS-005') attackType = 'c2_backdoor';
    if (rule.rule_id === 'IDS-006') attackType = 'exfiltration';

    api.injectAttackWave(attackType);
    showToast(`Injected test pattern: "${rule.name}". Triggering alert...`);
    setTimeout(() => setTestingRuleId(null), 1200);
  };

  const filteredRules = rules.filter(r => {
    const q = searchQuery.toLowerCase();
    const matchesSearch = !q || 
      r.rule_id.toLowerCase().includes(q) ||
      (r.name || r.rule_name || '').toLowerCase().includes(q) ||
      (r.description || '').toLowerCase().includes(q);

    let matchesCategory = true;
    if (categoryFilter === 'DOS') matchesCategory = r.rule_id === 'IDS-001' || r.rule_id === 'IDS-004' || r.rule_id === 'IDS-008';
    if (categoryFilter === 'SCAN') matchesCategory = r.rule_id === 'IDS-003';
    if (categoryFilter === 'AUTH') matchesCategory = r.rule_id === 'IDS-002';
    if (categoryFilter === 'POLICY') matchesCategory = r.rule_id === 'IDS-005' || r.rule_id === 'IDS-006' || r.rule_id === 'IDS-007';

    return matchesSearch && matchesCategory;
  });

  const activeCount = rules.filter(r => r.enabled).length;
  const criticalCount = rules.filter(r => r.severity === 'CRITICAL').length;

  return (
    <div style={{ paddingBottom: '3rem' }}>
      {/* Toast Alert */}
      {toastMessage && (
        <div style={{
          position: 'fixed',
          bottom: '24px',
          right: '24px',
          zIndex: 9999,
          padding: '12px 20px',
          borderRadius: '8px',
          backgroundColor: '#0f172a',
          border: '1px solid #38bdf8',
          boxShadow: '0 0 16px rgba(56, 189, 248, 0.4)',
          color: '#f8fafc',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          fontSize: '0.875rem'
        }}>
          <CheckCircle2 size={16} color="#38bdf8" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 className="page-title" style={{ margin: 0 }}>Detection Rules & Signatures</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginTop: '4px' }}>
            Configure heuristics, dynamic threshold limits, and signature activation for real-time packet inspection.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <button 
            className="secondary"
            onClick={fetchRules}
            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem' }}
          >
            <RotateCcw size={14} /> Reset to Defaults
          </button>
        </div>
      </div>

      {/* KPI Ribbon */}
      <div className="grid-container grid-cols-4" style={{ marginBottom: '1.5rem' }}>
        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid #22c55e' }}>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase' }}>Active Signatures</div>
          <div style={{ fontSize: '1.5rem', fontWeight: '800', fontFamily: 'monospace', color: '#4ade80', marginTop: '2px' }}>
            {activeCount} <span style={{ fontSize: '0.8rem', color: '#64748b' }}>/ {rules.length}</span>
          </div>
        </div>

        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid #ef4444' }}>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase' }}>Critical Signatures</div>
          <div style={{ fontSize: '1.5rem', fontWeight: '800', fontFamily: 'monospace', color: '#ef4444', marginTop: '2px' }}>
            {criticalCount}
          </div>
        </div>

        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid #38bdf8' }}>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase' }}>Inspection Engine</div>
          <div style={{ fontSize: '1.15rem', fontWeight: '800', color: '#38bdf8', marginTop: '6px' }}>
            Hybrid Tri-Engine
          </div>
        </div>

        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid #a855f7' }}>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase' }}>Evaluation Latency</div>
          <div style={{ fontSize: '1.5rem', fontWeight: '800', fontFamily: 'monospace', color: '#c084fc', marginTop: '2px' }}>
            &lt; 0.8 ms
          </div>
        </div>
      </div>

      {/* Filter Ribbon */}
      <div className="card" style={{ marginBottom: '1.5rem', padding: '1rem', display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <div style={{ position: 'relative', flex: 2, minWidth: '220px' }}>
          <Search size={16} color="#64748b" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
          <input 
            type="text" 
            placeholder="Search rule ID, name, or description..." 
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{ width: '100%', padding: '8px 12px 8px 36px', borderRadius: '8px', fontSize: '0.85rem' }}
          />
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          {[
            { id: 'ALL', label: 'All Rules' },
            { id: 'DOS', label: 'DoS / Flood' },
            { id: 'SCAN', label: 'Port Recon' },
            { id: 'AUTH', label: 'Brute Force' },
            { id: 'POLICY', label: 'Exfil & Ports' }
          ].map(cat => (
            <button
              key={cat.id}
              className={categoryFilter === cat.id ? '' : 'secondary'}
              onClick={() => setCategoryFilter(cat.id)}
              style={{ fontSize: '0.78rem', padding: '6px 12px' }}
            >
              {cat.label}
            </button>
          ))}
        </div>
      </div>

      {/* Rules Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(420px, 1fr))', gap: '1.25rem' }}>
        {filteredRules.map((rule) => {
          const isEnabled = Boolean(rule.enabled);
          const isTesting = testingRuleId === rule.rule_id;

          return (
            <div 
              key={rule.rule_id} 
              className="card"
              style={{
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                padding: '1.25rem',
                borderLeft: `4px solid ${isEnabled ? (rule.severity === 'CRITICAL' ? '#ef4444' : '#38bdf8') : '#475569'}`,
                opacity: isEnabled ? 1 : 0.65,
                transition: 'all 0.3s ease'
              }}
            >
              <div>
                {/* Card Top: Rule ID, Title & Toggle Switch */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '4px' }}>
                      <span style={{ fontFamily: 'monospace', fontWeight: '800', color: '#38bdf8', fontSize: '0.9rem' }}>
                        {rule.rule_id}
                      </span>
                      <SeverityBadge severity={rule.severity} />
                    </div>
                    <h3 style={{ fontSize: '1.05rem', fontWeight: '800', margin: 0, color: '#f8fafc' }}>
                      {rule.name || rule.rule_name}
                    </h3>
                  </div>

                  {/* Toggle Switch */}
                  <label style={{ display: 'inline-flex', alignItems: 'center', cursor: 'pointer', gap: '8px' }}>
                    <span style={{ fontSize: '0.7rem', fontWeight: '800', color: isEnabled ? '#22c55e' : '#94a3b8' }}>
                      {isEnabled ? 'ENABLED' : 'MUTED'}
                    </span>
                    <div 
                      onClick={() => handleToggle(rule.rule_id, isEnabled)}
                      style={{
                        width: '42px',
                        height: '22px',
                        borderRadius: '11px',
                        backgroundColor: isEnabled ? '#22c55e' : 'rgba(255, 255, 255, 0.1)',
                        position: 'relative',
                        transition: 'background-color 0.2s',
                        boxShadow: isEnabled ? '0 0 8px rgba(34, 197, 94, 0.5)' : 'none'
                      }}
                    >
                      <div style={{
                        width: '18px',
                        height: '18px',
                        borderRadius: '50%',
                        backgroundColor: '#ffffff',
                        position: 'absolute',
                        top: '2px',
                        left: isEnabled ? '22px' : '2px',
                        transition: 'left 0.2s cubic-bezier(0.4, 0, 0.2, 1)'
                      }} />
                    </div>
                  </label>
                </div>

                {/* Description */}
                <p style={{ color: '#94a3b8', fontSize: '0.85rem', lineHeight: 1.5, marginBottom: '1.25rem' }}>
                  {rule.description}
                </p>

                {/* Configurable Threshold Slider */}
                <div style={{
                  backgroundColor: 'rgba(0, 0, 0, 0.25)',
                  padding: '1rem',
                  borderRadius: '8px',
                  border: '1px solid rgba(255, 255, 255, 0.05)',
                  marginBottom: '1rem'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                    <span style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                      Detection Threshold
                    </span>
                    <span style={{ fontFamily: 'monospace', fontWeight: '800', color: '#fbbf24', fontSize: '0.9rem' }}>
                      {rule.threshold} {rule.metric ? `(${rule.metric})` : ''}
                    </span>
                  </div>

                  <input 
                    type="range"
                    min={rule.threshold < 1 ? 0.1 : (rule.threshold > 10000 ? 100000 : 5)}
                    max={rule.threshold < 1 ? 1.0 : (rule.threshold > 10000 ? 5000000 : 250)}
                    step={rule.threshold < 1 ? 0.05 : (rule.threshold > 10000 ? 50000 : 5)}
                    value={rule.threshold}
                    onChange={(e) => handleThresholdChange(rule.rule_id, e.target.value)}
                    style={{ width: '100%', accentColor: '#38bdf8', cursor: 'pointer' }}
                  />
                </div>
              </div>

              {/* Bottom Action Footer */}
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                paddingTop: '0.75rem',
                borderTop: '1px solid rgba(255, 255, 255, 0.06)'
              }}>
                <span style={{ fontSize: '0.72rem', color: '#64748b' }}>
                  Target Metric: <strong style={{ color: '#cbd5e1' }}>{rule.metric || 'flow_attribute'}</strong>
                </span>

                <button 
                  className="secondary"
                  disabled={!isEnabled || isTesting}
                  onClick={() => handleTestRule(rule)}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                    fontSize: '0.75rem',
                    padding: '4px 10px',
                    borderColor: isTesting ? '#22c55e' : undefined,
                    color: isTesting ? '#22c55e' : undefined
                  }}
                >
                  <Play size={12} /> {isTesting ? 'Simulating...' : 'Test Trigger'}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default Rules;
