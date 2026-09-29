import React, { useState, useEffect } from 'react';
import SeverityBadge from '../components/SeverityBadge';
import * as api from '../services/api';

const Rules = () => {
  const [rules, setRules] = useState([]);

  useEffect(() => {
    const fetch = async () => {
      setRules(await api.getRules());
    };
    fetch();
  }, []);

  const toggleRule = async (id, currentEnabled) => {
    // In real app, call API
    setRules(rules.map(r => r.id === id ? { ...r, enabled: !currentEnabled } : r));
  };

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Detection Rules Management</h1>
      </div>

      <div className="card">
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Rule ID</th>
                <th>Name</th>
                <th>Description</th>
                <th>Severity</th>
                <th>Threshold</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.id}>
                  <td style={{ fontFamily: 'monospace', color: 'var(--color-low)' }}>{rule.id}</td>
                  <td style={{ fontWeight: 'bold' }}>{rule.name}</td>
                  <td style={{ color: 'var(--text-secondary)' }}>{rule.description}</td>
                  <td><SeverityBadge severity={rule.severity} /></td>
                  <td>{rule.threshold}</td>
                  <td>
                    <span style={{ 
                      color: rule.enabled ? 'var(--color-normal)' : 'var(--text-secondary)',
                      fontWeight: 'bold' 
                    }}>
                      {rule.enabled ? 'ENABLED' : 'DISABLED'}
                    </span>
                  </td>
                  <td>
                    <button 
                      className={rule.enabled ? 'secondary' : ''} 
                      onClick={() => toggleRule(rule.id, rule.enabled)}
                    >
                      {rule.enabled ? 'Disable' : 'Enable'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Rules;
