import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import RiskGauge from '../components/RiskGauge';
import * as api from '../services/api';

const Alerts = () => {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState([]);
  
  useEffect(() => {
    const fetchAlerts = async () => {
      const data = await api.getAlerts();
      setAlerts(data);
    };
    fetchAlerts();
  }, []);

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Alert Investigation</h1>
      </div>
      
      <div className="card" style={{ marginBottom: '1.5rem', display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        <select defaultValue="">
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <select defaultValue="">
          <option value="">All Statuses</option>
          <option value="NEW">New</option>
          <option value="INVESTIGATING">Investigating</option>
          <option value="RESOLVED">Resolved</option>
        </select>
        <select defaultValue="">
          <option value="">All Protocols</option>
          <option value="TCP">TCP</option>
          <option value="UDP">UDP</option>
          <option value="ICMP">ICMP</option>
        </select>
        <button style={{ marginLeft: 'auto' }}>Filter Results</button>
      </div>

      <div className="card">
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Alert ID</th>
                <th>Time</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Risk</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => (
                <tr key={alert.id} onClick={() => navigate(`/alerts/${alert.id}`)} style={{ cursor: 'pointer' }}>
                  <td style={{ fontFamily: 'monospace', color: 'var(--color-low)' }}>{alert.id}</td>
                  <td>{new Date(alert.time).toLocaleString()}</td>
                  <td style={{ fontFamily: 'monospace' }}>{alert.sourceIp}</td>
                  <td style={{ fontFamily: 'monospace' }}>{alert.destIp}</td>
                  <td>{alert.type}</td>
                  <td><SeverityBadge severity={alert.severity} /></td>
                  <td style={{ width: '120px' }}><RiskGauge score={alert.riskScore} /></td>
                  <td><StatusBadge status={alert.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Alerts;
