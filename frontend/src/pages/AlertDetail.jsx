import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import RiskGauge from '../components/RiskGauge';
import * as api from '../services/api';
import { ArrowLeft, Send } from 'lucide-react';

const AlertDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [alert, setAlert] = useState(null);
  const [note, setNote] = useState('');
  const [status, setStatus] = useState('');

  useEffect(() => {
    const fetchAlert = async () => {
      const data = await api.getAlert(id);
      setAlert(data);
      setStatus(data.status);
    };
    fetchAlert();
  }, [id]);

  const handleUpdateStatus = async () => {
    await api.updateAlertStatus(id, status);
    alert('Status updated');
  };

  const handleAddNote = async () => {
    if (!note) return;
    await api.addAlertNote(id, note);
    setNote('');
    alert('Note added');
  };

  if (!alert) return <div>Loading...</div>;

  return (
    <div>
      <div className="page-header">
        <button className="secondary" onClick={() => navigate('/alerts')} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
          <ArrowLeft size={16} /> Back to Alerts
        </button>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <h1 className="page-title">{alert.id}: {alert.type}</h1>
          <SeverityBadge severity={alert.severity} />
          <StatusBadge status={alert.status} />
        </div>
      </div>

      <div className="grid-container grid-cols-2">
        <div className="grid-container" style={{ gap: '1.5rem', display: 'flex', flexDirection: 'column' }}>
          
          {/* Connection Details */}
          <div className="card">
            <h3 style={{ marginBottom: '1rem', color: 'var(--text-secondary)' }}>Connection Details</h3>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', backgroundColor: 'rgba(0,0,0,0.2)', padding: '1.5rem', borderRadius: '8px' }}>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontFamily: 'monospace', fontSize: '1.2rem', marginBottom: '0.5rem' }}>{alert.sourceIp}</div>
                <div style={{ color: 'var(--text-secondary)' }}>Source</div>
              </div>
              <div style={{ flex: 1, padding: '0 2rem', position: 'relative', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                <div style={{ color: 'var(--color-low)', fontWeight: 'bold', marginBottom: '0.5rem' }}>{alert.protocol}</div>
                <div style={{ width: '100%', height: '2px', backgroundColor: 'var(--border-color)', position: 'relative' }}>
                  <div style={{ position: 'absolute', right: 0, top: '-4px', width: 0, height: 0, borderTop: '5px solid transparent', borderBottom: '5px solid transparent', borderLeft: '10px solid var(--border-color)' }}></div>
                </div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontFamily: 'monospace', fontSize: '1.2rem', marginBottom: '0.5rem' }}>{alert.destIp}</div>
                <div style={{ color: 'var(--text-secondary)' }}>Destination</div>
              </div>
            </div>
          </div>

          {/* Detection Details */}
          <div className="card">
            <h3 style={{ marginBottom: '1rem', color: 'var(--text-secondary)' }}>Detection Details</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <div style={{ color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>Final Risk Score</div>
                <div style={{ width: '50%' }}>
                  <RiskGauge score={alert.riskScore} />
                </div>
              </div>
              <div>
                <div style={{ color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>Matched Rules</div>
                <ul style={{ listStylePosition: 'inside', paddingLeft: '0.5rem' }}>
                  <li>RUL-001: Excessive Connections</li>
                  <li>RUL-042: Known Malicious IP</li>
                </ul>
              </div>
            </div>
          </div>

          {/* Traffic Statistics */}
          <div className="card">
            <h3 style={{ marginBottom: '1rem', color: 'var(--text-secondary)' }}>Traffic Statistics</h3>
            <div className="grid-container grid-cols-2">
              <div><strong style={{color:'var(--text-secondary)'}}>Packets:</strong> 1,432</div>
              <div><strong style={{color:'var(--text-secondary)'}}>Bytes:</strong> 245 KB</div>
              <div><strong style={{color:'var(--text-secondary)'}}>Duration:</strong> 12.4s</div>
              <div><strong style={{color:'var(--text-secondary)'}}>Rate:</strong> 115 pps</div>
            </div>
          </div>
        </div>

        <div className="grid-container" style={{ gap: '1.5rem', display: 'flex', flexDirection: 'column' }}>
          
          {/* Actions */}
          <div className="card">
            <h3 style={{ marginBottom: '1rem', color: 'var(--text-secondary)' }}>Actions & Status</h3>
            <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem' }}>
              <select value={status} onChange={(e) => setStatus(e.target.value)} style={{ flex: 1 }}>
                <option value="NEW">New</option>
                <option value="INVESTIGATING">Investigating</option>
                <option value="RESOLVED">Resolved</option>
                <option value="FALSE_POSITIVE">False Positive</option>
              </select>
              <button onClick={handleUpdateStatus}>Update Status</button>
            </div>
            
            <h4 style={{ marginBottom: '0.5rem', color: 'var(--text-secondary)' }}>Add Analyst Note</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <textarea 
                rows="4" 
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Enter investigation notes..."
              ></textarea>
              <button style={{ alignSelf: 'flex-end', display: 'flex', alignItems: 'center', gap: '0.5rem' }} onClick={handleAddNote}>
                <Send size={16} /> Add Note
              </button>
            </div>
          </div>

          {/* Investigation Steps */}
          <div className="card">
            <h3 style={{ marginBottom: '1rem', color: 'var(--text-secondary)' }}>Investigation Steps</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <input type="checkbox" /> Check source IP reputation in Threat Intel
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <input type="checkbox" /> Review recent logs for {alert.destIp}
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <input type="checkbox" /> Identify process tied to port on destination
              </label>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
};

export default AlertDetail;
