import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer,
  BarChart, Bar, PieChart, Pie, Cell, Legend
} from 'recharts';
import { Activity, ShieldAlert, AlertTriangle, AlertOctagon, Info, Zap } from 'lucide-react';
import StatCard from '../components/StatCard';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import RiskGauge from '../components/RiskGauge';
import * as api from '../services/api';

const COLORS = ['#3b82f6', '#22c55e', '#eab308', '#f97316', '#ef4444', '#8b5cf6'];

const Dashboard = () => {
  const navigate = useNavigate();
  const [stats, setStats] = useState({});
  const [trafficData, setTrafficData] = useState([]);
  const [alertData, setAlertData] = useState([]);
  const [protocolData, setProtocolData] = useState([]);
  const [sourceData, setSourceData] = useState([]);
  const [recentAlerts, setRecentAlerts] = useState([]);

  const fetchData = async () => {
    try {
      setStats(await api.getStats());
      setTrafficData(await api.getTrafficTimeline());
      setAlertData(await api.getSeverityDist());
      setProtocolData(await api.getProtocolDist());
      setSourceData(await api.getTopSources());
      setRecentAlerts((await api.getAlerts()).slice(0, 10));
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="dashboard-page">
      <div className="page-header">
        <h1 className="page-title">SOC Overview</h1>
      </div>

      <div className="grid-container grid-cols-6" style={{ marginBottom: '1.5rem' }}>
        <StatCard title="Total Flows" value={stats.totalFlows || 0} icon={Activity} color="var(--color-low)" />
        <StatCard title="Normal Traffic" value={stats.normalTraffic || 0} icon={Info} color="var(--color-normal)" />
        <StatCard title="Suspicious Traffic" value={stats.suspiciousTraffic || 0} icon={Zap} color="var(--color-high)" />
        <StatCard title="Open Alerts" value={stats.openAlerts || 0} icon={AlertTriangle} color="var(--color-medium)" />
        <StatCard title="Critical Alerts" value={stats.criticalAlerts || 0} icon={ShieldAlert} color="var(--color-critical)" isPulsing={stats.criticalAlerts > 0} />
        <StatCard title="Avg Risk Score" value={stats.averageRiskScore || 0} icon={AlertOctagon} color="var(--color-high)" />
      </div>

      <div className="grid-container grid-cols-2" style={{ marginBottom: '1.5rem' }}>
        <div className="card">
          <h3 style={{ marginBottom: '1rem', color: 'var(--text-secondary)' }}>Traffic Over Time</h3>
          <div style={{ height: '300px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trafficData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="time" stroke="#8b9bb4" />
                <YAxis stroke="#8b9bb4" />
                <RechartsTooltip contentStyle={{ backgroundColor: '#131a2b', borderColor: '#1e293b' }} />
                <Area type="monotone" dataKey="normal" stackId="1" stroke="#22c55e" fill="#22c55e" fillOpacity={0.2} />
                <Area type="monotone" dataKey="suspicious" stackId="1" stroke="#ef4444" fill="#ef4444" fillOpacity={0.5} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <h3 style={{ marginBottom: '1rem', color: 'var(--text-secondary)' }}>Alerts by Severity</h3>
          <div style={{ height: '300px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={alertData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="name" stroke="#8b9bb4" />
                <YAxis stroke="#8b9bb4" />
                <RechartsTooltip contentStyle={{ backgroundColor: '#131a2b', borderColor: '#1e293b' }} />
                <Bar dataKey="count">
                  {alertData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={
                      entry.name === 'CRITICAL' ? '#ef4444' :
                      entry.name === 'HIGH' ? '#f97316' :
                      entry.name === 'MEDIUM' ? '#eab308' :
                      entry.name === 'LOW' ? '#3b82f6' : '#6b7280'
                    } />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid-container grid-cols-2" style={{ marginBottom: '1.5rem' }}>
        <div className="card">
          <h3 style={{ marginBottom: '1rem', color: 'var(--text-secondary)' }}>Protocol Distribution</h3>
          <div style={{ height: '250px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={protocolData} cx="50%" cy="50%" innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value">
                  {protocolData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <RechartsTooltip contentStyle={{ backgroundColor: '#131a2b', borderColor: '#1e293b' }} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <h3 style={{ marginBottom: '1rem', color: 'var(--text-secondary)' }}>Top Source IPs by Alerts</h3>
          <div style={{ height: '250px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={sourceData} layout="vertical" margin={{ top: 5, right: 30, left: 40, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis type="number" stroke="#8b9bb4" />
                <YAxis dataKey="ip" type="category" stroke="#8b9bb4" width={100} />
                <RechartsTooltip contentStyle={{ backgroundColor: '#131a2b', borderColor: '#1e293b' }} />
                <Bar dataKey="alerts" fill="#3b82f6" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="card">
        <h3 style={{ marginBottom: '1rem', color: 'var(--text-secondary)' }}>Recent Alerts</h3>
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Source IP</th>
                <th>Dest IP</th>
                <th>Protocol</th>
                <th>Alert Type</th>
                <th>Severity</th>
                <th>Risk Score</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {recentAlerts.map((alert) => (
                <tr key={alert.id} onClick={() => navigate(`/alerts/${alert.id}`)} style={{ cursor: 'pointer' }}>
                  <td>{new Date(alert.time).toLocaleTimeString()}</td>
                  <td style={{ fontFamily: 'monospace' }}>{alert.sourceIp}</td>
                  <td style={{ fontFamily: 'monospace' }}>{alert.destIp}</td>
                  <td>{alert.protocol}</td>
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

export default Dashboard;
