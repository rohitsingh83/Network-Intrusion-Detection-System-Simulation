import React, { useState, useEffect } from 'react';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer,
  BarChart, Bar, PieChart, Pie, Cell, Legend
} from 'recharts';
import * as api from '../services/api';
import { 
  Activity, Play, Pause, RefreshCw, Radio, HardDrive, 
  Layers, Terminal, Zap, ArrowDownUp, CheckCircle, AlertOctagon, X
} from 'lucide-react';

const PROTO_COLORS = ['#38bdf8', '#818cf8', '#c084fc', '#f43f5e', '#34d399'];

const Traffic = () => {
  const [trafficData, setTrafficData] = useState([]);
  const [portData, setPortData] = useState([]);
  const [protoData, setProtoData] = useState([]);
  const [recentFlows, setRecentFlows] = useState([]);
  const [stats, setStats] = useState(null);
  const [isStreaming, setIsStreaming] = useState(true);
  const [selectedFlow, setSelectedFlow] = useState(null);
  const [timeRange, setTimeRange] = useState('24h');

  const fetchData = async () => {
    const [t, p, pr, f, s] = await Promise.all([
      api.getTrafficTimeline(),
      api.getPortDist(),
      api.getProtocolDist(),
      api.getFlows(40),
      api.getStats()
    ]);
    setTrafficData(t);
    setPortData(p);
    setProtoData(pr);
    setRecentFlows(f);
    setStats(s);
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(() => {
      if (isStreaming) {
        fetchData();
      }
    }, 4000);
    return () => clearInterval(interval);
  }, [isStreaming]);

  const toggleStream = () => {
    const next = !isStreaming;
    setIsStreaming(next);
    api.toggleLiveStream(next);
  };

  const handleInjectBurst = () => {
    api.injectAttackWave('syn_flood');
    fetchData();
  };

  // Telemetry metrics
  const totalFlows = stats?.totalFlows || 402;
  const normalFlows = stats?.normalTraffic || 300;
  const suspiciousFlows = stats?.suspiciousTraffic || 102;
  const anomalyRate = totalFlows > 0 ? ((suspiciousFlows / totalFlows) * 100).toFixed(1) : '0.0';
  const estBandwidth = (totalFlows * 0.084).toFixed(2);
  const estPPS = Math.round(totalFlows * 3.4);

  return (
    <div style={{ paddingBottom: '3rem' }}>
      {/* Detail Modal for Selected Flow */}
      {selectedFlow && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          width: '100vw',
          height: '100vh',
          backgroundColor: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(6px)',
          zIndex: 99999,
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          padding: '1rem'
        }}>
          <div className="card" style={{
            width: '100%',
            maxWidth: '600px',
            backgroundColor: '#0d1322',
            border: '1px solid #38bdf8',
            boxShadow: '0 0 24px rgba(56, 189, 248, 0.3)',
            padding: '1.5rem',
            position: 'relative'
          }}>
            <button 
              onClick={() => setSelectedFlow(null)}
              style={{ position: 'absolute', right: '16px', top: '16px', background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: '4px' }}
            >
              <X size={20} />
            </button>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '1rem' }}>
              <Terminal size={20} color="#38bdf8" />
              <h2 style={{ fontSize: '1.2rem', margin: 0, color: '#f8fafc' }}>
                Flow Packet Inspection [{selectedFlow.flow_id || 'FLOW-DEMO'}]
              </h2>
            </div>

            <div style={{
              backgroundColor: '#050811',
              padding: '1rem',
              borderRadius: '8px',
              fontFamily: 'Consolas, monospace',
              fontSize: '0.8rem',
              color: '#38bdf8',
              lineHeight: 1.6,
              border: '1px solid rgba(56, 189, 248, 0.2)',
              marginBottom: '1rem'
            }}>
              <div>TIMESTAMP: {selectedFlow.timestamp || new Date().toISOString()}</div>
              <div>SOURCE: {selectedFlow.source_ip}:{selectedFlow.source_port}</div>
              <div>DESTINATION: {selectedFlow.destination_ip}:{selectedFlow.destination_port}</div>
              <div>PROTOCOL: {selectedFlow.protocol}</div>
              <div>CLASSIFICATION: <strong style={{ color: selectedFlow.classification === 'NORMAL' ? '#22c55e' : '#ef4444' }}>{selectedFlow.classification}</strong></div>
              <div>RISK SCORE: {selectedFlow.risk_score || 0}/100</div>
              <div style={{ borderTop: '1px dashed rgba(255,255,255,0.1)', marginTop: '8px', paddingTop: '8px', color: '#94a3b8' }}>
                METRICS: Packets={selectedFlow.packet_count || 120} | Bytes={selectedFlow.byte_count || 4520} | SYN={selectedFlow.syn_count || 0} | RST={selectedFlow.rst_count || 0}
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button onClick={() => setSelectedFlow(null)}>Close Inspector</button>
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 className="page-title" style={{ margin: 0 }}>Network Telemetry & Flow Analyzer</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginTop: '4px' }}>
            Continuous wire-speed packet feature extraction, connection rate monitoring, and anomaly distribution.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <button 
            className="secondary" 
            onClick={toggleStream}
            style={{ 
              display: 'inline-flex', 
              alignItems: 'center', 
              gap: '0.4rem', 
              fontSize: '0.8rem',
              borderColor: isStreaming ? 'rgba(34, 197, 94, 0.4)' : undefined,
              color: isStreaming ? '#4ade80' : '#94a3b8'
            }}
          >
            {isStreaming ? <Pause size={14} /> : <Play size={14} />}
            {isStreaming ? 'Pause Sensor Feed' : 'Resume Sensor Feed'}
          </button>

          <button 
            onClick={handleInjectBurst}
            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem' }}
          >
            <Zap size={14} /> Inject Traffic Spike
          </button>
        </div>
      </div>

      {/* Live Telemetry KPI Ribbon */}
      <div className="grid-container grid-cols-4" style={{ marginBottom: '1.5rem' }}>
        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid #38bdf8' }}>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase' }}>Ingress Velocity</div>
          <div style={{ fontSize: '1.5rem', fontWeight: '800', fontFamily: 'monospace', color: '#38bdf8', marginTop: '2px' }}>
            {estPPS} <span style={{ fontSize: '0.8rem', color: '#64748b' }}>PPS</span>
          </div>
        </div>

        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid #818cf8' }}>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase' }}>Estimated Bandwidth</div>
          <div style={{ fontSize: '1.5rem', fontWeight: '800', fontFamily: 'monospace', color: '#818cf8', marginTop: '2px' }}>
            {estBandwidth} <span style={{ fontSize: '0.8rem', color: '#64748b' }}>Mbps</span>
          </div>
        </div>

        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid #ef4444' }}>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase' }}>Anomaly Deviation Rate</div>
          <div style={{ fontSize: '1.5rem', fontWeight: '800', fontFamily: 'monospace', color: '#f87171', marginTop: '2px' }}>
            {anomalyRate}%
          </div>
        </div>

        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid #22c55e' }}>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase' }}>Ingested Sessions</div>
          <div style={{ fontSize: '1.5rem', fontWeight: '800', fontFamily: 'monospace', color: '#4ade80', marginTop: '2px' }}>
            {totalFlows}
          </div>
        </div>
      </div>

      {/* Main Flow Chart */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: '700', color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0 }}>
            <Activity size={18} color="#38bdf8" /> Flow Volume & Anomaly Velocity Over Time
          </h3>

          <div style={{ display: 'flex', gap: '0.4rem' }}>
            {['15m', '1h', '6h', '24h'].map(t => (
              <button 
                key={t}
                className={timeRange === t ? '' : 'secondary'}
                onClick={() => setTimeRange(t)}
                style={{ fontSize: '0.72rem', padding: '3px 8px' }}
              >
                {t}
              </button>
            ))}
          </div>
        </div>

        <div style={{ height: '320px', width: '100%' }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={trafficData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="normalGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#22c55e" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#22c55e" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="suspiciousGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.6} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 11 }} />
              <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
              <RechartsTooltip 
                contentStyle={{
                  backgroundColor: 'rgba(10, 14, 26, 0.95)',
                  borderColor: 'rgba(56, 189, 248, 0.3)',
                  borderRadius: '8px',
                  boxShadow: '0 0 16px rgba(0,0,0,0.6)',
                  color: '#f8fafc',
                  fontSize: '0.8rem'
                }} 
              />
              <Area type="monotone" dataKey="normal" name="Normal Flows" stroke="#22c55e" strokeWidth={2} fillOpacity={1} fill="url(#normalGrad)" />
              <Area type="monotone" dataKey="suspicious" name="Suspicious / Anomalous" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#suspiciousGrad)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Row: Protocol Distribution & Port Distribution */}
      <div className="grid-container grid-cols-2" style={{ marginBottom: '1.5rem' }}>
        {/* Protocol Pie Chart */}
        <div className="card">
          <h3 style={{ fontSize: '1rem', fontWeight: '700', color: '#cbd5e1', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Layers size={18} color="#818cf8" /> Protocol Breakdown
          </h3>
          <div style={{ height: '260px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={protoData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={5}
                  dataKey="value"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                >
                  {protoData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={PROTO_COLORS[index % PROTO_COLORS.length]} />
                  ))}
                </Pie>
                <RechartsTooltip 
                  contentStyle={{
                    backgroundColor: 'rgba(10, 14, 26, 0.95)',
                    borderColor: 'rgba(255,255,255,0.1)',
                    borderRadius: '6px',
                    fontSize: '0.8rem'
                  }} 
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Port Distribution Bar Chart */}
        <div className="card">
          <h3 style={{ fontSize: '1rem', fontWeight: '700', color: '#cbd5e1', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <HardDrive size={18} color="#c084fc" /> Destination Port Activity
          </h3>
          <div style={{ height: '260px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={portData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="name" stroke="#64748b" tick={{ fontSize: 10 }} />
                <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
                <RechartsTooltip 
                  contentStyle={{
                    backgroundColor: 'rgba(10, 14, 26, 0.95)',
                    borderColor: 'rgba(255,255,255,0.1)',
                    borderRadius: '6px',
                    fontSize: '0.8rem'
                  }} 
                />
                <Bar dataKey="value" fill="#a855f7" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Wireshark-Style Live Packet Capture Table */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
          <div>
            <h3 style={{ fontSize: '1rem', fontWeight: '700', color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0 }}>
              <Terminal size={18} color="#22c55e" /> Live Wire Packet Sniffer Stream
            </h3>
            <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
              Click any packet row to inspect headers and anomaly signature telemetry.
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.75rem', color: '#64748b', fontFamily: 'monospace' }}>
              BUFFER: {recentFlows.length} FLOWS
            </span>
          </div>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th style={{ width: '60px' }}>#</th>
                <th>Time</th>
                <th>Source (Host:Port)</th>
                <th>Destination (Host:Port)</th>
                <th>Proto</th>
                <th>Packets</th>
                <th>Bytes</th>
                <th>Status</th>
                <th>Threat Risk</th>
              </tr>
            </thead>
            <tbody>
              {recentFlows.map((flow, idx) => (
                <tr 
                  key={flow.flow_id || idx}
                  onClick={() => setSelectedFlow(flow)}
                  style={{ cursor: 'pointer' }}
                >
                  <td style={{ fontFamily: 'monospace', color: '#64748b', fontSize: '0.75rem' }}>
                    {String(idx + 1).padStart(3, '0')}
                  </td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.78rem', color: '#94a3b8' }}>
                    {new Date(flow.timestamp || Date.now()).toLocaleTimeString()}
                  </td>
                  <td style={{ fontFamily: 'monospace', color: flow.classification === 'NORMAL' ? '#cbd5e1' : '#f87171' }}>
                    {flow.source_ip}:{flow.source_port}
                  </td>
                  <td style={{ fontFamily: 'monospace', color: '#4ade80' }}>
                    {flow.destination_ip}:{flow.destination_port}
                  </td>
                  <td>
                    <span style={{ fontSize: '0.7rem', padding: '2px 6px', borderRadius: '4px', backgroundColor: 'rgba(255,255,255,0.06)', fontWeight: '700' }}>
                      {flow.protocol || 'TCP'}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                    {flow.packet_count?.toLocaleString() || 1}
                  </td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                    {(flow.byte_count || 500) > 1024 ? `${((flow.byte_count || 500) / 1024).toFixed(1)} KB` : `${flow.byte_count || 500} B`}
                  </td>
                  <td>
                    <span style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px',
                      fontSize: '0.72rem',
                      fontWeight: '700',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      backgroundColor: flow.classification === 'NORMAL' ? 'rgba(34, 197, 94, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                      color: flow.classification === 'NORMAL' ? '#4ade80' : '#f87171',
                      border: flow.classification === 'NORMAL' ? '1px solid rgba(34, 197, 94, 0.3)' : '1px solid rgba(239, 68, 68, 0.3)'
                    }}>
                      {flow.classification === 'NORMAL' ? <CheckCircle size={10} /> : <AlertOctagon size={10} />}
                      {flow.classification || 'NORMAL'}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'monospace', fontWeight: '800', color: (flow.risk_score || 0) > 60 ? '#f87171' : '#38bdf8' }}>
                    {flow.risk_score || 15}
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

export default Traffic;
