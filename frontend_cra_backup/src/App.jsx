import React, { useState, useEffect } from 'react';
import { HashRouter as Router, Routes, Route, NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, Bell, Activity, Shield, Play, Pause, 
  Flame, Radio, CheckCircle, Wifi, Terminal
} from 'lucide-react';
import './App.css';

// Pages
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import AlertDetail from './pages/AlertDetail';
import Traffic from './pages/Traffic';
import Rules from './pages/Rules';

import { 
  standaloneEngine, toggleLiveStream, injectAttackWave, checkBackend 
} from './services/api';

function App() {
  const [currentTime, setCurrentTime] = useState(new Date());
  const [isLiveStreaming, setIsLiveStreaming] = useState(true);
  const [backendActive, setBackendActive] = useState(false);
  const [recentPackets, setRecentPackets] = useState([]);
  const [threatBanner, setThreatBanner] = useState(null);

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    checkBackend().then(status => setBackendActive(status));

    // Subscribe to packet stream for live ticker
    const unsub = standaloneEngine.subscribe(evt => {
      if (evt.type === 'flow' && evt.flow) {
        setRecentPackets(prev => [evt.flow, ...prev.slice(0, 7)]);
        if (evt.alert && evt.alert.severity === 'CRITICAL') {
          setThreatBanner(`CRITICAL ALERT: ${evt.alert.alert_type} detected from ${evt.alert.source_ip}`);
          setTimeout(() => setThreatBanner(null), 6000);
        }
      }
    });

    return () => {
      clearInterval(timer);
      unsub();
    };
  }, []);

  const handleToggleStream = () => {
    const nextState = toggleLiveStream(!isLiveStreaming);
    setIsLiveStreaming(nextState);
  };

  const handleTriggerAttack = (attackType) => {
    injectAttackWave(attackType);
    setThreatBanner(`⚡ ATTACK WAVE INJECTED: ${attackType.toUpperCase().replace('_', ' ')}`);
    setTimeout(() => setThreatBanner(null), 5000);
  };

  return (
    <Router>
      <div className="app-container">
        {/* Left Sidebar */}
        <aside className="sidebar">
          <div className="sidebar-brand">
            <div className="brand-logo">
              <Shield size={22} color="#38bdf8" />
            </div>
            <div className="brand-text">
              <div className="brand-title">CYBER SHIELD</div>
              <div className="brand-subtitle">HYBRID NIDS CONSOLE</div>
            </div>
          </div>

          <div className="sidebar-status-box">
            <div className="status-indicator">
              <span className="radar-dot radar-green" />
              <span className="status-label">
                {backendActive ? 'CORE SERVER: CONNECTED' : 'IN-BROWSER IDS: ACTIVE'}
              </span>
            </div>
            <div className="status-metrics">
              <span>LATENCY: <strong>0.04ms</strong></span>
              <span>ACCURACY: <strong>99.3%</strong></span>
            </div>
          </div>

          <nav className="nav-menu">
            <NavLink to="/" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'} end>
              <LayoutDashboard size={19} />
              <span>SOC Dashboard</span>
            </NavLink>
            <NavLink to="/alerts" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
              <Bell size={19} />
              <span>Threat Alerts</span>
            </NavLink>
            <NavLink to="/traffic" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
              <Activity size={19} />
              <span>Traffic Telemetry</span>
            </NavLink>
            <NavLink to="/rules" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
              <Terminal size={19} />
              <span>Detection Rules</span>
            </NavLink>
          </nav>

          <div className="sidebar-footer">
            <div className="footer-clock">
              <div className="clock-label">SOC UTC TIME</div>
              <div className="clock-time mono">{currentTime.toUTCString().slice(17, 25)} UTC</div>
            </div>
            <div className="footer-meta">
              <span>RFC 5737 Compliant</span>
              <span>IITD Cybersecurity</span>
            </div>
          </div>
        </aside>

        {/* Main Body */}
        <div className="content-wrapper">
          {/* Top Mission Control Bar */}
          <header className="top-control-bar">
            {/* Live Packet Ticker */}
            <div className="packet-ticker">
              <div className="ticker-label">
                <Radio size={14} className="pulse-icon" />
                <span>PACKET STREAM</span>
              </div>
              <div className="ticker-items">
                {recentPackets.map((p, idx) => (
                  <div key={idx} className={`ticker-pill ${p.classification !== 'NORMAL' ? 'pill-threat' : 'pill-normal'}`}>
                    <span className="mono">{p.source_ip}:{p.source_port}</span>
                    <span className="arrow">→</span>
                    <span className="mono">{p.destination_ip}:{p.destination_port}</span>
                    <span className="pill-tag">[{p.protocol}]</span>
                    {p.classification !== 'NORMAL' && (
                      <span className="pill-threat-name">{p.scenario_type || 'ALERT'}</span>
                    )}
                  </div>
                ))}
                {recentPackets.length === 0 && (
                  <span className="ticker-idle">Listening on interface eth0 (promiscuous mode)...</span>
                )}
              </div>
            </div>

            {/* Simulation Controls */}
            <div className="controls-group">
              <button 
                className={`stream-btn ${isLiveStreaming ? 'btn-active' : 'btn-paused'}`}
                onClick={handleToggleStream}
                title="Pause or Resume Real-Time Traffic Ingestion"
              >
                {isLiveStreaming ? <Pause size={14} /> : <Play size={14} />}
                <span>{isLiveStreaming ? 'LIVE INGESTION' : 'STREAM PAUSED'}</span>
              </button>

              <div className="attack-dropdown-wrapper">
                <button className="attack-btn">
                  <Flame size={14} />
                  <span>INJECT ATTACK</span>
                </button>
                <div className="attack-menu">
                  <div className="attack-menu-header">DEMO ATTACK VECTORS</div>
                  <button onClick={() => handleTriggerAttack('syn_flood')}>
                    ⚡ TCP SYN Flood (T1498)
                  </button>
                  <button onClick={() => handleTriggerAttack('port_scan')}>
                    ⚡ Multi-Port Recon Scan (T1046)
                  </button>
                  <button onClick={() => handleTriggerAttack('brute_force')}>
                    ⚡ SSH Brute Force Burst (T1110)
                  </button>
                  <button onClick={() => handleTriggerAttack('exfiltration')}>
                    ⚡ High Volume Data Exfil (T1041)
                  </button>
                  <button onClick={() => handleTriggerAttack('c2_backdoor')}>
                    ⚡ Unusual Port C2 Activity (T1571)
                  </button>
                </div>
              </div>
            </div>
          </header>

          {/* Critical Threat Notification Flash */}
          {threatBanner && (
            <div className="threat-banner">
              <div className="threat-banner-content">
                <Flame size={18} />
                <span>{threatBanner}</span>
              </div>
            </div>
          )}

          {/* Routed Views */}
          <main className="main-content">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/alerts/:id" element={<AlertDetail />} />
              <Route path="/traffic" element={<Traffic />} />
              <Route path="/rules" element={<Rules />} />
            </Routes>
          </main>
        </div>
      </div>
    </Router>
  );
}

export default App;
