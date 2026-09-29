import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, NavLink } from 'react-router-dom';
import { LayoutDashboard, Bell, Activity, Shield } from 'lucide-react';
import './App.css';

// Pages
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import AlertDetail from './pages/AlertDetail';
import Traffic from './pages/Traffic';
import Rules from './pages/Rules';

function App() {
  const [currentTime, setCurrentTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <Router>
      <div className="app-container">
        {/* Sidebar */}
        <aside className="sidebar">
          <div className="sidebar-header">
            <Shield className="logo-icon" size={28} color="#3b82f6" />
            <h2>Network IDS</h2>
          </div>
          
          <div className="time-display">
            {currentTime.toLocaleTimeString()}
          </div>

          <nav className="nav-menu">
            <NavLink to="/" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'} end>
              <LayoutDashboard size={20} />
              <span>Dashboard</span>
            </NavLink>
            <NavLink to="/alerts" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
              <Bell size={20} />
              <span>Alerts</span>
            </NavLink>
            <NavLink to="/traffic" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
              <Activity size={20} />
              <span>Traffic</span>
            </NavLink>
            <NavLink to="/rules" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
              <Shield size={20} />
              <span>Rules</span>
            </NavLink>
          </nav>
        </aside>

        {/* Main Content */}
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
    </Router>
  );
}

export default App;
