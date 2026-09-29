import React, { useState, useEffect } from 'react';
import { 
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer,
  BarChart, Bar
} from 'recharts';
import * as api from '../services/api';

const Traffic = () => {
  const [trafficData, setTrafficData] = useState([]);
  const [portData, setPortData] = useState([]);

  useEffect(() => {
    const fetch = async () => {
      setTrafficData(await api.getTrafficTimeline());
      setPortData(await api.getPortDist());
    };
    fetch();
  }, []);

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Traffic Analytics</h1>
      </div>

      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <h3 style={{ marginBottom: '1rem', color: 'var(--text-secondary)' }}>Traffic Rate (Connections/min)</h3>
        <div style={{ height: '350px' }}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={trafficData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="time" stroke="#8b9bb4" />
              <YAxis stroke="#8b9bb4" />
              <RechartsTooltip contentStyle={{ backgroundColor: '#131a2b', borderColor: '#1e293b' }} />
              <Line type="monotone" dataKey="normal" stroke="#22c55e" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="suspicious" stroke="#ef4444" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid-container grid-cols-2">
        <div className="card">
          <h3 style={{ marginBottom: '1rem', color: 'var(--text-secondary)' }}>Top Ports (Destination)</h3>
          <div style={{ height: '300px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={portData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="name" stroke="#8b9bb4" />
                <YAxis stroke="#8b9bb4" />
                <RechartsTooltip contentStyle={{ backgroundColor: '#131a2b', borderColor: '#1e293b' }} />
                <Bar dataKey="value" fill="#8b5cf6" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Traffic;
