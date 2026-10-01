import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import RiskGauge from '../components/RiskGauge';
import * as api from '../services/api';
import { 
  Search, Filter, ShieldAlert, CheckCircle, Clock, Download, 
  ArrowUpDown, RefreshCw, ChevronLeft, ChevronRight, X
} from 'lucide-react';

const Alerts = () => {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [selectedAlerts, setSelectedAlerts] = useState(new Set());
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(15);
  const [sortField, setSortField] = useState('time');
  const [sortAsc, setSortAsc] = useState(false);

  const fetchAlerts = async () => {
    setLoading(true);
    const data = await api.getAlerts();
    setAlerts(data);
    setLoading(false);
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 10000);
    return () => clearInterval(interval);
  }, []);

  // Filtered and Sorted Alerts
  const filteredAlerts = useMemo(() => {
    return alerts.filter(a => {
      const q = searchQuery.toLowerCase().trim();
      const matchesSearch = !q || 
        a.id.toLowerCase().includes(q) ||
        a.sourceIp.toLowerCase().includes(q) ||
        a.destIp.toLowerCase().includes(q) ||
        a.type.toLowerCase().includes(q) ||
        String(a.destPort).includes(q);

      const matchesSeverity = severityFilter === 'ALL' || a.severity === severityFilter;
      const matchesStatus = statusFilter === 'ALL' || a.status === statusFilter;
      const matchesProtocol = protocolFilter === 'ALL' || a.protocol === protocolFilter;

      return matchesSearch && matchesSeverity && matchesStatus && matchesProtocol;
    }).sort((a, b) => {
      let valA = a[sortField];
      let valB = b[sortField];
      if (sortField === 'time') {
        valA = new Date(a.created_at || a.time).getTime();
        valB = new Date(b.created_at || b.time).getTime();
      }
      if (valA < valB) return sortAsc ? -1 : 1;
      if (valA > valB) return sortAsc ? 1 : -1;
      return 0;
    });
  }, [alerts, searchQuery, severityFilter, statusFilter, protocolFilter, sortField, sortAsc]);

  // Pagination slice
  const totalPages = Math.ceil(filteredAlerts.length / pageSize) || 1;
  const paginatedAlerts = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredAlerts.slice(start, start + pageSize);
  }, [filteredAlerts, currentPage, pageSize]);

  // Bulk Selection Handlers
  const toggleSelectAll = (e) => {
    if (e.target.checked) {
      setSelectedAlerts(new Set(paginatedAlerts.map(a => a.id)));
    } else {
      setSelectedAlerts(new Set());
    }
  };

  const toggleSelectOne = (id, e) => {
    e.stopPropagation();
    const next = new Set(selectedAlerts);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelectedAlerts(next);
  };

  const handleBulkStatus = async (newStatus) => {
    for (const id of selectedAlerts) {
      await api.updateAlertStatus(id, newStatus, 'SOC-Lead-Bulk');
    }
    setSelectedAlerts(new Set());
    await fetchAlerts();
  };

  const exportCSV = () => {
    const headers = ['Alert ID', 'Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Alert Type', 'Severity', 'Risk Score', 'Status'];
    const rows = filteredAlerts.map(a => [
      a.id,
      a.created_at || a.time,
      a.sourceIp,
      a.destIp,
      a.protocol,
      `"${a.type}"`,
      a.severity,
      a.riskScore,
      a.status
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `IDS-Alerts-${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Metrics
  const criticalCount = alerts.filter(a => a.severity === 'CRITICAL' && a.status !== 'RESOLVED').length;
  const highRiskCount = alerts.filter(a => a.riskScore >= 70).length;
  const unresolvedCount = alerts.filter(a => a.status === 'NEW' || a.status === 'INVESTIGATING').length;

  return (
    <div style={{ paddingBottom: '3rem' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 className="page-title" style={{ margin: 0 }}>Incident Alert Queue</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginTop: '4px' }}>
            Real-time correlation of signature rules, Z-score deviations, and ML inference predictions.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <button 
            className="secondary" 
            onClick={fetchAlerts}
            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem' }}
          >
            <RefreshCw size={14} className={loading ? 'spin' : ''} /> Refresh Feed
          </button>
          <button 
            className="secondary" 
            onClick={exportCSV}
            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem' }}
          >
            <Download size={14} color="#38bdf8" /> Export CSV ({filteredAlerts.length})
          </button>
        </div>
      </div>

      {/* KPI Ribbon */}
      <div className="grid-container grid-cols-4" style={{ marginBottom: '1.5rem' }}>
        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid #38bdf8' }}>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase' }}>Filtered Alerts</div>
          <div style={{ fontSize: '1.5rem', fontWeight: '800', fontFamily: 'monospace', color: '#f8fafc', marginTop: '2px' }}>
            {filteredAlerts.length} <span style={{ fontSize: '0.8rem', color: '#64748b' }}>/ {alerts.length}</span>
          </div>
        </div>

        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid #ef4444' }}>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase' }}>Active Criticals</div>
          <div style={{ fontSize: '1.5rem', fontWeight: '800', fontFamily: 'monospace', color: '#ef4444', marginTop: '2px' }}>
            {criticalCount}
          </div>
        </div>

        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid #f97316' }}>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase' }}>High Risk Flows (&ge;70)</div>
          <div style={{ fontSize: '1.5rem', fontWeight: '800', fontFamily: 'monospace', color: '#fbbf24', marginTop: '2px' }}>
            {highRiskCount}
          </div>
        </div>

        <div className="card" style={{ padding: '1rem', borderLeft: '4px solid #3b82f6' }}>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase' }}>Pending Triage</div>
          <div style={{ fontSize: '1.5rem', fontWeight: '800', fontFamily: 'monospace', color: '#60a5fa', marginTop: '2px' }}>
            {unresolvedCount}
          </div>
        </div>
      </div>

      {/* Cyber Search & Filter Toolbar */}
      <div className="card" style={{ marginBottom: '1.5rem', padding: '1rem' }}>
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
          {/* Search Box */}
          <div style={{ position: 'relative', flex: 2, minWidth: '240px' }}>
            <Search size={16} color="#64748b" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
            <input 
              type="text" 
              placeholder="Search by IP, Alert ID, port, or attack signature..." 
              value={searchQuery}
              onChange={(e) => { setSearchQuery(e.target.value); setCurrentPage(1); }}
              style={{
                width: '100%',
                padding: '8px 36px 8px 36px',
                borderRadius: '8px',
                backgroundColor: 'rgba(0, 0, 0, 0.35)',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                color: '#f8fafc',
                fontSize: '0.85rem'
              }}
            />
            {searchQuery && (
              <X 
                size={16} 
                color="#94a3b8" 
                onClick={() => setSearchQuery('')} 
                style={{ position: 'absolute', right: '12px', top: '50%', transform: 'translateY(-50%)', cursor: 'pointer' }} 
              />
            )}
          </div>

          {/* Severity Dropdown */}
          <select 
            value={severityFilter} 
            onChange={(e) => { setSeverityFilter(e.target.value); setCurrentPage(1); }}
            style={{ flex: 1, minWidth: '140px', padding: '8px 12px', borderRadius: '8px' }}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical Only</option>
            <option value="HIGH">High Only</option>
            <option value="MEDIUM">Medium Only</option>
            <option value="LOW">Low Only</option>
          </select>

          {/* Status Dropdown */}
          <select 
            value={statusFilter} 
            onChange={(e) => { setStatusFilter(e.target.value); setCurrentPage(1); }}
            style={{ flex: 1, minWidth: '140px', padding: '8px 12px', borderRadius: '8px' }}
          >
            <option value="ALL">All Statuses</option>
            <option value="NEW">New (Unassigned)</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="RESOLVED">Resolved</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>

          {/* Protocol Dropdown */}
          <select 
            value={protocolFilter} 
            onChange={(e) => { setProtocolFilter(e.target.value); setCurrentPage(1); }}
            style={{ flex: 1, minWidth: '110px', padding: '8px 12px', borderRadius: '8px' }}
          >
            <option value="ALL">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
          </select>
        </div>

        {/* Bulk Action Strip */}
        {selectedAlerts.size > 0 && (
          <div style={{
            marginTop: '1rem',
            padding: '0.65rem 1rem',
            borderRadius: '6px',
            backgroundColor: 'rgba(56, 189, 248, 0.1)',
            border: '1px solid rgba(56, 189, 248, 0.3)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '0.75rem'
          }}>
            <span style={{ fontSize: '0.85rem', color: '#38bdf8', fontWeight: '700' }}>
              {selectedAlerts.size} alerts selected for triage:
            </span>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button 
                className="secondary" 
                style={{ fontSize: '0.75rem', padding: '4px 10px' }}
                onClick={() => handleBulkStatus('INVESTIGATING')}
              >
                Mark Investigating
              </button>
              <button 
                className="secondary" 
                style={{ fontSize: '0.75rem', padding: '4px 10px', color: '#4ade80', borderColor: 'rgba(34,197,94,0.3)' }}
                onClick={() => handleBulkStatus('RESOLVED')}
              >
                Mark Resolved
              </button>
              <button 
                className="secondary" 
                style={{ fontSize: '0.75rem', padding: '4px 10px', color: '#94a3b8' }}
                onClick={() => handleBulkStatus('FALSE_POSITIVE')}
              >
                Mark False Positive
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Alerts Table */}
      <div className="card">
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th style={{ width: '40px' }}>
                  <input 
                    type="checkbox" 
                    onChange={toggleSelectAll} 
                    checked={paginatedAlerts.length > 0 && paginatedAlerts.every(a => selectedAlerts.has(a.id))}
                  />
                </th>
                <th 
                  onClick={() => { setSortField('id'); setSortAsc(!sortAsc); }} 
                  style={{ cursor: 'pointer' }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    Alert ID <ArrowUpDown size={12} />
                  </div>
                </th>
                <th 
                  onClick={() => { setSortField('time'); setSortAsc(!sortAsc); }} 
                  style={{ cursor: 'pointer' }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    Timestamp <ArrowUpDown size={12} />
                  </div>
                </th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Proto</th>
                <th>Alert Signature</th>
                <th>Severity</th>
                <th 
                  onClick={() => { setSortField('riskScore'); setSortAsc(!sortAsc); }} 
                  style={{ cursor: 'pointer', width: '130px' }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    Risk Index <ArrowUpDown size={12} />
                  </div>
                </th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {paginatedAlerts.length === 0 ? (
                <tr>
                  <td colSpan={10} style={{ textAlign: 'center', padding: '2.5rem', color: '#64748b' }}>
                    No alerts match the active filter criteria.
                  </td>
                </tr>
              ) : (
                paginatedAlerts.map((alert) => (
                  <tr 
                    key={alert.id} 
                    onClick={() => navigate(`/alerts/${alert.id}`)} 
                    style={{ 
                      cursor: 'pointer',
                      backgroundColor: selectedAlerts.has(alert.id) ? 'rgba(56, 189, 248, 0.05)' : undefined 
                    }}
                  >
                    <td onClick={(e) => toggleSelectOne(alert.id, e)}>
                      <input 
                        type="checkbox" 
                        checked={selectedAlerts.has(alert.id)}
                        onChange={() => {}}
                      />
                    </td>
                    <td style={{ fontFamily: 'monospace', fontWeight: '700', color: '#38bdf8' }}>
                      {alert.id}
                    </td>
                    <td style={{ color: '#94a3b8', fontSize: '0.8rem', whiteSpace: 'nowrap' }}>
                      {new Date(alert.created_at || alert.time).toLocaleTimeString()}
                    </td>
                    <td style={{ fontFamily: 'monospace', color: '#f87171', fontWeight: '600' }}>
                      {alert.sourceIp}:{alert.sourcePort || '51421'}
                    </td>
                    <td style={{ fontFamily: 'monospace', color: '#4ade80' }}>
                      {alert.destIp}:{alert.destPort || '80'}
                    </td>
                    <td>
                      <span style={{ fontSize: '0.7rem', padding: '2px 6px', borderRadius: '4px', backgroundColor: 'rgba(255,255,255,0.08)', fontWeight: '700' }}>
                        {alert.protocol}
                      </span>
                    </td>
                    <td style={{ fontWeight: '600', color: '#f8fafc', maxWidth: '220px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {alert.type}
                    </td>
                    <td>
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td>
                      <RiskGauge score={alert.riskScore} />
                    </td>
                    <td>
                      <StatusBadge status={alert.status} />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginTop: '1rem',
          paddingTop: '0.75rem',
          borderTop: '1px solid rgba(255, 255, 255, 0.06)',
          flexWrap: 'wrap',
          gap: '0.75rem'
        }}>
          <div style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
            Showing <strong>{(currentPage - 1) * pageSize + 1}</strong> - <strong>{Math.min(currentPage * pageSize, filteredAlerts.length)}</strong> of <strong>{filteredAlerts.length}</strong> alerts
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <button 
              className="secondary" 
              disabled={currentPage <= 1}
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
              style={{ padding: '4px 10px', fontSize: '0.8rem' }}
            >
              <ChevronLeft size={14} /> Previous
            </button>

            <span style={{ fontSize: '0.8rem', fontFamily: 'monospace', padding: '0 0.5rem' }}>
              Page {currentPage} of {totalPages}
            </span>

            <button 
              className="secondary" 
              disabled={currentPage >= totalPages}
              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
              style={{ padding: '4px 10px', fontSize: '0.8rem' }}
            >
              Next <ChevronRight size={14} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Alerts;
