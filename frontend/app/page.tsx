'use client';

import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Activity, ShieldCheck, AlertTriangle, Bell, Flame, ActivitySquare } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';
import { format } from 'date-fns';

import { api } from '@/lib/api-client';
import { useLiveTelemetry } from '@/hooks/use-live-telemetry';
import { MetricCard } from '@/components/dashboard/metric-card';
import { ClassificationBadge } from '@/components/dashboard/classification-badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

export default function Dashboard() {
  const [time, setTime] = useState(new Date());
  
  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const { connected, liveFlows } = useLiveTelemetry();
  
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: () => api.getStats(),
    refetchInterval: 5000,
  });

  const { data: traffic = [], isLoading: trafficLoading } = useQuery({
    queryKey: ['dashboard-traffic'],
    queryFn: () => api.getTraffic(),
    refetchInterval: 5000,
  });

  const { data: severityDist = [] } = useQuery({
    queryKey: ['dashboard-severity'],
    queryFn: () => api.getSeverity(),
    refetchInterval: 10000,
  });

  const { data: protocolsDist = [] } = useQuery({
    queryKey: ['dashboard-protocols'],
    queryFn: () => api.getProtocols(),
    refetchInterval: 10000,
  });

  const { data: sourcesDist = [] } = useQuery({
    queryKey: ['dashboard-sources'],
    queryFn: () => api.getSources(),
    refetchInterval: 10000,
  });

  const SEVERITY_COLORS = {
    CRITICAL: '#f43f5e',
    HIGH: '#f97316',
    MEDIUM: '#f59e0b',
    LOW: '#06b6d4',
    INFO: '#64748b'
  };

  return (
    <div className="p-8 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">SOC Command Center</h1>
          <p className="text-slate-400 mt-1">Network Intrusion Detection System</p>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-right">
            <div className="text-sm font-medium text-slate-300">{format(time, 'MMM d, yyyy')}</div>
            <div className="text-xl font-mono font-bold text-slate-100">{format(time, 'HH:mm:ss')}</div>
          </div>
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800">
            <div className={`w-2.5 h-2.5 rounded-full ${connected ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]' : 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.5)]'}`} />
            <span className="text-sm font-medium text-slate-300">{connected ? 'Live' : 'Disconnected'}</span>
          </div>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        <MetricCard title="Total Flows" value={stats?.total_flows || 0} icon={<Activity className="h-5 w-5" />} color="cyan" loading={statsLoading} />
        <MetricCard title="Normal Flows" value={stats?.normal_flows || 0} icon={<ShieldCheck className="h-5 w-5" />} color="emerald" loading={statsLoading} />
        <MetricCard title="Suspicious Flows" value={stats?.suspicious_flows || 0} icon={<AlertTriangle className="h-5 w-5" />} color="amber" loading={statsLoading} />
        <MetricCard title="Open Alerts" value={stats?.open_alerts || 0} icon={<Bell className="h-5 w-5" />} color="rose" loading={statsLoading} />
        <MetricCard title="Critical Alerts" value={stats?.critical_alerts || 0} icon={<Flame className="h-5 w-5" />} color="rose" loading={statsLoading} />
        <MetricCard title="Avg Risk Score" value={(stats?.avg_risk_score || 0).toFixed(1)} icon={<ActivitySquare className="h-5 w-5" />} color="violet" loading={statsLoading} />
      </div>

      {/* Traffic Chart */}
      <Card className="bg-slate-900 border-slate-800">
        <CardHeader>
          <CardTitle>Traffic Velocity (Flows/sec)</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={traffic} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorSuspicious" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="timestamp" stroke="#64748b" fontSize={12} tickFormatter={(v) => new Date(v).toLocaleTimeString()} />
                <YAxis stroke="#64748b" fontSize={12} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#f8fafc' }}
                  labelFormatter={(v: any) => new Date(v).toLocaleTimeString()}
                />
                <Area type="monotone" dataKey="count" name="Total Flows" stroke="#06b6d4" fillOpacity={1} fill="url(#colorTotal)" />
                <Area type="monotone" dataKey="suspicious" name="Suspicious" stroke="#f59e0b" fillOpacity={1} fill="url(#colorSuspicious)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      {/* Breakdown Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle>Severity Distribution</CardTitle>
          </CardHeader>
          <CardContent className="h-[250px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={severityDist} dataKey="count" nameKey="severity" cx="50%" cy="50%" innerRadius={60} outerRadius={80} paddingAngle={5}>
                  {severityDist.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry.severity as keyof typeof SEVERITY_COLORS] || '#64748b'} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b' }} />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle>Protocols</CardTitle>
          </CardHeader>
          <CardContent className="h-[250px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={protocolsDist} margin={{ top: 0, right: 0, left: -20, bottom: 0 }} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                <XAxis type="number" stroke="#64748b" fontSize={12} />
                <YAxis dataKey="protocol" type="category" stroke="#64748b" fontSize={12} />
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b' }} />
                <Bar dataKey="count" fill="#8b5cf6" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle>Top Source IPs</CardTitle>
          </CardHeader>
          <CardContent className="h-[250px] overflow-auto">
            <div className="space-y-4">
              {sourcesDist.map((source, i) => (
                <div key={i} className="flex items-center justify-between">
                  <span className="font-mono text-sm text-slate-300">{source.source_ip}</span>
                  <span className="text-sm font-medium">{source.count}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Live Feed */}
      <Card className="bg-slate-900 border-slate-800">
        <CardHeader>
          <CardTitle>Live Flow Feed</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow className="border-slate-800 hover:bg-slate-800/50">
                <TableHead>Time</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Destination</TableHead>
                <TableHead>Protocol</TableHead>
                <TableHead>Packets</TableHead>
                <TableHead>Classification</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {liveFlows.map((flow) => (
                <TableRow key={flow.flow_id} className={`border-slate-800 hover:bg-slate-800/50 transition-colors ${flow.classification !== 'NORMAL' ? 'bg-amber-500/5' : ''}`}>
                  <TableCell className="text-slate-400">{new Date(flow.timestamp).toLocaleTimeString()}</TableCell>
                  <TableCell className="font-mono text-sm">{flow.source_ip}:{flow.source_port}</TableCell>
                  <TableCell className="font-mono text-sm">{flow.destination_ip}:{flow.destination_port}</TableCell>
                  <TableCell>{flow.protocol}</TableCell>
                  <TableCell>{flow.packet_count}</TableCell>
                  <TableCell><ClassificationBadge classification={flow.classification} /></TableCell>
                </TableRow>
              ))}
              {liveFlows.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-slate-500 h-24">Waiting for live flows...</TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
