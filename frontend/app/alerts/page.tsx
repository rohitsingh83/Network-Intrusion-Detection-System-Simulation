'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { format } from 'date-fns';
import { Bell, Search } from 'lucide-react';
import { useAlerts } from '@/hooks/use-alerts';
import { SeverityBadge } from '@/components/dashboard/severity-badge';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

export default function AlertsPage() {
  const router = useRouter();
  const [severity, setSeverity] = useState('ALL');
  const [status, setStatus] = useState('ALL');
  const [search, setSearch] = useState('');

  const { data: alerts = [], isLoading } = useAlerts({
    severity: severity !== 'ALL' ? severity : undefined,
    status: status !== 'ALL' ? status : undefined,
  });

  const filteredAlerts = alerts.filter(a => 
    search === '' || 
    a.title.toLowerCase().includes(search.toLowerCase()) || 
    a.source_ip.includes(search) || 
    a.destination_ip.includes(search)
  );

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-3xl font-bold tracking-tight">Alert Management</h1>
          <Badge variant="secondary" className="bg-slate-800">{filteredAlerts.length}</Badge>
        </div>
      </div>

      <div className="flex flex-col sm:flex-row gap-4 items-center bg-slate-900/50 p-4 rounded-lg border border-slate-800">
        <div className="relative flex-1 w-full">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
          <Input 
            placeholder="Search alerts by title or IP..." 
            className="pl-9 bg-slate-900 border-slate-700 w-full"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="flex items-center gap-4 w-full sm:w-auto">
          <Select value={severity} onValueChange={(v) => v && setSeverity(v)}>
            <SelectTrigger className="w-[140px] bg-slate-900 border-slate-700">
              <SelectValue placeholder="Severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="ALL">All Severities</SelectItem>
              <SelectItem value="CRITICAL">Critical</SelectItem>
              <SelectItem value="HIGH">High</SelectItem>
              <SelectItem value="MEDIUM">Medium</SelectItem>
              <SelectItem value="LOW">Low</SelectItem>
              <SelectItem value="INFO">Info</SelectItem>
            </SelectContent>
          </Select>
          <Select value={status} onValueChange={(v) => v && setStatus(v)}>
            <SelectTrigger className="w-[140px] bg-slate-900 border-slate-700">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="ALL">All Statuses</SelectItem>
              <SelectItem value="NEW">New</SelectItem>
              <SelectItem value="INVESTIGATING">Investigating</SelectItem>
              <SelectItem value="RESOLVED">Resolved</SelectItem>
              <SelectItem value="FALSE_POSITIVE">False Positive</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="border border-slate-800 rounded-lg bg-slate-900 overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="border-slate-800 hover:bg-slate-800/50 bg-slate-900/80">
              <TableHead>Severity</TableHead>
              <TableHead>Title</TableHead>
              <TableHead>Source</TableHead>
              <TableHead>Destination</TableHead>
              <TableHead>Score</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Time</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={8} className="text-center h-32 text-slate-500">Loading alerts...</TableCell>
              </TableRow>
            ) : filteredAlerts.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="h-48 text-center">
                  <div className="flex flex-col items-center justify-center text-slate-500">
                    <Bell className="h-8 w-8 mb-2 opacity-20" />
                    <p>No alerts found matching your criteria</p>
                  </div>
                </TableCell>
              </TableRow>
            ) : (
              filteredAlerts.map(alert => (
                <TableRow 
                  key={alert.alert_id} 
                  className="border-slate-800 hover:bg-slate-800/50 cursor-pointer transition-colors"
                  onClick={() => router.push(`/alerts/${alert.alert_id}`)}
                >
                  <TableCell><SeverityBadge severity={alert.severity} /></TableCell>
                  <TableCell className="font-medium text-slate-200">{alert.title}</TableCell>
                  <TableCell className="font-mono text-sm">{alert.source_ip}</TableCell>
                  <TableCell className="font-mono text-sm">{alert.destination_ip}</TableCell>
                  <TableCell>{alert.risk_score}</TableCell>
                  <TableCell>
                    <Badge variant="outline" className={`
                      ${alert.status === 'NEW' ? 'text-blue-400 border-blue-400/30' : ''}
                      ${alert.status === 'INVESTIGATING' ? 'text-purple-400 border-purple-400/30' : ''}
                      ${alert.status === 'RESOLVED' ? 'text-emerald-400 border-emerald-400/30' : ''}
                      ${alert.status === 'FALSE_POSITIVE' ? 'text-slate-400 border-slate-400/30' : ''}
                    `}>
                      {alert.status.replace('_', ' ')}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-slate-400 text-sm whitespace-nowrap">
                    {format(new Date(alert.timestamp), 'MMM d, HH:mm:ss')}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="sm" className="text-slate-400 hover:text-white" onClick={(e) => { e.stopPropagation(); router.push(`/alerts/${alert.alert_id}`); }}>
                      Investigate
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
