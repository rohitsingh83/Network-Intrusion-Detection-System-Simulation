'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Activity, Play, Square, Settings2 } from 'lucide-react';
import { api } from '@/lib/api-client';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { toast } from 'sonner';

export default function SimulatorPage() {
  const [running, setRunning] = useState(false);
  const [speed, setSpeed] = useState('normal');
  const [duration, setDuration] = useState('60');

  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: () => api.health(),
    refetchInterval: 5000,
  });

  const { data: recentFlows = [] } = useQuery({
    queryKey: ['recent-flows'],
    queryFn: () => api.getFlows({ limit: 10 }),
    refetchInterval: running ? 2000 : 10000,
  });

  const handleStart = async () => {
    setRunning(true);
    toast.success('Simulation started');
    
    // In a real app, we'd make an API call to start the backend generator
    try {
      await fetch(process.env.NEXT_PUBLIC_API_URL + '/api/simulate' || 'http://localhost:8000/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ speed, duration: parseInt(duration) })
      });
    } catch (e) {
      // Ignore if endpoint doesn't exist, just simulate UI
    }

    setTimeout(() => {
      setRunning(false);
      toast.info('Simulation completed');
    }, parseInt(duration) * 1000);
  };

  return (
    <div className="p-8 space-y-6 max-w-6xl mx-auto">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Traffic Simulator</h1>
        <p className="text-slate-400 mt-1">Generate synthetic network traffic to test the IDS engine</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Settings2 className="h-5 w-5" /> Simulator Controls
            </CardTitle>
            <CardDescription>Configure traffic generation parameters</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="space-y-2">
              <label className="text-sm font-medium text-slate-300">Traffic Speed</label>
              <Select value={speed} onValueChange={(v) => v && setSpeed(v)} disabled={running}>
                <SelectTrigger className="bg-slate-950 border-slate-700">
                  <SelectValue placeholder="Select speed" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="slow">Slow (1-5 flows/sec)</SelectItem>
                  <SelectItem value="normal">Normal (10-50 flows/sec)</SelectItem>
                  <SelectItem value="fast">Fast (100+ flows/sec)</SelectItem>
                  <SelectItem value="burst">Burst (Attack Simulation)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium text-slate-300">Duration (seconds)</label>
              <Input 
                type="number" 
                value={duration} 
                onChange={e => setDuration(e.target.value)}
                className="bg-slate-950 border-slate-700"
                disabled={running}
              />
            </div>

            <div className="pt-4 flex gap-4">
              <Button 
                onClick={handleStart} 
                disabled={running}
                className="flex-1 bg-emerald-600 hover:bg-emerald-700"
              >
                <Play className="h-4 w-4 mr-2" /> Start Simulation
              </Button>
              <Button 
                onClick={() => setRunning(false)} 
                disabled={!running}
                variant="destructive"
              >
                <Square className="h-4 w-4 mr-2" /> Stop
              </Button>
            </div>
            
            <p className="text-xs text-slate-500 italic mt-4">
              The simulator generates synthetic RFC 5737 network traffic records for testing the IDS engine.
            </p>
          </CardContent>
        </Card>

        <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-5 w-5" /> Engine Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            {health ? (
              <div className="space-y-4">
                <div className="flex justify-between items-center p-3 bg-slate-950 rounded border border-slate-800">
                  <span className="text-slate-400">Connection Status</span>
                  <span className="text-emerald-400 font-medium flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-emerald-500" /> {health.status}
                  </span>
                </div>
                <div className="flex justify-between items-center p-3 bg-slate-950 rounded border border-slate-800">
                  <span className="text-slate-400">Uptime</span>
                  <span className="font-mono text-sm">{Math.floor(health.uptime_seconds / 3600)}h {Math.floor((health.uptime_seconds % 3600) / 60)}m</span>
                </div>
                <div className="flex justify-between items-center p-3 bg-slate-950 rounded border border-slate-800">
                  <span className="text-slate-400">Active Rules</span>
                  <span>{health.active_rules}</span>
                </div>
                <div className="flex justify-between items-center p-3 bg-slate-950 rounded border border-slate-800">
                  <span className="text-slate-400">ML Engine</span>
                  <span className={health.ml_ready ? 'text-emerald-400' : 'text-amber-400'}>
                    {health.ml_ready ? 'Ready' : 'Training'}
                  </span>
                </div>
              </div>
            ) : (
              <div className="text-center text-slate-500 py-8">Fetching engine status...</div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="bg-slate-900 border-slate-800">
        <CardHeader>
          <CardTitle>Recent Activity Simulator Logs</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {recentFlows.map(flow => (
              <div key={flow.flow_id} className="text-sm font-mono flex gap-4 p-2 bg-slate-950 rounded border border-slate-800 text-slate-300">
                <span className="text-slate-500">{new Date(flow.timestamp).toISOString().split('T')[1].slice(0, -1)}</span>
                <span className="text-blue-400">{flow.source_ip}:{flow.source_port}</span>
                <span className="text-slate-500">→</span>
                <span className="text-purple-400">{flow.destination_ip}:{flow.destination_port}</span>
                <span className="text-amber-400">{flow.protocol}</span>
                <span className="ml-auto text-emerald-500">{flow.byte_count}B</span>
              </div>
            ))}
            {recentFlows.length === 0 && (
              <div className="text-center text-slate-500 py-8">No recent flows detected.</div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
