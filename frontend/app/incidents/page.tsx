'use client';

import { AlertTriangle, ShieldCheck } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api-client';

export default function IncidentsPage() {
  const { data: rules, isLoading } = useQuery({
    queryKey: ['rules'],
    queryFn: () => api.getRules(),
  });

  return (
    <div className="p-8 space-y-6 max-w-5xl mx-auto">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Incidents</h1>
        <p className="text-slate-400 mt-1">Correlated security events and broader attack campaigns</p>
      </div>

      <Card className="bg-slate-900 border-slate-800 border-dashed">
        <CardContent className="py-24 text-center flex flex-col items-center">
          <div className="w-16 h-16 bg-emerald-500/10 rounded-full flex items-center justify-center mb-4">
            <ShieldCheck className="h-8 w-8 text-emerald-500" />
          </div>
          <h2 className="text-xl font-semibold mb-2">No incidents detected</h2>
          <p className="text-slate-500 max-w-md">
            The IDS engine has not correlated any isolated alerts into broader incident campaigns. Network traffic is currently behaving normally.
          </p>
        </CardContent>
      </Card>
      
      <Card className="bg-slate-900 border-slate-800">
        <CardHeader>
          <CardTitle>Active Detection Rules</CardTitle>
          <CardDescription>Rules engine is currently monitoring these signatures</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-slate-500">Loading rules...</div>
          ) : (
            <div className="grid gap-2">
              {rules && rules.length > 0 ? (
                rules.map((rule: any, i) => (
                  <div key={i} className="bg-slate-950 p-3 rounded border border-slate-800 text-sm flex justify-between">
                    <span className="font-medium text-slate-300">{rule.name || rule.id || 'Rule'}</span>
                    <span className="text-slate-500">{rule.category || 'Detection'}</span>
                  </div>
                ))
              ) : (
                <div className="text-slate-500 italic">No custom rules loaded. Using default ML baseline.</div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
