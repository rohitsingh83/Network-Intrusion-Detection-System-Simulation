'use client';

import { useState, use } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { format } from 'date-fns';
import { ArrowLeft, Send, CheckCircle2, XCircle, Clock, ShieldAlert } from 'lucide-react';
import { useAlert, useUpdateAlertStatus, useAddNote } from '@/hooks/use-alerts';
import { SeverityBadge } from '@/components/dashboard/severity-badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { Textarea } from '@/components/ui/textarea';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { toast } from 'sonner';

export default function ClientPage({ id: initialId }: { id: string }) {
  const router = useRouter();
  const params = useParams();
  const id = (params?.id as string) || initialId;
  
  const { data: alert, isLoading } = useAlert(id);
  const updateStatus = useUpdateAlertStatus();
  const addNote = useAddNote();

  const [newNote, setNewNote] = useState('');
  const [analystName, setAnalystName] = useState('Analyst-1');
  const [noteAction, setNoteAction] = useState('none');

  if (isLoading) return <div className="p-8 text-center text-slate-400">Loading alert details...</div>;
  if (!alert) return <div className="p-8 text-center text-rose-400">Alert not found</div>;

  const handleStatusChange = (status: string) => {
    updateStatus.mutate({ id, status, analyst: analystName }, {
      onSuccess: () => toast.success(`Alert marked as ${status.replace('_', ' ')}`)
    });
  };

  const handleAddNote = () => {
    if (!newNote.trim()) return;
    addNote.mutate({ 
      id, 
      note: newNote, 
      analyst: analystName, 
      action: noteAction === 'none' ? undefined : noteAction 
    }, {
      onSuccess: () => {
        setNewNote('');
        toast.success('Note added');
      }
    });
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center gap-4 text-sm text-slate-400 mb-2 cursor-pointer hover:text-slate-200 w-fit" onClick={() => router.back()}>
        <ArrowLeft className="h-4 w-4" /> Back to Alerts
      </div>

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <h1 className="text-3xl font-bold tracking-tight text-slate-100">{alert.title}</h1>
            <SeverityBadge severity={alert.severity} className="text-sm px-2 py-0.5" />
          </div>
          <p className="text-slate-400">{alert.description}</p>
          <div className="flex items-center gap-4 mt-4 text-sm font-medium">
            <Badge variant="outline" className="border-slate-700 bg-slate-800">
              {alert.status.replace('_', ' ')}
            </Badge>
            <span className="text-slate-500 flex items-center gap-1">
              <Clock className="h-4 w-4" />
              {format(new Date(alert.timestamp), 'PPpp')}
            </span>
          </div>
        </div>

        {/* Triage Panel */}
        <Card className="bg-slate-900 border-slate-800 min-w-[250px]">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm">Triage Actions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Select value={alert.status} onValueChange={(v) => v && handleStatusChange(v)}>
              <SelectTrigger className="w-full bg-slate-950 border-slate-700">
                <SelectValue placeholder="Update Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="NEW">New</SelectItem>
                <SelectItem value="INVESTIGATING">Investigating</SelectItem>
                <SelectItem value="RESOLVED">Resolved</SelectItem>
                <SelectItem value="FALSE_POSITIVE">False Positive</SelectItem>
              </SelectContent>
            </Select>
            <div className="flex gap-2">
              <Button 
                variant="outline" 
                size="sm" 
                className="flex-1 bg-emerald-500/10 text-emerald-500 border-emerald-500/20 hover:bg-emerald-500/20 hover:text-emerald-400"
                onClick={() => handleStatusChange('RESOLVED')}
                disabled={alert.status === 'RESOLVED'}
              >
                <CheckCircle2 className="h-4 w-4 mr-1.5" /> Resolve
              </Button>
              <Button 
                variant="outline" 
                size="sm" 
                className="flex-1 bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700 hover:text-white"
                onClick={() => handleStatusChange('FALSE_POSITIVE')}
                disabled={alert.status === 'FALSE_POSITIVE'}
              >
                <XCircle className="h-4 w-4 mr-1.5" /> False Pos
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Flow Details */}
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle>Network Context</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <div className="text-slate-500 mb-1">Source IP</div>
                <div className="font-mono bg-slate-950 p-2 rounded border border-slate-800">{alert.source_ip}</div>
              </div>
              <div>
                <div className="text-slate-500 mb-1">Source Port</div>
                <div className="font-mono bg-slate-950 p-2 rounded border border-slate-800">{alert.source_port}</div>
              </div>
              <div>
                <div className="text-slate-500 mb-1">Destination IP</div>
                <div className="font-mono bg-slate-950 p-2 rounded border border-slate-800">{alert.destination_ip}</div>
              </div>
              <div>
                <div className="text-slate-500 mb-1">Destination Port</div>
                <div className="font-mono bg-slate-950 p-2 rounded border border-slate-800">{alert.destination_port}</div>
              </div>
              <div>
                <div className="text-slate-500 mb-1">Protocol</div>
                <div className="bg-slate-950 p-2 rounded border border-slate-800">{alert.protocol}</div>
              </div>
              <div>
                <div className="text-slate-500 mb-1">Risk Score</div>
                <div className="bg-slate-950 p-2 rounded border border-slate-800 font-bold text-rose-400">{alert.risk_score}/100</div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Center: Detection */}
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle>Detection Intelligence</CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            <div>
              <div className="text-sm font-medium text-slate-400 mb-3">Triggered Rules</div>
              <div className="flex flex-wrap gap-2">
                {alert.triggered_rules.map((rule, i) => (
                  <Badge key={i} variant="outline" className="bg-rose-500/10 text-rose-400 border-rose-500/20">
                    {rule}
                  </Badge>
                ))}
                {alert.triggered_rules.length === 0 && <span className="text-slate-500 text-sm">No specific rules</span>}
              </div>
            </div>

            <Separator className="bg-slate-800" />
            
            {alert.anomaly_score !== undefined && (
              <div className="space-y-1.5">
                <div className="flex justify-between text-sm">
                  <span className="text-slate-400">Anomaly Score</span>
                  <span className="font-medium">{alert.anomaly_score.toFixed(1)}%</span>
                </div>
                <Progress value={alert.anomaly_score} className="h-2 bg-slate-800 [&_[data-slot=progress-indicator]]:bg-amber-500" />
              </div>
            )}

            {alert.ml_confidence !== undefined && (
              <div className="space-y-1.5">
                <div className="flex justify-between text-sm">
                  <span className="text-slate-400">ML Confidence</span>
                  <span className="font-medium">{(alert.ml_confidence * 100).toFixed(1)}%</span>
                </div>
                <Progress value={alert.ml_confidence * 100} className="h-2 bg-slate-800 [&_[data-slot=progress-indicator]]:bg-cyan-500" />
              </div>
            )}
          </CardContent>
        </Card>

        {/* Right: Actions */}
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-emerald-400" />
              Playbook Actions
            </CardTitle>
          </CardHeader>
          <CardContent>
            {alert.recommended_actions && alert.recommended_actions.length > 0 ? (
              <ul className="space-y-3">
                {alert.recommended_actions.map((action, i) => (
                  <li key={i} className="flex gap-3 text-sm items-start">
                    <div className="flex-shrink-0 w-5 h-5 rounded-full bg-slate-800 flex items-center justify-center text-xs text-slate-400 border border-slate-700 mt-0.5">
                      {i + 1}
                    </div>
                    <span className="text-slate-300">{action}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="text-sm text-slate-500 italic">No specific playbook actions defined.</div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Analyst Notes */}
      <Card className="bg-slate-900 border-slate-800 mt-6">
        <CardHeader>
          <CardTitle>Investigation Timeline</CardTitle>
          <CardDescription>Analyst notes and actions taken</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-6">
            {alert.notes && alert.notes.length > 0 ? (
              <div className="space-y-4">
                {alert.notes.map((note, i) => (
                  <div key={i} className="flex gap-4 border-l-2 border-slate-800 pl-4 py-1">
                    <div className="flex-1 space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-emerald-400">{note.analyst}</span>
                        <span className="text-xs text-slate-500">{format(new Date(note.timestamp), 'MMM d, HH:mm:ss')}</span>
                        {note.action && (
                          <Badge variant="outline" className="text-[10px] h-4 px-1.5 ml-2 border-slate-700">
                            Action: {note.action}
                          </Badge>
                        )}
                      </div>
                      <p className="text-sm text-slate-300">{note.note}</p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-sm text-slate-500 italic py-4">No notes added yet.</div>
            )}

            <Separator className="bg-slate-800" />

            <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-4">
              <div className="flex gap-4">
                <Input 
                  value={analystName} 
                  onChange={e => setAnalystName(e.target.value)}
                  placeholder="Analyst Name" 
                  className="w-48 bg-slate-900 border-slate-700"
                />
                <Select value={noteAction} onValueChange={(v) => v && setNoteAction(v)}>
                  <SelectTrigger className="w-48 bg-slate-900 border-slate-700">
                    <SelectValue placeholder="Action Taken" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">No Action</SelectItem>
                    <SelectItem value="block_ip">Block IP</SelectItem>
                    <SelectItem value="quarantine">Quarantine Host</SelectItem>
                    <SelectItem value="escalate">Escalate to L2</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <Textarea 
                placeholder="Add investigation notes..." 
                className="bg-slate-900 border-slate-700 min-h-[100px]"
                value={newNote}
                onChange={e => setNewNote(e.target.value)}
              />
              <Button onClick={handleAddNote} disabled={addNote.isPending || !newNote.trim()}>
                <Send className="h-4 w-4 mr-2" />
                {addNote.isPending ? 'Posting...' : 'Add Note'}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
