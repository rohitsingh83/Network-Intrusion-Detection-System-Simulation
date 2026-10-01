import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

const colors = {
  CRITICAL: 'bg-rose-500/20 text-rose-400 border-rose-500/30 hover:bg-rose-500/30',
  HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/30 hover:bg-orange-500/30',
  MEDIUM: 'bg-amber-500/20 text-amber-400 border-amber-500/30 hover:bg-amber-500/30',
  LOW: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30 hover:bg-cyan-500/30',
  INFO: 'bg-slate-500/20 text-slate-400 border-slate-500/30 hover:bg-slate-500/30',
};

export function SeverityBadge({ severity, className }: { severity: string, className?: string }) {
  const colorClass = colors[severity as keyof typeof colors] || colors.INFO;
  return (
    <Badge variant="outline" className={cn(colorClass, className)}>
      {severity}
    </Badge>
  );
}
