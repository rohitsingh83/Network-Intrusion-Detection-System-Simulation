import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

const colors = {
  NORMAL: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/30',
  SUSPICIOUS: 'bg-amber-500/20 text-amber-400 border-amber-500/30 hover:bg-amber-500/30',
  POTENTIAL_INTRUSION: 'bg-rose-500/20 text-rose-400 border-rose-500/30 hover:bg-rose-500/30',
};

export function ClassificationBadge({ classification, className }: { classification: string, className?: string }) {
  const colorClass = colors[classification as keyof typeof colors] || colors.NORMAL;
  return (
    <Badge variant="outline" className={cn(colorClass, className)}>
      {classification.replace('_', ' ')}
    </Badge>
  );
}
