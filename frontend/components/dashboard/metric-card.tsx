import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';

interface MetricCardProps {
  title: string;
  value: number | string;
  icon: React.ReactNode;
  color: 'cyan' | 'emerald' | 'amber' | 'rose' | 'violet';
  loading?: boolean;
  subtitle?: string;
}

const colorMaps = {
  cyan: 'text-cyan-400 bg-cyan-500/10',
  emerald: 'text-emerald-400 bg-emerald-500/10',
  amber: 'text-amber-400 bg-amber-500/10',
  rose: 'text-rose-400 bg-rose-500/10',
  violet: 'text-violet-400 bg-violet-500/10',
};

export function MetricCard({ title, value, icon, color, loading, subtitle }: MetricCardProps) {
  return (
    <Card className="bg-slate-900 border-slate-800">
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium text-slate-400">{title}</CardTitle>
        <div className={cn("p-2 rounded-md", colorMaps[color])}>
          {icon}
        </div>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-8 w-24 bg-slate-800" />
        ) : (
          <div className="text-2xl font-bold">{value}</div>
        )}
        {subtitle && (
          <p className="text-xs text-slate-500 mt-1">{subtitle}</p>
        )}
      </CardContent>
    </Card>
  );
}
