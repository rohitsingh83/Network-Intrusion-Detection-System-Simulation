'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Shield, Bell, AlertTriangle, Activity } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';

const navItems = [
  { href: '/', icon: Shield, label: 'Dashboard' },
  { href: '/alerts', icon: Bell, label: 'Alerts' },
  { href: '/incidents', icon: AlertTriangle, label: 'Incidents' },
  { href: '/simulator', icon: Activity, label: 'Simulator' },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <div className="group flex h-screen w-16 flex-col items-center bg-slate-900 border-r border-slate-800 py-4 transition-all duration-300 hover:w-56 hover:items-start z-50">
      <div className="flex h-12 w-full items-center justify-center group-hover:justify-start group-hover:px-4">
        <Shield className="h-8 w-8 text-emerald-500 flex-shrink-0" />
        <span className="ml-3 hidden text-lg font-bold text-slate-100 group-hover:block whitespace-nowrap">
          AegisFlow
        </span>
      </div>
      
      <div className="mt-8 flex w-full flex-col gap-2 px-2">
        {navItems.map((item) => {
          const isActive = pathname === item.href;
          const Icon = item.icon;
          
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex h-12 w-full items-center justify-center group-hover:justify-start group-hover:px-3 rounded-lg transition-colors",
                isActive 
                  ? "bg-emerald-500/10 text-emerald-500" 
                  : "text-slate-400 hover:bg-slate-800 hover:text-slate-100"
              )}
              title={item.label}
            >
              <Icon className="h-6 w-6 flex-shrink-0" />
              <span className="ml-3 hidden font-medium group-hover:block whitespace-nowrap">
                {item.label}
              </span>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
