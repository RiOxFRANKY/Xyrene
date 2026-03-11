import { useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { AppSidebar } from './AppSidebar';
import { Button } from '@/components/ui/button';
import { Play, Square } from 'lucide-react';

const pageTitles: Record<string, string> = {
  '/': 'Dashboard',
  '/live-feed': 'Live Feed',
  '/blocklist': 'Blocklist',
  '/logs': 'Logs',
  '/stats': 'Statistics',
  '/settings': 'Settings',
};

export function DashboardLayout() {
  const [capturing, setCapturing] = useState(true);
  const location = useLocation();
  const title = pageTitles[location.pathname] || 'Dashboard';

  return (
    <div className="flex h-screen w-full overflow-hidden">
      <AppSidebar />
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top bar */}
        <header className="h-14 border-b border-border bg-topbar flex items-center justify-between px-4 shrink-0">
          <div className="flex items-center gap-3">
            <h1 className="text-sm font-semibold text-topbar-foreground">{title}</h1>
            <div className="flex items-center gap-1.5 rounded-full bg-secondary px-2.5 py-1">
              {capturing && (
                <div className="h-1.5 w-1.5 rounded-full bg-zone-safe animate-pulse-dot" />
              )}
              <span className="text-[10px] font-semibold uppercase tracking-wider text-secondary-foreground">
                {capturing ? 'Capturing' : 'Stopped'}
              </span>
            </div>
            <span className="text-[11px] text-muted-foreground font-mono">eth0</span>
          </div>
          <Button
            size="sm"
            variant={capturing ? 'destructive' : 'default'}
            onClick={() => setCapturing(!capturing)}
            className="h-8 text-xs gap-1.5"
          >
            {capturing ? <Square className="h-3 w-3" /> : <Play className="h-3 w-3" />}
            {capturing ? 'Stop Capture' : 'Start Capture'}
          </Button>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-auto p-4">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
