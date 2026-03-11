import { useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, Activity, Shield, FileText,
  BarChart3, Settings, ChevronLeft, ChevronRight
} from 'lucide-react';
import { cn } from '@/lib/utils';

const navItems = [
  { title: 'Dashboard', path: '/', icon: LayoutDashboard },
  { title: 'Live Feed', path: '/live-feed', icon: Activity },
  { title: 'Blocklist', path: '/blocklist', icon: Shield },
  { title: 'Logs', path: '/logs', icon: FileText },
  { title: 'Stats', path: '/stats', icon: BarChart3 },
  { title: 'Settings', path: '/settings', icon: Settings },
];

export function AppSidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();

  return (
    <aside
      className={cn(
        'flex flex-col border-r border-border bg-sidebar transition-all duration-200 shrink-0',
        collapsed ? 'w-14' : 'w-56'
      )}
    >
      {/* Logo */}
      <div className="flex items-center gap-2 px-3 py-4 border-b border-border h-14">
        <Shield className="h-6 w-6 text-primary shrink-0" />
        {!collapsed && (
          <span className="text-sm font-bold text-foreground tracking-tight">
            Antigravity 3
          </span>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 py-2 space-y-0.5 px-1.5">
        {navItems.map((item) => {
          const active = location.pathname === item.path;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={cn(
                'flex items-center gap-2.5 px-2.5 py-2 rounded-sm text-[13px] transition-colors relative',
                active
                  ? 'bg-sidebar-accent text-primary'
                  : 'text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground'
              )}
            >
              {active && (
                <div className="absolute left-0 top-1 bottom-1 w-[3px] rounded-r bg-primary" />
              )}
              <item.icon className="h-4 w-4 shrink-0" />
              {!collapsed && <span>{item.title}</span>}
            </NavLink>
          );
        })}
      </nav>

      {/* Bottom */}
      <div className="border-t border-border px-3 py-3 space-y-2">
        {/* Connection status */}
        <div className="flex items-center gap-2">
          <div className="h-2 w-2 rounded-full bg-zone-safe animate-pulse-dot" />
          {!collapsed && (
            <span className="text-[11px] text-muted-foreground">API Connected</span>
          )}
        </div>

        {/* Collapse toggle */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="flex items-center gap-2 text-muted-foreground hover:text-foreground transition-colors text-[11px]"
        >
          {collapsed ? <ChevronRight className="h-3.5 w-3.5" /> : <ChevronLeft className="h-3.5 w-3.5" />}
          {!collapsed && <span>Collapse</span>}
        </button>
      </div>
    </aside>
  );
}
