import { threatDistribution } from '@/lib/mock-data';
import { useStats, usePackets, useBlocklist, startCapture, stopCapture } from '@/hooks/useIDS';
import { AnimatedNumber } from '@/components/AnimatedNumber';
import { ZoneBadge } from '@/components/ZoneBadge';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { Shield, AlertTriangle, Activity, Bug, Play, Square } from 'lucide-react';
import { useState } from 'react';

export default function DashboardPage() {
  const { data: stats } = useStats();
  const { data: packets } = usePackets();
  const { data: blocklist } = useBlocklist();
  const [isCapturing, setIsCapturing] = useState(false);

  if (!stats || !packets || !blocklist) {
    return <div className="p-4 text-xs text-muted-foreground flex items-center justify-center h-full">Connecting to ML Engine...</div>;
  }

  const handleStart = async () => {
    try {
        await startCapture();
        setIsCapturing(true);
    } catch (e) {
        console.error(e);
    }
  };

  const handleStop = async () => {
    try {
        await stopCapture();
        setIsCapturing(false);
    } catch (e) {
        console.error(e);
    }
  };

  const statCards = [
    { label: 'Total Analyzed', value: stats.total_analyzed, icon: Activity, color: 'text-primary' },
    { label: 'Malicious Caught', value: stats.total_malicious, icon: Bug, color: 'text-zone-malicious', sub: `${stats.total_analyzed ? ((stats.total_malicious / stats.total_analyzed) * 100).toFixed(1) : 0}% of total` },
    { label: 'Blocked IPs', value: stats.total_blocked, icon: Shield, color: 'text-zone-suspicious' },
    { label: 'Threats Today', value: stats.threats_today, icon: AlertTriangle, color: 'text-zone-suspicious' },
  ];

  const recentBlocked = blocklist.slice(0, 5);
  const liveFeed = packets.slice(0, 100);

  return (
    <div className="space-y-4">
      {/* Header with Capture Controls */}
      <div className="flex items-center justify-between bg-card border border-border rounded-md p-3">
        <div className="flex items-center gap-2">
            <div className={`h-2.5 w-2.5 rounded-full ${isCapturing ? 'bg-green-500 animate-pulse' : 'bg-muted-foreground'}`} />
            <span className="text-xs font-semibold">{isCapturing ? 'CAPTURE RUNNING' : 'CAPTURE STOPPED'}</span>
        </div>
        <div className="flex items-center gap-2">
            <button 
                onClick={handleStart} 
                disabled={isCapturing}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-primary/10 text-primary hover:bg-primary/20 disabled:opacity-50 disabled:cursor-not-allowed rounded-md text-[11px] font-medium transition-colors"
            >
                <Play className="h-3 w-3" />
                START CAPTURE
            </button>
            <button 
                onClick={handleStop}
                disabled={!isCapturing}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-destructive/10 text-destructive hover:bg-destructive/20 disabled:opacity-50 disabled:cursor-not-allowed rounded-md text-[11px] font-medium transition-colors"
            >
                <Square className="h-3 w-3" />
                STOP CAPTURE
            </button>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-4 gap-3">
        {statCards.map((s) => (
          <div key={s.label} className="bg-card border border-border rounded-md p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] text-muted-foreground uppercase tracking-wider">{s.label}</span>
              <s.icon className={`h-4 w-4 ${s.color}`} />
            </div>
            <div className={`text-2xl font-bold ${s.color} animate-count-up`}>
              <AnimatedNumber value={s.value} />
            </div>
            {s.sub && <span className="text-[10px] text-muted-foreground">{s.sub}</span>}
          </div>
        ))}
      </div>

      {/* Two columns */}
      <div className="grid grid-cols-5 gap-3">
        {/* Live Feed */}
        <div className="col-span-3 bg-card border border-border rounded-md flex flex-col items-stretch max-h-[520px]">
          <div className="px-3 py-2 border-b border-border flex-shrink-0">
            <span className="text-xs font-semibold text-card-foreground">Live Packet Feed</span>
          </div>
          {liveFeed.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-muted-foreground flex-grow">
               <span className="text-xs">No packets captured yet.</span>
            </div>
          ) : (
            <div className="overflow-auto flex-grow">
              <table className="w-full text-[11px]">
                <thead className="sticky top-0 bg-card z-10">
                  <tr className="border-b border-border text-muted-foreground uppercase tracking-wider">
                    <th className="text-left px-2 py-1.5 font-medium">Time</th>
                    <th className="text-left px-2 py-1.5 font-medium">Src IP</th>
                    <th className="text-left px-2 py-1.5 font-medium">Dst IP</th>
                    <th className="text-left px-2 py-1.5 font-medium">Proto</th>
                    <th className="text-left px-2 py-1.5 font-medium">Verdict</th>
                    <th className="text-right px-2 py-1.5 font-medium">Conf%</th>
                    <th className="text-left px-2 py-1.5 font-medium">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {liveFeed.map((p) => (
                    <tr key={p.id} className="border-b border-border/50 hover:bg-accent/50 transition-colors">
                      <td className="px-2 py-1 font-mono text-muted-foreground">
                        {new Date(p.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="px-2 py-1 font-mono">{p.src_ip}</td>
                      <td className="px-2 py-1 font-mono">{p.dst_ip}</td>
                      <td className="px-2 py-1 font-mono">{p.protocol}</td>
                      <td className="px-2 py-1"><ZoneBadge zone={p.verdict} /></td>
                      <td className="px-2 py-1 text-right font-mono">{p.confidence.toFixed(1)}</td>
                      <td className="px-2 py-1 font-mono text-muted-foreground">{p.action === 'DROP' ? 'BLOCK' : p.action === 'PASS' ? 'ALLOW' : p.action}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right column */}
        <div className="col-span-2 space-y-3">
          {/* Donut */}
          <div className="bg-card border border-border rounded-md p-3">
            <span className="text-xs font-semibold text-card-foreground">Threat Distribution</span>
            <div className="h-48 mt-2">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={[
                      { name: 'BENIGN', value: stats.total_analyzed - stats.total_suspicious - stats.total_malicious - stats.total_critical, color: 'hsl(215, 10%, 45%)' },
                      { name: 'SUSPICIOUS', value: stats.total_suspicious, color: 'hsl(39, 87%, 49%)' },
                      { name: 'MALICIOUS', value: stats.total_malicious, color: 'hsl(0, 93%, 63%)' },
                      { name: 'CRITICAL', value: stats.total_critical, color: 'hsl(0, 93%, 50%)' },
                    ]}
                    innerRadius={50}
                    outerRadius={75}
                    dataKey="value"
                    stroke="none"
                  >
                    {threatDistribution.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: 'hsl(215, 15%, 16%)', border: '1px solid hsl(215, 12%, 20%)', borderRadius: '4px', fontSize: '11px' }}
                    itemStyle={{ color: 'hsl(210, 20%, 90%)' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="flex flex-wrap gap-3 mt-1">
              {threatDistribution.map((t) => (
                <div key={t.name} className="flex items-center gap-1.5">
                  <div className="h-2 w-2 rounded-full" style={{ background: t.color }} />
                  <span className="text-[10px] text-muted-foreground">{t.name}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Recently blocked */}
          <div className="bg-card border border-border rounded-md p-3">
            <span className="text-xs font-semibold text-card-foreground">Recently Blocked IPs</span>
            <div className="mt-2 space-y-1.5">
              {recentBlocked.length === 0 ? (
                <div className="text-xs text-muted-foreground text-center py-4">No recent blocks</div>
              ) : recentBlocked.map((b) => (
                <div key={b.ip} className="flex items-center justify-between text-[11px]">
                  <span className="font-mono">{b.ip}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-muted-foreground">
                      {new Date(b.blocked_since).toLocaleTimeString()}
                    </span>
                    <ZoneBadge zone={b.zone} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
