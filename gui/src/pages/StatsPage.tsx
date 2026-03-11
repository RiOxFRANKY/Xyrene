import { confidenceDistribution } from '@/lib/mock-data';
import { useStats } from '@/hooks/useIDS';
import { AnimatedNumber } from '@/components/AnimatedNumber';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';

export default function StatsPage() {
  const { data: stats } = useStats();

  if (!stats) {
    return <div className="p-4 text-xs text-muted-foreground flex items-center justify-center h-full">Connecting to ML Engine...</div>;
  }

  const metricCards = [
    { label: 'Total Analyzed', value: stats.total_analyzed },
    { label: 'Total Malicious', value: stats.total_malicious },
    { label: 'Total Suspicious', value: stats.total_suspicious },
    { label: 'Total Critical', value: stats.total_critical },
    { label: 'Total Blocked', value: stats.total_blocked },
  ];

  const infoCards = [
    { label: 'False Positive Rate', value: `${stats.false_positive_rate}%` },
    { label: 'Avg Malicious Conf', value: `${stats.avg_malicious_confidence}%` },
    { label: 'Model Version', value: stats.model_version },
    { label: 'API Uptime', value: stats.api_uptime },
  ];

  return (
    <div className="space-y-4 flex flex-col h-[calc(100vh-8rem)]">
      {/* Metric cards */}
      <div className="grid grid-cols-5 gap-3 flex-shrink-0">
        {metricCards.map((m) => (
          <div key={m.label} className="bg-card border border-border rounded-md p-3">
            <span className="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1">{m.label}</span>
            <span className="text-xl font-bold text-foreground">
              <AnimatedNumber value={m.value} />
            </span>
          </div>
        ))}
      </div>

      {/* Info cards */}
      <div className="grid grid-cols-4 gap-3 flex-shrink-0">
        {infoCards.map((m) => (
          <div key={m.label} className="bg-card border border-border rounded-md p-3">
            <span className="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1">{m.label}</span>
            <span className="text-sm font-semibold font-mono text-foreground">{m.value}</span>
          </div>
        ))}
      </div>

      {/* Confidence chart */}
      <div className="bg-card border border-border rounded-md p-4 flex flex-col flex-grow min-h-0">
        <span className="text-xs font-semibold text-card-foreground flex-shrink-0">Confidence Distribution</span>
        <div className="mt-3 flex-grow">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={confidenceDistribution}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(215, 12%, 20%)" />
              <XAxis dataKey="range" tick={{ fontSize: 10, fill: 'hsl(215, 10%, 55%)' }} />
              <YAxis tick={{ fontSize: 10, fill: 'hsl(215, 10%, 55%)' }} />
              <Tooltip
                contentStyle={{ background: 'hsl(215, 15%, 16%)', border: '1px solid hsl(215, 12%, 20%)', borderRadius: '4px', fontSize: '11px' }}
                itemStyle={{ color: 'hsl(210, 20%, 90%)' }}
              />
              <Bar dataKey="count" radius={[2, 2, 0, 0]}>
                {confidenceDistribution.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
