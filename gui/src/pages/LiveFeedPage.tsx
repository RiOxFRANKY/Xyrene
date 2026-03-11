import { useState } from 'react';
import { Zone, Packet } from '@/lib/mock-data';
import { usePackets } from '@/hooks/useIDS';
import { ZoneBadge } from '@/components/ZoneBadge';
import { ChevronRight, ChevronDown, Search } from 'lucide-react';
import { cn } from '@/lib/utils';

const zones: (Zone | 'ALL')[] = ['ALL', 'BENIGN', 'SUSPICIOUS', 'MALICIOUS', 'CRITICAL'];
const borderColors: Record<string, string> = {
  BENIGN: 'border-l-zone-benign',
  SUSPICIOUS: 'border-l-zone-suspicious',
  MALICIOUS: 'border-l-zone-malicious',
  CRITICAL: 'border-l-zone-critical',
};

export default function LiveFeedPage() {
  const { data: packets } = usePackets();
  const [filter, setFilter] = useState<Zone | 'ALL'>('ALL');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);

  if (!packets) {
    return <div className="p-4 text-xs text-muted-foreground">Connecting to ML Engine...</div>;
  }

  const filtered = packets.filter((p) => {
    if (filter !== 'ALL' && p.verdict !== filter) return false;
    if (search && !p.src_ip.includes(search) && !p.dst_ip.includes(search)) return false;
    return true;
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / 50));
  const pageData = filtered.slice(page * 50, (page + 1) * 50);

  return (
    <div className="space-y-3 h-[calc(100vh-8rem)] flex flex-col">
      {/* Filters */}
      <div className="flex items-center gap-3">
        <select
          value={filter}
          onChange={(e) => { setFilter(e.target.value as any); setPage(0); }}
          className="h-8 rounded-md bg-secondary text-secondary-foreground border border-border px-2 text-xs"
        >
          {zones.map((z) => <option key={z} value={z}>{z}</option>)}
        </select>
        <div className="relative">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <input
            placeholder="Search IP..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(0); }}
            className="h-8 rounded-md bg-secondary text-secondary-foreground border border-border pl-7 pr-3 text-xs w-48 placeholder:text-muted-foreground"
          />
        </div>
        <span className="text-[11px] text-muted-foreground ml-auto">{filtered.length} packets</span>
      </div>

      {/* Table - make it flex grow to fill remaining height */}
      <div className="bg-card border border-border rounded-md overflow-hidden flex flex-col flex-grow min-h-0">
        <div className="overflow-auto flex-grow">
          {filtered.length === 0 ? (
            <div className="flex items-center justify-center p-12 text-muted-foreground text-xs">
              No matching packets found.
            </div>
          ) : (
            <table className="w-full text-[11px]">
              <thead className="sticky top-0 z-10">
                <tr className="border-b border-border text-muted-foreground uppercase tracking-wider bg-secondary/90 backdrop-blur">
                  <th className="w-6 py-2" />
                  <th className="text-left px-2 py-2 font-medium">Time</th>
                  <th className="text-left px-2 py-2 font-medium">Src IP</th>
                  <th className="text-left px-2 py-2 font-medium">Dst IP</th>
                  <th className="text-left px-2 py-2 font-medium">Proto</th>
                  <th className="text-left px-2 py-2 font-medium">Length</th>
                  <th className="text-left px-2 py-2 font-medium">Events</th>
                  <th className="text-left px-2 py-2 font-medium">Verdict</th>
                  <th className="text-right px-2 py-2 font-medium">Conf%</th>
                  <th className="text-left px-2 py-2 font-medium">Action</th>
                </tr>
              </thead>
              <tbody>
                {pageData.map((p) => (
                  <PacketRow
                    key={p.id}
                    packet={p}
                    expanded={expanded === p.id}
                    onToggle={() => setExpanded(expanded === p.id ? null : p.id)}
                  />
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between mt-2 flex-shrink-0">
        <span className="text-[11px] text-muted-foreground">
          Page {page + 1} of {totalPages}
        </span>
        <div className="flex gap-1">
          <button
            disabled={page === 0}
            onClick={() => setPage(page - 1)}
            className="h-7 px-2.5 rounded bg-secondary text-xs text-secondary-foreground disabled:opacity-30"
          >
            Prev
          </button>
          <button
            disabled={page >= totalPages - 1}
            onClick={() => setPage(page + 1)}
            className="h-7 px-2.5 rounded bg-secondary text-xs text-secondary-foreground disabled:opacity-30"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}

function PacketRow({ packet: p, expanded, onToggle }: { packet: Packet; expanded: boolean; onToggle: () => void }) {
  return (
    <>
      <tr
        onClick={onToggle}
        className={cn(
          'border-b border-border/50 hover:bg-accent/50 cursor-pointer transition-colors border-l-2',
          borderColors[p.verdict] || 'border-l-transparent'
        )}
      >
        <td className="px-1 py-1.5 flex items-center justify-center">
          {expanded ? <ChevronDown className="h-3 w-3 text-muted-foreground" /> : <ChevronRight className="h-3 w-3 text-muted-foreground" />}
        </td>
        <td className="px-2 py-1.5 font-mono text-muted-foreground">{new Date(p.timestamp).toLocaleTimeString()}</td>
        <td className="px-2 py-1.5 font-mono">{p.src_ip}</td>
        <td className="px-2 py-1.5 font-mono">{p.dst_ip}</td>
        <td className="px-2 py-1.5 font-mono">{p.protocol}</td>
        <td className="px-2 py-1.5 font-mono">{p.length}</td>
        <td className="px-2 py-1.5 font-mono">{p.event_count}</td>
        <td className="px-2 py-1.5"><ZoneBadge zone={p.verdict} /></td>
        <td className="px-2 py-1.5 text-right font-mono">{p.confidence.toFixed(1)}</td>
        <td className="px-2 py-1.5 font-mono text-muted-foreground">{p.action === 'DROP' ? 'BLOCK' : p.action === 'PASS' ? 'ALLOW' : p.action}</td>
      </tr>
      {expanded && (
        <tr className="bg-secondary/30">
          <td colSpan={10} className="px-6 py-3 border-b border-border/50">
            <div className="grid grid-cols-4 gap-4 text-[11px]">
              <div><span className="text-muted-foreground">Packet ID:</span> <br/><span className="font-mono">{p.id}</span></div>
              <div><span className="text-muted-foreground">Confidence:</span> <br/><span className="font-mono">{p.confidence.toFixed(1)}%</span></div>
              <div><span className="text-muted-foreground">IP Event Count:</span> <br/><span className="font-mono">{p.ip_event_count}</span></div>
              <div><span className="text-muted-foreground">Threshold Target:</span> <br/><span className="font-mono">{p.threshold}</span></div>
              <div className="col-span-4"><span className="text-muted-foreground">Timestamp:</span> <span className="font-mono ml-2">{p.timestamp}</span></div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
