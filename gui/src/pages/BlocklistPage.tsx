import { useState } from 'react';
import { useBlocklist, blockIp, unblockIp } from '@/hooks/useIDS';
import { ZoneBadge } from '@/components/ZoneBadge';
import { Shield, Plus, X } from 'lucide-react';
import { Button } from '@/components/ui/button';

export default function BlocklistPage() {
  const { data: blocklist, refetch } = useBlocklist();
  const [showModal, setShowModal] = useState(false);
  const [newIP, setNewIP] = useState('');
  const [newHours, setNewHours] = useState('12');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleUnblock = async (ip: string) => {
    try {
      await unblockIp(ip);
      refetch();
    } catch (e) {
      console.error("Failed to unblock", e);
    }
  };

  const handleBlock = async () => {
    if (!newIP) return;
    setIsSubmitting(true);
    try {
      await blockIp(newIP, parseInt(newHours) * 3600); // Send as seconds
      setNewIP('');
      setNewHours('12');
      setShowModal(false);
      refetch();
    } catch (e) {
      console.error("Failed to block", e);
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!blocklist) {
    return <div className="p-4 text-xs text-muted-foreground flex items-center justify-center h-full">Connecting to ML Engine...</div>;
  }

  return (
    <div className="space-y-3 flex flex-col h-[calc(100vh-8rem)]">
      <div className="flex items-center justify-between flex-shrink-0">
        <span className="text-xs text-muted-foreground">{blocklist.length} IPs currently blocked</span>
        <Button size="sm" className="h-8 text-xs gap-1.5" onClick={() => setShowModal(true)}>
          <Plus className="h-3 w-3" /> Block IP
        </Button>
      </div>

      <div className="bg-card border border-border rounded-md overflow-hidden flex flex-col flex-grow min-h-0">
        <div className="overflow-auto flex-grow">
          {blocklist.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
              <Shield className="h-12 w-12 text-muted-foreground mb-3 opacity-20" />
              <span className="text-xs">No IPs currently blocked</span>
            </div>
          ) : (
            <table className="w-full text-[11px]">
              <thead className="sticky top-0 z-10">
                <tr className="border-b border-border text-muted-foreground uppercase tracking-wider bg-secondary/90 backdrop-blur">
                  <th className="text-left px-3 py-2 font-medium">IP Address</th>
                  <th className="text-left px-3 py-2 font-medium">Blocked Since</th>
                  <th className="text-left px-3 py-2 font-medium">Expires</th>
                  <th className="text-left px-3 py-2 font-medium">Zone</th>
                  <th className="text-left px-3 py-2 font-medium">Duration</th>
                  <th className="text-right px-3 py-2 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {blocklist.map((b) => (
                  <tr key={b.ip} className="border-b border-border/50 hover:bg-accent/50 transition-colors">
                    <td className="px-3 py-2 font-mono">{b.ip}</td>
                    <td className="px-3 py-2 font-mono text-muted-foreground">{new Date(b.blocked_since).toLocaleString()}</td>
                    <td className="px-3 py-2 font-mono text-muted-foreground">{new Date(b.expires).toLocaleString()}</td>
                    <td className="px-3 py-2"><ZoneBadge zone={b.zone} /></td>
                    <td className="px-3 py-2 font-mono">{b.duration}</td>
                    <td className="px-3 py-2 text-right">
                      <button
                        onClick={() => handleUnblock(b.ip)}
                        className="inline-flex items-center gap-1 rounded border border-destructive text-destructive px-2 py-0.5 text-[10px] hover:bg-destructive/10 transition-colors"
                      >
                        Unblock
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm">
          <div className="bg-card border border-border rounded-lg p-5 w-96 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold">Block IP Address</h3>
              <button disabled={isSubmitting} onClick={() => setShowModal(false)}>
                <X className="h-4 w-4 text-muted-foreground hover:text-foreground" />
              </button>
            </div>
            <div className="space-y-3">
              <div>
                <label className="text-[11px] text-muted-foreground block mb-1">IP Address</label>
                <input
                  value={newIP}
                  onChange={(e) => setNewIP(e.target.value)}
                  placeholder="e.g. 192.168.1.100"
                  disabled={isSubmitting}
                  className="h-8 w-full rounded-md bg-secondary text-secondary-foreground border border-border px-3 text-xs font-mono placeholder:text-muted-foreground"
                />
              </div>
              <div>
                <label className="text-[11px] text-muted-foreground block mb-1">Duration (hours)</label>
                <input
                  value={newHours}
                  onChange={(e) => setNewHours(e.target.value)}
                  type="number"
                  disabled={isSubmitting}
                  className="h-8 w-full rounded-md bg-secondary text-secondary-foreground border border-border px-3 text-xs font-mono"
                />
              </div>
            </div>
            <div className="flex justify-end gap-2">
              <Button size="sm" variant="ghost" className="h-8 text-xs" disabled={isSubmitting} onClick={() => setShowModal(false)}>Cancel</Button>
              <Button size="sm" className="h-8 text-xs" disabled={isSubmitting || !newIP} onClick={handleBlock}>
                {isSubmitting ? 'Loading...' : 'Block'}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
