import { useState } from 'react';
import { useSystemLogs } from '@/hooks/useIDS';
import { Download } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

type Tab = 'verdicts' | 'blocks' | 'errors';

export default function LogsPage() {
  const [tab, setTab] = useState<Tab>('verdicts');
  const { data: logsData } = useSystemLogs();

  if (!logsData) {
    return <div className="p-4 text-xs text-muted-foreground flex items-center justify-center h-[calc(100vh-8rem)]">Connecting to ML Engine...</div>;
  }

  const logs = logsData[tab] || [];

  const handleDownload = () => {
    const blob = new Blob([logs.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${tab}-logs.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-3 flex flex-col h-[calc(100vh-8rem)]">
      <div className="flex items-center justify-between flex-shrink-0">
        <div className="flex gap-0.5 bg-secondary rounded-md p-0.5">
          {(['verdicts', 'blocks', 'errors'] as Tab[]).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={cn(
                'px-3 py-1.5 rounded text-xs capitalize transition-colors',
                tab === t ? 'bg-card text-foreground' : 'text-muted-foreground hover:text-foreground'
              )}
            >
              {t}
            </button>
          ))}
        </div>
        <Button size="sm" variant="ghost" className="h-8 text-xs gap-1.5" onClick={handleDownload}>
          <Download className="h-3 w-3" /> Export .txt
        </Button>
      </div>

      <div className="bg-card border border-border rounded-md p-3 flex flex-col flex-grow min-h-0">
        <div className="overflow-auto flex-grow space-y-0.5">
          {logs.length === 0 ? (
            <div className="text-muted-foreground text-[11px] p-4 text-center">No logs available for {tab}.</div>
          ) : (
            logs.map((line, i) => (
              <div key={i} className="font-mono text-[11px] text-secondary-foreground py-0.5 px-2 rounded hover:bg-accent/30 break-all">
                {line}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
